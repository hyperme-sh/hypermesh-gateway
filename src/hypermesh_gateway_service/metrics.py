"""Tunnel/session metrics to spanopticon. No prompt body. Ever.

Completions stay on this gateway. Control plane gets ids and counters only.
A failed hop queues the counters on this door and retries. Chat still
returns; usage does not vanish.
"""

from __future__ import annotations

import json
import logging
import os
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from hypermesh_gateway_service.control_plane import ControlPlane
from hypermesh_gateway_service.quota import ChatQuota

logger = logging.getLogger(__name__)

METRIC_KEYS = frozenset({"tunnel_id", "lease_id", "bytes_in", "bytes_out", "handshake_count"})
QUEUE_KEYS = frozenset(
    {
        "metric_id",
        "tenant_id",
        "tunnel_id",
        "lease_id",
        "bytes_in",
        "bytes_out",
        "handshake_count",
        "recorded_at",
    }
)
_FORBIDDEN = ("prompt", "message", "messages", "completion", "content", "weight")
_MAX_PENDING = 10_000


class MeterQueueFull(Exception):
    """Door cannot accept more unbilled usage. Routes map this to HTTP 429."""


@dataclass(frozen=True)
class PendingMetric:
    metric_id: uuid.UUID
    tenant_id: uuid.UUID
    tunnel_id: uuid.UUID | None
    lease_id: uuid.UUID | None
    bytes_in: int
    bytes_out: int
    handshake_count: int
    recorded_at: datetime

    def as_export(self) -> dict[str, Any]:
        return sanitize_queue_payload(
            {
                "metric_id": str(self.metric_id),
                "tenant_id": str(self.tenant_id),
                "tunnel_id": str(self.tunnel_id) if self.tunnel_id else None,
                "lease_id": str(self.lease_id) if self.lease_id else None,
                "bytes_in": self.bytes_in,
                "bytes_out": self.bytes_out,
                "handshake_count": self.handshake_count,
                "recorded_at": self.recorded_at.astimezone(UTC).isoformat().replace("+00:00", "Z"),
            }
        )


def sanitize_metric_payload(
    *,
    tunnel_id: uuid.UUID | None,
    lease_id: uuid.UUID | None,
    bytes_in: int,
    bytes_out: int,
    handshake_count: int,
) -> dict[str, Any]:
    """Session/tunnel counters only. Drop anything that looks like a prompt."""

    payload: dict[str, Any] = {
        "tunnel_id": tunnel_id,
        "lease_id": lease_id,
        "bytes_in": max(0, int(bytes_in)),
        "bytes_out": max(0, int(bytes_out)),
        "handshake_count": max(0, int(handshake_count)),
    }
    extra = set(payload) - METRIC_KEYS
    for key in extra:
        payload.pop(key, None)
    blob = str(payload).lower()
    if any(token in blob for token in _FORBIDDEN):
        logger.info("metrics dropped (payload not session-only)")
        return {
            "tunnel_id": tunnel_id,
            "lease_id": lease_id,
            "bytes_in": 0,
            "bytes_out": 0,
            "handshake_count": 0,
        }
    return payload


def sanitize_queue_payload(payload: dict[str, Any]) -> dict[str, Any]:
    """Lock fields only. Never copy prompt or completion bodies onto disk."""

    cleaned: dict[str, Any] = {}
    for key in (
        "metric_id",
        "tenant_id",
        "tunnel_id",
        "lease_id",
        "bytes_in",
        "bytes_out",
        "handshake_count",
        "recorded_at",
    ):
        if key not in payload:
            continue
        value = payload[key]
        if key in {"bytes_in", "bytes_out", "handshake_count"}:
            cleaned[key] = max(0, int(value))
        elif key in {"tunnel_id", "lease_id"} and value in (None, ""):
            cleaned[key] = None
        else:
            cleaned[key] = str(value)
    blob = str(cleaned).lower()
    if any(token in blob for token in _FORBIDDEN):
        return {}
    return cleaned


class MeterQueue:
    """Pending usage on this door. File persist so a bounce does not drop counters."""

    def __init__(
        self,
        persist_path: str | os.PathLike[str] | None = None,
        *,
        max_pending: int = _MAX_PENDING,
    ) -> None:
        if max_pending < 1:
            raise ValueError("max_pending must be at least 1")
        self._path = Path(persist_path) if persist_path else None
        self._max = max_pending
        self._rows: dict[uuid.UUID, PendingMetric] = {}
        if self._path is not None:
            self._load()

    def is_full(self) -> bool:
        return len(self._rows) >= self._max

    def pending_count(self) -> int:
        return len(self._rows)

    def pending(self) -> list[PendingMetric]:
        return list(self._rows.values())

    def enqueue(
        self,
        *,
        tenant_id: uuid.UUID,
        tunnel_id: uuid.UUID | None,
        lease_id: uuid.UUID | None,
        bytes_in: int,
        bytes_out: int,
        handshake_count: int,
        metric_id: uuid.UUID | None = None,
        now: datetime | None = None,
    ) -> PendingMetric:
        if self.is_full():
            raise MeterQueueFull("usage queue is full")
        item = PendingMetric(
            metric_id=metric_id or uuid.uuid4(),
            tenant_id=tenant_id,
            tunnel_id=tunnel_id,
            lease_id=lease_id,
            bytes_in=max(0, int(bytes_in)),
            bytes_out=max(0, int(bytes_out)),
            handshake_count=max(0, int(handshake_count)),
            recorded_at=now if now is not None else datetime.now(UTC),
        )
        self._rows[item.metric_id] = item
        self._flush()
        return item

    def ack(self, metric_id: uuid.UUID) -> None:
        if metric_id in self._rows:
            del self._rows[metric_id]
            self._flush()

    def _load(self) -> None:
        if self._path is None or not self._path.is_file():
            return
        try:
            raw = json.loads(self._path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return
        if not isinstance(raw, list):
            return
        for item in raw:
            if not isinstance(item, dict):
                continue
            cleaned = sanitize_queue_payload(item)
            if set(cleaned) != QUEUE_KEYS:
                continue
            try:
                tunnel_raw = cleaned["tunnel_id"]
                lease_raw = cleaned["lease_id"]
                pending = PendingMetric(
                    metric_id=uuid.UUID(str(cleaned["metric_id"])),
                    tenant_id=uuid.UUID(str(cleaned["tenant_id"])),
                    tunnel_id=uuid.UUID(str(tunnel_raw)) if tunnel_raw else None,
                    lease_id=uuid.UUID(str(lease_raw)) if lease_raw else None,
                    bytes_in=int(cleaned["bytes_in"]),
                    bytes_out=int(cleaned["bytes_out"]),
                    handshake_count=int(cleaned["handshake_count"]),
                    recorded_at=datetime.fromisoformat(
                        str(cleaned["recorded_at"]).replace("Z", "+00:00")
                    ),
                )
            except (ValueError, KeyError, TypeError):
                continue
            self._rows[pending.metric_id] = pending
        overflow = len(self._rows) - self._max
        if overflow > 0:
            # Refuse to evict billable rows. Drop the load of extras only if
            # the file was written over the cap (should not happen).
            extra = list(self._rows)[self._max :]
            for metric_id in extra:
                del self._rows[metric_id]

    def _flush(self) -> None:
        if self._path is None:
            return
        rows = [item.as_export() for item in self._rows.values()]
        self._path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self._path.with_suffix(self._path.suffix + ".tmp")
        tmp.write_text(json.dumps(rows, indent=2), encoding="utf-8")
        tmp.replace(self._path)


def resolve_meter_queue(path: str | os.PathLike[str] | None = None) -> MeterQueue:
    persist = path if path is not None else os.environ.get("HYPERMESH_METER_QUEUE_PATH")
    if persist is not None and str(persist).strip() == "":
        persist = None
    raw_max = os.environ.get("HYPERMESH_METER_QUEUE_MAX", "").strip()
    max_pending = int(raw_max) if raw_max else _MAX_PENDING
    return MeterQueue(persist_path=persist, max_pending=max_pending)


async def flush_meter_queue(plane: ControlPlane, queue: MeterQueue) -> int:
    """Deliver oldest pending first. Stop on the first hop failure."""

    sent = 0
    for item in queue.pending():
        try:
            await plane.post_metrics(
                item.tenant_id,
                tunnel_id=item.tunnel_id,
                lease_id=item.lease_id,
                bytes_in=item.bytes_in,
                bytes_out=item.bytes_out,
                handshake_count=item.handshake_count,
                metric_id=item.metric_id,
            )
        except Exception:
            logger.info("metrics flush deferred")
            break
        queue.ack(item.metric_id)
        sent += 1
    return sent


async def report_session_metrics(
    plane: ControlPlane,
    tenant_id: uuid.UUID,
    queue: MeterQueue,
    *,
    tunnel_id: uuid.UUID | None,
    lease_id: uuid.UUID | None,
    bytes_in: int,
    bytes_out: int,
    handshake_count: int = 0,
    quota: ChatQuota | None = None,
) -> None:
    """Queue first, then POST. Chat callers ignore hop failures."""

    payload = sanitize_metric_payload(
        tunnel_id=tunnel_id,
        lease_id=lease_id,
        bytes_in=bytes_in,
        bytes_out=bytes_out,
        handshake_count=handshake_count,
    )
    item = queue.enqueue(tenant_id=tenant_id, **payload)
    if quota is not None and lease_id is not None:
        quota.add_bytes(lease_id, item.bytes_in + item.bytes_out)
    try:
        await plane.post_metrics(
            tenant_id,
            metric_id=item.metric_id,
            **payload,
        )
    except Exception:
        logger.info("metrics post queued")
        return
    queue.ack(item.metric_id)
    await flush_meter_queue(plane, queue)
