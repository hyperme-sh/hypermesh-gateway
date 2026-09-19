"""IR door receipts. Customer artifact. Not a Fyber product event.

Held on this door. Human-exportable into a ticket or SIEM.
Fields: who, why, what left, class, allow/hold, time.
No prompt body. No completion body. Never publish on Azure Monitor,
Service Bus, or hypermesh.* events.
"""

from __future__ import annotations

import json
import os
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal

Decision = Literal["allow", "hold"]

RECEIPT_KEYS = frozenset(
    {
        "receipt_id",
        "who",
        "why",
        "what_left",
        "class",
        "decision",
        "time",
        "lease_id",
        "tenant_id",
    }
)
_MAX_RECEIPTS = 10_000


@dataclass(frozen=True)
class Receipt:
    receipt_id: uuid.UUID
    who: str
    why: str
    what_left: str
    prompt_class: str
    decision: Decision
    time: datetime
    lease_id: uuid.UUID
    tenant_id: uuid.UUID

    def as_export(self) -> dict[str, str]:
        """Customer export row. No prompt or completion body."""

        return sanitize_receipt_payload(
            {
                "receipt_id": str(self.receipt_id),
                "who": self.who,
                "why": self.why,
                "what_left": self.what_left,
                "class": self.prompt_class,
                "decision": self.decision,
                "time": self.time.astimezone(UTC).isoformat().replace("+00:00", "Z"),
                "lease_id": str(self.lease_id),
                "tenant_id": str(self.tenant_id),
            }
        )


def sanitize_receipt_payload(payload: dict[str, Any]) -> dict[str, str]:
    """Keep the lock fields only. Never copy prompt or completion bodies."""

    cleaned: dict[str, str] = {}
    for key in (
        "receipt_id",
        "who",
        "why",
        "what_left",
        "class",
        "decision",
        "time",
        "lease_id",
        "tenant_id",
    ):
        if key not in payload:
            continue
        cleaned[key] = str(payload[key])
    return cleaned


class ReceiptStore:
    """Tenant-scoped receipts on this door. Not the product event bus.

    Optional JSON file persist so a bounce does not drop customer receipts.
    The file holds sanitized export rows only — never prompt or completion bodies.
    """

    def __init__(self, persist_path: str | os.PathLike[str] | None = None) -> None:
        self._path = Path(persist_path) if persist_path else None
        self._rows: dict[uuid.UUID, list[Receipt]] = {}
        if self._path is not None:
            self._load()

    def record(
        self,
        *,
        tenant_id: uuid.UUID,
        lease_id: uuid.UUID,
        who: str,
        why: str,
        what_left: str,
        prompt_class: str,
        decision: Decision,
        now: datetime | None = None,
    ) -> Receipt:
        receipt = Receipt(
            receipt_id=uuid.uuid4(),
            who=who,
            why=why,
            what_left=what_left,
            prompt_class=prompt_class,
            decision=decision,
            time=now if now is not None else datetime.now(UTC),
            lease_id=lease_id,
            tenant_id=tenant_id,
        )
        bucket = self._rows.setdefault(tenant_id, [])
        bucket.append(receipt)
        overflow = len(bucket) - _MAX_RECEIPTS
        if overflow > 0:
            del bucket[:overflow]
        self._flush()
        return receipt

    def export_for(self, tenant_id: uuid.UUID) -> list[dict[str, str]]:
        rows = list(self._rows.get(tenant_id, ()))
        return [row.as_export() for row in rows]

    def count_for(self, tenant_id: uuid.UUID) -> int:
        return len(self._rows.get(tenant_id, ()))

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
            cleaned = sanitize_receipt_payload(item)
            if set(cleaned) != RECEIPT_KEYS:
                continue
            try:
                receipt = Receipt(
                    receipt_id=uuid.UUID(cleaned["receipt_id"]),
                    who=cleaned["who"],
                    why=cleaned["why"],
                    what_left=cleaned["what_left"],
                    prompt_class=cleaned["class"],
                    decision=cleaned["decision"],  # type: ignore[arg-type]
                    time=datetime.fromisoformat(cleaned["time"].replace("Z", "+00:00")),
                    lease_id=uuid.UUID(cleaned["lease_id"]),
                    tenant_id=uuid.UUID(cleaned["tenant_id"]),
                )
            except (ValueError, KeyError):
                continue
            if receipt.decision not in {"allow", "hold"}:
                continue
            bucket = self._rows.setdefault(receipt.tenant_id, [])
            bucket.append(receipt)
        for tenant_id, bucket in self._rows.items():
            overflow = len(bucket) - _MAX_RECEIPTS
            if overflow > 0:
                del bucket[:overflow]
            self._rows[tenant_id] = bucket

    def _flush(self) -> None:
        if self._path is None:
            return
        rows: list[dict[str, str]] = []
        for bucket in self._rows.values():
            rows.extend(row.as_export() for row in bucket)
        self._path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self._path.with_suffix(self._path.suffix + ".tmp")
        tmp.write_text(json.dumps(rows, indent=2), encoding="utf-8")
        tmp.replace(self._path)


def resolve_receipt_store(path: str | os.PathLike[str] | None = None) -> ReceiptStore:
    persist = path if path is not None else os.environ.get("HYPERMESH_IR_RECEIPT_PATH")
    if persist is not None and str(persist).strip() == "":
        persist = None
    return ReceiptStore(persist_path=persist)
