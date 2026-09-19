"""Tunnel/session metrics to Panopticon. No prompt body. Ever.

Completions stay on this gateway. Control plane gets ids and counters only.
"""

from __future__ import annotations

import logging
import uuid
from typing import Any

from hypermesh_gateway_service.control_plane import ControlPlane

logger = logging.getLogger(__name__)

METRIC_KEYS = frozenset({"tunnel_id", "lease_id", "bytes_in", "bytes_out", "handshake_count"})
_FORBIDDEN = ("prompt", "message", "messages", "completion", "content", "weight")


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


async def report_session_metrics(
    plane: ControlPlane,
    tenant_id: uuid.UUID,
    *,
    tunnel_id: uuid.UUID | None,
    lease_id: uuid.UUID | None,
    bytes_in: int,
    bytes_out: int,
    handshake_count: int = 0,
) -> None:
    """Best-effort POST to Panopticon. Chat does not fail if this hop is quiet."""

    payload = sanitize_metric_payload(
        tunnel_id=tunnel_id,
        lease_id=lease_id,
        bytes_in=bytes_in,
        bytes_out=bytes_out,
        handshake_count=handshake_count,
    )
    try:
        await plane.post_metrics(tenant_id, **payload)
    except Exception:
        logger.info("metrics post skipped")
