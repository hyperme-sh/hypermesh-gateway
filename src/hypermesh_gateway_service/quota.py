"""Request ceiling on this door. The edge is not on the chat hop.

A lease ticket is the grant, not a rate card. Until Contract.meters exists,
the door still refuses a flood: per-lease request rate and optional byte quota.
"""

from __future__ import annotations

import os
import time
import uuid


class QuotaExceeded(Exception):
    """Door refused the completion. Routes map this to HTTP 429."""

    def __init__(self, detail: str) -> None:
        super().__init__(detail)
        self.detail = detail


class ChatQuota:
    """In-process per-lease ceiling. Survives only as long as this door process."""

    def __init__(
        self,
        *,
        rate_limit: int = 60,
        window_s: float = 60.0,
        bytes_quota: int = 0,
    ) -> None:
        if rate_limit < 1:
            raise ValueError("rate_limit must be at least 1")
        if window_s <= 0:
            raise ValueError("window_s must be positive")
        if bytes_quota < 0:
            raise ValueError("bytes_quota must be >= 0")
        self._rate_limit = rate_limit
        self._window_s = float(window_s)
        self._bytes_quota = bytes_quota
        self._hits: dict[uuid.UUID, list[float]] = {}
        self._bytes: dict[uuid.UUID, int] = {}

    def allow(
        self,
        lease_id: uuid.UUID,
        *,
        now: float | None = None,
        incoming_bytes: int = 0,
    ) -> None:
        """Count this request. Raise before the host hop if the lease is over."""

        clock = time.monotonic() if now is None else now
        hits = self._hits.setdefault(lease_id, [])
        cutoff = clock - self._window_s
        hits[:] = [stamp for stamp in hits if stamp > cutoff]
        if len(hits) >= self._rate_limit:
            raise QuotaExceeded("rate limited")
        used = self._bytes.get(lease_id, 0)
        extra = max(0, int(incoming_bytes))
        if self._bytes_quota > 0 and used + extra > self._bytes_quota:
            raise QuotaExceeded("quota exceeded")
        hits.append(clock)

    def add_bytes(self, lease_id: uuid.UUID, total: int) -> None:
        if total <= 0:
            return
        self._bytes[lease_id] = self._bytes.get(lease_id, 0) + int(total)

    def used_bytes(self, lease_id: uuid.UUID) -> int:
        return self._bytes.get(lease_id, 0)


def resolve_chat_quota() -> ChatQuota:
    rate = int(os.environ.get("HYPERMESH_CHAT_RATE_LIMIT", "60"))
    window = float(os.environ.get("HYPERMESH_CHAT_RATE_WINDOW_S", "60"))
    bytes_quota = int(os.environ.get("HYPERMESH_CHAT_BYTES_QUOTA", "0"))
    return ChatQuota(rate_limit=rate, window_s=window, bytes_quota=bytes_quota)
