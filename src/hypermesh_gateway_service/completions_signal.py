"""Per-lease signal for the host completions path.

This does not send a chat completion and it does not decide whether the
gateway process is up. /ready stays process health.
"""

from __future__ import annotations

import os
import time
import uuid

import httpx

from hypermesh_gateway_service.chat import CHAT_PATH, chat_upstream_port, client_ip

SIGNAL_INTERVAL_ENV = "HYPERMESH_COMPLETIONS_SIGNAL_INTERVAL_S"
DEFAULT_INTERVAL_S = 30.0
_REACH_TIMEOUT = httpx.Timeout(connect=2.0, read=2.0, write=2.0, pool=2.0)


class CompletionsSignalCache:
    """Last reachability result per lease. A fresh row skips another probe."""

    def __init__(self) -> None:
        self._rows: dict[tuple[uuid.UUID, uuid.UUID], tuple[float, str]] = {}

    def fresh(
        self,
        tenant_id: uuid.UUID,
        lease_id: uuid.UUID,
        *,
        interval_s: float,
        now: float | None = None,
    ) -> str | None:
        row = self._rows.get((tenant_id, lease_id))
        if row is None or interval_s <= 0:
            return None
        recorded_at, state = row
        clock = time.monotonic() if now is None else now
        if clock - recorded_at >= interval_s:
            return None
        return state

    def store(self, tenant_id: uuid.UUID, lease_id: uuid.UUID, state: str) -> None:
        self._rows[(tenant_id, lease_id)] = (time.monotonic(), state)


def signal_cache(app_state: object) -> CompletionsSignalCache:
    cache = getattr(app_state, "completions_signals", None)
    if not isinstance(cache, CompletionsSignalCache):
        cache = CompletionsSignalCache()
        setattr(app_state, "completions_signals", cache)
    return cache


def signal_interval_s() -> float:
    raw = os.environ.get(SIGNAL_INTERVAL_ENV, "").strip()
    if not raw:
        return DEFAULT_INTERVAL_S
    try:
        return float(raw)
    except ValueError:
        return DEFAULT_INTERVAL_S


async def completions_route_reachable(
    client_address: str | None,
    *,
    runtime_client: httpx.AsyncClient | None = None,
) -> bool:
    """True when host:8080 answers on the completions path.

    GET only. No message body, so this does not spend a generation.
    """

    if not client_address or not client_ip(client_address):
        return False
    url = f"http://{client_ip(client_address)}:{chat_upstream_port()}{CHAT_PATH}"
    owned: httpx.AsyncClient | None = None
    client = runtime_client
    if client is None:
        owned = httpx.AsyncClient(timeout=_REACH_TIMEOUT)
        client = owned
    try:
        try:
            response = await client.get(url)
        except httpx.HTTPError:
            return False
        return response.status_code < 500
    finally:
        if owned is not None:
            await owned.aclose()
