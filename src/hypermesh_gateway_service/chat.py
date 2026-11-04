"""OpenAI-shaped renter chat proxy. Never log prompts or keys.

Chat path is renter HTTPS → this gateway → the host over the standing
WireGuard peer. No (s)panopticon HTTP, no get_lease, no Service Bus.

The door streams the host body. It does not buffer response.json().
"""

from __future__ import annotations

import json
import logging
import os
import secrets
import uuid
from collections.abc import AsyncIterator
from dataclasses import dataclass, field
from typing import Any

import httpx
from pydantic import BaseModel, Field

from hypermesh_gateway_service.control_plane import (
    INSTANCE_NOT_READY,  # noqa: F401 (re-exported)
)
from hypermesh_gateway_service.errors import instance_not_ready

logger = logging.getLogger(__name__)

CHAT_PORT = 8080
CHAT_PATH = "/v1/chat/completions"
CHAT_PORT_ENV = "HYPERMESH_CHAT_UPSTREAM_PORT"
CHAT_READ_TIMEOUT_ENV = "HYPERMESH_CHAT_READ_TIMEOUT_S"


def chat_timeout() -> httpx.Timeout:
    """Streaming read budget. Connect/pool stay short; the body may run long.

    ``HYPERMESH_CHAT_READ_TIMEOUT_S`` defaults to 1800, matching the host
    ``LLAMA_ARG_TIMEOUT`` and the HAProxy timeouts in infra#130. ``none``
    waits on the host with no read limit. The edge timeout in front of this
    process is owned by infra and is not set here.
    """

    raw = os.environ.get(CHAT_READ_TIMEOUT_ENV, "1800").strip().lower()
    read: float | None
    if raw in {"", "none", "off", "inf", "infinite"}:
        read = None
    else:
        try:
            read = float(raw)
        except ValueError:
            read = 1800.0
        if read <= 0:
            read = None
    return httpx.Timeout(connect=10.0, read=read, write=60.0, pool=10.0)


def chat_upstream_port() -> int:
    """Standing WG peer port. Override only for hermetic mock-host tests."""

    raw = os.environ.get(CHAT_PORT_ENV, "").strip()
    if not raw:
        return CHAT_PORT
    try:
        port = int(raw)
    except ValueError:
        return CHAT_PORT
    if not (1 <= port <= 65535):
        return CHAT_PORT
    return port


class ChatCompletionRequest(BaseModel):
    lease_id: uuid.UUID | None = None
    model: str | None = Field(default=None, max_length=128)
    messages: list[dict[str, Any]] = Field(default_factory=list)

    model_config = {"extra": "allow"}


def client_ip(client_address: str) -> str:
    return client_address.split("/", 1)[0]


@dataclass
class ProxiedChat:
    """Open upstream response. Bytes pass through; the door does not parse them."""

    response: httpx.Response
    _owned_client: httpx.AsyncClient | None = None
    bytes_out: int = 0
    _closed: bool = field(default=False, init=False, repr=False)

    @property
    def media_type(self) -> str:
        return self.response.headers.get("content-type") or "application/json"

    async def iter_bytes(self) -> AsyncIterator[bytes]:
        try:
            async for chunk in self.response.aiter_bytes():
                if chunk:
                    self.bytes_out += len(chunk)
                    yield chunk
        finally:
            await self.aclose()

    async def aclose(self) -> None:
        if self._closed:
            return
        self._closed = True
        await self.response.aclose()
        if self._owned_client is not None:
            await self._owned_client.aclose()


async def proxy_chat(
    *,
    lease_id: uuid.UUID,
    payload: dict[str, Any],
    client_address: str | None,
    runtime_client: httpx.AsyncClient | None = None,
) -> ProxiedChat:
    if not client_address:
        raise instance_not_ready("no_tunnel_address")
    url = f"http://{client_ip(client_address)}:{chat_upstream_port()}{CHAT_PATH}"
    logger.info("proxy chat lease_id=%s", lease_id)
    body = dict(payload)
    body.pop("lease_id", None)
    owned: httpx.AsyncClient | None = None
    client = runtime_client
    if client is None:
        owned = httpx.AsyncClient(timeout=chat_timeout())
        client = owned
    try:
        request = client.build_request("POST", url, json=body)
        response = await client.send(request, stream=True)
    except httpx.HTTPError:
        if owned is not None:
            await owned.aclose()
        logger.info("proxy chat upstream unreachable lease_id=%s", lease_id)
        raise instance_not_ready("host_unreachable") from None
    if response.status_code >= 400:
        upstream_status = response.status_code
        await response.aread()
        await response.aclose()
        if owned is not None:
            await owned.aclose()
        # llama-server answers 503 while it is still loading the model.
        logger.info("proxy chat upstream status=%s lease_id=%s", upstream_status, lease_id)
        raise instance_not_ready(f"host_status_{upstream_status}")
    return ProxiedChat(response=response, _owned_client=owned)


def _new_tool_call_id() -> str:
    return "call_" + secrets.token_hex(12)


def fill_tool_call_ids(payload: dict[str, Any], ids: dict[int, str]) -> bool:
    """Fill blank tool_calls[].id. The same index keeps the same id."""

    changed = False
    choices = payload.get("choices")
    if not isinstance(choices, list):
        return False
    for choice in choices:
        if not isinstance(choice, dict):
            continue
        for key in ("message", "delta"):
            message = choice.get(key)
            if not isinstance(message, dict):
                continue
            calls = message.get("tool_calls")
            if not isinstance(calls, list):
                continue
            for position, call in enumerate(calls):
                if not isinstance(call, dict):
                    continue
                raw_index = call.get("index", position)
                try:
                    index = int(raw_index)
                except (TypeError, ValueError):
                    index = position
                current = call.get("id")
                if isinstance(current, str) and current.strip():
                    ids[index] = current
                    continue
                filled = ids.get(index) or _new_tool_call_id()
                ids[index] = filled
                call["id"] = filled
                changed = True
    return changed


class SseToolCallIds:
    """Rewrite ``data:`` lines that carry a tool_calls delta. Hold only a partial line."""

    def __init__(self) -> None:
        self._pending = b""
        self._ids: dict[int, str] = {}

    def feed(self, chunk: bytes) -> bytes:
        self._pending += chunk
        out = bytearray()
        while True:
            newline = self._pending.find(b"\n")
            if newline < 0:
                break
            line = self._pending[: newline + 1]
            self._pending = self._pending[newline + 1 :]
            out += self._rewrite_line(line)
        return bytes(out)

    def flush(self) -> bytes:
        if not self._pending:
            return b""
        line = self._pending
        self._pending = b""
        return self._rewrite_line(line)

    def _rewrite_line(self, line: bytes) -> bytes:
        if b"tool_calls" not in line:
            return line
        stripped = line.strip()
        if not stripped.startswith(b"data:"):
            return line
        raw = stripped[5:].strip()
        if not raw or raw == b"[DONE]":
            return line
        try:
            payload = json.loads(raw)
        except json.JSONDecodeError:
            return line
        if not isinstance(payload, dict) or not fill_tool_call_ids(payload, self._ids):
            return line
        body = json.dumps(payload, separators=(",", ":"), ensure_ascii=False)
        return f"data: {body}\n".encode()


def _media_type(proxied: ProxiedChat) -> str:
    return (proxied.media_type or "").split(";", 1)[0].strip().lower()


async def iter_chat_bytes(proxied: ProxiedChat) -> AsyncIterator[bytes]:
    """Pass host bytes through. Rewrite only empty tool-call ids.

    SSE is released line by line. A non-stream JSON body is rewritten only
    when it contains tool_calls; otherwise the original bytes are returned.
    """

    if _media_type(proxied) == "text/event-stream":
        rewriter = SseToolCallIds()
        async for chunk in proxied.iter_bytes():
            piece = rewriter.feed(chunk)
            if piece:
                yield piece
        tail = rewriter.flush()
        if tail:
            yield tail
        return
    buf = bytearray()
    async for chunk in proxied.iter_bytes():
        buf += chunk
    raw = bytes(buf)
    if _media_type(proxied) == "application/json" and b"tool_calls" in raw:
        try:
            payload = json.loads(raw)
        except json.JSONDecodeError:
            yield raw
            return
        ids: dict[int, str] = {}
        if isinstance(payload, dict) and fill_tool_call_ids(payload, ids):
            yield json.dumps(payload).encode()
            return
    if raw:
        yield raw
