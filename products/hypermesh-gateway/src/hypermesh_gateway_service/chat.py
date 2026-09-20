"""OpenAI-shaped renter chat proxy. Never log prompts or keys.

Chat path is renter HTTPS → this gateway → the host over the standing
WireGuard peer. No Panopticon HTTP, no get_lease, no Service Bus.

The door streams the host body. It does not buffer response.json().
"""

from __future__ import annotations

import logging
import os
import uuid
from collections.abc import AsyncIterator
from dataclasses import dataclass, field
from typing import Any

import httpx
from fastapi import HTTPException
from pydantic import BaseModel, Field

from hypermesh_gateway_service.control_plane import INSTANCE_NOT_READY

logger = logging.getLogger(__name__)

CHAT_PORT = 8080
CHAT_PATH = "/v1/chat/completions"
CHAT_PORT_ENV = "HYPERMESH_CHAT_UPSTREAM_PORT"


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
        raise HTTPException(status_code=409, detail=INSTANCE_NOT_READY)
    url = f"http://{client_ip(client_address)}:{chat_upstream_port()}{CHAT_PATH}"
    logger.info("proxy chat lease_id=%s", lease_id)
    body = dict(payload)
    body.pop("lease_id", None)
    owned: httpx.AsyncClient | None = None
    client = runtime_client
    if client is None:
        owned = httpx.AsyncClient(timeout=60.0)
        client = owned
    try:
        request = client.build_request("POST", url, json=body)
        response = await client.send(request, stream=True)
    except httpx.HTTPError:
        if owned is not None:
            await owned.aclose()
        logger.info("proxy chat upstream unreachable lease_id=%s", lease_id)
        raise HTTPException(status_code=409, detail=INSTANCE_NOT_READY) from None
    if response.status_code >= 400:
        await response.aread()
        await response.aclose()
        if owned is not None:
            await owned.aclose()
        raise HTTPException(status_code=409, detail=INSTANCE_NOT_READY)
    return ProxiedChat(response=response, _owned_client=owned)
