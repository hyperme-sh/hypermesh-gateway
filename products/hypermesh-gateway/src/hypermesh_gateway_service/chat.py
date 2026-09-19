"""OpenAI-shaped renter chat proxy. Never log prompts or keys.

Chat path is renter HTTPS → this gateway → the host over the standing
WireGuard peer. No Panopticon HTTP, no get_lease, no Service Bus.
"""

from __future__ import annotations

import logging
import os
import uuid
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


async def proxy_chat(
    *,
    lease_id: uuid.UUID,
    payload: dict[str, Any],
    client_address: str | None,
    runtime_client: httpx.AsyncClient | None = None,
) -> dict[str, Any]:
    if not client_address:
        raise HTTPException(status_code=409, detail=INSTANCE_NOT_READY)
    url = f"http://{client_ip(client_address)}:{chat_upstream_port()}{CHAT_PATH}"
    logger.info("proxy chat lease_id=%s", lease_id)
    body = dict(payload)
    body.pop("lease_id", None)
    client = runtime_client or httpx.AsyncClient(timeout=60.0)
    close = runtime_client is None
    try:
        response = await client.post(url, json=body)
    except httpx.HTTPError:
        logger.info("proxy chat upstream unreachable lease_id=%s", lease_id)
        raise HTTPException(status_code=409, detail=INSTANCE_NOT_READY) from None
    finally:
        if close:
            await client.aclose()
    if response.status_code >= 400:
        raise HTTPException(status_code=409, detail=INSTANCE_NOT_READY)
    return response.json()
