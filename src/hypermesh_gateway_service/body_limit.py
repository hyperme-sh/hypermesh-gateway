"""Raw request body cap, enforced before the body is parsed or decoded.

A body larger than ``HYPERMESH_MAX_BODY_BYTES`` (default 8 MiB) gets 413
``request_too_large``. A declared Content-Length over the cap is refused
without reading the body; a chunked or undeclared body is read only up to the
cap and refused as soon as it passes it. At most the cap is held in memory.
"""

from __future__ import annotations

import json
import logging
import os
from typing import Any, Awaitable, Callable

from hypermesh_gateway_service.errors import openai_error_body

logger = logging.getLogger(__name__)

MAX_BODY_BYTES_ENV = "HYPERMESH_MAX_BODY_BYTES"
DEFAULT_MAX_BODY_BYTES = 8 * 1024 * 1024
BODY_TOO_LARGE_MESSAGE = "This request body is too large."
BODY_TOO_LARGE_CODE = "request_too_large"

Scope = dict[str, Any]
Message = dict[str, Any]
Receive = Callable[[], Awaitable[Message]]
Send = Callable[[Message], Awaitable[None]]


def max_body_bytes() -> int:
    raw = (os.environ.get(MAX_BODY_BYTES_ENV) or "").strip()
    try:
        value = int(raw) if raw else DEFAULT_MAX_BODY_BYTES
    except ValueError:
        value = DEFAULT_MAX_BODY_BYTES
    return max(value, 1)


class BodyLimitMiddleware:
    def __init__(self, app: Callable[[Scope, Receive, Send], Awaitable[None]]) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope.get("type") != "http" or scope.get("method") in {"GET", "HEAD", "OPTIONS"}:
            await self.app(scope, receive, send)
            return
        limit = max_body_bytes()
        for name, value in scope.get("headers") or []:
            if name == b"content-length":
                try:
                    declared = int(value)
                except ValueError:
                    declared = -1
                if declared > limit:
                    await self._refuse(scope, send, declared)
                    return
        chunks: list[bytes] = []
        size = 0
        more = True
        while more:
            message = await receive()
            if message["type"] == "http.disconnect":
                return
            chunk = message.get("body", b"")
            size += len(chunk)
            if size > limit:
                await self._refuse(scope, send, size)
                return
            chunks.append(chunk)
            more = message.get("more_body", False)
        body = b"".join(chunks)
        replayed = False

        async def replay() -> Message:
            nonlocal replayed
            if not replayed:
                replayed = True
                return {"type": "http.request", "body": body, "more_body": False}
            return await receive()

        await self.app(scope, replay, send)

    @staticmethod
    async def _refuse(scope: Scope, send: Send, size: int) -> None:
        logger.warning("request body refused path=%s bytes>=%d", scope.get("path"), size)
        if str(scope.get("path", "")).startswith("/v1/"):
            content = openai_error_body(BODY_TOO_LARGE_MESSAGE, BODY_TOO_LARGE_CODE)
        else:
            content = {"detail": BODY_TOO_LARGE_MESSAGE}
        payload = json.dumps(content).encode()
        await send(
            {
                "type": "http.response.start",
                "status": 413,
                "headers": [
                    (b"content-type", b"application/json"),
                    (b"content-length", str(len(payload)).encode()),
                    (b"connection", b"close"),
                ],
            }
        )
        await send({"type": "http.response.body", "body": payload})
