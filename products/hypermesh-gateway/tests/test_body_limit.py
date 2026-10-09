"""Raw body cap before parsing (#367)."""

from __future__ import annotations

import json

import pytest

from hypermesh_gateway_service.body_limit import BodyLimitMiddleware


class _App:
    def __init__(self) -> None:
        self.called = False
        self.body = b""

    async def __call__(self, scope, receive, send):
        self.called = True
        message = await receive()
        self.body = message["body"]
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"ok"})


async def _run(middleware, *, path="/v1/chat/completions", headers=(), chunks=(b"",)):
    sent: list[dict] = []
    pulled = 0
    queue = list(chunks)

    async def receive():
        nonlocal pulled
        pulled += 1
        if not queue:
            return {"type": "http.disconnect"}
        chunk = queue.pop(0)
        return {"type": "http.request", "body": chunk, "more_body": bool(queue)}

    async def send(message):
        sent.append(message)

    scope = {"type": "http", "method": "POST", "path": path, "headers": list(headers)}
    await middleware(scope, receive, send)
    return sent, pulled


@pytest.mark.asyncio
async def test_declared_length_over_cap_is_refused_unread(monkeypatch):
    monkeypatch.setenv("HYPERMESH_MAX_BODY_BYTES", "100")
    app = _App()
    sent, pulled = await _run(
        BodyLimitMiddleware(app), headers=[(b"content-length", b"1000000")], chunks=[b"x" * 10]
    )
    assert sent[0]["status"] == 413
    assert json.loads(sent[1]["body"])["error"]["code"] == "request_too_large"
    assert pulled == 0
    assert app.called is False


@pytest.mark.asyncio
async def test_streamed_body_stops_reading_at_the_cap(monkeypatch):
    monkeypatch.setenv("HYPERMESH_MAX_BODY_BYTES", "100")
    app = _App()
    chunks = [b"x" * 40] * 50
    sent, pulled = await _run(BodyLimitMiddleware(app), chunks=chunks)
    assert sent[0]["status"] == 413
    assert pulled == 3  # 120 bytes read, then refused; the other 47 chunks are never read
    assert app.called is False


@pytest.mark.asyncio
async def test_sibling_route_gets_detail_body(monkeypatch):
    monkeypatch.setenv("HYPERMESH_MAX_BODY_BYTES", "10")
    sent, _ = await _run(BodyLimitMiddleware(_App()), path="/chat", chunks=[b"x" * 11])
    assert sent[0]["status"] == 413
    assert "detail" in json.loads(sent[1]["body"])


@pytest.mark.asyncio
async def test_body_under_cap_is_replayed(monkeypatch):
    monkeypatch.setenv("HYPERMESH_MAX_BODY_BYTES", "100")
    app = _App()
    sent, _ = await _run(BodyLimitMiddleware(app), chunks=[b"abc", b"def"])
    assert sent[0]["status"] == 200
    assert app.body == b"abcdef"


@pytest.mark.asyncio
async def test_gateway_refuses_oversized_chat_body(http_client, tenant_headers, monkeypatch):
    monkeypatch.setenv("HYPERMESH_MAX_BODY_BYTES", "1000")
    response = await http_client.post(
        "/v1/chat/completions",
        headers=tenant_headers,
        content=b'{"messages": "' + b"x" * 5000 + b'"}',
    )
    assert response.status_code == 413
    assert response.json()["error"]["code"] == "request_too_large"
