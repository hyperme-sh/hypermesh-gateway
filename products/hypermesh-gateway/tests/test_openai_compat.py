"""Bearer-only OpenAI door: lease choice, models, revoke, tool-call ids, SSE."""

from __future__ import annotations

import json
import time
import uuid
from datetime import UTC, datetime, timedelta

import httpx
import pytest

from hypermesh_gateway_service.chat import (
    CHAT_PORT_ENV,
    chat_timeout,
    fill_tool_call_ids,
    proxy_chat,
)
from hypermesh_gateway_service.errors import no_active_lease_message
from hypermesh_gateway_service.route_resolve import (
    ModelNotFound,
    TenantOwnedKeyPolicy,
    resolve_route,
    select_lease,
)
from hypermesh_gateway_service.tickets import CachedTicket, TicketCache
from hypermesh_service.seed import FYBER_AGX_DEVICE_ID, FYBER_TEST_GATEWAY_ID
from hypermesh_service.ticket import (
    RENTER_CHAT_PURPOSES,
    TicketClaims,
    issue_ticket,
    renter_key_fingerprint,
)
from test_hypermesh_gateway import TEST_RENTER_KEY, _mock_runtime, _signed_ticket
from mock_host import MockHost


def _ticket(
    lease_id: uuid.UUID,
    *,
    catalog_id: str,
    activated_at: datetime,
    tenant_id: uuid.UUID,
) -> CachedTicket:
    base = _signed_ticket(lease_id)
    return CachedTicket(
        lease_id=base.lease_id,
        ticket=base.ticket,
        client_address=base.client_address,
        assigned_gateway_id=base.assigned_gateway_id,
        status=base.status,
        exp=base.exp,
        device_id=base.device_id,
        path_b_state=base.path_b_state,
        peer_public_key=base.peer_public_key,
        catalog_id=catalog_id,
        activated_at=activated_at,
    )


def test_chat_timeout_defaults_and_env(monkeypatch):
    monkeypatch.delenv("HYPERMESH_CHAT_READ_TIMEOUT_S", raising=False)
    timeout = chat_timeout()
    assert timeout.connect == 10.0
    assert timeout.read == 1800.0
    assert timeout.write == 60.0
    assert timeout.pool == 10.0
    monkeypatch.setenv("HYPERMESH_CHAT_READ_TIMEOUT_S", "none")
    assert chat_timeout().read is None


@pytest.mark.asyncio
async def test_proxy_chat_builds_streaming_timeout(monkeypatch):
    seen: dict[str, object] = {}

    class _Client:
        def __init__(self, timeout=None):
            seen["timeout"] = timeout

        def build_request(self, *args, **kwargs):
            raise httpx.HTTPError("stop")

        async def aclose(self):
            return None

    monkeypatch.setattr("hypermesh_gateway_service.chat.httpx.AsyncClient", _Client)
    with pytest.raises(Exception):
        await proxy_chat(
            lease_id=uuid.uuid4(),
            payload={"messages": []},
            client_address="127.0.0.1/32",
        )
    timeout = seen["timeout"]
    assert timeout.connect == 10.0
    assert timeout.read == 1800.0


def test_select_lease_rules():
    older = datetime(2026, 1, 1, tzinfo=UTC)
    newer = datetime(2026, 6, 1, tzinfo=UTC)
    first = CachedTicket(
        lease_id=uuid.uuid4(),
        ticket="t",
        client_address="10.0.0.2/32",
        assigned_gateway_id=FYBER_TEST_GATEWAY_ID,
        status="active",
        catalog_id="llama-3.1-8b-q4",
        activated_at=older,
    )
    second = CachedTicket(
        lease_id=uuid.uuid4(),
        ticket="t",
        client_address="10.0.0.3/32",
        assigned_gateway_id=FYBER_TEST_GATEWAY_ID,
        status="active",
        catalog_id="other-model",
        activated_at=newer,
    )
    assert select_lease([first], None) is first
    assert select_lease([first], "") is first
    with pytest.raises(ModelNotFound) as missed:
        select_lease([first], "ignored")
    assert missed.value.available == ["llama-3.1-8b-q4"]
    assert select_lease([first, second], "other-model") is second
    assert select_lease([first, second], "llama-3.1-8b-q4") is first
    assert select_lease([first, second], None) is second
    assert select_lease([first, second], "  ") is second
    with pytest.raises(ModelNotFound) as unknown:
        select_lease([first, second], "not-a-model")
    assert unknown.value.available == ["other-model", "llama-3.1-8b-q4"]
    same = CachedTicket(
        lease_id=uuid.uuid4(),
        ticket="t",
        client_address="10.0.0.4/32",
        assigned_gateway_id=FYBER_TEST_GATEWAY_ID,
        status="active",
        catalog_id="llama-3.1-8b-q4",
        activated_at=newer,
    )
    assert select_lease([first, same], "llama-3.1-8b-q4") is same
    assert select_lease([], "llama-3.1-8b-q4") is None


def test_key_policy_seam_can_narrow_leases(monkeypatch):
    monkeypatch.setenv("HYPERMESH_TICKET_HMAC_KEY", "test-plane-hypermesh-ticket-hmac")
    tenant_id = uuid.uuid4()
    cache = TicketCache()
    kept = uuid.uuid4()
    other = uuid.uuid4()
    for lease_id in (kept, other):
        exp = datetime.now(UTC) + timedelta(hours=1)
        token = issue_ticket(
            TicketClaims(
                lease_id=lease_id,
                device_id=FYBER_AGX_DEVICE_ID,
                gateway_id=FYBER_TEST_GATEWAY_ID,
                client_address="10.77.0.2/32",
                status="active",
                exp=exp,
                tenant_id=tenant_id,
            )
        )
        cache.put(
            tenant_id,
            CachedTicket(
                lease_id=lease_id,
                ticket=token,
                client_address="10.77.0.2/32",
                assigned_gateway_id=FYBER_TEST_GATEWAY_ID,
                status="active",
                exp=exp,
                device_id=FYBER_AGX_DEVICE_ID,
                path_b_state="green",
                catalog_id="llama-3.1-8b-q4",
                activated_at=datetime.now(UTC),
            ),
        )

    class _OneKey:
        def candidate_leases(self, cache, tenant_id, *, key, purposes):
            rows = TenantOwnedKeyPolicy().candidate_leases(
                cache, tenant_id, key=key, purposes=purposes
            )
            return [row for row in rows if row.lease_id == kept]

    chosen = resolve_route(
        cache,
        key="pk_test.renter-key",
        tenant_id=tenant_id,
        requested_model=None,
        purposes=RENTER_CHAT_PURPOSES,
        policy=_OneKey(),
    )
    assert chosen is not None
    assert chosen.lease_id == kept


def test_fill_tool_call_ids_on_json_and_keeps_stream_index():
    payload = {
        "choices": [
            {
                "message": {
                    "tool_calls": [
                        {"id": "", "type": "function", "function": {"name": "a"}},
                        {"id": "call_kept", "type": "function", "function": {"name": "b"}},
                    ]
                }
            }
        ]
    }
    ids: dict[int, str] = {}
    assert fill_tool_call_ids(payload, ids) is True
    assert payload["choices"][0]["message"]["tool_calls"][0]["id"].startswith("call_")
    assert payload["choices"][0]["message"]["tool_calls"][1]["id"] == "call_kept"
    delta = {
        "choices": [
            {"delta": {"tool_calls": [{"index": 0, "id": "", "function": {"arguments": "{}"}}]}}
        ]
    }
    fill_tool_call_ids(delta, ids)
    assert delta["choices"][0]["delta"]["tool_calls"][0]["id"] == (
        payload["choices"][0]["message"]["tool_calls"][0]["id"]
    )


@pytest.mark.asyncio
async def test_bearer_only_chat_uses_the_only_active_lease(
    http_client, app, tenant_id, control_plane
):
    lease_id = uuid.uuid4()
    app.state.ticket_cache.put(
        tenant_id,
        _ticket(
            lease_id,
            catalog_id="llama-3.1-8b-q4",
            activated_at=datetime.now(UTC),
            tenant_id=tenant_id,
        ),
    )
    _mock_runtime(app)
    chat = await http_client.post(
        "/v1/chat/completions",
        headers={"Authorization": f"Bearer {TEST_RENTER_KEY}"},
        json={"model": "llama-3.1-8b-q4", "messages": [{"role": "user", "content": "hi"}]},
    )
    assert chat.status_code == 200, chat.text
    assert chat.json()["object"] == "chat.completion"
    assert control_plane.list_tickets_calls == 0


@pytest.mark.asyncio
async def test_no_active_lease_is_402_and_models_are_an_empty_list(http_client, app, tenant_id):
    missing = await http_client.post(
        "/v1/chat/completions",
        headers={"Authorization": f"Bearer {TEST_RENTER_KEY}"},
        json={"model": "llama-3.1-8b-q4", "messages": [{"role": "user", "content": "hi"}]},
    )
    assert missing.status_code == 402
    assert missing.json() == {
        "error": {
            "message": no_active_lease_message(),
            "type": "invalid_request_error",
            "code": "no_active_lease",
        }
    }
    models = await http_client.get(
        "/v1/models",
        headers={"Authorization": f"Bearer {TEST_RENTER_KEY}"},
    )
    assert models.status_code == 200
    assert models.json() == {"object": "list", "data": []}
    bad = await http_client.get("/v1/models", headers={"Authorization": "Bearer nope.nope"})
    assert bad.status_code == 401
    assert bad.json()["error"]["code"] == "invalid_api_key"


@pytest.mark.asyncio
async def test_models_list_catalog_from_active_leases(http_client, app, tenant_id):
    now = datetime.now(UTC)
    app.state.ticket_cache.put(
        tenant_id,
        _ticket(uuid.uuid4(), catalog_id="llama-3.1-8b-q4", activated_at=now, tenant_id=tenant_id),
    )
    listed = await http_client.get(
        "/api/v1/hypermesh-gateway/v1/models",
        headers={"Authorization": f"Bearer {TEST_RENTER_KEY}", "X-Tenant-ID": str(tenant_id)},
    )
    assert listed.status_code == 200, listed.text
    assert listed.json()["data"] == [
        {"id": "llama-3.1-8b-q4", "object": "model", "owned_by": "hypermesh"}
    ]
    assert "auto" not in listed.text


@pytest.mark.asyncio
async def test_tenant_header_mismatch_is_403(http_client):
    refused = await http_client.post(
        "/v1/chat/completions",
        headers={
            "Authorization": f"Bearer {TEST_RENTER_KEY}",
            "X-Tenant-ID": str(uuid.uuid4()),
        },
        json={"messages": [{"role": "user", "content": "hi"}]},
    )
    assert refused.status_code == 403
    assert refused.json()["error"]["code"] == "tenant_mismatch"


@pytest.mark.asyncio
async def test_revoked_fingerprint_is_401_even_inside_validate_ttl(
    http_client, app, tenant_id
):
    lease_id = uuid.uuid4()
    app.state.ticket_cache.put(
        tenant_id,
        _ticket(
            lease_id,
            catalog_id="llama-3.1-8b-q4",
            activated_at=datetime.now(UTC),
            tenant_id=tenant_id,
        ),
    )
    _mock_runtime(app)
    calls = {"n": 0}

    async def validate(*, base_url, api_key, tenant_id, timeout_s=5.0):
        calls["n"] += 1
        if calls["n"] == 1:
            return {
                "valid": True,
                "tenant_id": str(tenant_id),
                "key_id": str(uuid.uuid4()),
                "scopes": [],
                "purpose": "renter",
            }
        return None

    app.state.api_key_validator = validate
    headers = {"Authorization": f"Bearer {TEST_RENTER_KEY}"}
    body = {
        "lease_id": str(lease_id),
        "messages": [{"role": "user", "content": "hi"}],
    }
    first = await http_client.post("/v1/chat/completions", headers=headers, json=body)
    assert first.status_code == 200, first.text
    second = await http_client.post("/v1/chat/completions", headers=headers, json=body)
    assert second.status_code == 200, second.text
    assert calls["n"] == 1
    fingerprint = renter_key_fingerprint(TEST_RENTER_KEY)
    app.state.ticket_cache.replace_revoked_keys(tenant_id, [fingerprint])
    app.state.ticket_cache.accept_keys(tenant_id, [])
    revoked = await http_client.post("/v1/chat/completions", headers=headers, json=body)
    assert revoked.status_code == 401
    assert revoked.json()["error"]["code"] == "invalid_api_key"


@pytest.mark.asyncio
async def test_tool_call_ids_filled_on_json_and_sse(http_client, app, tenant_id):
    lease_id = uuid.uuid4()
    app.state.ticket_cache.put(
        tenant_id,
        _ticket(
            lease_id,
            catalog_id="llama-3.1-8b-q4",
            activated_at=datetime.now(UTC),
            tenant_id=tenant_id,
        ),
    )
    headers = {"Authorization": f"Bearer {TEST_RENTER_KEY}", "X-Tenant-ID": str(tenant_id)}
    payload = {
        "lease_id": str(lease_id),
        "messages": [{"role": "user", "content": "hi"}],
    }

    async def json_handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "id": "cmpl",
                "object": "chat.completion",
                "choices": [
                    {
                        "message": {
                            "role": "assistant",
                            "tool_calls": [{"id": "", "type": "function", "function": {"name": "now"}}],
                        }
                    }
                ],
            },
        )

    app.state.runtime_client = httpx.AsyncClient(transport=httpx.MockTransport(json_handler))
    chat = await http_client.post("/v1/chat/completions", headers=headers, json=payload)
    assert chat.status_code == 200, chat.text
    tool_id = chat.json()["choices"][0]["message"]["tool_calls"][0]["id"]
    assert tool_id.startswith("call_")
    assert tool_id != ""

    first = {
        "choices": [
            {"delta": {"tool_calls": [{"index": 0, "id": "", "function": {"name": "now"}}]}}
        ]
    }
    second = {
        "choices": [
            {"delta": {"tool_calls": [{"index": 0, "id": "", "function": {"arguments": "{}"}}]}}
        ]
    }
    sse = (
        f"data: {json.dumps(first)}\n\n"
        f"data: {json.dumps(second)}\n\n"
        "data: [DONE]\n\n"
    ).encode()

    async def sse_handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=sse, headers={"content-type": "text/event-stream"})

    app.state.runtime_client = httpx.AsyncClient(transport=httpx.MockTransport(sse_handler))
    streamed = await http_client.post("/v1/chat/completions", headers=headers, json=payload)
    assert streamed.status_code == 200, streamed.text
    assert "text/event-stream" in streamed.headers["content-type"]
    assert "data: [DONE]" in streamed.text
    ids = []
    for line in streamed.text.splitlines():
        if not line.startswith("data: ") or line == "data: [DONE]":
            continue
        row = json.loads(line.removeprefix("data: "))
        calls = row["choices"][0]["delta"]["tool_calls"]
        ids.append(calls[0]["id"])
    assert ids[0].startswith("call_")
    assert ids[0] == ids[1]


@pytest.mark.asyncio
async def test_sse_chunks_arrive_incrementally(http_client, app, tenant_id, monkeypatch):
    host = MockHost()
    host.sse_delay_s = 0.25
    host.sse_chunks = [
        b'data: {"choices":[{"delta":{"content":"a"}}]}\n\n',
        b'data: {"choices":[{"delta":{"content":"b"}}]}\n\n',
        b"data: [DONE]\n\n",
    ]
    host.start()
    try:
        monkeypatch.setenv(CHAT_PORT_ENV, str(host.port))
        lease_id = uuid.uuid4()
        exp = datetime.now(UTC) + timedelta(hours=1)
        token = issue_ticket(
            TicketClaims(
                lease_id=lease_id,
                device_id=FYBER_AGX_DEVICE_ID,
                gateway_id=FYBER_TEST_GATEWAY_ID,
                client_address=host.client_address,
                status="active",
                exp=exp,
                tenant_id=tenant_id,
            )
        )
        app.state.ticket_cache.put(
            tenant_id,
            CachedTicket(
                lease_id=lease_id,
                ticket=token,
                client_address=host.client_address,
                assigned_gateway_id=FYBER_TEST_GATEWAY_ID,
                status="active",
                exp=exp,
                device_id=FYBER_AGX_DEVICE_ID,
                path_b_state="green",
                peer_public_key="peer-pub",
            ),
        )
        # httpx.ASGITransport joins the body before the client iterates it.
        # Drive the app as ASGI 2.4 so each StreamingResponse yield is visible.
        body = json.dumps({"messages": [{"role": "user", "content": "hi"}]}).encode()
        started: list[float] = []
        status_code = 0
        response_headers: dict[str, str] = {}

        async def receive():
            return {"type": "http.request", "body": body, "more_body": False}

        async def send(message):
            nonlocal status_code
            if message["type"] == "http.response.start":
                status_code = int(message["status"])
                for key, value in message.get("headers") or []:
                    response_headers[key.decode().lower()] = value.decode()
            elif message["type"] == "http.response.body" and message.get("body"):
                started.append(time.monotonic())

        await app(
            {
                "type": "http",
                "asgi": {"version": "3.0", "spec_version": "2.4"},
                "http_version": "1.1",
                "method": "POST",
                "scheme": "http",
                "path": "/v1/chat/completions",
                "raw_path": b"/v1/chat/completions",
                "query_string": b"",
                "headers": [
                    (b"authorization", f"Bearer {TEST_RENTER_KEY}".encode()),
                    (b"content-type", b"application/json"),
                ],
                "client": ("127.0.0.1", 50000),
                "server": ("test", 80),
            },
            receive,
            send,
        )
        assert status_code == 200
        assert "text/event-stream" in response_headers["content-type"]
        assert response_headers["x-accel-buffering"] == "no"
        assert len(started) >= 2
        assert started[-1] - started[0] >= 0.2
    finally:
        host.stop()


def test_no_active_lease_message_reads_portal_origin(monkeypatch):
    monkeypatch.setenv("HYPERMESH_PORTAL_ORIGIN", "https://portal.example")
    text = no_active_lease_message()
    assert text.endswith(
        "https://portal.example/dashboard/hypermesh/renter/catalog"
    )
    assert "portal.test" not in text
    monkeypatch.setenv("HYPERMESH_PORTAL_ORIGIN", "")
    bare = no_active_lease_message()
    assert bare.endswith("Start a lease at /dashboard/hypermesh/renter/catalog")
    assert "portal.test" not in bare


@pytest.mark.asyncio
async def test_unknown_model_is_404_and_lists_available_ids(http_client, app, tenant_id):
    app.state.ticket_cache.put(
        tenant_id,
        _ticket(
            uuid.uuid4(),
            catalog_id="llama-3.1-8b-q4",
            activated_at=datetime.now(UTC),
            tenant_id=tenant_id,
        ),
    )
    refused = await http_client.post(
        "/v1/chat/completions",
        headers={"Authorization": f"Bearer {TEST_RENTER_KEY}"},
        json={"model": "other-model", "messages": [{"role": "user", "content": "hi"}]},
    )
    assert refused.status_code == 404
    error = refused.json()["error"]
    assert error["code"] == "model_not_found"
    assert error["type"] == "invalid_request_error"
    assert "llama-3.1-8b-q4" in error["message"]
    assert "other-model" in error["message"]


@pytest.mark.asyncio
async def test_prod_requires_remote_key_validate(http_client, app, tenant_id, monkeypatch):
    monkeypatch.setenv("FASTAPI_ENV", "production")
    app.state.ticket_cache.put(
        tenant_id,
        _ticket(
            uuid.uuid4(),
            catalog_id="llama-3.1-8b-q4",
            activated_at=datetime.now(UTC),
            tenant_id=tenant_id,
        ),
    )
    _mock_runtime(app)
    refused = await http_client.post(
        "/v1/chat/completions",
        headers={"Authorization": f"Bearer {TEST_RENTER_KEY}"},
        json={"messages": [{"role": "user", "content": "hi"}]},
    )
    assert refused.status_code == 401
    assert refused.json()["error"]["code"] == "invalid_api_key"


@pytest.mark.asyncio
async def test_revoke_then_next_gateway_request_is_401(
    http_client, app, tenant_id, monkeypatch
):
    """Unpublish on the plane, pull, then the next chat with that key is 401."""

    import sys
    from pathlib import Path

    from asgi_lifespan import LifespanManager

    from api.core.config import settings

    keys_src = Path(__file__).resolve().parents[3] / "core" / "api-keys-service" / "src"
    sys.path.insert(0, str(keys_src))
    from api_keys_service.fingerprint import revoke_renter_key_fingerprint
    from hypermesh_gateway_service.control_plane import HttpControlPlane
    from hypermesh_gateway_service.routes import refresh_assignments
    from hypermesh_service.app import create_app as create_hypermesh

    monkeypatch.setattr(settings, "hypermesh_internal_token", "test-hypermesh-internal-token")
    plane = create_hypermesh(enable_db_middleware=False)
    fingerprint = renter_key_fingerprint(TEST_RENTER_KEY)
    headers = {
        "X-Internal-Token": "test-hypermesh-internal-token",
        "X-Tenant-ID": str(tenant_id),
    }
    async with LifespanManager(plane):
        transport = httpx.ASGITransport(app=plane)

        class _PlaneClient(httpx.AsyncClient):
            def __init__(self, timeout=None, **kwargs):
                super().__init__(
                    transport=transport,
                    base_url="http://hypermesh",
                    timeout=timeout,
                )

        async with _PlaneClient() as client:
            registered = await client.post(
                "/api/v1/hypermesh/internal/renter-key-fingerprints",
                headers=headers,
                json={"fingerprint": fingerprint},
            )
            assert registered.status_code == 201, registered.text
            minted = await client.post(
                "/api/v1/hypermesh/internal/gateways",
                headers=headers,
                params={"name": "fyber-test-gateway-door"},
            )
            assert minted.status_code == 201, minted.text
            secret = minted.json()["service_secret"]

        app.state.ticket_cache.put(
            tenant_id,
            _ticket(
                uuid.uuid4(),
                catalog_id="llama-3.1-8b-q4",
                activated_at=datetime.now(UTC),
                tenant_id=tenant_id,
            ),
        )
        _mock_runtime(app)
        chat_headers = {"Authorization": f"Bearer {TEST_RENTER_KEY}"}
        body = {"messages": [{"role": "user", "content": "hi"}]}
        first = await http_client.post("/v1/chat/completions", headers=chat_headers, json=body)
        assert first.status_code == 200, first.text

        monkeypatch.setattr(
            "api_keys_service.fingerprint.httpx.AsyncClient", _PlaneClient
        )
        monkeypatch.setenv("HYPERMESH_CONTROL_PLANE_URL", "http://hypermesh")
        await revoke_renter_key_fingerprint(tenant_id, fingerprint)

        import hypermesh_gateway_service.control_plane as cp

        monkeypatch.setattr(cp.httpx, "AsyncClient", _PlaneClient)
        await refresh_assignments(
            HttpControlPlane("http://hypermesh", secret),
            app.state.ticket_cache,
            tenant_id,
        )
        refused = await http_client.post(
            "/v1/chat/completions", headers=chat_headers, json=body
        )
        assert refused.status_code == 401
        assert refused.json()["error"]["code"] == "invalid_api_key"
