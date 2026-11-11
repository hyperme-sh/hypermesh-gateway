from __future__ import annotations
from gateway_host_fixture import FYBER_AGX_DEVICE_ID

import inspect
import json
import uuid
from datetime import UTC, datetime, timedelta

import pytest
from fastapi import HTTPException

from hypermesh_gateway_service.chat import INSTANCE_NOT_READY, proxy_chat
from hypermesh_gateway_service.control_plane import GatewayTunnel, HttpControlPlane, LeaseView
from hypermesh_gateway_service.posture import require_chat_posture
from hypermesh_gateway_service.tickets import CachedTicket, TicketCache, TicketPull
from gateway_host_fixture import FYBER_TEST_GATEWAY_ID
from hypermesh_gateway_service.tenants import MARKETPLACE_TENANT_ID
from hypermesh_ticket import TicketClaims, TicketNotReady, issue_ticket, renter_key_fingerprint

TEST_RENTER_KEY = "pk_test.renter-key"
TEST_RENTER_FINGERPRINTS = [renter_key_fingerprint(TEST_RENTER_KEY)]
TEST_IR_KEY = "pk_test.ir-key"
TEST_IR_FINGERPRINTS = [renter_key_fingerprint(TEST_IR_KEY)]


def _renter(tenant_headers: dict[str, str]) -> dict[str, str]:
    return {**tenant_headers, "Authorization": f"Bearer {TEST_RENTER_KEY}"}


def _ir(tenant_headers: dict[str, str]) -> dict[str, str]:
    return {**tenant_headers, "Authorization": f"Bearer {TEST_IR_KEY}"}


def _ticket_pull(
    tickets: list[CachedTicket],
    revoked: list[uuid.UUID] | None = None,
) -> TicketPull:
    return TicketPull(
        tickets=tickets,
        revoked_lease_ids=revoked or [],
        key_fingerprints=TEST_RENTER_FINGERPRINTS,
    )


def _gateway(tenant_headers: dict[str, str]) -> dict[str, str]:
    return {**tenant_headers, "Authorization": "Bearer hm_gw_test"}


@pytest.mark.asyncio
async def test_health_and_openapi_has_no_host_ips(http_client):
    health = await http_client.get("/api/v1/health/")
    assert health.status_code == 200
    spec = await http_client.get("/openapi.json")
    assert spec.status_code == 200
    text = spec.text
    assert "/api/v1/hypermesh-gateway" in text
    assert "/v1/chat/completions" in text
    assert "10.77." not in text
    assert "host ip" not in text.lower()
    assert "Hypermesh" in spec.json()["info"]["title"]


@pytest.mark.asyncio
async def test_gateway_rejects_missing_service_cred(http_client, tenant_headers):
    missing = await http_client.get("/api/v1/hypermesh-gateway/ready", headers=tenant_headers)
    assert missing.status_code == 401
    wrong = await http_client.get(
        "/api/v1/hypermesh-gateway/ready",
        headers={**tenant_headers, "Authorization": "Bearer hm_gw_nope"},
    )
    assert wrong.status_code == 401
    ok = await http_client.get("/api/v1/hypermesh-gateway/ready", headers=_gateway(tenant_headers))
    assert ok.status_code == 200


@pytest.mark.asyncio
async def test_gateway_denies_when_no_service_cred_is_configured(
    http_client, tenant_headers, app, monkeypatch
):
    """Unconfigured must deny, not accept whatever the caller sent."""

    monkeypatch.delenv("HYPERMESH_GATEWAY_SERVICE_SECRET", raising=False)
    app.state.gateway_service_secret = ""
    for sent in ("", "hm_gw_test", "anything"):
        refused = await http_client.get(
            "/api/v1/hypermesh-gateway/ready",
            headers={**tenant_headers, "Authorization": f"Bearer {sent}"},
        )
        assert refused.status_code == 401, f"accepted {sent!r} with no secret configured"


def _signed_ticket(
    lease_id: uuid.UUID,
    *,
    client_address: str = "10.77.0.2/32",
    path_b_state: str = "green",
    peer_public_key: str | None = "peer-pub",
    purpose: str = "renter",
) -> CachedTicket:
    exp = datetime.now(UTC) + timedelta(hours=1)
    token = issue_ticket(
        TicketClaims(
            lease_id=lease_id,
            device_id=FYBER_AGX_DEVICE_ID,
            gateway_id=FYBER_TEST_GATEWAY_ID,
            client_address=client_address,
            status="active",
            exp=exp,
            purpose=purpose,
            tenant_id=MARKETPLACE_TENANT_ID,
        )
    )
    return CachedTicket(
        lease_id=lease_id,
        ticket=token,
        client_address=client_address,
        assigned_gateway_id=FYBER_TEST_GATEWAY_ID,
        status="active",
        exp=exp,
        device_id=FYBER_AGX_DEVICE_ID,
        path_b_state=path_b_state,
        peer_public_key=peer_public_key,
    )


def _allocated_tunnel(lease_id: uuid.UUID) -> GatewayTunnel:
    return GatewayTunnel(
        tunnel_id=uuid.uuid4(),
        lease_id=lease_id,
        status="allocated",
        endpoint="wg.test.hyperme.sh:51820",
        server_private_key="server-priv",
        server_public_key="server-pub",
        peer_public_key="peer-pub",
        allowed_ips="10.77.0.0/24",
        client_address="10.77.0.2/32",
    )


@pytest.mark.asyncio
async def test_proxy_chat_cached_ticket_does_not_call_get_lease(control_plane):
    assert "control" not in inspect.signature(proxy_chat).parameters
    import httpx

    async def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/v1/chat/completions"
        assert request.url.host == "10.77.0.2"
        assert request.url.port == 8080
        return httpx.Response(200, json={"id": "cmpl-test", "object": "chat.completion"})

    lease_id = uuid.uuid4()
    control_plane.leases[lease_id] = LeaseView(
        id=lease_id,
        status="active",
        kind="p2_loaded_model",
        catalog_id="llama-3.1-8b-q4",
    )
    runtime = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    proxied = await proxy_chat(
        lease_id=lease_id,
        payload={"messages": [{"role": "user", "content": "hi"}]},
        client_address="10.77.0.2/32",
        runtime_client=runtime,
    )
    raw = b"".join([chunk async for chunk in proxied.iter_bytes()])
    out = json.loads(raw)
    assert out["object"] == "chat.completion"
    assert control_plane.get_lease_calls == 0
    assert control_plane.list_tunnels_calls == 0


@pytest.mark.asyncio
@pytest.mark.synthetic
async def test_proxy_chat_yields_first_chunk_before_upstream_finishes(monkeypatch):
    import threading
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

    import httpx

    gate = threading.Event()

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self) -> None:
            length = int(self.headers.get("Content-Length") or 0)
            if length:
                self.rfile.read(length)
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.end_headers()
            self.wfile.write(b"data: one\n\n")
            self.wfile.flush()
            gate.wait(timeout=2)
            self.wfile.write(b"data: [DONE]\n\n")
            self.wfile.flush()

        def log_message(self, format: str, *args) -> None:
            del format, args

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    monkeypatch.setenv("HYPERMESH_CHAT_UPSTREAM_PORT", str(server.server_address[1]))
    runtime = httpx.AsyncClient()
    try:
        proxied = await proxy_chat(
            lease_id=uuid.uuid4(),
            payload={"messages": [{"role": "user", "content": "hi"}], "stream": True},
            client_address="127.0.0.1/32",
            runtime_client=runtime,
        )
        agen = proxied.iter_bytes()
        first = await agen.__anext__()
        assert b"one" in first
        gate.set()
        rest = b"".join([chunk async for chunk in agen])
        assert b"[DONE]" in rest
    finally:
        gate.set()
        await runtime.aclose()
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


@pytest.mark.asyncio
async def test_proxy_chat_missing_or_inactive_ticket_is_instance_not_ready():
    lease_id = uuid.uuid4()
    with pytest.raises(HTTPException) as missing:
        await proxy_chat(
            lease_id=lease_id,
            payload={"messages": []},
            client_address=None,
        )
    assert missing.value.status_code == 409
    assert missing.value.detail == INSTANCE_NOT_READY

    with pytest.raises(HTTPException) as inactive:
        await proxy_chat(
            lease_id=lease_id,
            payload={"messages": []},
            client_address="",
        )
    assert inactive.value.status_code == 409
    assert inactive.value.detail == INSTANCE_NOT_READY


@pytest.mark.asyncio
async def test_renter_chat_without_paid_active_lease_fails(
    http_client, tenant_headers, control_plane
):
    lease_id = uuid.uuid4()
    control_plane.leases[lease_id] = LeaseView(
        id=lease_id,
        status="offered",
        kind="p2_loaded_model",
        catalog_id="llama-3.1-8b-q4",
    )
    no_key = await http_client.post(
        "/v1/chat/completions",
        headers=tenant_headers,
        json={"lease_id": str(lease_id), "messages": [{"role": "user", "content": "secret prompt"}]},
    )
    assert no_key.status_code == 401

    refused = await http_client.post(
        "/api/v1/hypermesh-gateway/v1/chat/completions",
        headers=_renter(tenant_headers),
        json={"lease_id": str(lease_id), "messages": [{"role": "user", "content": "secret prompt"}]},
    )
    assert refused.status_code == 403
    assert refused.json()["detail"] == "lease_id is not owned by this API key"
    assert control_plane.get_lease_calls == 0
    assert control_plane.list_tunnels_calls == 0
    assert "path b" not in refused.text.lower()
    assert "soak" not in refused.text.lower()
    assert "agent" not in refused.text.lower()


@pytest.mark.asyncio
async def test_renter_chat_uses_cached_ticket_not_control_plane(
    http_client, tenant_headers, control_plane, app
):
    import httpx

    lease_id = uuid.uuid4()
    control_plane.tunnels.append(_allocated_tunnel(lease_id))
    control_plane.ticket_pull = _ticket_pull([_signed_ticket(lease_id)])
    pulled = await http_client.post(
        "/api/v1/hypermesh-gateway/tunnels/apply",
        headers=_gateway(tenant_headers),
    )
    assert pulled.status_code == 200
    assert control_plane.list_tunnels_calls == 1
    assert control_plane.list_tickets_calls == 1
    assert control_plane.get_lease_calls == 0
    pulls_before_chat = control_plane.list_tunnels_calls
    tickets_before_chat = control_plane.list_tickets_calls

    async def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/v1/chat/completions"
        assert request.url.port == 8080
        return httpx.Response(
            200,
            json={
                "id": "cmpl-test",
                "object": "chat.completion",
                "model": "llama-3.1-8b-q4",
                "choices": [{"index": 0, "message": {"role": "assistant", "content": "ok"}}],
            },
        )

    app.state.runtime_client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    chat = await http_client.post(
        "/v1/chat/completions",
        headers=_renter(tenant_headers),
        json={
            "lease_id": str(lease_id),
            "model": "llama-3.1-8b-q4",
            "messages": [{"role": "user", "content": "secret prompt must not be logged"}],
        },
    )
    assert chat.status_code == 200
    assert chat.json()["object"] == "chat.completion"
    assert control_plane.get_lease_calls == 0
    assert control_plane.list_tunnels_calls == pulls_before_chat
    assert control_plane.list_tickets_calls == tickets_before_chat
    assert control_plane.post_metrics_calls == 1
    metric = control_plane.metrics[-1]
    assert set(metric) <= {
        "tenant_id",
        "tunnel_id",
        "lease_id",
        "bytes_in",
        "bytes_out",
        "handshake_count",
        "metric_id",
    }
    dumped = str(metric)
    assert "secret prompt" not in dumped
    assert "messages" not in dumped
    assert "prompt" not in dumped.lower()


@pytest.mark.asyncio
async def test_inactive_cached_ticket_is_instance_not_ready(
    http_client, tenant_headers, app, tenant_id
):
    lease_id = uuid.uuid4()
    app.state.ticket_cache.put(
        tenant_id,
        CachedTicket(
            lease_id=lease_id,
            ticket="",
            client_address="",
            assigned_gateway_id=FYBER_TEST_GATEWAY_ID,
            status="revoked",
        ),
    )
    refused = await http_client.post(
        "/v1/chat/completions",
        headers=_renter(tenant_headers),
        json={"lease_id": str(lease_id), "messages": [{"role": "user", "content": "hi"}]},
    )
    assert refused.status_code == 409
    assert refused.json()["detail"] == INSTANCE_NOT_READY


@pytest.mark.asyncio
async def test_pull_tunnels_and_metrics_use_hm_gw_(
    http_client, tenant_headers, control_plane
):
    denied_pull = await http_client.get(
        "/api/v1/hypermesh-gateway/tunnels",
        headers=_renter(tenant_headers),
    )
    denied_metrics = await http_client.post(
        "/api/v1/hypermesh-gateway/metrics",
        headers=_renter(tenant_headers),
        json={"bytes_in": 12, "bytes_out": 4},
    )
    assert denied_pull.status_code == 401
    assert denied_metrics.status_code == 401
    assert control_plane.list_tunnels_calls == 0
    assert control_plane.list_tickets_calls == 0
    assert control_plane.post_metrics_calls == 0

    pulled = await http_client.get(
        "/api/v1/hypermesh-gateway/tunnels",
        headers=_gateway(tenant_headers),
    )
    recorded = await http_client.post(
        "/api/v1/hypermesh-gateway/metrics",
        headers=_gateway(tenant_headers),
        json={"bytes_in": 12, "bytes_out": 4, "handshake_count": 1},
    )
    assert pulled.status_code == 200
    assert recorded.status_code == 201
    assert control_plane.list_tunnels_calls == 1
    assert control_plane.list_tickets_calls == 1
    assert control_plane.post_metrics_calls == 1
    assert control_plane.get_lease_calls == 0


@pytest.mark.asyncio
async def test_http_control_plane_pull_and_metrics_send_hm_gw_(tenant_id, monkeypatch):
    import httpx

    captured: list[tuple[str, str, dict[str, str]]] = []

    class DummyResponse:
        def __init__(self, status_code: int = 200) -> None:
            self.status_code = status_code

        def raise_for_status(self) -> None:
            return None

        def json(self) -> list:
            return []

    class DummyClient:
        def __init__(self, *args, **kwargs) -> None:
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            return None

        async def get(self, url, headers=None):
            captured.append(("GET", url, dict(headers or {})))
            return DummyResponse()

        async def post(self, url, headers=None, json=None):
            captured.append(("POST", url, dict(headers or {})))
            return DummyResponse(201)

    monkeypatch.setattr(httpx, "AsyncClient", DummyClient)
    secret = "hm_gw_test_plane_secret"
    plane = HttpControlPlane("http://hypermesh-service:8000", secret)
    await plane.list_tunnels(tenant_id)
    await plane.list_tickets(tenant_id)
    await plane.post_metrics(
        tenant_id,
        tunnel_id=None,
        lease_id=None,
        bytes_in=1,
        bytes_out=2,
        handshake_count=0,
    )
    assert len(captured) == 3
    assert captured[0][0] == "GET"
    assert captured[0][1].endswith("/api/v1/hypermesh/gateway/tunnels")
    assert captured[1][0] == "GET"
    assert captured[1][1].endswith("/api/v1/hypermesh/gateway/tickets")
    assert captured[2][0] == "POST"
    assert captured[2][1].endswith("/api/v1/hypermesh/gateway/metrics")
    for _method, url, headers in captured:
        assert headers["Authorization"] == f"Bearer {secret}"
        assert headers["X-Tenant-ID"] == str(tenant_id)
        assert "/leases/" not in url


def _mock_runtime(app) -> None:
    import httpx

    async def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "id": "cmpl-test",
                "object": "chat.completion",
                "choices": [{"index": 0, "message": {"role": "assistant", "content": "ok"}}],
            },
        )

    app.state.runtime_client = httpx.AsyncClient(transport=httpx.MockTransport(handler))


@pytest.mark.asyncio
async def test_revoked_ticket_cannot_keep_session(
    http_client, tenant_headers, control_plane, app, tenant_id
):
    lease_id = uuid.uuid4()
    ticket = _signed_ticket(lease_id)
    control_plane.tunnels.append(_allocated_tunnel(lease_id))
    control_plane.ticket_pull = _ticket_pull([ticket])
    applied = await http_client.post(
        "/api/v1/hypermesh-gateway/tunnels/apply",
        headers=_gateway(tenant_headers),
    )
    assert applied.status_code == 200
    _mock_runtime(app)
    first = await http_client.post(
        "/v1/chat/completions",
        headers=_renter(tenant_headers),
        json={"lease_id": str(lease_id), "messages": [{"role": "user", "content": "keep going"}]},
    )
    assert first.status_code == 200

    control_plane.ticket_pull = TicketPull(
        tickets=[],
        revoked_lease_ids=[lease_id],
        key_fingerprints=TEST_RENTER_FINGERPRINTS,
    )
    from hypermesh_gateway_service.routes import refresh_assignments

    await refresh_assignments(control_plane, app.state.ticket_cache, tenant_id)
    refused = await http_client.post(
        "/v1/chat/completions",
        headers=_renter(tenant_headers),
        json={"lease_id": str(lease_id), "messages": [{"role": "user", "content": "keep going"}]},
    )
    assert refused.status_code == 409
    assert refused.json()["detail"] == INSTANCE_NOT_READY
    assert "path b" not in refused.text.lower()
    assert control_plane.get_lease_calls == 0


@pytest.mark.asyncio
async def test_path_b_not_green_cannot_keep_session(
    http_client, tenant_headers, app, tenant_id
):
    lease_id = uuid.uuid4()
    app.state.ticket_cache.put(
        tenant_id,
        _signed_ticket(lease_id, path_b_state="suspended"),
    )
    _mock_runtime(app)
    refused = await http_client.post(
        "/v1/chat/completions",
        headers=_renter(tenant_headers),
        json={"lease_id": str(lease_id), "messages": [{"role": "user", "content": "hi"}]},
    )
    assert refused.status_code == 409
    assert refused.json()["detail"] == INSTANCE_NOT_READY
    assert "path b" not in refused.text.lower()
    assert "soak" not in refused.text.lower()


@pytest.mark.asyncio
async def test_peer_down_cannot_keep_session(http_client, tenant_headers, app, tenant_id):
    lease_id = uuid.uuid4()
    app.state.ticket_cache.put(tenant_id, _signed_ticket(lease_id))
    app.state.peer_up = False
    _mock_runtime(app)
    refused = await http_client.post(
        "/v1/chat/completions",
        headers=_renter(tenant_headers),
        json={"lease_id": str(lease_id), "messages": [{"role": "user", "content": "hi"}]},
    )
    assert refused.status_code == 409
    assert refused.json()["detail"] == INSTANCE_NOT_READY


def _runtime_answering(app, handler) -> None:
    import httpx

    app.state.runtime_client = httpx.AsyncClient(transport=httpx.MockTransport(handler))


def _not_ready(response) -> dict:
    assert response.status_code == 409
    body = response.json()
    assert body["detail"] == INSTANCE_NOT_READY
    assert body["error"]["code"] == "instance_not_ready"
    assert body["error"]["message"] == INSTANCE_NOT_READY
    assert response.headers["x-hypermesh-not-ready"] == body["error"]["reason"]
    return body["error"]


@pytest.mark.asyncio
async def test_peer_down_is_retryable_instance_not_ready(http_client, tenant_headers, app, tenant_id):
    lease_id = uuid.uuid4()
    app.state.ticket_cache.put(tenant_id, _signed_ticket(lease_id))
    app.state.peer_up = False
    _mock_runtime(app)
    refused = await http_client.post(
        "/v1/chat/completions",
        headers=_renter(tenant_headers),
        json={"lease_id": str(lease_id), "messages": [{"role": "user", "content": "hi"}]},
    )
    error = _not_ready(refused)
    assert error["reason"] == "peer_down"
    assert error["retryable"] is True
    assert refused.headers["retry-after"] == "5"


@pytest.mark.asyncio
async def test_host_still_loading_is_retryable_instance_not_ready(
    http_client, tenant_headers, app, tenant_id
):
    import httpx

    lease_id = uuid.uuid4()
    app.state.ticket_cache.put(tenant_id, _signed_ticket(lease_id))

    async def loading(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            503,
            json={"error": {"code": 503, "message": "Loading model", "type": "unavailable_error"}},
        )

    _runtime_answering(app, loading)
    refused = await http_client.post(
        "/v1/chat/completions",
        headers=_renter(tenant_headers),
        json={"lease_id": str(lease_id), "messages": [{"role": "user", "content": "hi"}]},
    )
    error = _not_ready(refused)
    assert error["reason"] == "host_status_503"
    assert error["retryable"] is True
    assert refused.headers["retry-after"] == "5"
    assert "Loading model" not in refused.text


@pytest.mark.asyncio
async def test_host_port_closed_is_retryable_instance_not_ready(
    http_client, tenant_headers, app, tenant_id
):
    import httpx

    lease_id = uuid.uuid4()
    app.state.ticket_cache.put(tenant_id, _signed_ticket(lease_id))

    async def refused_connect(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("connection refused", request=request)

    _runtime_answering(app, refused_connect)
    refused = await http_client.post(
        "/v1/chat/completions",
        headers=_renter(tenant_headers),
        json={"lease_id": str(lease_id), "messages": [{"role": "user", "content": "hi"}]},
    )
    error = _not_ready(refused)
    assert error["reason"] == "host_unreachable"
    assert error["retryable"] is True


@pytest.mark.asyncio
async def test_host_4xx_and_unhonored_ticket_are_not_retryable(
    http_client, tenant_headers, app, tenant_id
):
    import httpx

    lease_id = uuid.uuid4()
    app.state.ticket_cache.put(tenant_id, _signed_ticket(lease_id))

    async def bad_request(request: httpx.Request) -> httpx.Response:
        return httpx.Response(400, json={"error": {"message": "bad tools"}})

    _runtime_answering(app, bad_request)
    refused = await http_client.post(
        "/v1/chat/completions",
        headers=_renter(tenant_headers),
        json={"lease_id": str(lease_id), "messages": [{"role": "user", "content": "hi"}]},
    )
    error = _not_ready(refused)
    assert error["reason"] == "host_status_400"
    assert error["retryable"] is False
    assert "retry-after" not in refused.headers

    suspended = uuid.uuid4()
    app.state.ticket_cache.put(tenant_id, _signed_ticket(suspended, path_b_state="suspended"))
    refused = await http_client.post(
        "/v1/chat/completions",
        headers=_renter(tenant_headers),
        json={"lease_id": str(suspended), "messages": [{"role": "user", "content": "hi"}]},
    )
    error = _not_ready(refused)
    assert error["reason"] == "not_honored"
    assert error["retryable"] is False
    assert "retry-after" not in refused.headers


@pytest.mark.asyncio
async def test_unhonored_ticket_with_peer_down_is_not_retryable(
    http_client, tenant_headers, app, tenant_id
):
    _mock_runtime(app)
    app.state.peer_up = False
    suspended = uuid.uuid4()
    app.state.ticket_cache.put(tenant_id, _signed_ticket(suspended, path_b_state="suspended"))
    wrong_purpose = uuid.uuid4()
    app.state.ticket_cache.put(tenant_id, _signed_ticket(wrong_purpose, purpose="ir"))
    for lease_id in (suspended, wrong_purpose):
        refused = await http_client.post(
            "/v1/chat/completions",
            headers=_renter(tenant_headers),
            json={"lease_id": str(lease_id), "messages": [{"role": "user", "content": "hi"}]},
        )
        error = _not_ready(refused)
        assert error["reason"] == "not_honored"
        assert error["retryable"] is False
        assert "retry-after" not in refused.headers


@pytest.mark.asyncio
async def test_renter_chat_accepts_service_purpose(
    http_client, tenant_headers, app, tenant_id
):
    lease_id = uuid.uuid4()
    app.state.ticket_cache.put(tenant_id, _signed_ticket(lease_id, purpose="service"))
    _mock_runtime(app)
    chat = await http_client.post(
        "/v1/chat/completions",
        headers=_renter(tenant_headers),
        json={"lease_id": str(lease_id), "messages": [{"role": "user", "content": "hi"}]},
    )
    assert chat.status_code == 200


@pytest.mark.asyncio
async def test_renter_chat_rejects_ir_purpose_as_instance_not_ready(
    http_client, tenant_headers, app, tenant_id
):
    lease_id = uuid.uuid4()
    app.state.ticket_cache.put(tenant_id, _signed_ticket(lease_id, purpose="ir"))
    _mock_runtime(app)
    refused = await http_client.post(
        "/v1/chat/completions",
        headers=_renter(tenant_headers),
        json={"lease_id": str(lease_id), "messages": [{"role": "user", "content": "hi"}]},
    )
    assert refused.status_code == 409
    assert refused.json()["detail"] == INSTANCE_NOT_READY
    assert "ir" not in refused.text.lower()
    assert "classify" not in refused.text.lower()
    assert "receipt" not in refused.text.lower()


@pytest.mark.asyncio
async def test_session_metrics_never_include_prompt_body(
    http_client, tenant_headers, control_plane, app, tenant_id
):
    from hypermesh_gateway_service.metrics import sanitize_metric_payload

    lease_id = uuid.uuid4()
    tunnel = _allocated_tunnel(lease_id)
    app.state.ticket_cache.put(
        tenant_id,
        _signed_ticket(lease_id, peer_public_key=tunnel.peer_public_key),
    )
    cached = app.state.ticket_cache.get(tenant_id, lease_id)
    assert cached is not None
    app.state.ticket_cache.put(
        tenant_id,
        CachedTicket(
            lease_id=cached.lease_id,
            ticket=cached.ticket,
            client_address=cached.client_address,
            assigned_gateway_id=cached.assigned_gateway_id,
            status=cached.status,
            exp=cached.exp,
            device_id=cached.device_id,
            path_b_state=cached.path_b_state,
            tunnel_id=tunnel.tunnel_id,
            peer_public_key=tunnel.peer_public_key,
        ),
    )
    _mock_runtime(app)
    prompt = "secret prompt must never reach spanopticon"
    chat = await http_client.post(
        "/v1/chat/completions",
        headers=_renter(tenant_headers),
        json={"lease_id": str(lease_id), "messages": [{"role": "user", "content": prompt}]},
    )
    assert chat.status_code == 200
    assert control_plane.post_metrics_calls == 1
    assert control_plane.get_lease_calls == 0
    metric = control_plane.metrics[-1]
    assert metric["lease_id"] == lease_id
    assert metric["tunnel_id"] == tunnel.tunnel_id
    assert isinstance(metric["bytes_in"], int)
    assert isinstance(metric["bytes_out"], int)
    dumped = str(control_plane.metrics)
    assert prompt not in dumped
    assert "secret prompt" not in dumped
    assert "messages" not in dumped
    sanitized = sanitize_metric_payload(
        tunnel_id=tunnel.tunnel_id,
        lease_id=lease_id,
        bytes_in=12,
        bytes_out=4,
        handshake_count=1,
    )
    assert set(sanitized) == {
        "tunnel_id",
        "lease_id",
        "bytes_in",
        "bytes_out",
        "handshake_count",
    }


@pytest.mark.asyncio
async def test_refresh_known_tenants_applies_allocated_host_peer(
    tenant_id, control_plane, monkeypatch
):
    from hypermesh_gateway_service.routes import refresh_known_tenants
    from hypermesh_gateway_service.tickets import TicketCache

    monkeypatch.setenv("HYPERMESH_TICKET_HMAC_KEY", "test-plane-hypermesh-ticket-hmac")
    applied: list[dict[str, str]] = []
    monkeypatch.setattr(
        "hypermesh_gateway_service.routes.apply_gateway",
        lambda **kwargs: applied.append(kwargs),
    )
    lease_id = uuid.uuid4()
    tunnel = _allocated_tunnel(lease_id)
    control_plane.tunnels.append(tunnel)
    control_plane.ticket_pull = _ticket_pull([_signed_ticket(lease_id)])
    cache = TicketCache()
    cache.watch(tenant_id)

    await refresh_known_tenants(control_plane, cache)

    assert control_plane.list_tunnels_calls == 1
    assert control_plane.list_tickets_calls == 1
    assert applied == [
        {
            "server_private_key": "server-priv",
            "peer_public_key": "peer-pub",
            "client_address": "10.77.0.2/32",
        }
    ]
    cached = cache.get(tenant_id, lease_id)
    assert cached is not None
    assert cached.peer_public_key == "peer-pub"


@pytest.mark.asyncio
async def test_refresh_known_tenants_skips_revoked_and_keyless_tunnels(
    tenant_id, control_plane, monkeypatch
):
    from hypermesh_gateway_service.routes import refresh_known_tenants
    from hypermesh_gateway_service.tickets import TicketCache

    applied: list[dict[str, str]] = []
    monkeypatch.setattr(
        "hypermesh_gateway_service.routes.apply_gateway",
        lambda **kwargs: applied.append(kwargs),
    )
    revoked = _allocated_tunnel(uuid.uuid4())
    revoked = GatewayTunnel(
        tunnel_id=revoked.tunnel_id,
        lease_id=revoked.lease_id,
        status="revoked",
        endpoint=revoked.endpoint,
        server_private_key=revoked.server_private_key,
        server_public_key=revoked.server_public_key,
        peer_public_key=revoked.peer_public_key,
        allowed_ips=revoked.allowed_ips,
        client_address=revoked.client_address,
    )
    keyless = GatewayTunnel(
        tunnel_id=uuid.uuid4(),
        lease_id=uuid.uuid4(),
        status="allocated",
        endpoint="wg.test.hyperme.sh:51820",
        server_private_key=None,
        server_public_key="server-pub",
        peer_public_key=None,
        allowed_ips="10.77.0.0/24",
        client_address="10.77.0.3/32",
    )
    control_plane.tunnels.extend([revoked, keyless])
    cache = TicketCache()
    cache.watch(tenant_id)

    await refresh_known_tenants(control_plane, cache)

    assert applied == []
    assert control_plane.list_tunnels_calls == 1


@pytest.mark.asyncio
async def test_refresh_known_tenants_does_not_remove_peer(
    tenant_id, control_plane, monkeypatch
):
    from hypermesh_gateway_service import wg
    from hypermesh_gateway_service.routes import refresh_known_tenants
    from hypermesh_gateway_service.tickets import TicketCache

    removed: list[str] = []
    monkeypatch.setattr(
        "hypermesh_gateway_service.routes.apply_gateway",
        lambda **kwargs: None,
    )
    monkeypatch.setattr(wg, "remove_peer", lambda key: removed.append(key))
    lease_id = uuid.uuid4()
    control_plane.tunnels.append(_allocated_tunnel(lease_id))
    cache = TicketCache()
    cache.watch(tenant_id)

    await refresh_known_tenants(control_plane, cache)

    assert removed == []


@pytest.mark.asyncio
async def test_refresh_known_tenants_drops_a_revoked_host_peer(
    tenant_id, control_plane, monkeypatch
):
    from hypermesh_gateway_service.routes import refresh_known_tenants
    from hypermesh_gateway_service.tickets import TicketCache

    removed: list[str] = []
    monkeypatch.setattr(
        "hypermesh_gateway_service.routes.remove_peer",
        lambda key: removed.append(key),
    )
    monkeypatch.setattr(
        "hypermesh_gateway_service.routes.apply_gateway",
        lambda **kwargs: None,
    )
    revoked = _allocated_tunnel(uuid.uuid4())
    control_plane.tunnels.append(
        GatewayTunnel(
            tunnel_id=revoked.tunnel_id,
            lease_id=revoked.lease_id,
            status="revoked",
            endpoint=revoked.endpoint,
            server_private_key=None,
            server_public_key=revoked.server_public_key,
            peer_public_key="revoked-peer",
            allowed_ips=revoked.allowed_ips,
            client_address=revoked.client_address,
        )
    )
    cache = TicketCache()
    cache.watch(tenant_id)

    await refresh_known_tenants(control_plane, cache)

    assert removed == ["revoked-peer"]


@pytest.mark.asyncio
async def test_tunnels_apply_uses_same_allocated_apply_path(
    http_client, tenant_headers, control_plane, monkeypatch
):
    applied: list[dict[str, str]] = []
    monkeypatch.setattr(
        "hypermesh_gateway_service.routes.apply_gateway",
        lambda **kwargs: applied.append(kwargs) is None,
    )
    lease_id = uuid.uuid4()
    control_plane.tunnels.append(_allocated_tunnel(lease_id))
    control_plane.ticket_pull = _ticket_pull([_signed_ticket(lease_id)])

    pulled = await http_client.post(
        "/api/v1/hypermesh-gateway/tunnels/apply",
        headers=_gateway(tenant_headers),
    )

    assert pulled.status_code == 200
    assert pulled.json() == {"applied": 1}
    assert applied == [
        {
            "server_private_key": "server-priv",
            "peer_public_key": "peer-pub",
            "client_address": "10.77.0.2/32",
        }
    ]


def test_seed_watched_tenants_defaults_to_marketplace_tenant(monkeypatch, tenant_id):
    from hypermesh_gateway_service.routes import seed_watched_tenants
    from hypermesh_gateway_service.tickets import TicketCache

    monkeypatch.delenv("HYPERMESH_TENANT_IDS", raising=False)
    cache = TicketCache()
    seed_watched_tenants(cache)
    assert tenant_id in cache.known_tenants()


def test_seed_watched_tenants_skips_invalid_ids(monkeypatch):
    from hypermesh_gateway_service.routes import seed_watched_tenants
    from hypermesh_gateway_service.tickets import TicketCache

    monkeypatch.setenv("HYPERMESH_TENANT_IDS", "not-a-uuid,")
    cache = TicketCache()
    seed_watched_tenants(cache)
    assert cache.known_tenants() == []


@pytest.mark.asyncio
async def test_lifespan_watches_marketplace_tenant_for_cold_refresh(
    http_client, app, tenant_id
):
    assert tenant_id in app.state.ticket_cache.known_tenants()


@pytest.mark.asyncio
async def test_chat_does_not_flap_host_peer(http_client, tenant_headers, app, tenant_id, monkeypatch):
    from hypermesh_gateway_service import wg

    calls: list[str] = []
    monkeypatch.setattr(wg, "apply_gateway", lambda **kwargs: calls.append("apply"))
    monkeypatch.setattr(wg, "remove_peer", lambda key: calls.append("remove"))
    lease_id = uuid.uuid4()
    app.state.ticket_cache.put(tenant_id, _signed_ticket(lease_id))
    _mock_runtime(app)
    chat = await http_client.post(
        "/v1/chat/completions",
        headers=_renter(tenant_headers),
        json={"lease_id": str(lease_id), "messages": [{"role": "user", "content": "hi"}]},
    )
    assert chat.status_code == 200
    assert calls == []


def test_peer_is_up_fail_closed_when_apply_on(monkeypatch):
    from hypermesh_gateway_service import wg

    monkeypatch.setattr(wg, "should_apply", lambda: True)
    monkeypatch.setattr(wg, "peer_handshake_epoch", lambda key: 0)
    assert wg.peer_is_up("peer-pub") is False
    monkeypatch.setattr(wg, "peer_handshake_epoch", lambda key: None)
    assert wg.peer_is_up("peer-pub") is False
    assert wg.peer_is_up(None) is False


def test_peer_status_does_not_call_remove(monkeypatch):
    from hypermesh_gateway_service import wg

    removed: list[str] = []
    monkeypatch.setattr(wg, "should_apply", lambda: True)
    monkeypatch.setattr(wg, "remove_peer", lambda key: removed.append(key))
    monkeypatch.setattr(wg, "peer_handshake_epoch", lambda key: 1)
    assert wg.peer_is_up("peer-pub", now=2) is True
    assert removed == []


def test_require_chat_posture_fails_closed_on_never_run(tenant_id, monkeypatch):
    monkeypatch.setenv("HYPERMESH_TICKET_HMAC_KEY", "test-plane-hypermesh-ticket-hmac")
    cache = TicketCache()
    lease_id = uuid.uuid4()
    cache.put(tenant_id, _signed_ticket(lease_id, path_b_state="never-run"))
    with pytest.raises(TicketNotReady):
        require_chat_posture(cache, tenant_id, lease_id, peer_up=True)


@pytest.mark.asyncio
async def test_http_control_plane_parses_path_b_state(tenant_id, monkeypatch):
    import httpx

    class DummyResponse:
        status_code = 200

        def raise_for_status(self) -> None:
            return None

        def json(self) -> dict:
            return {
                "tickets": [
                    {
                        "lease_id": str(uuid.uuid4()),
                        "ticket": "hm1.not-verified",
                        "client_address": "10.77.0.2/32",
                        "assigned_gateway_id": str(FYBER_TEST_GATEWAY_ID),
                        "status": "active",
                        "device_id": str(FYBER_AGX_DEVICE_ID),
                        "path_b_state": "green",
                    }
                ],
                "revoked_lease_ids": [],
            }

    class DummyClient:
        def __init__(self, *args, **kwargs) -> None:
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            return None

        async def get(self, url, headers=None):
            return DummyResponse()

    monkeypatch.setattr(httpx, "AsyncClient", DummyClient)
    plane = HttpControlPlane("http://hypermesh-service:8000", "hm_gw_test")
    pull = await plane.list_tickets(tenant_id)
    assert pull.tickets[0].path_b_state == "green"
    assert pull.tickets[0].device_id == FYBER_AGX_DEVICE_ID


class _AcceptJwt:
    def __init__(self, token: str, tenant_id: uuid.UUID | None = None) -> None:
        self.token = token
        self.tenant_id = tenant_id
        self.calls = 0

    def validate_sync(self, token: str) -> dict[str, object]:
        self.calls += 1
        if token != self.token:
            raise ValueError("rejected")
        claims: dict[str, object] = {"sub": "portal-user", "azp": "controlplane-frontend"}
        if self.tenant_id is not None:
            claims["https://spanopticon.dev/tenant_id"] = str(self.tenant_id)
        return claims

    async def validate(self, token: str) -> dict[str, object]:
        return self.validate_sync(token)


@pytest.mark.asyncio
async def test_chat_portal_jwt_local_verify_plus_ticket(
    http_client, tenant_headers, control_plane, app, tenant_id
):
    lease_id = uuid.uuid4()
    app.state.ticket_cache.put(tenant_id, _signed_ticket(lease_id))
    validator = _AcceptJwt("portal.jwt.token", tenant_id)
    app.state.renter_jwt_validator = validator
    _mock_runtime(app)
    chat = await http_client.post(
        "/v1/chat/completions",
        headers={**tenant_headers, "Authorization": "Bearer portal.jwt.token"},
        json={"lease_id": str(lease_id), "messages": [{"role": "user", "content": "hi"}]},
    )
    assert chat.status_code == 200
    assert chat.json()["object"] == "chat.completion"
    assert validator.calls == 1
    assert control_plane.get_lease_calls == 0
    assert control_plane.list_tickets_calls == 0

    refused = await http_client.post(
        "/v1/chat/completions",
        headers={**tenant_headers, "Authorization": "Bearer other.jwt.token"},
        json={"lease_id": str(lease_id), "messages": [{"role": "user", "content": "hi"}]},
    )
    assert refused.status_code == 401
    assert refused.json()["error"]["code"] == "invalid_api_key"
    assert control_plane.get_lease_calls == 0


@pytest.mark.asyncio
async def test_chat_exchange_jwt_plus_ticket_does_not_hit_control_plane(
    http_client, tenant_headers, control_plane, app, tenant_id
):
    from controlplane_identity.security.api_key_exchange_jwt import mint_api_key_session_jwt

    lease_id = uuid.uuid4()
    app.state.ticket_cache.put(tenant_id, _signed_ticket(lease_id))
    _mock_runtime(app)
    token = mint_api_key_session_jwt(
        key_record_id=uuid.uuid4(),
        tenant_id=tenant_id,
        scopes=[],
    )
    chat = await http_client.post(
        "/v1/chat/completions",
        headers={**tenant_headers, "Authorization": f"Bearer {token}"},
        json={"lease_id": str(lease_id), "messages": [{"role": "user", "content": "hi"}]},
    )
    assert chat.status_code == 200
    assert control_plane.get_lease_calls == 0
    assert control_plane.list_tunnels_calls == 0
    assert control_plane.list_tickets_calls == 0


@pytest.mark.asyncio
async def test_chat_x_api_key_plus_paid_ticket(
    http_client, tenant_headers, control_plane, app, tenant_id
):
    lease_id = uuid.uuid4()
    app.state.ticket_cache.put(tenant_id, _signed_ticket(lease_id))
    _mock_runtime(app)
    chat = await http_client.post(
        "/v1/chat/completions",
        headers={**tenant_headers, "X-Api-Key": "pk_test.renter-key"},
        json={"lease_id": str(lease_id), "messages": [{"role": "user", "content": "hi"}]},
    )
    assert chat.status_code == 200
    assert control_plane.get_lease_calls == 0


@pytest.mark.asyncio
async def test_chat_rejects_host_and_gateway_secrets(
    http_client, tenant_headers, control_plane, app, tenant_id
):
    lease_id = uuid.uuid4()
    app.state.ticket_cache.put(tenant_id, _signed_ticket(lease_id))
    _mock_runtime(app)
    for secret in ("hm_gw_test", "hm_dev_box-secret", "hm1.payload.sig", "hm_site_cottage"):
        refused = await http_client.post(
            "/v1/chat/completions",
            headers={**tenant_headers, "Authorization": f"Bearer {secret}"},
            json={"lease_id": str(lease_id), "messages": [{"role": "user", "content": "hi"}]},
        )
        assert refused.status_code == 401
        assert refused.json()["error"]["code"] == "invalid_api_key"
    assert control_plane.get_lease_calls == 0


@pytest.mark.asyncio
async def test_jwt_without_paid_ticket_is_instance_not_ready(
    http_client, tenant_headers, control_plane, app, tenant_id
):
    validator = _AcceptJwt("portal.jwt.token", tenant_id)
    app.state.renter_jwt_validator = validator
    refused = await http_client.post(
        "/v1/chat/completions",
        headers={**tenant_headers, "Authorization": "Bearer portal.jwt.token"},
        json={"lease_id": str(uuid.uuid4()), "messages": [{"role": "user", "content": "hi"}]},
    )
    assert refused.status_code == 403
    assert refused.json()["error"]["code"] == "lease_not_owned"
    assert validator.calls == 1
    assert control_plane.get_lease_calls == 0


@pytest.mark.asyncio
async def test_http_plane_accepts_idle_host_peer_without_lease(monkeypatch):
    """An idle allocated peer remains syncable after its lease is detached (#206)."""
    import httpx

    tenant_id = uuid.uuid4()
    tunnel_id = uuid.uuid4()
    row = {
        "tunnel_id": str(tunnel_id), "lease_id": None,
        "status": "allocated", "endpoint": "gateway.example.test:51820",
        "server_private_key": "test-private-key", "server_public_key": "test-server-key",
        "peer_public_key": "test-host-key", "allowed_ips": "10.77.0.0/24",
        "client_address": "10.77.0.2/32",
    }
    original_client = httpx.AsyncClient
    transport = httpx.MockTransport(lambda request: httpx.Response(200, json=[row]))
    monkeypatch.setattr(httpx, "AsyncClient", lambda **kwargs: original_client(transport=transport, **kwargs))
    tunnels = await HttpControlPlane("https://plane.example.test", "test-service-secret").list_tunnels(tenant_id)
    assert len(tunnels) == 1
    assert tunnels[0].lease_id is None
    assert tunnels[0].tunnel_id == tunnel_id
    assert tunnels[0].status == "allocated"
    assert tunnels[0].client_address == row["client_address"]
