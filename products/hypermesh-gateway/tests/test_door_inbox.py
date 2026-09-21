from __future__ import annotations

import uuid
from datetime import UTC, datetime

import httpx
import pytest
from asgi_lifespan import LifespanManager

from hypermesh_gateway_service.app import create_app
from hypermesh_gateway_service.inbox import (
    ClosedApprovalInbox,
    FakeApprovalInbox,
    HttpApprovalInbox,
    InboxUnavailable,
    InboxView,
    _view_from_body,
    resolve_approval_inbox,
)
from test_hypermesh_gateway import (
    TEST_IR_FINGERPRINTS,
    _ir as ir_headers,
    _mock_runtime,
    _renter as renter_headers,
    _signed_ticket,
)
from test_ir_door import _HoldAllClassifier


def _view(
    *,
    lease_id: uuid.UUID,
    status: str = "held",
    decision: str | None = None,
    consumed: bool = False,
    who: str = "pk_test",
    prompt_class: str = "out_of_scope",
) -> InboxView:
    return InboxView(
        id=uuid.uuid4(),
        status=status,
        decision=decision,
        consumed=consumed,
        lease_id=lease_id,
        who=who,
        prompt_class=prompt_class,
    )


@pytest.mark.asyncio
async def test_closed_inbox_keeps_receipt_only_hold(
    http_client, tenant_headers, app, tenant_id
):
    lease_id = uuid.uuid4()
    app.state.ticket_cache.put(tenant_id, _signed_ticket(lease_id, purpose="ir"))
    app.state.approval_inbox = ClosedApprovalInbox()

    async def boom(request):  # pragma: no cover
        raise AssertionError("hold must not proxy")

    app.state.runtime_client = httpx.AsyncClient(transport=httpx.MockTransport(boom))
    held = await http_client.post(
        "/v1/ir/chat/completions",
        headers=ir_headers(tenant_headers),
        json={
            "lease_id": str(lease_id),
            "messages": [{"role": "user", "content": "Write a haiku about coffee."}],
        },
    )
    assert held.status_code == 200
    body = held.json()
    assert body["decision"] == "hold"
    assert "approval_id" not in body
    assert body["receipt"]["decision"] == "hold"


@pytest.mark.asyncio
async def test_renter_chat_does_not_file_inbox(
    http_client, tenant_headers, app, tenant_id
):
    lease_id = uuid.uuid4()
    inbox = FakeApprovalInbox()
    app.state.approval_inbox = inbox
    app.state.ticket_cache.put(tenant_id, _signed_ticket(lease_id, purpose="renter"))
    _mock_runtime(app)
    chat = await http_client.post(
        "/v1/chat/completions",
        headers=renter_headers(tenant_headers),
        json={
            "lease_id": str(lease_id),
            "messages": [{"role": "user", "content": "Write a haiku about coffee."}],
        },
    )
    assert chat.status_code == 200
    assert inbox.hold_calls == []
    assert chat.json()["object"] == "chat.completion"


@pytest.mark.asyncio
async def test_ir_hold_files_inbox_row(
    http_client, tenant_headers, app, tenant_id
):
    lease_id = uuid.uuid4()
    inbox = FakeApprovalInbox()
    app.state.approval_inbox = inbox
    app.state.ticket_cache.put(tenant_id, _signed_ticket(lease_id, purpose="ir"))

    async def boom(request):  # pragma: no cover
        raise AssertionError("hold must not proxy")

    app.state.runtime_client = httpx.AsyncClient(transport=httpx.MockTransport(boom))
    held = await http_client.post(
        "/v1/ir/chat/completions",
        headers=ir_headers(tenant_headers),
        json={
            "lease_id": str(lease_id),
            "messages": [{"role": "user", "content": "Write a haiku about coffee."}],
        },
    )
    assert held.status_code == 200
    body = held.json()
    assert body["decision"] == "hold"
    assert body["approval_id"]
    assert inbox.hold_calls == [
        {
            "lease_id": lease_id,
            "who": "pk_test",
            "prompt_class": "out_of_scope",
            "purpose": "ir",
        }
    ]
    retry = await http_client.post(
        "/v1/ir/chat/completions",
        headers=ir_headers(tenant_headers),
        json={
            "lease_id": str(lease_id),
            "messages": [{"role": "user", "content": "Write a haiku about coffee."}],
        },
    )
    assert retry.status_code == 200
    assert retry.json()["approval_id"] == body["approval_id"]
    assert len(inbox.hold_calls) == 1


@pytest.mark.asyncio
async def test_allow_session_resumes_on_retry(
    tenant_headers, tenant_id, control_plane, monkeypatch
):
    monkeypatch.setenv("HYPERMESH_WG_APPLY", "0")
    monkeypatch.setenv("HYPERMESH_ASSIGNMENT_REFRESH_S", "0")
    monkeypatch.setenv("HYPERMESH_TICKET_HMAC_KEY", "test-plane-hypermesh-ticket-hmac")
    lease_id = uuid.uuid4()
    inbox = FakeApprovalInbox()
    inbox.seed(
        _view(
            lease_id=lease_id,
            status="allowed",
            decision="allow_session",
        )
    )
    app = create_app(
        control_plane=control_plane,
        gateway_service_secret="hm_gw_test",
        classifier=_HoldAllClassifier(),
        approval_inbox=inbox,
    )
    async with LifespanManager(app):
        app.state.ticket_cache.put(tenant_id, _signed_ticket(lease_id, purpose="ir"))
        app.state.ticket_cache.accept_ir_keys(tenant_id, TEST_IR_FINGERPRINTS)
        _mock_runtime(app)
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            chat = await client.post(
                "/v1/ir/chat/completions",
                headers=ir_headers(tenant_headers),
                json={
                    "lease_id": str(lease_id),
                    "messages": [{"role": "user", "content": "Write a haiku about coffee."}],
                },
            )
    assert chat.status_code == 200, chat.text
    assert chat.json()["object"] == "chat.completion"
    assert inbox.consume_calls == []
    assert inbox.hold_calls == []


@pytest.mark.asyncio
async def test_allow_once_resumes_once_then_holds_again(
    tenant_headers, tenant_id, control_plane, monkeypatch
):
    monkeypatch.setenv("HYPERMESH_WG_APPLY", "0")
    monkeypatch.setenv("HYPERMESH_ASSIGNMENT_REFRESH_S", "0")
    monkeypatch.setenv("HYPERMESH_TICKET_HMAC_KEY", "test-plane-hypermesh-ticket-hmac")
    lease_id = uuid.uuid4()
    inbox = FakeApprovalInbox()
    inbox.seed(
        _view(lease_id=lease_id, status="allowed", decision="allow_once")
    )
    app = create_app(
        control_plane=control_plane,
        gateway_service_secret="hm_gw_test",
        classifier=_HoldAllClassifier(),
        approval_inbox=inbox,
    )
    async with LifespanManager(app):
        app.state.ticket_cache.put(tenant_id, _signed_ticket(lease_id, purpose="ir"))
        app.state.ticket_cache.accept_ir_keys(tenant_id, TEST_IR_FINGERPRINTS)
        _mock_runtime(app)
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            first = await client.post(
                "/v1/ir/chat/completions",
                headers=ir_headers(tenant_headers),
                json={
                    "lease_id": str(lease_id),
                    "messages": [{"role": "user", "content": "Write a haiku about coffee."}],
                },
            )
            app.state.runtime_client = httpx.AsyncClient(
                transport=httpx.MockTransport(
                    lambda request: (_ for _ in ()).throw(
                        AssertionError("second hold must not proxy")
                    )
                )
            )
            second = await client.post(
                "/v1/ir/chat/completions",
                headers=ir_headers(tenant_headers),
                json={
                    "lease_id": str(lease_id),
                    "messages": [{"role": "user", "content": "Write a haiku about coffee."}],
                },
            )
    assert first.status_code == 200
    assert first.json()["object"] == "chat.completion"
    assert len(inbox.consume_calls) == 1
    assert second.status_code == 200
    assert second.json()["decision"] == "hold"
    assert second.json()["approval_id"]
    assert len(inbox.hold_calls) == 1


@pytest.mark.asyncio
async def test_deny_stays_denied_on_retry(
    tenant_headers, tenant_id, control_plane, monkeypatch
):
    monkeypatch.setenv("HYPERMESH_WG_APPLY", "0")
    monkeypatch.setenv("HYPERMESH_ASSIGNMENT_REFRESH_S", "0")
    monkeypatch.setenv("HYPERMESH_TICKET_HMAC_KEY", "test-plane-hypermesh-ticket-hmac")
    lease_id = uuid.uuid4()
    inbox = FakeApprovalInbox()
    denied = inbox.seed(
        _view(lease_id=lease_id, status="denied", decision="deny")
    )
    app = create_app(
        control_plane=control_plane,
        gateway_service_secret="hm_gw_test",
        classifier=_HoldAllClassifier(),
        approval_inbox=inbox,
    )

    async def boom(request):  # pragma: no cover
        raise AssertionError("deny must not proxy")

    async with LifespanManager(app):
        app.state.ticket_cache.put(tenant_id, _signed_ticket(lease_id, purpose="ir"))
        app.state.ticket_cache.accept_ir_keys(tenant_id, TEST_IR_FINGERPRINTS)
        app.state.runtime_client = httpx.AsyncClient(
            transport=httpx.MockTransport(boom)
        )
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            refused = await client.post(
                "/v1/ir/chat/completions",
                headers=ir_headers(tenant_headers),
                json={
                    "lease_id": str(lease_id),
                    "messages": [{"role": "user", "content": "Write a haiku about coffee."}],
                },
            )
    assert refused.status_code == 409
    body = refused.json()
    assert body["decision"] == "deny"
    assert body["approval_id"] == str(denied.id)
    assert body["receipt"]["decision"] == "deny"
    assert inbox.hold_calls == []


@pytest.mark.asyncio
async def test_inbox_hop_failure_holds_without_proxy(
    tenant_headers, tenant_id, control_plane, monkeypatch
):
    monkeypatch.setenv("HYPERMESH_WG_APPLY", "0")
    monkeypatch.setenv("HYPERMESH_ASSIGNMENT_REFRESH_S", "0")
    monkeypatch.setenv("HYPERMESH_TICKET_HMAC_KEY", "test-plane-hypermesh-ticket-hmac")
    lease_id = uuid.uuid4()
    inbox = FakeApprovalInbox()
    inbox.latest_error = "down"
    inbox.hold_error = "down"
    app = create_app(
        control_plane=control_plane,
        gateway_service_secret="hm_gw_test",
        classifier=_HoldAllClassifier(),
        approval_inbox=inbox,
    )

    async def boom(request):  # pragma: no cover
        raise AssertionError("failed inbox must not proxy")

    async with LifespanManager(app):
        app.state.ticket_cache.put(tenant_id, _signed_ticket(lease_id, purpose="ir"))
        app.state.ticket_cache.accept_ir_keys(tenant_id, TEST_IR_FINGERPRINTS)
        app.state.runtime_client = httpx.AsyncClient(
            transport=httpx.MockTransport(boom)
        )
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            held = await client.post(
                "/v1/ir/chat/completions",
                headers=ir_headers(tenant_headers),
                json={
                    "lease_id": str(lease_id),
                    "messages": [{"role": "user", "content": "Write a haiku about coffee."}],
                },
            )
    assert held.status_code == 200
    assert held.json()["decision"] == "hold"
    assert "approval_id" not in held.json()


def test_resolve_approval_inbox_closed_without_url(monkeypatch):
    monkeypatch.delenv("AIUDITOR_SERVICE_URL", raising=False)
    monkeypatch.delenv("AIUDITOR_INTERNAL_TOKEN", raising=False)
    assert isinstance(resolve_approval_inbox(), ClosedApprovalInbox)
    monkeypatch.setenv("AIUDITOR_SERVICE_URL", "http://aiuditor-service:8000")
    assert isinstance(resolve_approval_inbox(), ClosedApprovalInbox)
    monkeypatch.setenv("AIUDITOR_INTERNAL_TOKEN", "door-token")
    resolved = resolve_approval_inbox()
    assert isinstance(resolved, HttpApprovalInbox)


@pytest.mark.asyncio
async def test_http_inbox_hold_latest_consume(monkeypatch):
    approval_id = uuid.uuid4()
    lease_id = uuid.uuid4()
    tenant_id = uuid.uuid4()
    store: dict[str, object] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.headers["x-internal-token"] == "door-token"
        assert request.headers["x-tenant-id"] == str(tenant_id)
        if request.method == "POST" and request.url.path.endswith("/approvals"):
            store["row"] = {
                "id": str(approval_id),
                "status": "held",
                "decision": None,
                "consumed_at": None,
                "lease_id": str(lease_id),
                "who": "pk_test",
                "prompt_class": "out_of_scope",
                "expires_at": datetime(2026, 9, 20, 18, 0, tzinfo=UTC).isoformat(),
            }
            return httpx.Response(201, json=store["row"])
        if request.method == "GET" and request.url.path.endswith("/approvals/latest"):
            if "row" not in store:
                return httpx.Response(404, json={"detail": "Approval not found"})
            return httpx.Response(200, json=store["row"])
        if request.method == "POST" and str(request.url).endswith("/consume"):
            row = dict(store["row"])
            row["status"] = "allowed"
            row["decision"] = "allow_once"
            row["consumed_at"] = datetime(2026, 9, 20, 17, 10, tzinfo=UTC).isoformat()
            store["row"] = row
            return httpx.Response(200, json=row)
        return httpx.Response(500, json={"detail": "unexpected"})

    hop = HttpApprovalInbox("http://aiuditor-service:8000", "door-token")
    transport = httpx.MockTransport(handler)

    class _Client(httpx.AsyncClient):
        def __init__(self, *args, **kwargs):
            kwargs["transport"] = transport
            super().__init__(*args, **kwargs)

    monkeypatch.setattr(httpx, "AsyncClient", _Client)
    missing = await hop.latest(
        tenant_id, lease_id=lease_id, who="pk_test", prompt_class="out_of_scope"
    )
    assert missing is None
    created = await hop.hold(
        tenant_id,
        lease_id=lease_id,
        who="pk_test",
        prompt_class="out_of_scope",
    )
    assert created is not None
    assert created.id == approval_id
    assert created.status == "held"
    found = await hop.latest(
        tenant_id, lease_id=lease_id, who="pk_test", prompt_class="out_of_scope"
    )
    assert found is not None
    assert found.id == approval_id
    consumed = await hop.consume(tenant_id, approval_id)
    assert consumed.consumed is True


@pytest.mark.asyncio
async def test_http_inbox_errors_are_unavailable(monkeypatch):
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(503, json={"detail": "down"})

    hop = HttpApprovalInbox("http://aiuditor-service:8000", "door-token")

    class _Client(httpx.AsyncClient):
        def __init__(self, *args, **kwargs):
            kwargs["transport"] = httpx.MockTransport(handler)
            super().__init__(*args, **kwargs)

    monkeypatch.setattr(httpx, "AsyncClient", _Client)
    with pytest.raises(InboxUnavailable):
        await hop.hold(
            uuid.uuid4(),
            lease_id=uuid.uuid4(),
            who="pk_test",
            prompt_class="out_of_scope",
        )
    with pytest.raises(InboxUnavailable):
        await hop.latest(
            uuid.uuid4(),
            lease_id=uuid.uuid4(),
            who="pk_test",
            prompt_class="out_of_scope",
        )
    with pytest.raises(InboxUnavailable):
        await hop.consume(uuid.uuid4(), uuid.uuid4())


@pytest.mark.asyncio
async def test_closed_consume_is_unavailable():
    with pytest.raises(InboxUnavailable):
        await ClosedApprovalInbox().consume(uuid.uuid4(), uuid.uuid4())


@pytest.mark.asyncio
async def test_fake_latest_session_covers_other_class():
    inbox = FakeApprovalInbox()
    lease = uuid.uuid4()
    inbox.seed(
        _view(
            lease_id=lease,
            status="allowed",
            decision="allow_session",
            prompt_class="incident_triage",
        )
    )
    found = await inbox.latest(
        uuid.uuid4(),
        lease_id=lease,
        who="pk_test",
        prompt_class="out_of_scope",
    )
    assert found is not None
    assert found.decision == "allow_session"
    with pytest.raises(InboxUnavailable):
        await inbox.consume(uuid.uuid4(), uuid.uuid4())


def test_view_from_body_rejects_junk():
    with pytest.raises(InboxUnavailable):
        _view_from_body([])
    with pytest.raises(InboxUnavailable):
        _view_from_body({})
    with pytest.raises(InboxUnavailable):
        _view_from_body({"id": "not-a-uuid"})
    with pytest.raises(InboxUnavailable):
        _view_from_body({"id": str(uuid.uuid4()), "lease_id": "nope"})
    with pytest.raises(InboxUnavailable):
        _view_from_body({"id": str(uuid.uuid4()), "expires_at": "not-a-date"})


@pytest.mark.asyncio
async def test_http_inbox_transport_errors(monkeypatch):
    class _Boom:
        def __init__(self, *args, **kwargs):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            return False

        async def post(self, *args, **kwargs):
            raise httpx.ConnectError("nope")

        async def get(self, *args, **kwargs):
            raise httpx.ConnectError("nope")

    monkeypatch.setattr(httpx, "AsyncClient", _Boom)
    hop = HttpApprovalInbox("http://aiuditor-service:8000", "door-token")
    with pytest.raises(InboxUnavailable):
        await hop.hold(
            uuid.uuid4(),
            lease_id=uuid.uuid4(),
            who="pk_test",
            prompt_class="out_of_scope",
        )
    with pytest.raises(InboxUnavailable):
        await hop.latest(
            uuid.uuid4(),
            lease_id=uuid.uuid4(),
            who="pk_test",
            prompt_class="out_of_scope",
        )
    with pytest.raises(InboxUnavailable):
        await hop.consume(uuid.uuid4(), uuid.uuid4())


@pytest.mark.asyncio
async def test_allow_once_consume_failure_holds(
    tenant_headers, tenant_id, control_plane, monkeypatch
):
    monkeypatch.setenv("HYPERMESH_WG_APPLY", "0")
    monkeypatch.setenv("HYPERMESH_ASSIGNMENT_REFRESH_S", "0")
    monkeypatch.setenv("HYPERMESH_TICKET_HMAC_KEY", "test-plane-hypermesh-ticket-hmac")
    lease_id = uuid.uuid4()
    inbox = FakeApprovalInbox()
    inbox.seed(_view(lease_id=lease_id, status="allowed", decision="allow_once"))
    inbox.consume_error = "down"
    app = create_app(
        control_plane=control_plane,
        gateway_service_secret="hm_gw_test",
        classifier=_HoldAllClassifier(),
        approval_inbox=inbox,
    )

    async def boom(request):  # pragma: no cover
        raise AssertionError("failed consume must not proxy")

    async with LifespanManager(app):
        app.state.ticket_cache.put(tenant_id, _signed_ticket(lease_id, purpose="ir"))
        app.state.ticket_cache.accept_ir_keys(tenant_id, TEST_IR_FINGERPRINTS)
        app.state.runtime_client = httpx.AsyncClient(
            transport=httpx.MockTransport(boom)
        )
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            held = await client.post(
                "/v1/ir/chat/completions",
                headers=ir_headers(tenant_headers),
                json={
                    "lease_id": str(lease_id),
                    "messages": [{"role": "user", "content": "Write a haiku about coffee."}],
                },
            )
    assert held.status_code == 200
    assert held.json()["decision"] == "hold"
    assert inbox.consume_calls == [inbox.rows[0].id]
