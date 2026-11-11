from __future__ import annotations

import uuid

import httpx
import pytest
from asgi_lifespan import LifespanManager

from hypermesh_gateway_service.app import create_app
from hypermesh_gateway_service.inbox import FakeApprovalInbox
from hypermesh_gateway_service.policy import PolicyView, decide_policy, policy_needs_classify
from test_hypermesh_gateway import (
    TEST_IR_FINGERPRINTS,
    _ir as ir_headers,
    _mock_runtime,
    _renter as renter_headers,
    _signed_ticket,
)
from test_ir_door import _HoldAllClassifier


def test_decide_policy_defaults():
    assert (
        decide_policy("renter", [], prompt_class=None, taxonomy_decision="hold")
        == "allow"
    )
    assert (
        decide_policy("ir", [], prompt_class="out_of_scope", taxonomy_decision="hold")
        == "hold"
    )
    rows = [
        PolicyView(purpose="renter", disposition="hold"),
        PolicyView(
            purpose="renter", disposition="allow", prompt_class="incident_triage"
        ),
    ]
    assert (
        decide_policy(
            "renter",
            rows,
            prompt_class="incident_triage",
            taxonomy_decision="hold",
        )
        == "allow"
    )
    assert (
        decide_policy(
            "renter", rows, prompt_class="out_of_scope", taxonomy_decision="hold"
        )
        == "hold"
    )
    assert policy_needs_classify(rows) is True
    assert policy_needs_classify([PolicyView(purpose="renter", disposition="deny")]) is False


@pytest.mark.asyncio
async def test_renter_chat_stays_unclassified_without_policy(
    http_client, tenant_headers, app, tenant_id
):
    lease_id = uuid.uuid4()
    inbox = FakeApprovalInbox()
    inbox.policy_rows = []
    app.state.approval_inbox = inbox
    app.state.ticket_cache.put(tenant_id, _signed_ticket(lease_id, purpose="renter"))
    _mock_runtime(app)
    prompt = "Write a haiku about coffee."
    chat = await http_client.post(
        "/v1/chat/completions",
        headers=renter_headers(tenant_headers),
        json={"lease_id": str(lease_id), "messages": [{"role": "user", "content": prompt}]},
    )
    assert chat.status_code == 200
    assert chat.json()["object"] == "chat.completion"
    assert "decision" not in chat.json()
    assert inbox.hold_calls == []
    assert app.state.receipt_store.count_for(tenant_id) == 0


@pytest.mark.asyncio
async def test_renter_opt_in_hold_files_inbox(
    http_client, tenant_headers, app, tenant_id
):
    lease_id = uuid.uuid4()
    inbox = FakeApprovalInbox()
    inbox.policy_rows = [PolicyView(purpose="renter", disposition="hold")]
    app.state.approval_inbox = inbox
    app.state.classifier = _HoldAllClassifier()
    app.state.ticket_cache.put(tenant_id, _signed_ticket(lease_id, purpose="renter"))

    async def boom(request):  # pragma: no cover
        raise AssertionError("renter hold must not proxy")

    app.state.runtime_client = httpx.AsyncClient(transport=httpx.MockTransport(boom))
    held = await http_client.post(
        "/v1/chat/completions",
        headers=renter_headers(tenant_headers),
        json={
            "lease_id": str(lease_id),
            "messages": [{"role": "user", "content": "Write a haiku about coffee."}],
        },
    )
    assert held.status_code == 200
    body = held.json()
    assert body["decision"] == "hold"
    assert body["approval_id"]
    assert inbox.hold_calls[0]["purpose"] == "renter"
    assert inbox.hold_calls[0]["prompt_class"] == "out_of_scope"


@pytest.mark.asyncio
async def test_renter_purpose_wide_deny(
    http_client, tenant_headers, app, tenant_id
):
    lease_id = uuid.uuid4()
    inbox = FakeApprovalInbox()
    inbox.policy_rows = [PolicyView(purpose="renter", disposition="deny")]
    app.state.approval_inbox = inbox
    app.state.ticket_cache.put(tenant_id, _signed_ticket(lease_id, purpose="renter"))

    async def boom(request):  # pragma: no cover
        raise AssertionError("policy deny must not proxy")

    app.state.runtime_client = httpx.AsyncClient(transport=httpx.MockTransport(boom))
    refused = await http_client.post(
        "/v1/chat/completions",
        headers=renter_headers(tenant_headers),
        json={
            "lease_id": str(lease_id),
            "messages": [{"role": "user", "content": "Write a haiku about coffee."}],
        },
    )
    assert refused.status_code == 409
    assert refused.json()["decision"] == "deny"
    assert "approval_id" not in refused.json()
    assert inbox.hold_calls == []


@pytest.mark.asyncio
async def test_ir_policy_can_allow_a_held_class(
    tenant_headers, tenant_id, control_plane, monkeypatch
):
    monkeypatch.setenv("HYPERMESH_WG_APPLY", "0")
    monkeypatch.setenv("HYPERMESH_ASSIGNMENT_REFRESH_S", "0")
    monkeypatch.setenv("HYPERMESH_TICKET_HMAC_KEY", "test-plane-hypermesh-ticket-hmac")
    lease_id = uuid.uuid4()
    inbox = FakeApprovalInbox()
    inbox.policy_rows = [
        PolicyView(
            purpose="ir", disposition="allow", prompt_class="out_of_scope"
        )
    ]
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
    assert inbox.hold_calls == []


@pytest.mark.asyncio
async def test_ir_policy_can_deny_a_class(
    tenant_headers, tenant_id, control_plane, monkeypatch
):
    monkeypatch.setenv("HYPERMESH_WG_APPLY", "0")
    monkeypatch.setenv("HYPERMESH_ASSIGNMENT_REFRESH_S", "0")
    monkeypatch.setenv("HYPERMESH_TICKET_HMAC_KEY", "test-plane-hypermesh-ticket-hmac")
    lease_id = uuid.uuid4()
    inbox = FakeApprovalInbox()
    inbox.policy_rows = [
        PolicyView(
            purpose="ir", disposition="deny", prompt_class="out_of_scope"
        )
    ]
    app = create_app(
        control_plane=control_plane,
        gateway_service_secret="hm_gw_test",
        classifier=_HoldAllClassifier(),
        approval_inbox=inbox,
    )

    async def boom(request):  # pragma: no cover
        raise AssertionError("policy deny must not proxy")

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
    assert refused.json()["decision"] == "deny"
    assert inbox.hold_calls == []


@pytest.mark.asyncio
@pytest.mark.parametrize("ir", [False, True])
@pytest.mark.parametrize("disposition", ["deny", "hold"])
async def test_policy_hop_failure_refuses_renter(
    http_client, tenant_headers, app, tenant_id, ir, disposition
):
    lease_id = uuid.uuid4()
    inbox = FakeApprovalInbox()
    inbox.policy_error = "down"
    inbox.policy_rows = [PolicyView(purpose="ir" if ir else "renter", disposition=disposition)]
    app.state.approval_inbox = inbox
    app.state.ticket_cache.put(tenant_id, _signed_ticket(lease_id, purpose="ir" if ir else "renter"))
    app.state.ticket_cache.accept_ir_keys(tenant_id, TEST_IR_FINGERPRINTS)
    async def forbidden(request):
        raise AssertionError("policy outage must not reach host")
    app.state.runtime_client = httpx.AsyncClient(transport=httpx.MockTransport(forbidden))
    chat = await http_client.post(
        "/v1/ir/chat/completions" if ir else "/v1/chat/completions",
        headers=(ir_headers if ir else renter_headers)(tenant_headers),
        json={
            "lease_id": str(lease_id),
            "messages": [{"role": "user", "content": "Write a haiku about coffee."}],
        },
    )
    assert chat.status_code == 503
    assert inbox.hold_calls == []
