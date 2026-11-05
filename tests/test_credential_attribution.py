"""One presented credential must own authorization and all downstream attribution."""
import uuid
from unittest.mock import AsyncMock

import httpx
import pytest

from hypermesh_gateway_service.inbox import FakeApprovalInbox
from hypermesh_gateway_service.renter_auth import (
    RenterUnauthorized, presented_renter_key, require_renter_grant,
)
from hypermesh_gateway_service.safety import CATEGORY_SELF_HARM, SafetyFlag
from hypermesh_ticket import renter_key_fingerprint
from test_hypermesh_gateway import _signed_ticket
from test_ir_door import _HoldAllClassifier
from test_renter_auth import _AcceptJwt, _request


@pytest.mark.parametrize("consumer", [require_renter_grant, presented_renter_key])
@pytest.mark.parametrize("bearer,key", [("Bearer aaa.bbb.ccc", "pk_test.ir-key"), ("Bearer forged.key", "pk_test.ir-key"), ("", "pk_test.ir-key"), ("Bearer pk_test.renter-key", ""), ("invalid", "garbage")])
def test_credential_consumers_reject_dual_headers_before_verification(consumer, bearer, key):
    validator = _AcceptJwt("aaa.bbb.ccc", uuid.uuid4())
    request = _request(authorization=bearer, api_key=key, validator=validator)
    with pytest.raises(RenterUnauthorized):
        consumer(request)
    assert validator.calls == 0


@pytest.mark.asyncio
@pytest.mark.parametrize("path,purpose", [
    ("/v1/chat/completions", "renter"), ("/v1/ir/chat/completions", "ir"),
    ("/api/v1/hypermesh-gateway/v1/chat/completions", "renter"),
    ("/api/v1/hypermesh-gateway/v1/ir/chat/completions", "ir"),
])
@pytest.mark.parametrize("authorization", ["Bearer forged.subject", "", "malformed"])
async def test_both_chat_doors_deny_before_lookup_or_attribution(http_client, app, tenant_id, control_plane, monkeypatch, path, purpose, authorization):
    lease = uuid.uuid4()
    app.state.ticket_cache.put(tenant_id, _signed_ticket(lease, purpose=purpose))
    inbox = FakeApprovalInbox()
    app.state.approval_inbox = inbox
    validate = AsyncMock(side_effect=AssertionError("must not validate an ambiguous credential"))
    app.state.api_key_validator = validate
    calls = []

    async def runtime(request):
        calls.append(request)
        raise AssertionError("ambiguous request reached the host")

    app.state.runtime_client = httpx.AsyncClient(transport=httpx.MockTransport(runtime))
    response = await http_client.post(path, headers={
        "aUtHoRiZaTiOn": authorization, "X-aPi-KeY": "pk_test.ir-key" if purpose == "ir" else "pk_test.renter-key",
        "X-Tenant-ID": str(tenant_id),
    }, json={"lease_id": str(lease), "messages": [{"role": "user", "content": "Synthetic attribution request"}]})
    assert response.status_code == 401, response.text
    validate.assert_not_awaited()
    assert calls == [] and inbox.hold_calls == [] and inbox.consume_calls == []
    assert app.state.receipt_store.count_for(tenant_id) == 0
    assert control_plane.safety_flags == []
    assert control_plane.get_lease_calls == 0 and control_plane.list_tickets_calls == 0


class _SyntheticSafetyFlag:
    version = "attribution-test-v1"

    def screen(self, text):
        return SafetyFlag(CATEGORY_SELF_HARM, "synthetic-attribution", self.version)


@pytest.mark.asyncio
@pytest.mark.parametrize("header", ["Authorization", "X-Api-Key"])
async def test_single_valid_key_owns_approval_receipt_and_safety(http_client, app, tenant_id, control_plane, header, monkeypatch):
    monkeypatch.setenv("HYPERMESH_SAFETY_TIMEOUT_MS", "5000")
    key = "verified_subject.fixture-key"
    lease = uuid.uuid4()
    app.state.ticket_cache.put(tenant_id, _signed_ticket(lease, purpose="ir"))
    app.state.ticket_cache.accept_ir_keys(tenant_id, [renter_key_fingerprint(key)])
    app.state.classifier = _HoldAllClassifier()
    app.state.safety_classifier = _SyntheticSafetyFlag()
    inbox = FakeApprovalInbox()
    app.state.approval_inbox = inbox
    response = await http_client.post("/v1/ir/chat/completions", headers={
        header: "Bearer " + key if header == "Authorization" else key,
        "X-Tenant-ID": str(tenant_id),
    }, json={"lease_id": str(lease), "messages": [{"role": "user", "content": "Synthetic out-of-scope request"}]})
    assert response.status_code == 200, response.text
    assert response.json()["decision"] == "hold"
    assert response.json()["receipt"]["who"] == "verified_subject"
    assert len(inbox.hold_calls) == 1 and inbox.hold_calls[0]["who"] == "verified_subject"
    assert len(control_plane.safety_flags) == 1
    assert control_plane.safety_flags[0].subject == "verified_subject"
