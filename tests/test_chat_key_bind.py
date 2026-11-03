"""Chat proves possession of a tenant-bound key. Two UUIDs are not a credential."""

from __future__ import annotations

import uuid

import pytest

from hypermesh_ticket import renter_key_fingerprint
from test_hypermesh_gateway import _AcceptJwt, _mock_runtime, _signed_ticket


@pytest.mark.asyncio
async def test_forged_api_key_cannot_use_paid_ticket(
    http_client, tenant_headers, control_plane, app, tenant_id
):
    lease_id = uuid.uuid4()
    app.state.ticket_cache.put(tenant_id, _signed_ticket(lease_id))
    _mock_runtime(app)
    refused = await http_client.post(
        "/v1/chat/completions",
        headers={**tenant_headers, "Authorization": "Bearer attacker.forged"},
        json={"lease_id": str(lease_id), "messages": [{"role": "user", "content": "hi"}]},
    )
    assert refused.status_code == 401
    assert refused.json()["error"]["code"] == "invalid_api_key"
    assert control_plane.get_lease_calls == 0
    assert control_plane.list_tickets_calls == 0


@pytest.mark.asyncio
async def test_portal_jwt_without_tenant_claim_cannot_use_paid_ticket(
    http_client, tenant_headers, control_plane, app, tenant_id
):
    lease_id = uuid.uuid4()
    app.state.ticket_cache.put(tenant_id, _signed_ticket(lease_id))
    app.state.renter_jwt_validator = _AcceptJwt("portal.jwt.token")
    _mock_runtime(app)
    refused = await http_client.post(
        "/v1/chat/completions",
        headers={**tenant_headers, "Authorization": "Bearer portal.jwt.token"},
        json={"lease_id": str(lease_id), "messages": [{"role": "user", "content": "hi"}]},
    )
    assert refused.status_code == 401
    assert refused.json()["error"]["code"] == "invalid_api_key"
    assert control_plane.get_lease_calls == 0


@pytest.mark.asyncio
async def test_portal_jwt_for_other_tenant_cannot_use_paid_ticket(
    http_client, tenant_headers, control_plane, app, tenant_id
):
    lease_id = uuid.uuid4()
    app.state.ticket_cache.put(tenant_id, _signed_ticket(lease_id))
    app.state.renter_jwt_validator = _AcceptJwt("portal.jwt.token", uuid.uuid4())
    _mock_runtime(app)
    refused = await http_client.post(
        "/v1/chat/completions",
        headers={**tenant_headers, "Authorization": "Bearer portal.jwt.token"},
        json={"lease_id": str(lease_id), "messages": [{"role": "user", "content": "hi"}]},
    )
    assert refused.status_code == 403
    assert refused.json()["error"]["code"] == "tenant_mismatch"
    assert control_plane.get_lease_calls == 0


def test_renter_key_fingerprint_is_hex_of_full_key():
    assert renter_key_fingerprint("pk_test.renter-key") == renter_key_fingerprint(
        "pk_test.renter-key"
    )
    assert renter_key_fingerprint("pk_test.renter-key") != renter_key_fingerprint(
        "pk_test.other"
    )
    assert len(renter_key_fingerprint("pk_test.renter-key")) == 64


@pytest.mark.asyncio
@pytest.mark.parametrize("door", ["/v1/chat/completions", "/v1/ir/chat/completions"])
@pytest.mark.parametrize("authorization", ["Bearer approved-user.forged", "Bearer portal.jwt.token", "Basic invalid", ""])
async def test_dual_credentials_rejected_before_approval_or_proxy(
    http_client, tenant_headers, app, tenant_id, monkeypatch, door, authorization
):
    import hypermesh_gateway_service.routes as routes

    def forbidden(*args, **kwargs):
        raise AssertionError("ambiguous credentials must not reach approval or proxy")

    monkeypatch.setattr(routes, "_hold_or_resume", forbidden)
    monkeypatch.setattr(routes, "proxy_chat", forbidden)
    lease_id = uuid.uuid4()
    app.state.ticket_cache.put(tenant_id, _signed_ticket(lease_id))
    response = await http_client.post(
        door,
        headers={**tenant_headers, "Authorization": authorization,
                 "X-Api-Key": "pk_test.ir-key" if "/ir/" in door else "pk_test.renter-key"},
        json={"lease_id": str(lease_id), "messages": [{"role": "user", "content": "hi"}]},
    )
    assert response.status_code == 401, response.text


@pytest.mark.parametrize("extractor", ["require_renter_grant", "presented_renter_key"])
def test_both_credential_consumers_reject_dual_headers(extractor):
    from starlette.requests import Request
    from hypermesh_gateway_service import renter_auth

    request = Request({"type": "http", "headers": [
        (b"authorization", b"Bearer approved-user.forged"),
        (b"x-api-key", b"pk_test.renter-key"),
    ]})
    with pytest.raises(renter_auth.RenterUnauthorized):
        getattr(renter_auth, extractor)(request)
