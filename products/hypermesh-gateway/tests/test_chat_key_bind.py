"""Chat proves possession of a tenant-bound key. Two UUIDs are not a credential."""

from __future__ import annotations

import uuid

import pytest

from hypermesh_gateway_service.renter_auth import RENTER_AUTH_REQUIRED
from hypermesh_service.ticket import renter_key_fingerprint
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
    assert refused.json()["detail"] == RENTER_AUTH_REQUIRED
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
    assert refused.json()["detail"] == RENTER_AUTH_REQUIRED
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
    assert refused.status_code == 401
    assert refused.json()["detail"] == RENTER_AUTH_REQUIRED
    assert control_plane.get_lease_calls == 0


def test_renter_key_fingerprint_is_hex_of_full_key():
    assert renter_key_fingerprint("pk_test.renter-key") == renter_key_fingerprint(
        "pk_test.renter-key"
    )
    assert renter_key_fingerprint("pk_test.renter-key") != renter_key_fingerprint(
        "pk_test.other"
    )
    assert len(renter_key_fingerprint("pk_test.renter-key")) == 64
