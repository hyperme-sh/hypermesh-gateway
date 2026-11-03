"""The receipts door exports tenant-wide history, so it must bind the tenant.

require_renter_grant is format-only and the tenant arrives in a header. Without
the checks these cover, `Bearer anything.at.all` plus a guessed X-Tenant-ID
returned another tenant's receipts.

The tenant-bound credential is the whole guard. This history spans every lease,
so the door honors no ticket and callers send no lease id.
"""

import uuid

import pytest
from conftest import stub_api_key_validator
from hypermesh_gateway_service.receipts import ReceiptStore

TENANT_CLAIM = "https://panopticon.dev/tenant_id"


def _store(app) -> ReceiptStore:
    store = ReceiptStore()
    app.state.receipt_store = store
    return store


def _record(store: ReceiptStore, tenant_id: uuid.UUID, who: str) -> uuid.UUID:
    lease_id = uuid.uuid4()
    store.record(
        tenant_id=tenant_id,
        lease_id=lease_id,
        who=who,
        why="ir",
        what_left="none",
        prompt_class="benign",
        decision="allow",
    )
    return lease_id


def _seed(app, tenant_id: uuid.UUID) -> None:
    """One receipt and deliberately no ticket: this door does not honor one."""

    _record(_store(app), tenant_id, "victim@example.com")


@pytest.mark.asyncio
async def test_forged_api_key_cannot_export(http_client, app, tenant_id):
    _seed(app, tenant_id)
    app.state.api_key_validator = stub_api_key_validator(None)
    resp = await http_client.get(
        "/v1/ir/receipts",
        headers={
            "Authorization": "Bearer attacker.forged",
            "X-Tenant-ID": str(tenant_id),
        },
    )
    assert resp.status_code == 401
    assert "victim@example.com" not in resp.text


@pytest.mark.asyncio
async def test_api_key_from_another_tenant_cannot_export(http_client, app, tenant_id):
    _seed(app, tenant_id)
    # api-keys-service answers for the attacker's own tenant, not the victim's.
    app.state.api_key_validator = stub_api_key_validator(uuid.uuid4())
    resp = await http_client.get(
        "/v1/ir/receipts",
        headers={
            "Authorization": "Bearer pk_other.key",
            "X-Tenant-ID": str(tenant_id),
        },
    )
    assert resp.status_code == 401
    assert "victim@example.com" not in resp.text


@pytest.mark.asyncio
async def test_jwt_without_tenant_claim_cannot_export(http_client, app, tenant_id):
    _seed(app, tenant_id)

    class _AnyJwt:
        def validate_sync(self, token: str) -> dict:
            return {"sub": "someone", "email": "someone@example.com"}

        async def validate(self, token: str) -> dict:
            return self.validate_sync(token)

    app.state.renter_jwt_validator = _AnyJwt()
    resp = await http_client.get(
        "/v1/ir/receipts",
        headers={
            "Authorization": "Bearer head.body.sig",
            "X-Tenant-ID": str(tenant_id),
        },
    )
    assert resp.status_code == 401
    assert "victim@example.com" not in resp.text


@pytest.mark.asyncio
async def test_jwt_with_matching_tenant_claim_exports(http_client, app, tenant_id):
    _seed(app, tenant_id)

    class _TenantJwt:
        def validate_sync(self, token: str) -> dict:
            return {"sub": "owner", TENANT_CLAIM: str(tenant_id)}

        async def validate(self, token: str) -> dict:
            return self.validate_sync(token)

    app.state.renter_jwt_validator = _TenantJwt()
    resp = await http_client.get(
        "/v1/ir/receipts",
        headers={
            "Authorization": "Bearer head.body.sig",
            "X-Tenant-ID": str(tenant_id),
        },
    )
    assert resp.status_code == 200
    assert resp.json()["receipts"][0]["who"] == "victim@example.com"


@pytest.mark.asyncio
async def test_console_header_shape_exports(http_client, app, tenant_id):
    """buildEdgeHeaders sends the tenant and a credential, never a lease id."""

    _seed(app, tenant_id)
    app.state.api_key_validator = stub_api_key_validator(tenant_id)
    resp = await http_client.get(
        "/v1/ir/receipts",
        headers={
            "X-Api-Key": "pk_test.renter-key",
            "X-Tenant-ID": str(tenant_id),
        },
    )
    assert resp.status_code == 200
    assert resp.json()["receipts"][0]["who"] == "victim@example.com"


@pytest.mark.asyncio
async def test_export_spans_every_lease(http_client, app, tenant_id):
    """Why no ticket gates this door: one call answers for many leases."""

    store = _store(app)
    _record(store, tenant_id, "first@example.com")
    _record(store, tenant_id, "second@example.com")
    app.state.api_key_validator = stub_api_key_validator(tenant_id)
    resp = await http_client.get(
        "/v1/ir/receipts",
        headers={
            "Authorization": "Bearer pk_test.renter-key",
            "X-Tenant-ID": str(tenant_id),
        },
    )
    assert resp.status_code == 200
    assert {row["who"] for row in resp.json()["receipts"]} == {
        "first@example.com",
        "second@example.com",
    }
