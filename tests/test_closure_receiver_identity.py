"""A misrouted closure must fail before changing any gateway-owned data."""

import uuid
from datetime import UTC, datetime

import pytest
from hypermesh_gateway_service.account_ledger import AccountLedger


async def test_pinned_receiver_rejects_wrong_identity_before_denial(
    app, http_client, control_plane, tenant_id, monkeypatch, tmp_path
):
    from hypermesh_gateway_service import account_closure

    monkeypatch.setenv("ACCOUNT_CLOSURE_ENFORCEMENT_ENABLED", "true")
    monkeypatch.setenv("ACCOUNT_CLOSURE_GUARD_TOKEN", "r" * 32)
    monkeypatch.setenv("ACCOUNT_CLOSURE_OPERATIONS_TOKEN", "w" * 32)

    async def permit(**kwargs):
        return None

    monkeypatch.setattr(account_closure, "require_closure_permit", permit)
    ledger = AccountLedger(str(tmp_path / "receiver.sqlite"))
    app.state.account_ledger = ledger
    subject = str(uuid.uuid4())
    actual, expected = uuid.uuid4(), uuid.uuid4()
    control_plane.gateway_id = actual
    body = {
        "tenant_id": str(tenant_id),
        "subject": subject,
        "closed_at": datetime.now(UTC).isoformat(),
        "expected_gateway_id": str(expected),
    }
    headers = {
        "X-Tenant-ID": str(tenant_id),
        "X-Account-Lifecycle-Token": "w" * 32,
    }
    path = "/api/v1/internal/account-lifecycle/deny-principal"
    response = await http_client.post(path, json=body, headers=headers)
    assert response.status_code == 409
    assert not ledger.principal_retired(tenant_id, subject)
    control_plane.gateway_id = None
    response = await http_client.post(path, json=body, headers=headers)
    assert response.status_code == 503
    assert not ledger.principal_retired(tenant_id, subject)
    control_plane.gateway_id = expected
    response = await http_client.post(path, json=body, headers=headers)
    assert response.status_code == 200, response.text
    assert response.json() == {"gateway_id": str(expected), "denial_persisted": True}
    assert ledger.principal_retired(tenant_id, subject)


async def test_http_receiver_identity_requires_exact_tenant_and_valid_uuid(monkeypatch):
    import httpx
    from hypermesh_gateway_service import control_plane as module

    tenant, other, gateway = uuid.uuid4(), uuid.uuid4(), uuid.uuid4()
    answer = {"tenant_id": str(tenant), "gateway_id": str(gateway),
              "service_version": "0.1.1", "new_optional_field": {"enabled": True}}
    client_type = httpx.AsyncClient

    async def respond(request):
        assert request.headers["X-Tenant-ID"] == str(tenant)
        assert request.headers["Authorization"] == "Bearer hm_gw_test"
        assert request.url.path == "/api/v1/hypermesh/gateway/identity"
        return httpx.Response(200, json=answer)

    def client(**kwargs):
        assert kwargs["trust_env"] is False
        assert kwargs["follow_redirects"] is False
        return client_type(transport=httpx.MockTransport(respond), **kwargs)

    monkeypatch.setattr(module.httpx, "AsyncClient", client)
    control = module.HttpControlPlane("https://control.example", "hm_gw_test")
    assert await control.gateway_identity(tenant) == gateway
    answer["tenant_id"] = str(other)
    with pytest.raises(PermissionError, match="scope mismatch"):
        await control.gateway_identity(tenant)
    answer["tenant_id"] = str(tenant)
    answer["gateway_id"] = "invalid"
    with pytest.raises(ValueError):
        await control.gateway_identity(tenant)


async def test_grant_denial_needs_no_personal_data_owners(
    app, http_client, control_plane, tenant_id, monkeypatch, tmp_path
):
    from hypermesh_gateway_service import account_closure

    monkeypatch.setenv("ACCOUNT_CLOSURE_ENFORCEMENT_ENABLED", "true")
    monkeypatch.setenv("ACCOUNT_CLOSURE_GUARD_TOKEN", "r" * 32)
    monkeypatch.setenv("ACCOUNT_CLOSURE_OPERATIONS_TOKEN", "w" * 32)

    permits = []

    async def permit(**kwargs):
        permits.append(kwargs)
        return None

    monkeypatch.setattr(account_closure, "require_closure_permit", permit)
    ledger = AccountLedger(str(tmp_path / "grants.sqlite"))
    ledger.apply_snapshot(
        tenant_id,
        {
            "version": 1,
            "complete": True,
            "subjects": [],
            "keys": [],
            "fingerprints": [],
            "leases": [],
        },
    )
    app.state.account_ledger = ledger
    app.state.history_store = None
    app.state.training_store = None
    gateway, lease, key_id = uuid.uuid4(), uuid.uuid4(), uuid.uuid4()
    subject = str(uuid.uuid4())
    closed_at = datetime.now(UTC)
    control_plane.gateway_id = gateway

    async def snapshot(body):
        return {
            "allowed": True,
            "key_ids": [str(key_id)],
            "fingerprints": ["a" * 64],
            "lease_ids": [str(lease)],
        }

    monkeypatch.setattr(account_closure, "grant_snapshot", snapshot)
    assert not ledger.key_blocked(tenant_id, "a" * 64)
    assert not ledger.lease_blocked(tenant_id, lease)
    response = await http_client.post(
        "/api/v1/internal/account-lifecycle/deny-grants",
        headers={"X-Tenant-ID": str(tenant_id), "X-Account-Lifecycle-Token": "w" * 32},
        json={
            "tenant_id": str(tenant_id),
            "subject": subject,
            "closed_at": closed_at.isoformat(),
            "expected_gateway_id": str(gateway),
            "key_ids": [str(key_id)],
            "fingerprints": ["a" * 64],
            "lease_ids": [str(lease)],
        },
    )
    assert response.status_code == 200, response.text
    assert response.json() == {"gateway_id": str(gateway), "denial_persisted": True}
    assert ledger.key_blocked(tenant_id, "a" * 64)
    assert ledger.lease_blocked(tenant_id, lease)
    assert permits == [
        {"subject": subject, "closed_at": closed_at, "tenant_id": tenant_id}
    ]


async def test_deny_grants_refuses_a_tenant_outside_the_closure_scope(
    app, http_client, control_plane, tenant_id, monkeypatch, tmp_path
):
    from hypermesh_gateway_service import account_closure

    monkeypatch.setenv("ACCOUNT_CLOSURE_ENFORCEMENT_ENABLED", "true")
    monkeypatch.setenv("ACCOUNT_CLOSURE_GUARD_TOKEN", "r" * 32)
    monkeypatch.setenv("ACCOUNT_CLOSURE_OPERATIONS_TOKEN", "w" * 32)
    scoped, other = tenant_id, uuid.uuid4()
    permits = []

    async def permit(**kwargs):
        permits.append(kwargs["tenant_id"])
        if kwargs["tenant_id"] != scoped:
            raise RuntimeError("Account closure permit unavailable")

    monkeypatch.setattr(account_closure, "require_closure_permit", permit)
    ledger = AccountLedger(str(tmp_path / "cross-tenant.sqlite"))
    snapshot = {
        "version": 1,
        "complete": True,
        "subjects": [],
        "keys": [],
        "fingerprints": [],
        "leases": [],
    }
    ledger.apply_snapshot(scoped, snapshot)
    ledger.apply_snapshot(other, snapshot)
    app.state.account_ledger = ledger
    app.state.history_store = None
    app.state.training_store = None
    gateway, lease, key = uuid.uuid4(), uuid.uuid4(), uuid.uuid4()
    subject = str(uuid.uuid4())
    closed_at = datetime.now(UTC)
    control_plane.gateway_id = gateway

    def body(tenant):
        return {
            "tenant_id": str(tenant),
            "subject": subject,
            "closed_at": closed_at.isoformat(),
            "expected_gateway_id": str(gateway),
            "key_ids": [str(key)],
            "fingerprints": ["b" * 64],
            "lease_ids": [str(lease)],
        }

    async def snapshot(delivery):
        assert delivery.tenant_id == scoped
        return {
            "allowed": True,
            "key_ids": [str(key)],
            "fingerprints": ["b" * 64],
            "lease_ids": [str(lease)],
        }

    monkeypatch.setattr(account_closure, "grant_snapshot", snapshot)

    refused = await http_client.post(
        "/api/v1/internal/account-lifecycle/deny-grants",
        headers={"X-Tenant-ID": str(other), "X-Account-Lifecycle-Token": "w" * 32},
        json=body(other),
    )
    assert refused.status_code == 503, refused.text
    assert not ledger.key_blocked(other, "b" * 64)
    assert not ledger.lease_blocked(other, lease)
    assert not ledger.principal_retired(other, subject)
    allowed = await http_client.post(
        "/api/v1/internal/account-lifecycle/deny-grants",
        headers={"X-Tenant-ID": str(scoped), "X-Account-Lifecycle-Token": "w" * 32},
        json=body(scoped),
    )
    assert allowed.status_code == 200, allowed.text
    assert ledger.key_blocked(scoped, "b" * 64)
    assert ledger.lease_blocked(scoped, lease)
    assert not ledger.key_blocked(other, "b" * 64)
    assert permits == [other, scoped]
