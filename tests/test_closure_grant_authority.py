"""Mutation credentials cannot redirect a closing account's grant denial."""

import uuid
from datetime import UTC, datetime

import pytest
from hypermesh_gateway_service.account_ledger import AccountLedger


@pytest.mark.parametrize("action", ["deny-grants", "close-owner"])
@pytest.mark.parametrize("forged", ["key_ids", "fingerprints", "lease_ids", "omitted"])
async def test_grant_denial_is_tenant_scoped_and_matches_frozen_inventory(
    app, http_client, tenant_id, monkeypatch, tmp_path, forged, action
):
    from hypermesh_gateway_service import account_closure

    ledger = AccountLedger(str(tmp_path / "scoped-grants.sqlite"))
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
    app.state.history_store = app.state.training_store = None
    ledger.configure_owner("history", False, never_configured=True)
    ledger.configure_owner("training", False, never_configured=True)
    monkeypatch.setenv("ACCOUNT_CLOSURE_ENFORCEMENT_ENABLED", "true")
    monkeypatch.setenv("ACCOUNT_CLOSURE_GUARD_TOKEN", "r" * 32)
    monkeypatch.setenv("ACCOUNT_CLOSURE_OPERATIONS_TOKEN", "w" * 32)
    key_id, lease_id = uuid.uuid4(), uuid.uuid4()
    canonical = {
        "key_ids": [str(key_id)],
        "fingerprints": ["a" * 64],
        "lease_ids": [str(lease_id)],
    }
    permits = []

    async def permit(**kwargs):
        permits.append(kwargs)
        if kwargs["tenant_id"] != tenant_id:
            raise RuntimeError("Unregistered tenant")

    async def snapshot(body):
        return {"allowed": True, **canonical}

    monkeypatch.setattr(account_closure, "require_closure_permit", permit)
    monkeypatch.setattr(account_closure, "grant_snapshot", snapshot)
    body = {
        "subject": str(uuid.uuid4()),
        "closed_at": datetime.now(UTC).isoformat(),
        "tenant_id": str(tenant_id),
        **canonical,
    }
    headers = {"X-Tenant-ID": str(tenant_id), "X-Account-Lifecycle-Token": "w" * 32}
    path = "/api/v1/internal/account-lifecycle/" + action
    if forged == "omitted":
        invalid = {**body, "key_ids": [], "fingerprints": [], "lease_ids": []}
    else:
        invalid = {
            **body,
            forged: ["b" * 64] if forged == "fingerprints" else [str(uuid.uuid4())],
        }
    result = await http_client.post(path, headers=headers, json=invalid)
    assert result.status_code == 409
    assert not ledger.principal_retired(tenant_id, body["subject"])
    assert not ledger.key_blocked(tenant_id, "a" * 64)
    assert not ledger.lease_blocked(tenant_id, lease_id)
    other = uuid.uuid4()
    refused = await http_client.post(
        path,
        headers={**headers, "X-Tenant-ID": str(other)},
        json={**body, "tenant_id": str(other)},
    )
    assert refused.status_code == 503
    accepted = await http_client.post(path, headers=headers, json=body)
    assert accepted.status_code == 200, accepted.text
    assert ledger.key_blocked(tenant_id, "a" * 64) and ledger.lease_blocked(
        tenant_id, lease_id
    )
    assert all(value["tenant_id"] is not None for value in permits)


async def test_grant_snapshot_uses_read_authority_and_exact_tenant_without_redirects(
    monkeypatch,
):
    import json

    import httpx
    from hypermesh_gateway_service import account_closure

    monkeypatch.setenv("ACCOUNT_CLOSURE_GUARD_URL", "https://authority.example")
    monkeypatch.setenv("ACCOUNT_CLOSURE_GUARD_TOKEN", "r" * 32)
    monkeypatch.setenv("ACCOUNT_CLOSURE_OPERATIONS_TOKEN", "w" * 32)
    tenant, key, lease = uuid.uuid4(), uuid.uuid4(), uuid.uuid4()
    body = account_closure.ClosureDelivery(
        tenant_id=tenant,
        subject="exact-owner",
        closed_at=datetime.now(UTC),
        key_ids=[key],
        fingerprints=["a" * 64],
        lease_ids=[lease],
    )
    client_type = httpx.AsyncClient
    answer = {
        "allowed": True,
        "key_ids": [str(key)],
        "fingerprints": ["a" * 64],
        "lease_ids": [str(lease)],
    }

    async def response(request):
        assert request.headers["X-Account-Lifecycle-Token"] == "r" * 32
        assert request.headers["X-Tenant-ID"] == str(tenant)
        assert request.url.host == "authority.example"
        assert request.url.path == "/api/v1/internal/account-lifecycle/grant-scope"
        assert json.loads(request.content) == {
            "subject": "exact-owner",
            "tenant_id": str(tenant),
            "closed_at": body.closed_at.isoformat(),
        }
        return httpx.Response(200, json=answer)

    def client(**kwargs):
        assert kwargs["follow_redirects"] is False and kwargs["trust_env"] is False
        return client_type(transport=httpx.MockTransport(response), **kwargs)

    monkeypatch.setattr(account_closure.httpx, "AsyncClient", client)
    await account_closure.require_grant_inventory(body)
