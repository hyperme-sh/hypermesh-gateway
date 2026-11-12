import uuid
from datetime import UTC, datetime
import pytest
from hypermesh_gateway_service.account_ledger import AccountLedger

@pytest.fixture
def empty_grant_inventory(monkeypatch):
    async def grants(body):
        return {"allowed": True, "key_ids": [], "fingerprints": [], "lease_ids": []}
    monkeypatch.setattr("hypermesh_gateway_service.account_closure.grant_snapshot", grants)

async def test_disabled_owner_capabilities_are_durable_and_do_not_hide_lost_database(
    empty_grant_inventory, app, http_client, tenant_id, monkeypatch, tmp_path
):
    from hypermesh_gateway_service import account_closure

    ledger = AccountLedger(str(tmp_path / "capabilities.sqlite"))
    app.state.account_ledger = ledger
    app.state.history_store = app.state.training_store = None
    monkeypatch.setenv("ACCOUNT_CLOSURE_ENFORCEMENT_ENABLED", "true")
    monkeypatch.setenv("ACCOUNT_CLOSURE_GUARD_TOKEN", "r" * 32)
    monkeypatch.setenv("ACCOUNT_CLOSURE_OPERATIONS_TOKEN", "w" * 32)

    async def permit(**kwargs):
        return None

    monkeypatch.setattr(account_closure, "require_closure_permit", permit)
    body = {
        "tenant_id": str(tenant_id),
        "subject": str(uuid.uuid4()),
        "closed_at": datetime.now(UTC).isoformat(),
    }
    headers = {"X-Tenant-ID": str(tenant_id), "X-Account-Lifecycle-Token": "w" * 32}
    path = "/api/v1/internal/account-lifecycle"
    assert (
        await http_client.post(path + "/deny-principal", json=body, headers=headers)
    ).status_code == 200
    # Missing evidence is never interpreted as a disabled owner.
    assert (
        await http_client.post(path + "/owner-inventory", json=body, headers=headers)
    ).status_code == 503
    ledger.configure_owner("history", False, never_configured=True)
    ledger.configure_owner("training", False, never_configured=True)
    response = await http_client.post(
        path + "/owner-inventory", json=body, headers=headers
    )
    assert response.status_code == 200, response.text
    assert response.json()["has_resources"] is False
    assert response.json()["capabilities"] == {
        "history": "disabled",
        "training": "disabled",
    }
    assert response.json()["history"]["disabled"] is True
    assert (
        await http_client.post(path + "/close-owner", json=body, headers=headers)
    ).status_code == 200
    # Once configured, a missing database remains an outstanding obligation,
    # including after a restart or a configuration change that drops its URL.
    ledger.configure_owner("training", True)
    ledger = AccountLedger(str(tmp_path / "capabilities.sqlite"))
    ledger.configure_owner("training", False, never_configured=True)
    app.state.account_ledger = ledger
    assert not ledger.owner_disabled("training")
    assert (
        await http_client.post(path + "/owner-inventory", json=body, headers=headers)
    ).status_code == 503


async def test_fresh_stateless_startup_requires_explicit_disabled_owner_attestation(
    monkeypatch, tmp_path, control_plane
):
    from asgi_lifespan import LifespanManager
    from hypermesh_gateway_service.app import create_app

    monkeypatch.setenv("HYPERMESH_ASSIGNMENT_REFRESH_S", "0")
    monkeypatch.delenv("HYPERMESH_HISTORY_DATABASE_URL", raising=False)
    monkeypatch.delenv("HYPERMESH_TRAINING_DATABASE_URL", raising=False)
    monkeypatch.setenv("ACCOUNT_CLOSURE_ENFORCEMENT_ENABLED", "true")
    monkeypatch.setenv(
        "HYPERMESH_ACCOUNT_DENIAL_DATABASE", str(tmp_path / "attested-stateless.sqlite")
    )
    monkeypatch.delenv("HYPERMESH_ACCOUNT_HISTORY_NEVER_CONFIGURED", raising=False)
    monkeypatch.delenv("HYPERMESH_ACCOUNT_TRAINING_NEVER_CONFIGURED", raising=False)
    unknown = create_app(
        control_plane=control_plane, gateway_service_secret="hm_gw_test"
    )
    async with LifespanManager(unknown):
        assert not unknown.state.account_ledger.owner_disabled("history")
        assert not unknown.state.account_ledger.owner_disabled("training")
    monkeypatch.setenv("HYPERMESH_ACCOUNT_HISTORY_NEVER_CONFIGURED", "true")
    monkeypatch.setenv("HYPERMESH_ACCOUNT_TRAINING_NEVER_CONFIGURED", "true")
    attested = create_app(
        control_plane=control_plane, gateway_service_secret="hm_gw_test"
    )
    async with LifespanManager(attested):
        assert attested.state.account_ledger.owner_disabled("history")
        assert attested.state.account_ledger.owner_disabled("training")



async def test_owner_effect_failure_keeps_denial_and_retry_is_required(
    empty_grant_inventory, app, http_client, tenant_id, monkeypatch, tmp_path
):
    from hypermesh_gateway_service import account_closure
    ledger = AccountLedger(str(tmp_path / 'retry.sqlite'))
    app.state.account_ledger = ledger
    ledger.configure_owner('training', False, never_configured=True)
    app.state.training_store = None
    monkeypatch.setenv('ACCOUNT_CLOSURE_ENFORCEMENT_ENABLED', 'true')
    monkeypatch.setenv('ACCOUNT_CLOSURE_GUARD_TOKEN', 'r' * 32)
    monkeypatch.setenv('ACCOUNT_CLOSURE_OPERATIONS_TOKEN', 'w' * 32)

    async def permit(**kwargs):
        pass

    class History:
        fail = True
        async def record_closure(self, *args):
            if self.fail:
                raise OSError('store offline')

    history = History()
    app.state.history_store = history
    monkeypatch.setattr(account_closure, 'require_closure_permit', permit)
    body = {'tenant_id': str(tenant_id), 'subject': 'owner', 'closed_at': datetime.now(UTC).isoformat()}
    headers = {'X-Tenant-ID': str(tenant_id), 'X-Account-Lifecycle-Token': 'w' * 32}
    path = '/api/v1/internal/account-lifecycle/close-owner'
    failed = await http_client.post(path, json=body, headers=headers)
    assert failed.status_code == 503
    assert ledger.principal_retired(tenant_id, 'owner')
    history.fail = False
    assert (await http_client.post(path, json=body, headers=headers)).status_code == 200


async def test_enrollment_and_capture_remain_unavailable():
    from fastapi import HTTPException
    from hypermesh_gateway_service.history import HistoryStore
    from hypermesh_gateway_service.training import TrainingStore
    with pytest.raises(HTTPException) as refused:
        await TrainingStore(None).set_consent(uuid.uuid4(), 'owner', True)
    assert refused.value.status_code == 409
    assert not hasattr(TrainingStore, 'save') and not hasattr(HistoryStore, 'save')
    assert not hasattr(HistoryStore, 'set_preference')
