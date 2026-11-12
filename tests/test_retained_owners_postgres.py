"""Retained-store checks selected only by the scheduled package batch."""
import os
import uuid
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from hypermesh_gateway_service.account_ledger import AccountLedger
from hypermesh_gateway_service.history import HistoryStore
from hypermesh_gateway_service.training import TrainingStore

pytestmark = pytest.mark.synthetic
TENANT = uuid.UUID('00000000-0000-4000-8000-000000000101')
OTHER = uuid.UUID('00000000-0000-4000-8000-000000000102')
SUBJECT = 'nightly-retained-owner'


@pytest.fixture
async def owners():
    assert os.environ.get('GITHUB_ACTIONS') == 'true'
    assert os.environ.get('GITHUB_EVENT_NAME') == 'schedule'
    url = os.environ['GATEWAY_NIGHTLY_DATABASE_URL']
    engine = create_async_engine(url, echo=False, hide_parameters=True)
    try:
        async with engine.connect() as connection:
            outer = await connection.begin()
            try:
                maker = async_sessionmaker(connection, expire_on_commit=False,
                                          join_transaction_mode='create_savepoint')
                yield HistoryStore(maker), TrainingStore(maker)
            finally:
                await outer.rollback()
    finally:
        await engine.dispose()


async def test_retained_closure_preserves_time_and_replays_deletion_counts(owners):
    history, training = owners
    closed = datetime.now(UTC) - timedelta(days=100)
    assert await history.record_closure(TENANT, SUBJECT, closed, 'nightly')
    assert not await history.record_closure(TENANT, SUBJECT, closed, 'nightly')
    with pytest.raises(ValueError, match='immutable'):
        await history.record_closure(TENANT, SUBJECT, closed + timedelta(seconds=1), 'nightly')
    await training.set_consent(TENANT, SUBJECT, False)
    assert await training.delete_account(TENANT, SUBJECT, 'account-lifecycle') == 1
    assert await training.delete_account(TENANT, SUBJECT, 'account-lifecycle') == 0
    first = await history.purge_account(TENANT, SUBJECT, closed)
    assert first['deleted'] == 1 and first['remaining'] == 0
    assert await history.purge_account(TENANT, SUBJECT, closed) == first
    assert await training.purge_account(TENANT, SUBJECT) == {'deleted': 1, 'remaining': 0}
    assert await training.purge_account(TENANT, SUBJECT) == {'deleted': 1, 'remaining': 0}
    assert (await history.lifecycle_status(OTHER, SUBJECT))['entries'] == 1
    assert (await training.lifecycle_status(OTHER, SUBJECT))['entries'] == 1


async def test_inventory_creates_no_account_rows_and_role_enforces_scope(owners):
    history, training = owners
    assert not (await history.lifecycle_status(TENANT, 'absent'))['present']
    assert not (await training.lifecycle_status(TENANT, 'absent'))['present']
    async with history.transaction(TENANT) as db:
        assert (await db.execute(text('SELECT DISTINCT tenant_id FROM hypermesh_history_entries'))).scalars().all() == [TENANT]
        role = (await db.execute(text('SELECT rolsuper,rolbypassrls FROM pg_roles WHERE rolname=current_user'))).one()
        assert not role.rolsuper and not role.rolbypassrls
        assert await db.scalar(text("SELECT count(*) FROM hypermesh_history_preferences WHERE subject='absent'")) == 0
    async with training.transaction(OTHER) as db:
        assert (await db.execute(text('SELECT DISTINCT tenant_id FROM hypermesh_training_submissions'))).scalars().all() == [OTHER]


async def test_history_purge_requires_due_original_closure(owners, monkeypatch):
    from hypermesh_gateway_service import history as module
    history, _ = owners
    monkeypatch.setattr(module, '_closure_retention', lambda: timedelta(days=90))
    now = datetime.now(UTC)
    await history.record_closure(TENANT, SUBJECT, now, 'nightly')
    with pytest.raises(ValueError, match='not yet due'):
        await history.purge_account(TENANT, SUBJECT, now)
    with pytest.raises(ValueError, match='Original history'):
        await history.purge_account(TENANT, SUBJECT, now - timedelta(days=100))
    assert (await history.lifecycle_status(TENANT, SUBJECT))['entries'] == 1


async def test_receiver_requires_erasure_authority_and_retries_exact_counts(
    owners, app, http_client, monkeypatch, tmp_path
):
    from hypermesh_gateway_service import account_closure
    history, training = owners
    ledger = AccountLedger(str(tmp_path / 'denials.sqlite'))
    app.state.account_ledger = ledger
    app.state.history_store, app.state.training_store = owners
    monkeypatch.setenv('ACCOUNT_CLOSURE_ENFORCEMENT_ENABLED', 'true')
    monkeypatch.setenv('ACCOUNT_CLOSURE_GUARD_TOKEN', 'r' * 32)
    monkeypatch.setenv('ACCOUNT_CLOSURE_OPERATIONS_TOKEN', 'w' * 32)

    async def permit(**kwargs):
        return None

    async def grants(body):
        return {'allowed': True, 'key_ids': [], 'fingerprints': [], 'lease_ids': []}

    proof = {'erasure_allowed': False}

    async def scope(**kwargs):
        return proof

    monkeypatch.setattr(account_closure, 'require_closure_permit', permit)
    monkeypatch.setattr(account_closure, 'grant_snapshot', grants)
    monkeypatch.setattr('controlplane_identity.account_lifecycle.closure_scope', scope)
    body = {'tenant_id': str(TENANT), 'subject': SUBJECT,
            'closed_at': (datetime.now(UTC) - timedelta(days=100)).isoformat()}
    headers = {'X-Tenant-ID': str(TENANT), 'X-Account-Lifecycle-Token': 'w' * 32}
    base = '/api/v1/internal/account-lifecycle'
    assert (await http_client.post(base + '/owner-inventory', json=body, headers=headers)).status_code == 409
    assert (await http_client.post(base + '/close-owner', json=body, headers=headers)).status_code == 200
    assert (await http_client.post(base + '/purge-owner', json=body, headers=headers)).status_code == 409
    proof['erasure_allowed'] = True
    first = await http_client.post(base + '/purge-owner', json=body, headers=headers)
    assert first.status_code == 200
    assert first.json()['history']['deleted'] == first.json()['training']['deleted'] == 1
    repeated = await http_client.post(base + '/purge-owner', json=body, headers=headers)
    assert repeated.status_code == 200 and repeated.json() == first.json()
