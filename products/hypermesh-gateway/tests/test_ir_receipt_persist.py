from __future__ import annotations

import uuid
from pathlib import Path

import pytest

from hypermesh_gateway_service.receipts import (
    DEFAULT_IR_RECEIPT_NAME,
    ReceiptStore,
    default_ir_receipt_path,
    resolve_receipt_store,
)
from conftest import stub_api_key_validator
from test_hypermesh_gateway import (
    TEST_RENTER_FINGERPRINTS,
    _mock_runtime,
    _renter as renter_headers,
    _signed_ticket,
)


def test_default_receipt_path_uses_data_dir(tmp_path, monkeypatch):
    monkeypatch.delenv("HYPERMESH_IR_RECEIPT_PATH", raising=False)
    monkeypatch.delenv("HYPERMESH_DATA_DIR", raising=False)
    assert default_ir_receipt_path() == Path("var/lib/hypermesh") / DEFAULT_IR_RECEIPT_NAME
    monkeypatch.setenv("HYPERMESH_DATA_DIR", str(tmp_path))
    assert default_ir_receipt_path() == tmp_path / DEFAULT_IR_RECEIPT_NAME


def test_resolve_defaults_to_persist_and_memory_sentinel(tmp_path, monkeypatch, tenant_id):
    monkeypatch.delenv("HYPERMESH_IR_RECEIPT_PATH", raising=False)
    monkeypatch.setenv("HYPERMESH_DATA_DIR", str(tmp_path))
    first = resolve_receipt_store()
    prompt = "secret prompt must never be persisted"
    first.record(
        tenant_id=tenant_id,
        lease_id=uuid.uuid4(),
        who="pk_test",
        why="ir",
        what_left="completion",
        prompt_class="incident_triage",
        decision="allow",
    )
    path = tmp_path / DEFAULT_IR_RECEIPT_NAME
    assert path.is_file()
    assert prompt not in path.read_text(encoding="utf-8")
    bounced = resolve_receipt_store()
    rows = bounced.export_for(tenant_id)
    assert len(rows) == 1
    assert rows[0]["class"] == "incident_triage"
    assert prompt not in str(rows)

    monkeypatch.setenv("HYPERMESH_IR_RECEIPT_PATH", "memory")
    memory = resolve_receipt_store()
    memory.record(
        tenant_id=tenant_id,
        lease_id=uuid.uuid4(),
        who="pk_test",
        why="ir",
        what_left="none",
        prompt_class="out_of_scope",
        decision="hold",
    )
    assert "out_of_scope" not in path.read_text(encoding="utf-8")
    assert resolve_receipt_store().export_for(tenant_id) == []
    assert isinstance(memory, ReceiptStore)


@pytest.mark.asyncio
async def test_unset_env_persists_ir_receipts_across_app_bounce(
    tmp_path, tenant_headers, tenant_id, control_plane, monkeypatch
):
    from asgi_lifespan import LifespanManager
    import httpx

    from hypermesh_gateway_service.app import create_app

    monkeypatch.setenv("HYPERMESH_WG_APPLY", "0")
    monkeypatch.setenv("HYPERMESH_ASSIGNMENT_REFRESH_S", "0")
    monkeypatch.setenv("HYPERMESH_TICKET_HMAC_KEY", "test-plane-hypermesh-ticket-hmac")
    monkeypatch.delenv("HYPERMESH_IR_RECEIPT_PATH", raising=False)
    monkeypatch.setenv("HYPERMESH_DATA_DIR", str(tmp_path))
    first_app = create_app(
        control_plane=control_plane,
        gateway_service_secret="hm_gw_test",
    )
    lease_id = uuid.uuid4()
    prompt = "secret prompt must never be persisted"
    async with LifespanManager(first_app):
        first_app.state.ticket_cache.put(tenant_id, _signed_ticket(lease_id, purpose="ir"))
        first_app.state.ticket_cache.accept_keys(tenant_id, TEST_RENTER_FINGERPRINTS)
        _mock_runtime(first_app)
        transport = httpx.ASGITransport(app=first_app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            chat = await client.post(
                "/v1/ir/chat/completions",
                headers=renter_headers(tenant_headers),
                json={
                    "lease_id": str(lease_id),
                    "messages": [{"role": "user", "content": prompt}],
                },
            )
            assert chat.status_code == 200, chat.text

    path = tmp_path / DEFAULT_IR_RECEIPT_NAME
    assert path.is_file()
    assert prompt not in path.read_text(encoding="utf-8")
    bounced = create_app(
        control_plane=control_plane,
        gateway_service_secret="hm_gw_test",
    )
    async with LifespanManager(bounced):
        bounced.state.ticket_cache.put(tenant_id, _signed_ticket(lease_id, purpose="ir"))
        transport = httpx.ASGITransport(app=bounced)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            bounced.state.api_key_validator = stub_api_key_validator(tenant_id)
            exported = await client.get(
                "/v1/ir/receipts",
                headers=renter_headers(tenant_headers),
            )
            assert exported.status_code == 200
            rows = exported.json()["receipts"]
            assert len(rows) == 1
            assert rows[0]["lease_id"] == str(lease_id)
            assert prompt not in str(rows)


@pytest.mark.asyncio
async def test_memory_sentinel_drops_receipts_on_bounce(
    tenant_headers, tenant_id, control_plane, monkeypatch
):
    from asgi_lifespan import LifespanManager
    import httpx

    from hypermesh_gateway_service.app import create_app

    monkeypatch.setenv("HYPERMESH_WG_APPLY", "0")
    monkeypatch.setenv("HYPERMESH_ASSIGNMENT_REFRESH_S", "0")
    monkeypatch.setenv("HYPERMESH_TICKET_HMAC_KEY", "test-plane-hypermesh-ticket-hmac")
    monkeypatch.setenv("HYPERMESH_IR_RECEIPT_PATH", "memory")
    first_app = create_app(
        control_plane=control_plane,
        gateway_service_secret="hm_gw_test",
    )
    lease_id = uuid.uuid4()
    async with LifespanManager(first_app):
        first_app.state.ticket_cache.put(tenant_id, _signed_ticket(lease_id, purpose="ir"))
        first_app.state.ticket_cache.accept_keys(tenant_id, TEST_RENTER_FINGERPRINTS)
        _mock_runtime(first_app)
        transport = httpx.ASGITransport(app=first_app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            chat = await client.post(
                "/v1/ir/chat/completions",
                headers=renter_headers(tenant_headers),
                json={
                    "lease_id": str(lease_id),
                    "messages": [{"role": "user", "content": "secret prompt"}],
                },
            )
            assert chat.status_code == 200, chat.text
            assert first_app.state.receipt_store.count_for(tenant_id) == 1

    bounced = create_app(
        control_plane=control_plane,
        gateway_service_secret="hm_gw_test",
    )
    async with LifespanManager(bounced):
        transport = httpx.ASGITransport(app=bounced)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            bounced.state.api_key_validator = stub_api_key_validator(tenant_id)
            exported = await client.get(
                "/v1/ir/receipts",
                headers=renter_headers(tenant_headers),
            )
            assert exported.status_code == 200
            assert exported.json()["receipts"] == []
