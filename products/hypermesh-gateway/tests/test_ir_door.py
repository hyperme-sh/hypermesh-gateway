from __future__ import annotations

import uuid

import pytest

from hypermesh_gateway_service.chat import INSTANCE_NOT_READY
from hypermesh_gateway_service.receipts import ReceiptStore, sanitize_receipt_payload
from conftest import stub_api_key_validator
from test_hypermesh_gateway import (
    TEST_RENTER_FINGERPRINTS,
    _mock_runtime,
    _renter as renter_headers,
    _signed_ticket,
)


@pytest.mark.asyncio
async def test_default_chat_does_not_classify_or_store_prompt(
    http_client, tenant_headers, app, tenant_id, control_plane
):
    lease_id = uuid.uuid4()
    app.state.ticket_cache.put(tenant_id, _signed_ticket(lease_id, purpose="renter"))
    _mock_runtime(app)
    prompt = "Triage this SIEM alert and list containment steps."
    chat = await http_client.post(
        "/v1/chat/completions",
        headers=renter_headers(tenant_headers),
        json={"lease_id": str(lease_id), "messages": [{"role": "user", "content": prompt}]},
    )
    assert chat.status_code == 200
    assert chat.json()["object"] == "chat.completion"
    assert "hypermesh_receipt" not in chat.json()
    assert "decision" not in chat.json()
    assert app.state.receipt_store.count_for(tenant_id) == 0
    dumped = str(control_plane.metrics)
    assert prompt not in dumped


@pytest.mark.asyncio
async def test_renter_chat_still_rejects_ir_as_instance_not_ready(
    http_client, tenant_headers, app, tenant_id
):
    lease_id = uuid.uuid4()
    app.state.ticket_cache.put(tenant_id, _signed_ticket(lease_id, purpose="ir"))
    _mock_runtime(app)
    refused = await http_client.post(
        "/v1/chat/completions",
        headers=renter_headers(tenant_headers),
        json={"lease_id": str(lease_id), "messages": [{"role": "user", "content": "hi"}]},
    )
    assert refused.status_code == 409
    assert refused.json()["detail"] == INSTANCE_NOT_READY
    assert "receipt" not in refused.text.lower()
    assert app.state.receipt_store.count_for(tenant_id) == 0


@pytest.mark.asyncio
async def test_ir_door_rejects_renter_purpose_as_instance_not_ready(
    http_client, tenant_headers, app, tenant_id
):
    lease_id = uuid.uuid4()
    app.state.ticket_cache.put(tenant_id, _signed_ticket(lease_id, purpose="renter"))
    _mock_runtime(app)
    refused = await http_client.post(
        "/v1/ir/chat/completions",
        headers=renter_headers(tenant_headers),
        json={"lease_id": str(lease_id), "messages": [{"role": "user", "content": "hi"}]},
    )
    assert refused.status_code == 409
    assert refused.json()["detail"] == INSTANCE_NOT_READY


class _HoldAllClassifier:
    pack_version = "test-hold-all"

    def classify(self, text: str):
        from hypermesh_gateway_service.classify import CLASS_OUT_OF_SCOPE, Classification

        del text
        return Classification(CLASS_OUT_OF_SCOPE, "hold", pack_version=self.pack_version)


@pytest.mark.asyncio
async def test_ir_door_allows_authorized_work_and_holds_receipt(
    http_client, tenant_headers, app, tenant_id, control_plane
):
    lease_id = uuid.uuid4()
    app.state.ticket_cache.put(tenant_id, _signed_ticket(lease_id, purpose="ir"))
    _mock_runtime(app)
    prompt = "Triage this SIEM alert and list containment steps."
    chat = await http_client.post(
        "/v1/ir/chat/completions",
        headers=renter_headers(tenant_headers),
        json={"lease_id": str(lease_id), "messages": [{"role": "user", "content": prompt}]},
    )
    assert chat.status_code == 200
    body = chat.json()
    assert body["object"] == "chat.completion"
    receipt = body["hypermesh_receipt"]
    assert receipt["decision"] == "allow"
    assert receipt["class"] == "incident_triage"
    assert receipt["why"] == "ir"
    assert receipt["what_left"] == "completion"
    assert receipt["who"] == "pk_test"
    assert prompt not in str(receipt)
    assert "messages" not in receipt
    assert control_plane.get_lease_calls == 0
    dumped = str(control_plane.metrics)
    assert prompt not in dumped
    assert "messages" not in dumped
    assert "pack_version" not in receipt
    assert set(receipt) <= {
        "receipt_id",
        "who",
        "why",
        "what_left",
        "class",
        "decision",
        "time",
        "lease_id",
        "tenant_id",
    }


@pytest.mark.asyncio
async def test_ir_door_holds_out_of_scope_and_does_not_proxy(
    http_client, tenant_headers, app, tenant_id, control_plane
):
    lease_id = uuid.uuid4()
    app.state.ticket_cache.put(tenant_id, _signed_ticket(lease_id, purpose="ir"))

    async def boom(request):  # pragma: no cover
        raise AssertionError("hold must not proxy")

    import httpx

    app.state.runtime_client = httpx.AsyncClient(transport=httpx.MockTransport(boom))
    prompt = "Write a haiku about coffee."
    held = await http_client.post(
        "/api/v1/hypermesh-gateway/v1/ir/chat/completions",
        headers=renter_headers(tenant_headers),
        json={"lease_id": str(lease_id), "messages": [{"role": "user", "content": prompt}]},
    )
    assert held.status_code == 200
    body = held.json()
    assert body["decision"] == "hold"
    receipt = body["receipt"]
    assert receipt["decision"] == "hold"
    assert receipt["class"] == "out_of_scope"
    assert receipt["what_left"] == "none"
    assert receipt["why"] == "ir"
    assert prompt not in str(receipt)
    assert control_plane.post_metrics_calls == 0
    assert control_plane.get_lease_calls == 0


@pytest.mark.asyncio
async def test_ir_receipts_export_has_no_prompt_body(
    http_client, tenant_headers, app, tenant_id
):
    lease_id = uuid.uuid4()
    app.state.ticket_cache.put(tenant_id, _signed_ticket(lease_id, purpose="ir"))
    _mock_runtime(app)
    prompt = "secret prompt must never be exported"
    await http_client.post(
        "/v1/ir/chat/completions",
        headers=renter_headers(tenant_headers),
        json={"lease_id": str(lease_id), "messages": [{"role": "user", "content": prompt}]},
    )
    app.state.api_key_validator = stub_api_key_validator(tenant_id)
    exported = await http_client.get(
        "/v1/ir/receipts",
        headers=renter_headers(tenant_headers),
    )
    assert exported.status_code == 200
    rows = exported.json()["receipts"]
    assert len(rows) == 1
    blob = str(rows)
    assert prompt not in blob
    assert "secret prompt" not in blob
    assert "messages" not in blob
    assert set(rows[0]) <= {
        "receipt_id",
        "who",
        "why",
        "what_left",
        "class",
        "decision",
        "time",
        "lease_id",
        "tenant_id",
    }
    sanitized = sanitize_receipt_payload({**rows[0], "prompt": prompt, "messages": [prompt]})
    assert "prompt" not in sanitized
    assert "messages" not in sanitized
    assert prompt not in str(sanitized)


@pytest.mark.asyncio
async def test_ir_door_uses_injected_classifier_without_proxy(
    tenant_headers, tenant_id, control_plane, monkeypatch, caplog
):
    from hypermesh_gateway_service.app import create_app

    monkeypatch.setenv("HYPERMESH_WG_APPLY", "0")
    monkeypatch.setenv("HYPERMESH_ASSIGNMENT_REFRESH_S", "0")
    monkeypatch.setenv("HYPERMESH_TICKET_HMAC_KEY", "test-plane-hypermesh-ticket-hmac")
    app = create_app(
        control_plane=control_plane,
        gateway_service_secret="hm_gw_test",
        classifier=_HoldAllClassifier(),
    )
    lease_id = uuid.uuid4()
    prompt = "Triage this SIEM alert and list containment steps."
    import httpx
    from asgi_lifespan import LifespanManager

    async def boom(request):  # pragma: no cover
        raise AssertionError("swapped hold must not proxy")

    async with LifespanManager(app):
        app.state.ticket_cache.put(tenant_id, _signed_ticket(lease_id, purpose="ir"))
        app.state.ticket_cache.accept_keys(tenant_id, TEST_RENTER_FINGERPRINTS)
        app.state.runtime_client = httpx.AsyncClient(transport=httpx.MockTransport(boom))
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            with caplog.at_level("INFO"):
                held = await client.post(
                    "/v1/ir/chat/completions",
                    headers=renter_headers(tenant_headers),
                    json={
                        "lease_id": str(lease_id),
                        "messages": [{"role": "user", "content": prompt}],
                    },
                )
    assert held.status_code == 200
    body = held.json()
    assert body["decision"] == "hold"
    assert body["receipt"]["class"] == "out_of_scope"
    assert "pack_version" not in body["receipt"]
    assert prompt not in caplog.text
    assert prompt not in str(control_plane.metrics)
    assert control_plane.post_metrics_calls == 0


@pytest.mark.asyncio
async def test_ir_door_requires_grant(http_client, tenant_headers, app, tenant_id):
    lease_id = uuid.uuid4()
    app.state.ticket_cache.put(tenant_id, _signed_ticket(lease_id, purpose="ir"))
    missing = await http_client.post(
        "/v1/ir/chat/completions",
        headers=tenant_headers,
        json={"lease_id": str(lease_id), "messages": []},
    )
    assert missing.status_code == 401


@pytest.mark.asyncio
async def test_openapi_lists_ir_door_and_has_no_host_ips(http_client):
    spec = await http_client.get("/openapi.json")
    assert spec.status_code == 200
    text = spec.text
    assert "/v1/ir/chat/completions" in text
    assert "/v1/ir/receipts" in text
    assert "10.77." not in text
    assert "Hypermesh" in spec.json()["info"]["title"]


def test_receipt_file_persist_survives_new_store_without_prompt(tmp_path, tenant_id):
    path = tmp_path / "ir-receipts.json"
    first = ReceiptStore(persist_path=path)
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
    blob = path.read_text(encoding="utf-8")
    assert prompt not in blob
    assert "messages" not in blob
    assert "secret prompt" not in blob
    second = ReceiptStore(persist_path=path)
    rows = second.export_for(tenant_id)
    assert len(rows) == 1
    assert rows[0]["why"] == "ir"
    assert rows[0]["class"] == "incident_triage"
    assert rows[0]["decision"] == "allow"
    assert prompt not in str(rows)


@pytest.mark.asyncio
async def test_ir_door_receipts_reload_from_file(
    tmp_path, tenant_headers, tenant_id, control_plane, monkeypatch
):
    from hypermesh_gateway_service.app import create_app

    path = tmp_path / "ir-receipts.json"
    monkeypatch.setenv("HYPERMESH_WG_APPLY", "0")
    monkeypatch.setenv("HYPERMESH_ASSIGNMENT_REFRESH_S", "0")
    monkeypatch.setenv("HYPERMESH_TICKET_HMAC_KEY", "test-plane-hypermesh-ticket-hmac")
    monkeypatch.setenv("HYPERMESH_IR_RECEIPT_PATH", str(path))
    first_app = create_app(
        control_plane=control_plane,
        gateway_service_secret="hm_gw_test",
    )
    lease_id = uuid.uuid4()
    prompt = "secret prompt must never be persisted"
    import httpx
    from asgi_lifespan import LifespanManager

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
            assert prompt not in path.read_text(encoding="utf-8")
