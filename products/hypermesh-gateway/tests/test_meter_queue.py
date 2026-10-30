"""Failed meter hops must not drop usage. The door rate-limits the lease."""

from __future__ import annotations

import uuid

import pytest

from hypermesh_gateway_service.metrics import (
    MeterQueue,
    flush_meter_queue,
    sanitize_queue_payload,
)
from hypermesh_gateway_service.quota import ChatQuota, QuotaExceeded
from test_hypermesh_gateway import (
    TEST_RENTER_FINGERPRINTS,
    _mock_runtime,
    _renter,
    _signed_ticket,
)


@pytest.mark.asyncio
async def test_failed_metrics_post_is_queued_and_chat_still_succeeds(
    http_client, tenant_headers, control_plane, app, tenant_id
):
    lease_id = uuid.uuid4()
    app.state.ticket_cache.put(tenant_id, _signed_ticket(lease_id))
    _mock_runtime(app)
    control_plane.fail_metrics = True
    prompt = "secret prompt must never sit on the meter queue"
    chat = await http_client.post(
        "/v1/chat/completions",
        headers=_renter(tenant_headers),
        json={"lease_id": str(lease_id), "messages": [{"role": "user", "content": prompt}]},
    )
    assert chat.status_code == 200
    assert control_plane.post_metrics_calls == 1
    assert control_plane.metrics == []
    assert app.state.meter_queue.pending_count() == 1
    pending = app.state.meter_queue.pending()[0]
    assert pending.lease_id == lease_id
    dumped = str(pending.as_export())
    assert prompt not in dumped
    assert "messages" not in dumped


@pytest.mark.asyncio
async def test_flush_delivers_queued_metrics_once(
    http_client, tenant_headers, control_plane, app, tenant_id
):
    lease_id = uuid.uuid4()
    app.state.ticket_cache.put(tenant_id, _signed_ticket(lease_id))
    _mock_runtime(app)
    control_plane.fail_metrics = True
    chat = await http_client.post(
        "/v1/chat/completions",
        headers=_renter(tenant_headers),
        json={"lease_id": str(lease_id), "messages": [{"role": "user", "content": "hi"}]},
    )
    assert chat.status_code == 200
    queued_id = app.state.meter_queue.pending()[0].metric_id
    control_plane.fail_metrics = False
    sent = await flush_meter_queue(control_plane, app.state.meter_queue)
    assert sent == 1
    assert app.state.meter_queue.pending_count() == 0
    assert control_plane.post_metrics_calls == 2
    assert control_plane.metrics[-1]["metric_id"] == queued_id
    again = await flush_meter_queue(control_plane, app.state.meter_queue)
    assert again == 0
    assert control_plane.post_metrics_calls == 2


@pytest.mark.asyncio
async def test_refresh_flushes_queued_metrics(tenant_id, control_plane):
    from hypermesh_gateway_service.routes import refresh_known_tenants
    from hypermesh_gateway_service.tickets import TicketCache

    queue = MeterQueue()
    item = queue.enqueue(
        tenant_id=tenant_id,
        tunnel_id=None,
        lease_id=uuid.uuid4(),
        bytes_in=8,
        bytes_out=2,
        handshake_count=1,
    )
    cache = TicketCache()
    cache.watch(tenant_id)
    await refresh_known_tenants(control_plane, cache, queue)
    assert queue.pending_count() == 0
    assert control_plane.metrics[-1]["metric_id"] == item.metric_id


def test_meter_queue_survives_bounce_without_prompt(tmp_path, tenant_id):
    path = tmp_path / "meter-queue.json"
    first = MeterQueue(persist_path=path)
    lease_id = uuid.uuid4()
    prompt = "secret prompt must never be persisted"
    first.enqueue(
        tenant_id=tenant_id,
        tunnel_id=None,
        lease_id=lease_id,
        bytes_in=12,
        bytes_out=4,
        handshake_count=1,
    )
    blob = path.read_text(encoding="utf-8")
    assert prompt not in blob
    assert "messages" not in blob
    assert "secret prompt" not in blob
    second = MeterQueue(persist_path=path)
    rows = second.pending()
    assert len(rows) == 1
    assert rows[0].lease_id == lease_id
    assert rows[0].bytes_in == 12
    assert prompt not in str(rows[0].as_export())
    cleaned = sanitize_queue_payload({**rows[0].as_export(), "prompt": prompt, "messages": [prompt]})
    assert "prompt" not in cleaned
    assert "messages" not in cleaned


@pytest.mark.asyncio
async def test_full_queue_refuses_chat_without_dropping_pending(
    http_client, tenant_headers, control_plane, app, tenant_id
):
    held = uuid.uuid4()
    app.state.meter_queue = MeterQueue(max_pending=1)
    app.state.meter_queue.enqueue(
        tenant_id=tenant_id,
        tunnel_id=None,
        lease_id=held,
        bytes_in=3,
        bytes_out=1,
        handshake_count=0,
    )
    lease_id = uuid.uuid4()
    app.state.ticket_cache.put(tenant_id, _signed_ticket(lease_id))
    _mock_runtime(app)
    refused = await http_client.post(
        "/v1/chat/completions",
        headers=_renter(tenant_headers),
        json={"lease_id": str(lease_id), "messages": [{"role": "user", "content": "hi"}]},
    )
    assert refused.status_code == 429
    assert refused.json()["detail"] == "usage queue is full"
    assert app.state.meter_queue.pending_count() == 1
    assert app.state.meter_queue.pending()[0].lease_id == held
    assert control_plane.post_metrics_calls == 0


@pytest.mark.asyncio
async def test_lease_rate_limit_returns_429(
    http_client, tenant_headers, control_plane, app, tenant_id
):
    lease_id = uuid.uuid4()
    app.state.ticket_cache.put(tenant_id, _signed_ticket(lease_id))
    app.state.chat_quota = ChatQuota(rate_limit=1, window_s=60)
    _mock_runtime(app)
    first = await http_client.post(
        "/v1/chat/completions",
        headers=_renter(tenant_headers),
        json={"lease_id": str(lease_id), "messages": [{"role": "user", "content": "one"}]},
    )
    second = await http_client.post(
        "/v1/chat/completions",
        headers=_renter(tenant_headers),
        json={"lease_id": str(lease_id), "messages": [{"role": "user", "content": "two"}]},
    )
    assert first.status_code == 200
    assert second.status_code == 429
    assert second.json()["detail"] == "rate limited"
    assert control_plane.post_metrics_calls == 1


def test_byte_quota_refuses_before_host_hop(tenant_id):
    quota = ChatQuota(rate_limit=10, window_s=60, bytes_quota=10)
    lease_id = uuid.uuid4()
    quota.allow(lease_id, incoming_bytes=4)
    quota.add_bytes(lease_id, 8)
    with pytest.raises(QuotaExceeded, match="quota exceeded"):
        quota.allow(lease_id, incoming_bytes=4)
    other = uuid.uuid4()
    quota.allow(other, incoming_bytes=4)


@pytest.mark.asyncio
async def test_meter_queue_reloads_from_file_on_new_app(
    tmp_path, tenant_headers, tenant_id, control_plane, monkeypatch
):
    from hypermesh_gateway_service.app import create_app
    import httpx
    from asgi_lifespan import LifespanManager

    path = tmp_path / "meter-queue.json"
    monkeypatch.setenv("HYPERMESH_WG_APPLY", "0")
    monkeypatch.setenv("HYPERMESH_ASSIGNMENT_REFRESH_S", "0")
    monkeypatch.setenv("HYPERMESH_TICKET_HMAC_KEY", "test-plane-hypermesh-ticket-hmac")
    monkeypatch.setenv("HYPERMESH_METER_QUEUE_PATH", str(path))
    first_app = create_app(
        control_plane=control_plane,
        gateway_service_secret="hm_gw_test",
    )
    lease_id = uuid.uuid4()
    prompt = "secret prompt must never be persisted"
    async with LifespanManager(first_app):
        first_app.state.ticket_cache.put(tenant_id, _signed_ticket(lease_id))
        first_app.state.ticket_cache.accept_keys(tenant_id, TEST_RENTER_FINGERPRINTS)
        _mock_runtime(first_app)
        control_plane.fail_metrics = True
        transport = httpx.ASGITransport(app=first_app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            chat = await client.post(
                "/v1/chat/completions",
                headers=_renter(tenant_headers),
                json={
                    "lease_id": str(lease_id),
                    "messages": [{"role": "user", "content": prompt}],
                },
            )
            assert chat.status_code == 200, chat.text
            queued_id = first_app.state.meter_queue.pending()[0].metric_id

    assert prompt not in path.read_text(encoding="utf-8")
    control_plane.fail_metrics = False
    bounced = create_app(
        control_plane=control_plane,
        gateway_service_secret="hm_gw_test",
    )
    async with LifespanManager(bounced):
        assert bounced.state.meter_queue.pending_count() == 1
        sent = await flush_meter_queue(control_plane, bounced.state.meter_queue)
        assert sent == 1
        assert bounced.state.meter_queue.pending_count() == 0
        assert control_plane.metrics[-1]["metric_id"] == queued_id
        assert prompt not in str(control_plane.metrics)
