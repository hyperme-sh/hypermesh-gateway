"""Offline regressions for bounded admission, delivery and stream identity."""
import asyncio
import json
import uuid
from types import SimpleNamespace

import httpx
import pytest
from starlette.requests import Request

from hypermesh_gateway_service.chat import SseToolCallIds
from hypermesh_gateway_service.metrics import MeterQueue, MeterQueueFull, flush_meter_queue
from hypermesh_gateway_service.routes import _tenant_from_api_key
from hypermesh_gateway_service.errors import DoorError
from hypermesh_gateway_service.tickets import TicketCache
from test_hypermesh_gateway import _signed_ticket, _renter, _ir, TEST_IR_FINGERPRINTS


def test_stream_ids_are_emitted_once_per_choice_and_call():
    rewriter = SseToolCallIds()
    accumulated = {}
    for part in range(3):
        payload = {"choices": [{"index": choice, "delta": {"tool_calls": [
            {"index": 0, "id": "" if part == 0 else "repeated", "function": {"arguments": str(part)}}
        ]}} for choice in range(2)]}
        raw = rewriter.feed(('data: ' + json.dumps(payload) + '\n\n').encode())
        for choice in json.loads(raw.decode().strip()[5:])["choices"]:
            call = choice["delta"]["tool_calls"][0]
            entry = accumulated.setdefault(choice["index"], ["", ""])
            entry[0] += call.get("id", "")
            entry[1] += call["function"]["arguments"]
    assert accumulated[0][0].startswith('call_')
    assert accumulated[0][0] != accumulated[1][0]
    assert all(len(value[0]) == 29 and value[1] == '012' for value in accumulated.values())


def test_reservation_cannot_be_stolen_or_consumed_twice():
    queue = MeterQueue(max_pending=1)
    token = queue.reserve()
    fields = dict(tenant_id=uuid.uuid4(), tunnel_id=None, lease_id=None,
                  bytes_in=3, bytes_out=4, handshake_count=0)
    with pytest.raises(MeterQueueFull):
        queue.enqueue(**fields)
    queue.enqueue(**fields, reservation=token)
    with pytest.raises(ValueError):
        queue.enqueue(**fields, reservation=token)
    assert queue.pending_count() == 1


@pytest.mark.asyncio
async def test_flush_batch_and_deadline_preserve_pending(control_plane, tenant_id):
    queue = MeterQueue()
    for _ in range(50):
        queue.enqueue(tenant_id=tenant_id, tunnel_id=None, lease_id=None,
                      bytes_in=1, bytes_out=2, handshake_count=0)
    assert await flush_meter_queue(control_plane, queue, batch_size=3) == 3
    assert queue.pending_count() == 47
    async def blocked(*args, **kwargs):
        await asyncio.Event().wait()
    control_plane.post_metrics = blocked
    assert await flush_meter_queue(control_plane, queue, budget_s=0.01) == 0
    assert queue.pending_count() == 47


@pytest.mark.asyncio
async def test_distinct_unknown_keys_share_refresh_and_failure_cooldown():
    entered, finish = asyncio.Event(), asyncio.Event()
    calls = 0
    async def index():
        nonlocal calls
        calls += 1
        entered.set()
        await finish.wait()
        raise RuntimeError('owner unavailable')
    state = SimpleNamespace(ticket_cache=TicketCache(), control_plane=SimpleNamespace(list_key_index=index))
    request = Request({'type': 'http', 'app': SimpleNamespace(state=state)})
    tasks = [asyncio.create_task(_tenant_from_api_key(request, f'pk_test.miss-{i}', ir=False)) for i in range(100)]
    await entered.wait()
    finish.set()
    results = await asyncio.gather(*tasks, return_exceptions=True)
    assert all(isinstance(result, DoorError) for result in results)
    assert calls == 1
    state.key_index_retry_at = 0
    with pytest.raises(DoorError):
        await _tenant_from_api_key(request, 'pk_test.retry', ir=False)
    assert calls == 2


@pytest.mark.asyncio
@pytest.mark.parametrize('ir', [False, True])
async def test_concurrent_chat_reserves_last_slot(http_client, app, tenant_id, tenant_headers, control_plane, ir):
    lease = uuid.uuid4()
    app.state.ticket_cache.put(tenant_id, _signed_ticket(lease, purpose='ir' if ir else 'renter'))
    app.state.ticket_cache.accept_ir_keys(tenant_id, TEST_IR_FINGERPRINTS)
    from hypermesh_gateway_service.classify import Classification
    app.state.classifier = SimpleNamespace(classify=lambda _: Classification("incident_triage", "allow", pack_version="test"))
    app.state.meter_queue = MeterQueue(max_pending=1)
    control_plane.fail_metrics = True
    entered, finish = asyncio.Event(), asyncio.Event()
    async def host(request):
        entered.set()
        await finish.wait()
        return httpx.Response(200, json={'object': 'chat.completion'})
    app.state.runtime_client = httpx.AsyncClient(transport=httpx.MockTransport(host))
    path = '/v1/ir/chat/completions' if ir else '/v1/chat/completions'
    headers = (_ir if ir else _renter)(tenant_headers)
    body = {'lease_id': str(lease), 'messages': [{'role': 'user', 'content': 'Summarize these incident logs.'}]}
    first = asyncio.create_task(http_client.post(path, headers=headers, json=body))
    try:
        await asyncio.wait_for(entered.wait(), 3)
        second = await http_client.post(path, headers=headers, json=body)
        assert second.status_code == 429
    finally:
        finish.set()
        response = await first
    assert response.status_code == 200, response.text
    assert app.state.meter_queue.pending_count() == 1
    assert not app.state.meter_queue._reservations


@pytest.mark.asyncio
@pytest.mark.parametrize('ir', [False, True])
async def test_chunked_body_metering_ignores_peer_totals(http_client, app, tenant_id, tenant_headers, control_plane, monkeypatch, ir):
    from test_hypermesh_gateway import _mock_runtime
    lease = uuid.uuid4()
    app.state.ticket_cache.put(tenant_id, _signed_ticket(lease, purpose='ir' if ir else 'renter'))
    app.state.ticket_cache.accept_ir_keys(tenant_id, TEST_IR_FINGERPRINTS)
    from hypermesh_gateway_service.classify import Classification
    app.state.classifier = SimpleNamespace(classify=lambda _: Classification("incident_triage", "allow", pack_version="test"))
    _mock_runtime(app)
    monkeypatch.setattr('hypermesh_gateway_service.routes.peer_counters', lambda _: (999999, 888888, 1))
    raw = json.dumps({'lease_id': str(lease), 'messages': [{'role': 'user', 'content': 'Summarize these incident logs.'}]}).encode()
    async def chunks():
        yield raw[:10]
        yield raw[10:]
    for _ in range(2):
        response = await http_client.post('/v1/ir/chat/completions' if ir else '/v1/chat/completions',
            headers={**(_ir if ir else _renter)(tenant_headers), 'Content-Type': 'application/json'}, content=chunks())
        assert response.status_code == 200, response.text
        assert control_plane.metrics[-1]['bytes_in'] == len(raw)
        assert control_plane.metrics[-1]['bytes_out'] < 888888


def test_protective_checks_never_rescan_unbounded_prefix():
    from hypermesh_gateway_service.safety import _protective_context, _GUARD_LOOKBACK
    class BoundedText(str):
        def rfind(self, sub, start=0, end=None):
            assert end - start <= _GUARD_LOOKBACK
            return super().rfind(sub, start, end)
    text = BoundedText('ordinary words ' * 10000 + 'How can I report csam?')
    start = text.index('csam')
    assert _protective_context(text, start, start + 4)


@pytest.mark.asyncio
@pytest.mark.parametrize('ir', [False, True])
async def test_cancelled_host_hop_releases_usage_capacity(http_client, app, tenant_id, tenant_headers, ir):
    from hypermesh_gateway_service.classify import Classification
    lease = uuid.uuid4()
    app.state.ticket_cache.put(tenant_id, _signed_ticket(lease, purpose='ir' if ir else 'renter'))
    app.state.ticket_cache.accept_ir_keys(tenant_id, TEST_IR_FINGERPRINTS)
    app.state.classifier = SimpleNamespace(classify=lambda _: Classification('incident_triage', 'allow', pack_version='test'))
    app.state.meter_queue = MeterQueue(max_pending=1)
    entered = asyncio.Event()
    async def host(request):
        entered.set()
        await asyncio.Event().wait()
    app.state.runtime_client = httpx.AsyncClient(transport=httpx.MockTransport(host))
    task = asyncio.create_task(http_client.post('/v1/ir/chat/completions' if ir else '/v1/chat/completions',
        headers=(_ir if ir else _renter)(tenant_headers),
        json={'lease_id': str(lease), 'messages': [{'role': 'user', 'content': 'hello'}]}))
    await asyncio.wait_for(entered.wait(), 3)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert not app.state.meter_queue.is_full()
    assert not app.state.meter_queue._reservations


@pytest.mark.asyncio
@pytest.mark.parametrize('failure', ['disconnect', 'cancel', 'none'])
@pytest.mark.parametrize('spec_version', ['2.0', '2.4'])
async def test_response_finalizes_usage_even_before_body_starts(failure, spec_version):
    from hypermesh_gateway_service.chat import ProxiedChat
    from hypermesh_gateway_service.routes import _stream_chat
    from starlette.requests import ClientDisconnect

    queue = MeterQueue(max_pending=1)
    reservation = queue.reserve()
    upstream = httpx.Response(200, content=b'completion')
    proxied = ProxiedChat(upstream)
    calls = []

    async def meter(size):
        calls.append(size)
        queue.enqueue(tenant_id=uuid.uuid4(), tunnel_id=None, lease_id=None,
                      bytes_in=2, bytes_out=size, handshake_count=0, reservation=reservation)

    async def receive():
        await asyncio.Event().wait()

    async def send(message):
        if message['type'] == 'http.response.start':
            if failure == 'disconnect':
                raise OSError('client disconnected before headers')
            if failure == 'cancel':
                raise asyncio.CancelledError()

    response = _stream_chat(proxied, after_bytes=meter)
    scope = {'type': 'http', 'asgi': {'spec_version': spec_version}}
    if failure == 'none' or (spec_version == '2.0' and failure == 'cancel'):
        # The older ASGI task-group path suppresses child cancellation.
        await response(scope, receive, send)
    else:
        with pytest.raises((OSError, ClientDisconnect, asyncio.CancelledError, BaseExceptionGroup)):
            await response(scope, receive, send)
    assert calls == ([10] if failure == 'none' else [0])
    assert not queue._reservations
    assert queue.pending_count() == 1
    assert proxied._closed


@pytest.mark.asyncio
async def test_stalled_index_waiters_share_timeout_cooldown(monkeypatch):
    import hypermesh_gateway_service.routes as routes
    entered, finish = asyncio.Event(), asyncio.Event()
    clock = [100.0]
    # Replace only this module's clock, not asyncio's event-loop clock.
    monkeypatch.setattr(routes, 'time', SimpleNamespace(monotonic=lambda: clock[0]))
    calls = 0

    async def index():
        nonlocal calls
        calls += 1
        entered.set()
        await finish.wait()
        clock[0] += 5.0
        raise TimeoutError('index timed out')

    state = SimpleNamespace(ticket_cache=TicketCache(), control_plane=SimpleNamespace(list_key_index=index))
    request = Request({'type': 'http', 'app': SimpleNamespace(state=state)})
    tasks = [asyncio.create_task(_tenant_from_api_key(request, f'pk_test.timeout-{i}', ir=False)) for i in range(20)]
    await entered.wait()
    finish.set()
    results = await asyncio.gather(*tasks, return_exceptions=True)
    assert all(isinstance(result, DoorError) for result in results)
    assert calls == 1
    assert state.key_index_retry_at == 110.0
    clock[0] = 110.0
    with pytest.raises(DoorError):
        await _tenant_from_api_key(request, 'pk_test.retry-after-timeout', ir=False)
    assert calls == 2
