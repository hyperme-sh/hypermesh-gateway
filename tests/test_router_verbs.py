"""Router prompt verbs: same renter grant as chat, live policy vs explicit stubs."""

from __future__ import annotations

import json
import logging
import uuid
from datetime import UTC, datetime, timedelta

import httpx
import pytest

from gateway_host_fixture import (
    FYBER_AGX_DEVICE_ID,
    FYBER_TEST_GATEWAY_ID,
    LIVE_FYBER_AGX64_DEVICE_ID,
)
from hypermesh_gateway_service.posture import require_chat_posture
from hypermesh_gateway_service.tickets import CachedTicket
from hypermesh_gateway_service.verbs import VERB_SPECS
from hypermesh_ticket import TicketClaims, TicketNotReady, issue_ticket
from test_hypermesh_gateway import TEST_RENTER_KEY

OTHER_KEY = "other_prefix.other-secret"
SECRET_APPEND = "router-append-token-should-not-be-logged"
AUDIT_REASON = "reviewed-export-reason-should-not-be-logged"


def _renter(tenant_headers: dict[str, str], key: str = TEST_RENTER_KEY) -> dict[str, str]:
    return {**tenant_headers, "Authorization": f"Bearer {key}"}


def _plant(
    app,
    tenant_id: uuid.UUID,
    lease_id: uuid.UUID,
    *,
    device_id: uuid.UUID = FYBER_AGX_DEVICE_ID,
    client_address: str = "10.77.0.2/32",
    catalog_id: str = "llama-3.1-8b-q4",
    activated_at: datetime | None = None,
) -> CachedTicket:
    exp = datetime.now(UTC) + timedelta(hours=1)
    token = issue_ticket(
        TicketClaims(
            lease_id=lease_id,
            device_id=device_id,
            gateway_id=FYBER_TEST_GATEWAY_ID,
            client_address=client_address,
            status="active",
            exp=exp,
            tenant_id=tenant_id,
        )
    )
    ticket = CachedTicket(
        lease_id=lease_id,
        ticket=token,
        client_address=client_address,
        assigned_gateway_id=FYBER_TEST_GATEWAY_ID,
        status="active",
        exp=exp,
        device_id=device_id,
        path_b_state="green",
        peer_public_key="peer-pub",
        catalog_id=catalog_id,
        activated_at=activated_at or datetime.now(UTC),
    )
    app.state.ticket_cache.put(tenant_id, ticket)
    return ticket


def _capture(app, seen: list[dict]) -> None:
    async def handler(request: httpx.Request) -> httpx.Response:
        seen.append({"host": request.url.host, "json": json.loads(request.content)})
        return httpx.Response(
            200,
            json={
                "id": "cmpl-test",
                "object": "chat.completion",
                "choices": [{"index": 0, "message": {"role": "assistant", "content": "ok"}}],
            },
        )

    app.state.runtime_client = httpx.AsyncClient(transport=httpx.MockTransport(handler))


async def _verb(http_client, headers, verb: str, **kwargs):
    body: dict = {"verb": verb, "args": kwargs.pop("args", {})}
    if "lease_id" in kwargs and kwargs["lease_id"] is not None:
        body["lease_id"] = str(kwargs["lease_id"])
    if kwargs.get("model"):
        body["model"] = kwargs["model"]
    return await http_client.post("/v1/router/verbs", headers=headers, json=body)


async def _chat(http_client, headers, lease_id, *, model=None, extra=None):
    payload: dict = {"messages": [{"role": "user", "content": "hi"}]}
    if lease_id is not None:
        payload["lease_id"] = str(lease_id)
    if model is not None:
        payload["model"] = model
    if extra:
        payload.update(extra)
    return await http_client.post("/v1/chat/completions", headers=headers, json=payload)


@pytest.mark.asyncio
async def test_catalog_requires_renter_grant_and_marks_stubs(http_client, tenant_headers):
    missing = await http_client.get("/v1/router/verbs")
    assert missing.status_code == 401
    assert missing.json()["error"]["code"] == "invalid_api_key"
    listed = await http_client.get("/v1/router/verbs", headers=_renter(tenant_headers))
    assert listed.status_code == 200, listed.text
    verbs = listed.json()["verbs"]
    assert [row["verb"] for row in verbs] == [spec.verb for spec in VERB_SPECS]
    wired = {row["verb"] for row in verbs if row["wired"]}
    stubbed = {row["verb"] for row in verbs if not row["wired"]}
    assert wired == {spec.verb for spec in VERB_SPECS if spec.wired}
    assert stubbed == {
        "mix_models",
        "prefer_tier",
        "route_hint",
        "safety_context",
        "op_class",
        "skill_load",
        "skill_unload",
        "skill_list",
    }
    assert all("Not wired" in row["summary"] for row in verbs if not row["wired"])


@pytest.mark.asyncio
async def test_verb_auth_matches_the_chat_door(
    http_client, app, tenant_headers, tenant_id
):
    lease_id = uuid.uuid4()
    bare = await _verb(http_client, _renter(tenant_headers), "pause")
    assert bare.status_code == 402
    assert bare.json()["error"]["code"] == "no_active_lease"
    _plant(app, tenant_id, lease_id)
    no_grant = await _verb(http_client, tenant_headers, "pause", lease_id=lease_id)
    assert no_grant.status_code == 401
    for forbidden in ("hm_gw_test", "hm_dev_test", "hm_site_test"):
        refused = await _verb(
            http_client,
            {**tenant_headers, "Authorization": f"Bearer {forbidden}"},
            "pause",
            lease_id=lease_id,
        )
        assert refused.status_code == 401
    mismatch = await _verb(
        http_client,
        {**_renter(tenant_headers), "X-Tenant-ID": str(uuid.uuid4())},
        "pause",
        lease_id=lease_id,
    )
    assert mismatch.status_code == 403
    assert mismatch.json()["error"]["code"] == "tenant_mismatch"
    only = await _verb(http_client, _renter(tenant_headers), "resume")
    assert only.status_code == 200, only.text
    assert only.json()["lease_id"] == str(lease_id)
    unknown = await _verb(http_client, _renter(tenant_headers), "halt", lease_id=lease_id)
    assert unknown.status_code == 400
    assert unknown.json()["status"] == "unknown_verb"
    assert unknown.json()["wired"] is False
    sibling = await http_client.post(
        "/api/v1/hypermesh-gateway/v1/router/verbs",
        json={"verb": "pause"},
    )
    assert sibling.status_code == 401
    assert "detail" in sibling.json()
    header = await http_client.post(
        "/v1/router/verbs",
        headers={
            **tenant_headers,
            "X-Api-Key": TEST_RENTER_KEY,
            "X-Hypermesh-Lease-Id": str(lease_id),
        },
        json={"verb": "pause", "args": {}},
    )
    assert header.status_code == 200, header.text
    assert header.json()["run"] == "paused"
    from api.infrastructure.security.api_key_exchange_jwt import mint_api_key_session_jwt

    token = mint_api_key_session_jwt(
        key_record_id=uuid.uuid4(), tenant_id=tenant_id, scopes=[]
    )
    resumed = await _verb(
        http_client,
        {**tenant_headers, "Authorization": f"Bearer {token}"},
        "resume",
        lease_id=lease_id,
    )
    assert resumed.status_code == 200, resumed.text
    assert resumed.json()["run"] == "running"
    assert resumed.json()["recipient_ack"] == "not_delivered"
    sibling = await http_client.post(
        "/api/v1/hypermesh-gateway/v1/router/verbs",
        headers=_renter(tenant_headers),
        json={"verb": "pause", "lease_id": str(lease_id), "args": {}},
    )
    assert sibling.status_code == 200, sibling.text
    assert sibling.json()["object"] == "hypermesh.router_verb"
    assert sibling.json()["run"] == "paused"


@pytest.mark.asyncio
async def test_run_control_gates_new_completions_and_does_not_call_the_host(
    http_client, app, tenant_headers, tenant_id, caplog
):
    lease_id = uuid.uuid4()
    _plant(app, tenant_id, lease_id)
    seen: list[dict] = []
    _capture(app, seen)
    headers = _renter(tenant_headers)
    caplog.set_level(logging.INFO)
    app.state.peer_up = False
    paused = await _verb(http_client, headers, "pause", lease_id=lease_id)
    assert paused.status_code == 200, paused.text
    assert paused.json()["wired"] is True
    assert "host was not commanded" in paused.json()["detail"].lower() or "not commanded" in paused.json()["detail"]
    app.state.peer_up = True
    blocked = await _chat(http_client, headers, lease_id)
    assert blocked.status_code == 409
    assert blocked.json()["error"]["code"] == "run_paused"
    assert seen == []
    again = await _verb(http_client, headers, "pause", lease_id=lease_id)
    assert again.status_code == 200
    assert again.json()["run"] == "paused"
    drained = await _verb(http_client, headers, "drain", lease_id=lease_id)
    assert drained.json()["run"] == "draining"
    assert (await _chat(http_client, headers, lease_id)).json()["error"]["code"] == "run_draining"
    cancelled = await _verb(http_client, headers, "cancel", lease_id=lease_id)
    assert cancelled.json()["run"] == "cancelled"
    assert (await _chat(http_client, headers, lease_id)).json()["error"]["code"] == "run_cancelled"
    rejected = await _verb(http_client, headers, "pause", lease_id=lease_id)
    assert rejected.status_code == 409
    assert rejected.json()["status"] == "rejected"
    assert rejected.json()["run"] == "cancelled"
    resumed = await _verb(http_client, headers, "resume", lease_id=lease_id)
    assert resumed.json()["run"] == "running"
    allowed = await _chat(http_client, headers, lease_id)
    assert allowed.status_code == 200, allowed.text
    assert len(seen) == 1
    session = await http_client.get(
        "/v1/router/session",
        headers=headers,
        params={"lease_id": str(lease_id)},
    )
    assert session.status_code == 200
    assert session.json()["run"] == "running"
    assert session.json()["durable"] is False
    assert session.json()["recipient_ack"] == "not_delivered"
    blob = " ".join(record.getMessage() for record in caplog.records)
    assert "messages" not in blob


@pytest.mark.asyncio
async def test_revoked_ticket_cannot_take_a_verb(http_client, app, tenant_headers, tenant_id):
    lease_id = uuid.uuid4()
    _plant(app, tenant_id, lease_id)
    app.state.ticket_cache._revoked.setdefault(tenant_id, set()).add(lease_id)
    refused = await _verb(http_client, _renter(tenant_headers), "pause", lease_id=lease_id)
    assert refused.status_code == 409
    assert refused.json()["error"]["code"] == "instance_not_ready"


@pytest.mark.asyncio
async def test_model_pin_and_routing_change_lease_choice(
    http_client, app, tenant_headers, tenant_id
):
    older = datetime(2026, 1, 1, tzinfo=UTC)
    newer = datetime(2026, 6, 1, tzinfo=UTC)
    first = uuid.uuid4()
    second = uuid.uuid4()
    _plant(
        app,
        tenant_id,
        first,
        device_id=FYBER_AGX_DEVICE_ID,
        client_address="10.77.0.2/32",
        catalog_id="model-a",
        activated_at=older,
    )
    _plant(
        app,
        tenant_id,
        second,
        device_id=LIVE_FYBER_AGX64_DEVICE_ID,
        client_address="10.77.0.3/32",
        catalog_id="model-b",
        activated_at=newer,
    )
    seen: list[dict] = []
    _capture(app, seen)
    headers = _renter(tenant_headers)
    default = await _chat(http_client, headers, None)
    assert default.status_code == 200, default.text
    assert seen[-1]["host"] == "10.77.0.3"
    missing = await _verb(http_client, headers, "use_model", args={"model": "missing"})
    assert missing.status_code == 404
    assert missing.json()["error"]["code"] == "model_not_found"
    pinned = await _verb(http_client, headers, "use_model", args={"model": "model-a"})
    assert pinned.status_code == 200, pinned.text
    assert pinned.json()["model"] == "model-a"
    pinned_chat = await _chat(http_client, headers, None)
    assert pinned_chat.status_code == 200, pinned_chat.text
    assert seen[-1]["host"] == "10.77.0.2"
    explicit = await _chat(http_client, headers, None, model="model-b")
    assert explicit.status_code == 200, explicit.text
    assert seen[-1]["host"] == "10.77.0.3"
    mixed = await _verb(
        http_client,
        headers,
        "mix_models",
        args={"models": [{"model": "model-a", "weight": 1}, {"model": "model-b", "weight": 1}]},
    )
    assert mixed.status_code == 200
    assert mixed.json()["status"] == "not_wired"
    assert mixed.json()["wired"] is False
    hinted = await _verb(http_client, headers, "route_hint", args={"hint": "certified_only"})
    assert hinted.json()["status"] == "not_wired"
    tier = await _verb(http_client, headers, "prefer_tier", args={"tier": "frontier"})
    assert tier.json()["wired"] is False
    await _verb(http_client, headers, "use_model", args={"clear": True})
    preferred = await _verb(
        http_client,
        headers,
        "prefer_host",
        args={"device_id": str(FYBER_AGX_DEVICE_ID)},
    )
    assert preferred.status_code == 200, preferred.text
    prefer_chat = await _chat(http_client, headers, None)
    assert prefer_chat.status_code == 200, prefer_chat.text
    assert seen[-1]["host"] == "10.77.0.2"
    fallthrough = await _chat(http_client, headers, None, model="model-b")
    assert fallthrough.status_code == 200, fallthrough.text
    assert seen[-1]["host"] == "10.77.0.3"
    await _verb(http_client, headers, "prefer_host", args={"clear": True})
    stuck = await _verb(http_client, headers, "affinity", args={"lease_id": str(first)})
    assert stuck.status_code == 200, stuck.text
    sticky = await _chat(http_client, headers, None)
    assert seen[-1]["host"] == "10.77.0.2"
    await _verb(http_client, headers, "affinity", args={"clear": True})
    excluded = await _verb(
        http_client,
        headers,
        "exclude_host",
        args={"device_id": str(LIVE_FYBER_AGX64_DEVICE_ID)},
    )
    assert excluded.status_code == 200, excluded.text
    dropped = await _chat(http_client, headers, None)
    assert dropped.status_code == 200, dropped.text
    assert seen[-1]["host"] == "10.77.0.2"
    named = await _chat(http_client, headers, second)
    assert named.status_code == 409
    assert named.json()["error"]["code"] == "host_excluded"


@pytest.mark.asyncio
async def test_prompt_attachments_and_frames_are_forwarded_and_screened_with_the_request(
    http_client, app, tenant_headers, tenant_id, caplog
):
    lease_id = uuid.uuid4()
    _plant(app, tenant_id, lease_id)
    seen: list[dict] = []
    _capture(app, seen)
    headers = _renter(tenant_headers)
    caplog.set_level(logging.INFO)
    appended = await _verb(
        http_client, headers, "system_append", lease_id=lease_id, args={"text": SECRET_APPEND}
    )
    assert appended.status_code == 200, appended.text
    styled = await _verb(
        http_client, headers, "style", lease_id=lease_id, args={"text": "terse"}
    )
    assert styled.status_code == 200, styled.text
    hinted = await _verb(
        http_client,
        headers,
        "temperature_hint",
        lease_id=lease_id,
        args={"temperature": 0.2},
    )
    assert hinted.status_code == 200, hinted.text
    attached = await _verb(
        http_client,
        headers,
        "attach",
        lease_id=lease_id,
        args={"name": "note", "text": "inline-attachment-token"},
    )
    assert attached.status_code == 200, attached.text
    attachment_id = attached.json()["attachment"]["attachment_id"]
    fetched = await _verb(
        http_client,
        headers,
        "attach",
        lease_id=lease_id,
        args={"name": "remote", "text": "nope", "uri": "https://example.test/a"},
    )
    assert fetched.status_code == 400
    assert fetched.json()["status"] == "invalid_args"
    pushed = await _verb(
        http_client,
        headers,
        "frame_push",
        lease_id=lease_id,
        args={"name": "todo", "goal": "frame-goal-token"},
    )
    assert pushed.status_code == 200, pushed.text
    thought = await _verb(
        http_client,
        headers,
        "think",
        lease_id=lease_id,
        args={"name": "fact", "text": "thought-token"},
    )
    assert thought.status_code == 200, thought.text
    first = await _chat(http_client, headers, lease_id, extra={"stream": True})
    assert first.status_code == 200, first.text
    forwarded = seen[-1]["json"]
    contents = [message.get("content") for message in forwarded["messages"]]
    assert SECRET_APPEND in contents
    assert "Style: terse" in contents
    assert any("inline-attachment-token" in (item or "") for item in contents)
    assert any("frame-goal-token" in (item or "") for item in contents)
    assert any("thought-token" in (item or "") for item in contents)
    assert forwarded["temperature"] == 0.2
    assert forwarded["stream"] is True
    assert contents[-1] == "hi"
    explicit = await _chat(
        http_client, headers, lease_id, extra={"temperature": 0.9}
    )
    assert seen[-1]["json"]["temperature"] == 0.9
    nxt = await _verb(
        http_client,
        headers,
        "frame_next",
        lease_id=lease_id,
        args={"result": "frame-result-token", "name": "next", "goal": "next-goal-token"},
    )
    assert nxt.status_code == 200, nxt.text
    await _chat(http_client, headers, lease_id)
    preamble = "\n".join(
        message.get("content") or ""
        for message in seen[-1]["json"]["messages"]
        if message.get("role") == "system"
    )
    assert "frame-goal-token" not in preamble
    assert "frame-result-token" in preamble
    assert "next-goal-token" in preamble
    assert "thought-token" in preamble
    popped = await _verb(
        http_client,
        headers,
        "frame_pop",
        lease_id=lease_id,
        args={"result": "popped-result-token"},
    )
    assert popped.status_code == 200, popped.text
    await _chat(http_client, headers, lease_id)
    preamble = "\n".join(
        message.get("content") or ""
        for message in seen[-1]["json"]["messages"]
        if message.get("role") == "system"
    )
    assert "next-goal-token" not in preamble
    assert "popped-result-token" in preamble
    assert "thought-token" in preamble
    assert "hi" == seen[-1]["json"]["messages"][-1]["content"]
    empty = await _verb(http_client, headers, "frame_pop", lease_id=lease_id, args={})
    assert empty.status_code == 409
    assert empty.json()["status"] == "rejected"
    listed = await _verb(http_client, headers, "list_attachments", lease_id=lease_id)
    assert listed.json()["attachments"][0]["text"] == "inline-attachment-token"
    detached = await _verb(
        http_client,
        headers,
        "detach",
        lease_id=lease_id,
        args={"attachment_id": attachment_id},
    )
    assert detached.status_code == 200, detached.text
    await _chat(http_client, headers, lease_id)
    blob = json.dumps(seen[-1]["json"])
    assert "inline-attachment-token" not in blob
    logged = " ".join(record.getMessage() for record in caplog.records)
    assert SECRET_APPEND not in logged
    assert "inline-attachment-token" not in logged
    assert "thought-token" not in logged


@pytest.mark.asyncio
async def test_cache_is_private_until_shared_and_dies_at_ttl(
    http_client, app, tenant_headers, tenant_id
):
    from hypermesh_ticket import renter_key_fingerprint

    lease_id = uuid.uuid4()
    _plant(app, tenant_id, lease_id)
    app.state.ticket_cache.accept_keys(
        tenant_id,
        [renter_key_fingerprint(TEST_RENTER_KEY), renter_key_fingerprint(OTHER_KEY)],
    )
    clock = {"t": 1_000.0}
    app.state.verb_store._clock = lambda: clock["t"]
    owner = _renter(tenant_headers)
    other = _renter(tenant_headers, OTHER_KEY)
    stored = await _verb(
        http_client,
        owner,
        "cache_put",
        lease_id=lease_id,
        args={"key": "squad.note", "text": "cache-token", "ttl_s": 30},
    )
    assert stored.status_code == 200, stored.text
    hidden = await _verb(
        http_client, other, "cache_get", lease_id=lease_id, args={"key": "squad.note"}
    )
    assert hidden.status_code == 404
    assert hidden.json()["status"] == "miss"
    stolen = await _verb(
        http_client, other, "share", lease_id=lease_id, args={"key": "squad.note"}
    )
    assert stolen.status_code == 403
    shared = await _verb(
        http_client, owner, "share", lease_id=lease_id, args={"key": "squad.note"}
    )
    assert shared.status_code == 200, shared.text
    visible = await _verb(
        http_client, other, "cache_get", lease_id=lease_id, args={"key": "squad.note"}
    )
    assert visible.status_code == 200, visible.text
    assert visible.json()["text"] == "cache-token"
    await _verb(http_client, owner, "unshare", lease_id=lease_id, args={"key": "squad.note"})
    hidden_again = await _verb(
        http_client, other, "cache_get", lease_id=lease_id, args={"key": "squad.note"}
    )
    assert hidden_again.status_code == 404
    still = await _verb(
        http_client, owner, "cache_get", lease_id=lease_id, args={"key": "squad.note"}
    )
    assert still.json()["text"] == "cache-token"
    clock["t"] = 2_000.0
    expired = await _verb(
        http_client, owner, "cache_get", lease_id=lease_id, args={"key": "squad.note"}
    )
    assert expired.status_code == 404


@pytest.mark.asyncio
async def test_audit_override_is_logged_and_denied(http_client, app, tenant_headers, tenant_id, caplog):
    lease_id = uuid.uuid4()
    _plant(app, tenant_id, lease_id)
    seen: list[dict] = []
    _capture(app, seen)
    headers = _renter(tenant_headers)
    caplog.set_level(logging.INFO)
    denied = await _verb(
        http_client,
        headers,
        "audit_override_request",
        lease_id=lease_id,
        args={"reason": AUDIT_REASON},
    )
    assert denied.status_code == 403, denied.text
    body = denied.json()
    assert body["status"] == "denied"
    assert body["wired"] is True
    assert body["decision"] == "denied"
    assert body["verb"] == "audit_override_request"
    listed = await http_client.get(
        "/v1/router/audit-overrides",
        headers=headers,
        params={"lease_id": str(lease_id)},
    )
    assert listed.status_code == 200, listed.text
    assert listed.json()["overrides"][0]["reason"] == AUDIT_REASON
    assert listed.json()["overrides"][0]["decision"] == "denied"
    chat = await _chat(http_client, headers, lease_id)
    assert chat.status_code == 200, chat.text
    assert len(seen) == 1
    logged = " ".join(record.getMessage() for record in caplog.records)
    assert AUDIT_REASON not in logged
    other_tenant = uuid.uuid4()
    assert app.state.verb_store.audit_for(other_tenant) == []


@pytest.mark.asyncio
async def test_unwired_families_do_not_change_session(http_client, app, tenant_headers, tenant_id):
    lease_id = uuid.uuid4()
    _plant(app, tenant_id, lease_id)
    headers = _renter(tenant_headers)
    for verb, args in (
        ("safety_context", {"note": "payment review"}),
        ("op_class", {"op_class": "delete"}),
        ("skill_load", {"name": "pack"}),
        ("skill_unload", {"name": "pack"}),
        ("skill_list", {}),
    ):
        response = await _verb(http_client, headers, verb, lease_id=lease_id, args=args)
        assert response.status_code == 200, response.text
        assert response.json()["status"] == "not_wired"
        assert response.json()["wired"] is False
    listed = await _verb(http_client, headers, "skill_list", lease_id=lease_id)
    assert listed.json()["skills"] == []
    session = await http_client.get(
        "/v1/router/session", headers=headers, params={"lease_id": str(lease_id)}
    )
    view = session.json()
    assert view["run"] == "running"
    assert view["model_pin"] is None
    assert view["prompt"]["system_append"] == []
    assert view["frames"]["active"] == []
    assert view["frames"]["thoughts"] == []
    bad = await _verb(http_client, headers, "pause", lease_id=lease_id, args={"now": True})
    assert bad.status_code == 400
    assert bad.json()["status"] == "invalid_args"
    assert (await http_client.get(
        "/v1/router/session", headers=headers, params={"lease_id": str(lease_id)}
    )).json()["run"] == "running"


def test_verb_posture_does_not_require_the_peer(tenant_id, monkeypatch):
    from hypermesh_gateway_service.tickets import TicketCache

    monkeypatch.setenv("HYPERMESH_TICKET_HMAC_KEY", "test-plane-hypermesh-ticket-hmac")
    lease_id = uuid.uuid4()
    cache = TicketCache()

    class _App:
        class state:
            ticket_cache = cache

    _plant(_App, tenant_id, lease_id)
    claims = require_chat_posture(
        cache,
        tenant_id,
        lease_id,
        peer_up=False,
        require_peer=False,
    )
    assert claims.lease_id == lease_id
    with pytest.raises(TicketNotReady):
        require_chat_posture(
            cache,
            tenant_id,
            lease_id,
            peer_up=False,
        )


@pytest.mark.asyncio
@pytest.mark.parametrize("args", [{"clear": True}, {"remove": True, "device_id": str(FYBER_AGX_DEVICE_ID)}])
@pytest.mark.parametrize("explicit", [False, True])
async def test_excluded_only_host_can_be_restored(
    http_client, app, tenant_headers, tenant_id, args, explicit
):
    lease = uuid.uuid4()
    _plant(app, tenant_id, lease)
    headers = _renter(tenant_headers)
    assert (await _verb(http_client, headers, "exclude_host",
                       args={"device_id": str(FYBER_AGX_DEVICE_ID)})).status_code == 200
    assert (await _verb(http_client, headers, "exclude_host",
                       lease_id=lease if explicit else None, args=args)).status_code == 200
    seen = []
    _capture(app, seen)
    assert (await _chat(http_client, headers, lease)).status_code == 200
    assert len(seen) == 1


@pytest.mark.asyncio
async def test_frame_next_at_max_depth(http_client, app, tenant_headers, tenant_id):
    lease = uuid.uuid4()
    _plant(app, tenant_id, lease)
    headers = _renter(tenant_headers)
    for i in range(8):
        assert (await _verb(http_client, headers, "frame_push",
                           args={"name": str(i)})).status_code == 200
    result = await _verb(http_client, headers, "frame_next",
                         args={"name": "replacement", "result": "done"})
    assert result.status_code == 200
    assert result.json()["depth"] == 8


def test_frame_pop_overflow_restores_trimmed_history():
    from copy import deepcopy
    from hypermesh_gateway_service import verbs
    tenant, lease = uuid.uuid4(), uuid.uuid4()
    store = verbs.RouterVerbStore()
    session = store.caller(tenant, "caller")
    session.attachments["a"] = verbs._Attachment("a", "a", "text/plain", "x" * 16000)
    session.system_append = ["x" * 4096] * 8
    session.thoughts.update({str(i): "y" * 2000 for i in range(8)})
    session.frames = [verbs._Frame("f", "")]
    session.completed = [verbs._Done("n", "") for _ in range(16)]
    assert verbs._injected_size(session) <= verbs.MAX_INJECTED_CHARS
    before = deepcopy(session)
    with pytest.raises(verbs.VerbError):
        verbs._apply(next(s for s in verbs.VERB_SPECS if s.verb == "frame_pop"),
                     store, tenant_id=tenant, subject="caller", lease_id=lease,
                     cache=None, args={"result": "z" * 4096}, command_id="test")
    assert session == before


@pytest.mark.asyncio
@pytest.mark.parametrize("verb", ["pause", "drain", "cancel"])
@pytest.mark.parametrize("boundary", ["_screen", "_load_policies"])
async def test_control_accepted_during_await_prevents_host_hop(
    http_client, app, tenant_headers, tenant_id, monkeypatch, verb, boundary
):
    from hypermesh_gateway_service import routes
    lease = uuid.uuid4()
    _plant(app, tenant_id, lease)
    headers = _renter(tenant_headers)
    seen = []
    _capture(app, seen)

    async def intervene(*args, **kwargs):
        response = await _verb(http_client, headers, verb, lease_id=lease)
        assert response.status_code == 200
        return None

    monkeypatch.setattr(routes, boundary, intervene)
    response = await _chat(http_client, headers, lease)
    assert response.status_code == 409
    assert seen == []


@pytest.mark.asyncio
@pytest.mark.parametrize("state", ["paused", "draining", "cancelled"])
async def test_ir_rechecks_run_state_after_capture(
    http_client, app, tenant_headers, tenant_id, monkeypatch, state
):
    from hypermesh_gateway_service import routes
    from test_hypermesh_gateway import _ir, _signed_ticket
    lease = uuid.uuid4()
    app.state.ticket_cache.put(tenant_id, _signed_ticket(lease, purpose="ir"))
    seen = []
    _capture(app, seen)

    async def intervene(*args, **kwargs):
        app.state.verb_store.set_run(tenant_id, lease, state)
        return []

    monkeypatch.setattr(routes, "_load_policies", intervene)
    response = await http_client.post(
        "/v1/ir/chat/completions", headers=_ir(tenant_headers),
        json={"lease_id": str(lease), "messages": [{"role": "user",
              "content": "Triage this SIEM alert and list containment steps."}]},
    )
    assert response.status_code == 409
    assert seen == []


@pytest.mark.asyncio
@pytest.mark.parametrize("preference", ["use_model", "prefer_host", "affinity"])
@pytest.mark.parametrize("control,state", [("pause", "paused"), ("drain", "draining"),
                                          ("cancel", "cancelled"), ("resume", "running")])
async def test_run_control_follows_implicit_chat_route(
    http_client, app, tenant_headers, tenant_id, preference, control, state
):
    older, newer = uuid.uuid4(), uuid.uuid4()
    now = datetime.now(UTC)
    _plant(app, tenant_id, older, catalog_id="older-model",
           activated_at=now - timedelta(minutes=2))
    _plant(app, tenant_id, newer, device_id=LIVE_FYBER_AGX64_DEVICE_ID,
           catalog_id="newer-model", activated_at=now)
    headers = _renter(tenant_headers)
    args = {
        "use_model": {"model": "older-model"},
        "prefer_host": {"device_id": str(FYBER_AGX_DEVICE_ID)},
        "affinity": {"lease_id": str(older)},
    }[preference]
    assert (await _verb(http_client, headers, preference, args=args)).status_code == 200
    if control == "resume":
        assert (await _verb(http_client, headers, "pause",
                           lease_id=older)).status_code == 200
    response = await _verb(http_client, headers, control)
    assert response.status_code == 200
    assert response.json()["lease_id"] == str(older)
    assert app.state.verb_store.run_state(tenant_id, older) == state
    assert app.state.verb_store.run_state(tenant_id, newer) == "running"
    session = await http_client.get("/v1/router/session", headers=headers)
    assert session.status_code == 200
    assert session.json()["lease_id"] == str(older)
    assert session.json()["run"] == state
    seen = []
    _capture(app, seen)
    chat = await _chat(http_client, headers, None)
    assert chat.status_code == (200 if control == "resume" else 409)
    assert len(seen) == (1 if control == "resume" else 0)


@pytest.mark.asyncio
@pytest.mark.parametrize("preference,args", [
    ("exclude_host", {"device_id": str(FYBER_AGX_DEVICE_ID)}),
    ("use_model", {"model": "unavailable-model"}),
])
async def test_session_preserves_preferences_without_a_chat_route(
    http_client, app, tenant_headers, tenant_id, preference, args
):
    lease = uuid.uuid4()
    _plant(app, tenant_id, lease, catalog_id=args.get("model", "llama-3.1-8b-q4"))
    headers = _renter(tenant_headers)
    assert (await _verb(http_client, headers, preference, args=args)).status_code == 200
    if preference == "use_model":
        _plant(app, tenant_id, lease)  # The previously pinned model is no longer served.
    response = await http_client.get("/v1/router/session", headers=headers)
    assert response.status_code == 200
    view = response.json()
    assert view["lease_id"] is None
    assert view["run"] is None
    if preference == "use_model":
        assert view["model_pin"] == "unavailable-model"
    else:
        assert view["routing"]["exclude_hosts"] == [str(FYBER_AGX_DEVICE_ID)]


@pytest.mark.asyncio
async def test_jwt_router_state_uses_stable_subject(
    http_client, app, tenant_headers, tenant_id, monkeypatch
):
    from hypermesh_gateway_service import renter_auth

    lease = uuid.uuid4()
    _plant(app, tenant_id, lease)
    claims = {"iss": "test-issuer", "sub": "owner", "email": "same@example.com",
              "tenant_id": str(tenant_id)}
    monkeypatch.setattr(renter_auth, "verify_jwt_locally", lambda *a, **kw: dict(claims))
    headers = {**tenant_headers, "Authorization": "Bearer fake.signed.jwt"}
    assert (await _verb(http_client, headers, "system_append",
                        args={"text": "private-prompt"})).status_code == 200
    assert (await _verb(http_client, headers, "cache_put",
                        args={"key": "private", "text": "secret"})).status_code == 200
    claims["sub"] = "other-owner"
    session = await http_client.get("/v1/router/session", headers=headers)
    assert session.json()["prompt"]["system_append"] == []
    assert (await _verb(http_client, headers, "cache_get", args={"key": "private"})).status_code == 404
    claims["sub"] = "owner"
    claims["iss"] = "other-issuer"
    assert (await _verb(http_client, headers, "cache_get", args={"key": "private"})).status_code == 404
    claims["iss"] = "test-issuer"
    claims.pop("email")
    session = await http_client.get("/v1/router/session", headers=headers)
    assert session.json()["prompt"]["system_append"] == ["private-prompt"]
    assert (await _verb(http_client, headers, "cache_get", args={"key": "private"})).status_code == 200
    seen = []
    _capture(app, seen)
    response = await _chat(http_client, headers, lease)
    assert response.status_code == 200, response.text
    assert "private-prompt" in json.dumps(seen[0]["json"])
    claims.pop("sub")
    assert (await http_client.get("/v1/router/session", headers=headers)).status_code == 401
