"""Sibling Hypermesh router routes. Renter chat stays customer-readable."""

from __future__ import annotations

import logging
import os
import uuid
from typing import Any

from fastapi import APIRouter, HTTPException, Request, status
from pydantic import BaseModel, Field
from starlette.responses import JSONResponse, StreamingResponse

from api.common.internal_token import internal_token_matches
from hypermesh_gateway_service.chat import (
    ChatCompletionRequest,
    ProxiedChat,
    iter_chat_bytes,
    proxy_chat,
)
from hypermesh_gateway_service.errors import (
    INVALID_API_KEY_MESSAGE,
    LEASE_NOT_OWNED_MESSAGE,
    TENANT_MISMATCH_MESSAGE,
    DoorError,
    model_not_found_message,
    no_active_lease_message,
)
from hypermesh_gateway_service.control_plane import ControlPlane, GatewayTunnel
from hypermesh_gateway_service.inbox import (
    ApprovalInbox,
    InboxUnavailable,
    InboxView,
    resolve_approval_inbox,
)
from hypermesh_gateway_service.policy import (
    PolicyView,
    decide_policy,
    policy_needs_classify,
)
from hypermesh_gateway_service.metrics import (
    MeterQueue,
    flush_meter_queue,
    report_session_metrics,
)
from hypermesh_gateway_service.quota import ChatQuota, QuotaExceeded, resolve_chat_quota
from hypermesh_gateway_service.posture import require_chat_posture
from hypermesh_gateway_service.receipts import ReceiptStore
from hypermesh_gateway_service.renter_auth import (
    RenterGrant,
    confirm_api_key_live,
    jwt_tenant_id,
    presented_renter_key,
    require_auditor_grant,
    require_renter_grant,
    require_tenant_bound_grant,
    require_ticket_bound_grant,
)
from hypermesh_gateway_service.route_resolve import (
    KeyPolicy,
    LeaseNotOwned,
    ModelNotFound,
    TenantOwnedKeyPolicy,
    catalog_ids,
    resolve_route,
)
from hypermesh_gateway_service.tenants import MARKETPLACE_TENANT_ID
from hypermesh_gateway_service.tickets import TicketCache
from hypermesh_gateway_service.wg import apply_gateway, peer_counters, peer_is_up, remove_peer
from hypermesh_service.ticket import (
    IR_CHAT_PURPOSES,
    RENTER_CHAT_PURPOSES,
    TicketClaims,
    TicketNotReady,
    renter_key_fingerprint,
    require_ir_chat_purpose,
    require_renter_chat_purpose,
    require_ticket_tenant,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/hypermesh-gateway", tags=["hypermesh-gateway"])
openai_router = APIRouter(tags=["hypermesh-gateway-chat"])


def _control(request: Request) -> ControlPlane:
    return request.app.state.control_plane


def _tickets(request: Request) -> TicketCache:
    cache = getattr(request.app.state, "ticket_cache", None)
    if cache is None:
        cache = TicketCache()
        request.app.state.ticket_cache = cache
    return cache


def _receipts(request: Request) -> ReceiptStore:
    store = getattr(request.app.state, "receipt_store", None)
    if store is None:
        store = ReceiptStore()
        request.app.state.receipt_store = store
    return store


def _meters(request: Request) -> MeterQueue:
    queue = getattr(request.app.state, "meter_queue", None)
    if queue is None:
        queue = MeterQueue()
        request.app.state.meter_queue = queue
    return queue


def _quota(request: Request) -> ChatQuota:
    quota = getattr(request.app.state, "chat_quota", None)
    if quota is None:
        quota = resolve_chat_quota()
        request.app.state.chat_quota = quota
    return quota


def _require_door_capacity(request: Request, lease_id: uuid.UUID) -> None:
    """Refuse before the host hop when this door cannot bill or is over ceiling."""

    if _meters(request).is_full():
        raise HTTPException(status_code=429, detail="usage queue is full")
    try:
        _quota(request).allow(lease_id, incoming_bytes=_content_length(request))
    except QuotaExceeded as exc:
        raise HTTPException(status_code=429, detail=exc.detail) from exc


def _classifier(request: Request):
    """IR door only. Default chat must not call this."""

    existing = getattr(request.app.state, "classifier", None)
    if existing is not None:
        return existing
    from hypermesh_gateway_service.classify import resolve_classifier

    resolved = resolve_classifier()
    request.app.state.classifier = resolved
    return resolved


def _inbox(request: Request) -> ApprovalInbox:
    existing = getattr(request.app.state, "approval_inbox", None)
    if existing is not None:
        return existing
    resolved = resolve_approval_inbox()
    request.app.state.approval_inbox = resolved
    return resolved


def seed_watched_tenants(cache: TicketCache) -> None:
    """Watch the marketplace tenant (and optional HYPERMESH_TENANT_IDS) on boot.

    Refresh only iterates known tenants. Without a seed, a cold cache never
    pulls GET /router/tunnels, so allocated host peers sit until a human
    POST /tunnels/apply.
    """

    raw = os.environ.get("HYPERMESH_TENANT_IDS", str(MARKETPLACE_TENANT_ID))
    for part in raw.split(","):
        part = part.strip()
        if not part:
            continue
        try:
            cache.watch(uuid.UUID(part))
        except ValueError:
            logger.info("watch tenant skipped")


def apply_allocated_tunnels(tunnels: list[GatewayTunnel]) -> int:
    """Apply each allocated host peer. Drop a peer only when no live tunnel keeps it.

    A standing wg-hm iface still gets the peer. Lease end does not revoke the
    tunnel, so this does not drop a peer on lease_start or lease_stop.
    """

    live = {
        tunnel.peer_public_key
        for tunnel in tunnels
        if tunnel.status == "allocated"
        and tunnel.server_private_key
        and tunnel.peer_public_key
    }
    for tunnel in tunnels:
        key = tunnel.peer_public_key
        if tunnel.status == "revoked" and key and key not in live:
            remove_peer(key)
    applied = 0
    seen: set[str] = set()
    for tunnel in tunnels:
        key = tunnel.peer_public_key
        if (
            tunnel.status != "allocated"
            or not tunnel.server_private_key
            or not key
            or key in seen
        ):
            continue
        seen.add(key)
        apply_gateway(
            server_private_key=tunnel.server_private_key,
            peer_public_key=key,
            client_address=tunnel.client_address,
        )
        applied += 1
    return applied


async def refresh_assignments(
    plane: ControlPlane,
    cache: TicketCache,
    tenant_id: uuid.UUID,
) -> list[GatewayTunnel]:
    """hm_gw_ pull. Updates revoke / Path B cache. Does not flap the host peer."""

    tunnels = await plane.list_tunnels(tenant_id)
    pull = await plane.list_tickets(tenant_id)
    cache.replace_from_pull(tenant_id, pull, tunnels=tunnels)
    return tunnels


async def refresh_known_tenants(
    plane: ControlPlane,
    cache: TicketCache,
    queue: MeterQueue | None = None,
) -> None:
    """Background hop. Pull tickets, then apply pending allocated host peers.

    Chat still uses the cache if Panopticon is quiet. Apply is add-once
    (one WG peer per host); it does not drop a peer on lease_stop.
    A quiet plane still retries queued usage on this hop.
    """

    list_index = getattr(plane, "list_key_index", None)
    if list_index is not None:
        try:
            entries = await list_index()
            cache.note_key_index(
                (entry.tenant_id, entry.fingerprint, entry.kind) for entry in entries
            )
        except Exception:
            logger.info("key index refresh skipped")
    for tenant_id in cache.known_tenants():
        try:
            tunnels = await refresh_assignments(plane, cache, tenant_id)
            apply_allocated_tunnels(tunnels)
        except Exception:
            logger.info("assignment refresh skipped")
    if queue is not None:
        await flush_meter_queue(plane, queue)


async def _pull_assignments(request: Request, tenant_id: uuid.UUID) -> list[GatewayTunnel]:
    return await refresh_assignments(_control(request), _tickets(request), tenant_id)


def _peer_is_up(request: Request, peer_public_key: str | None) -> bool:
    override = getattr(request.app.state, "peer_up", None)
    if override is not None:
        if callable(override):
            return bool(override(peer_public_key))
        return bool(override)
    return peer_is_up(peer_public_key)


def _content_length(request: Request) -> int:
    raw = request.headers.get("content-length")
    if raw and raw.isdigit():
        return int(raw)
    return 0


def _stream_chat(
    proxied: ProxiedChat,
    *,
    after_bytes: Any | None = None,
) -> StreamingResponse:
    """Pass host bytes through. Do not parse or buffer the completion."""

    async def chunks():
        try:
            async for chunk in iter_chat_bytes(proxied):
                yield chunk
        finally:
            if after_bytes is not None:
                await after_bytes(proxied.bytes_out)

    return StreamingResponse(
        chunks(),
        media_type=proxied.media_type,
        headers={"x-accel-buffering": "no"},
    )


def _require_service_cred(request: Request) -> str:
    expected = os.environ.get("HYPERMESH_GATEWAY_SERVICE_SECRET", "").strip()
    override = getattr(request.app.state, "gateway_service_secret", None)
    if override is not None:
        expected = str(override)
    raw = request.headers.get("Authorization")
    if not raw:
        raise HTTPException(status_code=401, detail="Gateway service credential required")
    scheme, _, token = raw.partition(" ")
    if scheme.lower() != "bearer" or not token.strip():
        raise HTTPException(status_code=401, detail="Gateway service credential required")
    # Constant time: these routes are reachable on the public chat host.
    if not internal_token_matches(token.strip(), expected):
        raise HTTPException(status_code=401, detail="Invalid gateway service credential")
    return token.strip()


def _tenant_id(request: Request) -> uuid.UUID:
    raw = request.headers.get("X-Tenant-ID")
    if not raw:
        raise HTTPException(status_code=400, detail="X-Tenant-ID header is required")
    try:
        return uuid.UUID(str(raw))
    except ValueError as exc:
        raise HTTPException(status_code=400, detail="Invalid X-Tenant-ID") from exc


def _bind_renter_to_ticket(
    request: Request,
    grant: RenterGrant,
    claims: TicketClaims,
    tenant_id: uuid.UUID,
    cache: TicketCache,
) -> None:
    require_ticket_tenant(claims, tenant_id)
    require_ticket_bound_grant(
        grant,
        ticket_tenant_id=claims.tenant_id or tenant_id,
        key_fingerprints=cache.key_fingerprints(tenant_id),
        presented_key=presented_renter_key(request) if grant.kind == "api_key" else None,
    )


def _bind_auditor_to_ticket(
    request: Request,
    grant: RenterGrant,
    claims: TicketClaims,
    tenant_id: uuid.UUID,
    cache: TicketCache,
) -> None:
    """IR classify binds an AIuditor key, never the renter fingerprint set."""

    require_ticket_tenant(claims, tenant_id)
    require_ticket_bound_grant(
        grant,
        ticket_tenant_id=claims.tenant_id or tenant_id,
        key_fingerprints=cache.ir_key_fingerprints(tenant_id),
        presented_key=presented_renter_key(request) if grant.kind == "api_key" else None,
    )


def _lease_id(request: Request, body: ChatCompletionRequest) -> uuid.UUID:
    header = request.headers.get("X-Hypermesh-Lease-Id") or request.headers.get("X-Lease-Id")
    if body.lease_id is not None:
        return body.lease_id
    if header:
        try:
            return uuid.UUID(header)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail="Invalid lease id") from exc
    raise HTTPException(status_code=400, detail="lease_id is required")


def _optional_lease_id(request: Request, body: ChatCompletionRequest) -> uuid.UUID | None:
    if body.lease_id is None and not (
        request.headers.get("X-Hypermesh-Lease-Id") or request.headers.get("X-Lease-Id")
    ):
        return None
    return _lease_id(request, body)


def _optional_tenant_header(request: Request) -> uuid.UUID | None:
    raw = request.headers.get("X-Tenant-ID")
    if not raw:
        return None
    try:
        return uuid.UUID(str(raw))
    except ValueError as exc:
        raise HTTPException(status_code=400, detail="Invalid X-Tenant-ID") from exc


def _key_policy(request: Request) -> KeyPolicy:
    policy = getattr(request.app.state, "key_policy", None)
    if policy is None:
        policy = TenantOwnedKeyPolicy()
        request.app.state.key_policy = policy
    return policy


def _note_index(cache: TicketCache, entries: list[Any]) -> None:
    cache.note_key_index(
        (entry.tenant_id, entry.fingerprint, getattr(entry, "kind", "renter"))
        for entry in entries
    )


def _cached_key_tenant(cache: TicketCache, fingerprint: str, *, ir: bool) -> uuid.UUID | None:
    """Tenant that published this fingerprint.

    The IR door still recognizes a renter fingerprint so a renter-purpose
    ticket fails posture (409) before the IR fingerprint bind (401). An IR
    key that is only in the IR index resolves on the first lookup.
    """

    found = cache.tenant_for_fingerprint(fingerprint, ir=ir)
    if found is not None or not ir:
        return found
    return cache.tenant_for_fingerprint(fingerprint, ir=False)


async def _tenant_from_api_key(request: Request, raw_key: str, *, ir: bool) -> uuid.UUID:
    """Fingerprint to tenant. One-shot index pull when the cache has never seen it."""

    fingerprint = renter_key_fingerprint(raw_key)
    cache = _tickets(request)
    found = _cached_key_tenant(cache, fingerprint, ir=ir)
    if found is not None:
        return found
    plane = _control(request)
    list_index = getattr(plane, "list_key_index", None)
    entries: list[Any] = []
    if list_index is not None:
        try:
            entries = list(await list_index())
        except Exception:
            logger.info("key index refresh skipped")
            entries = []
    _note_index(cache, entries)
    hinted = _cached_key_tenant(cache, fingerprint, ir=ir)
    if hinted is None:
        raise DoorError(401, INVALID_API_KEY_MESSAGE, "invalid_api_key")
    try:
        await refresh_assignments(plane, cache, hinted)
    except Exception:
        logger.info("key tenant refresh skipped")
    found = _cached_key_tenant(cache, fingerprint, ir=ir)
    if found is None:
        raise DoorError(401, INVALID_API_KEY_MESSAGE, "invalid_api_key")
    return found


async def _report_key_use(request: Request, key_id: uuid.UUID | None) -> None:
    """At most one last_used write per key per minute. Failures do not fail chat."""

    if key_id is None:
        return
    import time

    now = time.monotonic()
    recent = getattr(request.app.state, "key_touch_at", None)
    if recent is None:
        recent = {}
        request.app.state.key_touch_at = recent
    if now < recent.get(key_id, 0.0):
        return
    recent[key_id] = now + 60.0
    hook = getattr(request.app.state, "key_toucher", None)
    if hook is not None:
        try:
            await hook(key_id)
        except Exception:
            logger.info("key touch skipped")
        return
    from api.core.config import settings

    token = settings.usable_api_keys_internal_token()
    base = os.environ.get("HYPERMESH_API_KEYS_URL", "").strip()
    if not token or not base:
        return
    try:
        import httpx

        async with httpx.AsyncClient(timeout=2.0) as client:
            await client.post(
                f"{base.rstrip('/')}/api/v1/internal/touch",
                headers={"X-Internal-Token": token},
                json={"key_id": str(key_id)},
            )
    except Exception:
        logger.info("key touch skipped")


async def _authorize_caller(
    request: Request, *, ir: bool
) -> tuple[RenterGrant, uuid.UUID, str | None]:
    if ir:
        grant = require_auditor_grant(request, bind_tenant_header=False)
    else:
        grant = require_renter_grant(request, bind_tenant_header=False)
    raw_key = presented_renter_key(request) if grant.kind == "api_key" else None
    if grant.kind == "api_key":
        if not raw_key:
            raise DoorError(401, INVALID_API_KEY_MESSAGE, "invalid_api_key")
        tenant_id = await _tenant_from_api_key(request, raw_key, ir=ir)
        header_tenant = _optional_tenant_header(request)
        if header_tenant is not None and header_tenant != tenant_id:
            raise DoorError(403, TENANT_MISMATCH_MESSAGE, "tenant_mismatch")
        key_id = await confirm_api_key_live(
            request,
            tenant_id=tenant_id,
            raw_key=raw_key,
            fingerprint=renter_key_fingerprint(raw_key),
            cache=_tickets(request),
        )
        await _report_key_use(request, key_id)
        return grant, tenant_id, raw_key
    tenant_id = jwt_tenant_id(grant)
    if tenant_id is None:
        raise DoorError(401, INVALID_API_KEY_MESSAGE, "invalid_api_key")
    header_tenant = _optional_tenant_header(request)
    if header_tenant is not None and header_tenant != tenant_id:
        raise DoorError(403, TENANT_MISMATCH_MESSAGE, "tenant_mismatch")
    return grant, tenant_id, None


async def _open_door(
    request: Request, body: ChatCompletionRequest, *, ir: bool
) -> tuple[RenterGrant, uuid.UUID, uuid.UUID]:
    grant, tenant_id, raw_key = await _authorize_caller(request, ir=ir)
    purposes = IR_CHAT_PURPOSES if ir else RENTER_CHAT_PURPOSES
    requested_lease_id = _optional_lease_id(request, body)
    try:
        lease = resolve_route(
            _tickets(request),
            key=raw_key,
            tenant_id=tenant_id,
            requested_model=body.model,
            requested_lease_id=requested_lease_id,
            purposes=purposes,
            policy=_key_policy(request),
        )
    except LeaseNotOwned as exc:
        # A lease this tenant already revoked is not ready (409 via posture).
        # A lease the cache has never held is not owned by the key.
        if (
            requested_lease_id is not None
            and requested_lease_id in _tickets(request).revoked_lease_ids(tenant_id)
        ):
            return grant, tenant_id, requested_lease_id
        raise DoorError(403, LEASE_NOT_OWNED_MESSAGE, "lease_not_owned") from exc
    except ModelNotFound as exc:
        raise DoorError(
            404,
            model_not_found_message(exc.requested, exc.available),
            "model_not_found",
        ) from exc
    if lease is None:
        raise DoorError(402, no_active_lease_message(), "no_active_lease")
    return grant, tenant_id, lease.lease_id


def _models_body(request: Request, tenant_id: uuid.UUID, raw_key: str | None) -> dict[str, Any]:
    candidates = _key_policy(request).candidate_leases(
        _tickets(request),
        tenant_id,
        key=raw_key,
        purposes=RENTER_CHAT_PURPOSES,
    )
    return {
        "object": "list",
        "data": [
            {"id": catalog_id, "object": "model", "owned_by": "hypermesh"}
            for catalog_id in catalog_ids(candidates)
        ],
    }


async def _list_models(request: Request) -> dict[str, Any]:
    """Catalog ids of the key's active leases. No lease is an empty 200 list."""

    _grant, tenant_id, raw_key = await _authorize_caller(request, ir=False)
    return _models_body(request, tenant_id, raw_key)


@router.get("/ready")
async def ready(request: Request) -> dict[str, str]:
    _require_service_cred(request)
    return {"status": "ready"}


@router.get("/tunnels")
async def list_tunnels(request: Request) -> list[dict[str, Any]]:
    _require_service_cred(request)
    tenant_id = _tenant_id(request)
    tunnels = await _pull_assignments(request, tenant_id)
    return [
        {
            "tunnel_id": str(t.tunnel_id),
            "lease_id": str(t.lease_id),
            "status": t.status,
            "endpoint": t.endpoint,
            "client_address": t.client_address,
        }
        for t in tunnels
    ]


@router.post("/tunnels/apply")
async def apply_assigned_tunnels(request: Request) -> dict[str, int]:
    _require_service_cred(request)
    tenant_id = _tenant_id(request)
    applied = apply_allocated_tunnels(await _pull_assignments(request, tenant_id))
    return {"applied": applied}


class MetricsBody(BaseModel):
    tunnel_id: uuid.UUID | None = None
    lease_id: uuid.UUID | None = None
    bytes_in: int = Field(default=0, ge=0)
    bytes_out: int = Field(default=0, ge=0)
    handshake_count: int = Field(default=0, ge=0)


@router.post("/metrics", status_code=status.HTTP_201_CREATED)
async def post_metrics(request: Request, body: MetricsBody) -> dict[str, str]:
    _require_service_cred(request)
    tenant_id = _tenant_id(request)
    await _control(request).post_metrics(
        tenant_id,
        tunnel_id=body.tunnel_id,
        lease_id=body.lease_id,
        bytes_in=body.bytes_in,
        bytes_out=body.bytes_out,
        handshake_count=body.handshake_count,
    )
    return {"status": "recorded"}


async def _chat(request: Request, body: ChatCompletionRequest) -> StreamingResponse:
    grant, tenant_id, lease_id = await _open_door(request, body, ir=False)
    cache = _tickets(request)
    cached = cache.get(tenant_id, lease_id)
    peer_key = cached.peer_public_key if cached else None
    try:
        claims = require_chat_posture(
            cache,
            tenant_id,
            lease_id,
            peer_up=_peer_is_up(request, peer_key),
        )
        require_renter_chat_purpose(claims)
    except TicketNotReady as exc:
        raise HTTPException(status_code=exc.status_code, detail=exc.detail) from exc
    _bind_renter_to_ticket(request, grant, claims, tenant_id, cache)
    _require_door_capacity(request, lease_id)
    purpose = claims.purpose
    policies = await _load_policies(request, tenant_id, purpose=purpose)
    if policies:
        from hypermesh_gateway_service.classify import prompt_text_from_messages

        prompt_class = None
        taxonomy = "allow"
        if policy_needs_classify(policies):
            classified = _classifier(request).classify(
                prompt_text_from_messages(body.messages)
            )
            prompt_class = classified.prompt_class
            taxonomy = classified.decision
        decision = decide_policy(
            purpose, policies, prompt_class=prompt_class, taxonomy_decision=taxonomy
        )
        if decision == "deny":
            return _policy_deny(
                request,
                tenant_id=tenant_id,
                lease_id=lease_id,
                who=grant.subject,
                prompt_class=prompt_class or "unclassified",
                why=purpose,
            )
        if decision == "hold":
            gated = await _hold_or_resume(
                request,
                tenant_id=tenant_id,
                lease_id=lease_id,
                who=grant.subject,
                prompt_class=prompt_class or "unclassified",
                purpose=purpose,
                why=purpose,
            )
            if gated is not None:
                return gated
    runtime = getattr(request.app.state, "runtime_client", None)
    proxied = await proxy_chat(
        lease_id=lease_id,
        payload=body.model_dump(mode="json"),
        client_address=claims.client_address,
        runtime_client=runtime,
    )
    rx, tx, handshakes = peer_counters(peer_key or "")

    async def _meter(bytes_out: int) -> None:
        await report_session_metrics(
            _control(request),
            tenant_id,
            _meters(request),
            tunnel_id=cached.tunnel_id if cached else None,
            lease_id=lease_id,
            bytes_in=_content_length(request) or rx,
            bytes_out=bytes_out or tx,
            handshake_count=handshakes,
            quota=_quota(request),
        )

    return _stream_chat(proxied, after_bytes=_meter)


def _inbox_outcome(view: InboxView | None) -> str:
    """allow, deny, or hold. Consumed allow_once is a new ask."""

    if view is None:
        return "hold"
    if view.status == "allowed" and view.decision == "allow_session":
        return "allow"
    if (
        view.status == "allowed"
        and view.decision == "allow_once"
        and not view.consumed
    ):
        return "allow"
    if view.status in {"denied", "timed_out"}:
        return "deny"
    return "hold"


async def _load_policies(
    request: Request, tenant_id: uuid.UUID, *, purpose: str
) -> list[PolicyView]:
    try:
        return await _inbox(request).policies(tenant_id, purpose=purpose)
    except InboxUnavailable:
        return []


def _policy_deny(
    request: Request,
    *,
    tenant_id: uuid.UUID,
    lease_id: uuid.UUID,
    who: str,
    prompt_class: str,
    why: str,
) -> JSONResponse:
    receipt = _receipts(request).record(
        tenant_id=tenant_id,
        lease_id=lease_id,
        who=who,
        why=why,
        what_left="none",
        prompt_class=prompt_class,
        decision="deny",
    )
    return JSONResponse(
        status_code=409,
        content={"decision": "deny", "receipt": receipt.as_export()},
    )


async def _hold_or_resume(
    request: Request,
    *,
    tenant_id: uuid.UUID,
    lease_id: uuid.UUID,
    who: str,
    prompt_class: str,
    purpose: str,
    why: str,
) -> dict[str, object] | JSONResponse | None:
    """Hold/deny from the inbox. None means resume (proxy)."""

    inbox = _inbox(request)
    store = _receipts(request)
    view: InboxView | None = None
    try:
        view = await inbox.latest(
            tenant_id,
            lease_id=lease_id,
            who=who,
            prompt_class=prompt_class,
        )
    except InboxUnavailable:
        view = None
    outcome = _inbox_outcome(view)
    if outcome == "allow" and view is not None and view.decision == "allow_once":
        try:
            view = await inbox.consume(tenant_id, view.id)
        except InboxUnavailable:
            outcome = "hold"
    if outcome == "allow":
        return None
    if outcome == "deny":
        receipt = store.record(
            tenant_id=tenant_id,
            lease_id=lease_id,
            who=who,
            why=why,
            what_left="none",
            prompt_class=prompt_class,
            decision="deny",
        )
        body_out: dict[str, object] = {
            "decision": "deny",
            "receipt": receipt.as_export(),
        }
        if view is not None:
            body_out["approval_id"] = str(view.id)
        return JSONResponse(status_code=409, content=body_out)
    if view is None or view.status != "held":
        try:
            view = await inbox.hold(
                tenant_id,
                lease_id=lease_id,
                who=who,
                prompt_class=prompt_class,
                purpose=purpose,
            )
        except InboxUnavailable:
            view = None
    receipt = store.record(
        tenant_id=tenant_id,
        lease_id=lease_id,
        who=who,
        why=why,
        what_left="none",
        prompt_class=prompt_class,
        decision="hold",
    )
    held: dict[str, object] = {"decision": "hold", "receipt": receipt.as_export()}
    if view is not None:
        held["approval_id"] = str(view.id)
    return held


async def _ir_chat(request: Request, body: ChatCompletionRequest):
    """Opt-in IR door. Classify, then org policy, then inbox."""

    grant, tenant_id, lease_id = await _open_door(request, body, ir=True)
    cache = _tickets(request)
    cached = cache.get(tenant_id, lease_id)
    peer_key = cached.peer_public_key if cached else None
    try:
        claims = require_chat_posture(
            cache,
            tenant_id,
            lease_id,
            peer_up=_peer_is_up(request, peer_key),
        )
        require_ir_chat_purpose(claims)
    except TicketNotReady as exc:
        raise HTTPException(status_code=exc.status_code, detail=exc.detail) from exc
    _bind_auditor_to_ticket(request, grant, claims, tenant_id, cache)
    _require_door_capacity(request, lease_id)
    from hypermesh_gateway_service.classify import prompt_text_from_messages

    classified = _classifier(request).classify(prompt_text_from_messages(body.messages))
    logger.info(
        "ir classify decision=%s class=%s pack=%s",
        classified.decision,
        classified.prompt_class,
        classified.pack_version,
    )
    store = _receipts(request)
    policies = await _load_policies(request, tenant_id, purpose="ir")
    decision = decide_policy(
        "ir",
        policies,
        prompt_class=classified.prompt_class,
        taxonomy_decision=classified.decision,
    )
    if decision == "deny":
        return _policy_deny(
            request,
            tenant_id=tenant_id,
            lease_id=lease_id,
            who=grant.subject,
            prompt_class=classified.prompt_class,
            why="ir",
        )
    if decision == "hold":
        gated = await _hold_or_resume(
            request,
            tenant_id=tenant_id,
            lease_id=lease_id,
            who=grant.subject,
            prompt_class=classified.prompt_class,
            purpose="ir",
            why="ir",
        )
        if gated is not None:
            return gated
    runtime = getattr(request.app.state, "runtime_client", None)
    try:
        proxied = await proxy_chat(
            lease_id=lease_id,
            payload=body.model_dump(mode="json"),
            client_address=claims.client_address,
            runtime_client=runtime,
        )
    except HTTPException:
        store.record(
            tenant_id=tenant_id,
            lease_id=lease_id,
            who=grant.subject,
            why="ir",
            what_left="none",
            prompt_class=classified.prompt_class,
            decision="allow",
        )
        raise
    store.record(
        tenant_id=tenant_id,
        lease_id=lease_id,
        who=grant.subject,
        why="ir",
        what_left="completion",
        prompt_class=classified.prompt_class,
        decision="allow",
    )
    rx, tx, handshakes = peer_counters(peer_key or "")

    async def _meter(bytes_out: int) -> None:
        await report_session_metrics(
            _control(request),
            tenant_id,
            _meters(request),
            tunnel_id=cached.tunnel_id if cached else None,
            lease_id=lease_id,
            bytes_in=_content_length(request) or rx,
            bytes_out=bytes_out or tx,
            handshake_count=handshakes,
            quota=_quota(request),
        )

    return _stream_chat(proxied, after_bytes=_meter)


async def _export_receipts(request: Request) -> dict[str, Any]:
    """Tenant-wide history, so the credential must prove the tenant.

    require_renter_grant alone is format-only and the tenant arrives in a
    header, which together would hand any caller another tenant's receipts.
    A tenant-bound credential is the whole guard: this history spans every
    lease, so there is no single ticket to hold against it.
    """

    tenant_id = _tenant_id(request)
    await require_tenant_bound_grant(request, tenant_id)
    return {"receipts": _receipts(request).export_for(tenant_id)}


@router.get("/v1/models")
async def sibling_models(request: Request) -> dict[str, Any]:
    return await _list_models(request)


@openai_router.get("/v1/models")
async def openai_models(request: Request) -> dict[str, Any]:
    return await _list_models(request)


@router.post("/v1/chat/completions")
async def sibling_chat(request: Request, body: ChatCompletionRequest):
    return await _chat(request, body)


@openai_router.post("/v1/chat/completions")
async def openai_chat(request: Request, body: ChatCompletionRequest):
    return await _chat(request, body)


@router.post("/v1/ir/chat/completions")
async def sibling_ir_chat(request: Request, body: ChatCompletionRequest):
    return await _ir_chat(request, body)


@openai_router.post("/v1/ir/chat/completions")
async def openai_ir_chat(request: Request, body: ChatCompletionRequest):
    return await _ir_chat(request, body)


@router.get("/v1/ir/receipts")
async def sibling_ir_receipts(request: Request) -> dict[str, Any]:
    return await _export_receipts(request)


@openai_router.get("/v1/ir/receipts")
async def openai_ir_receipts(request: Request) -> dict[str, Any]:
    return await _export_receipts(request)
