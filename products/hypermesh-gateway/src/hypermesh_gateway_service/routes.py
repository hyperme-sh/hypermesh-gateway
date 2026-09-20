"""Sibling Hypermesh router routes. Renter chat stays customer-readable."""

from __future__ import annotations

import logging
import os
import uuid
from typing import Any

from fastapi import APIRouter, HTTPException, Request, status
from pydantic import BaseModel, Field
from starlette.responses import StreamingResponse

from api.common.internal_token import internal_token_matches
from hypermesh_gateway_service.chat import ChatCompletionRequest, ProxiedChat, proxy_chat
from hypermesh_gateway_service.control_plane import ControlPlane, GatewayTunnel
from hypermesh_gateway_service.metrics import report_session_metrics
from hypermesh_gateway_service.posture import require_chat_posture
from hypermesh_gateway_service.receipts import ReceiptStore
from hypermesh_gateway_service.renter_auth import (
    RenterGrant,
    presented_renter_key,
    require_renter_grant,
    require_tenant_bound_grant,
    require_ticket_bound_grant,
)
from hypermesh_gateway_service.tenants import MARKETPLACE_TENANT_ID
from hypermesh_gateway_service.tickets import TicketCache
from hypermesh_gateway_service.wg import apply_gateway, peer_counters, peer_is_up
from hypermesh_service.ticket import (
    TicketClaims,
    TicketNotReady,
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


def _classifier(request: Request):
    """IR door only. Default chat must not call this."""

    existing = getattr(request.app.state, "classifier", None)
    if existing is not None:
        return existing
    from hypermesh_gateway_service.classify import resolve_classifier

    resolved = resolve_classifier()
    request.app.state.classifier = resolved
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
    """Apply each allocated host peer once. Skip incomplete / revoked rows."""

    applied = 0
    for tunnel in tunnels:
        if tunnel.status != "allocated" or not tunnel.server_private_key or not tunnel.peer_public_key:
            continue
        apply_gateway(
            server_private_key=tunnel.server_private_key,
            peer_public_key=tunnel.peer_public_key,
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


async def refresh_known_tenants(plane: ControlPlane, cache: TicketCache) -> None:
    """Background hop. Pull tickets, then apply pending allocated host peers.

    Chat still uses the cache if Panopticon is quiet. Apply is add-once
    (one WG peer per host); it does not drop a peer on lease_stop.
    """

    for tenant_id in cache.known_tenants():
        try:
            tunnels = await refresh_assignments(plane, cache, tenant_id)
            apply_allocated_tunnels(tunnels)
        except Exception:
            logger.info("assignment refresh skipped")


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
            async for chunk in proxied.iter_bytes():
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
    grant = require_renter_grant(request)
    tenant_id = _tenant_id(request)
    lease_id = _lease_id(request, body)
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
            tunnel_id=cached.tunnel_id if cached else None,
            lease_id=lease_id,
            bytes_in=_content_length(request) or rx,
            bytes_out=bytes_out or tx,
            handshake_count=handshakes,
        )

    return _stream_chat(proxied, after_bytes=_meter)


async def _ir_chat(request: Request, body: ChatCompletionRequest):
    """Opt-in IR door. Classify. Allow or hold. Receipt stays on this door."""

    grant = require_renter_grant(request)
    tenant_id = _tenant_id(request)
    lease_id = _lease_id(request, body)
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
    _bind_renter_to_ticket(request, grant, claims, tenant_id, cache)
    from hypermesh_gateway_service.classify import prompt_text_from_messages

    classified = _classifier(request).classify(prompt_text_from_messages(body.messages))
    logger.info(
        "ir classify decision=%s class=%s pack=%s",
        classified.decision,
        classified.prompt_class,
        classified.pack_version,
    )
    store = _receipts(request)
    if classified.decision == "hold":
        receipt = store.record(
            tenant_id=tenant_id,
            lease_id=lease_id,
            who=grant.subject,
            why="ir",
            what_left="none",
            prompt_class=classified.prompt_class,
            decision="hold",
        )
        return {"decision": "hold", "receipt": receipt.as_export()}
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
            tunnel_id=cached.tunnel_id if cached else None,
            lease_id=lease_id,
            bytes_in=_content_length(request) or rx,
            bytes_out=bytes_out or tx,
            handshake_count=handshakes,
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
