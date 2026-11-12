"""Purpose-bound closure delivery; no lease stop or host runtime mutation."""

from __future__ import annotations

import asyncio
import json
import uuid
from datetime import UTC, datetime

import httpx
from controlplane_identity.account_lifecycle import (
    authorized_call,
    require_closure_permit,
    service_secret,
    service_url,
)
from fastapi import APIRouter, HTTPException, Request, Response
from pydantic import BaseModel, ConfigDict, Field

from hypermesh_gateway_service.account_ledger import LedgerUnavailable

router = APIRouter(
    prefix="/api/v1/internal/account-lifecycle", tags=["Internal account lifecycle"]
)


class ClosureDelivery(BaseModel):
    model_config = ConfigDict(extra="forbid")
    tenant_id: uuid.UUID
    subject: str = Field(min_length=1, max_length=512)
    closed_at: datetime
    expected_gateway_id: uuid.UUID | None = None
    key_ids: list[uuid.UUID] = Field(default_factory=list, max_length=100_000)
    fingerprints: list[str] = Field(default_factory=list, max_length=100_000)
    lease_ids: list[uuid.UUID] = Field(default_factory=list, max_length=100_000)


async def verify_receiver(request: Request, body) -> None:
    """Pinned coordinator calls must reach this registered credential's receiver."""
    if body.expected_gateway_id is None:
        return  # Compatibility deliveries cannot prove roster completeness.
    control = getattr(request.app.state, "control_plane", None)
    if control is None:
        raise HTTPException(503, "Gateway identity unavailable")
    try:
        actual = await asyncio.wait_for(
            control.gateway_identity(body.tenant_id), timeout=5
        )
    except Exception:
        raise HTTPException(503, "Gateway identity unavailable") from None
    if actual != body.expected_gateway_id:
        raise HTTPException(409, "Gateway receiver identity mismatch")
    request.state.closure_gateway_id = actual


def receiver_receipt(request: Request) -> dict:
    identifier = getattr(request.state, "closure_gateway_id", None)
    return {"gateway_id": str(identifier)} if identifier is not None else {}


async def grant_snapshot(body):
    async with (
        httpx.AsyncClient(timeout=3, trust_env=False, follow_redirects=False) as client,
        client.stream(
            "POST",
            service_url("ACCOUNT_CLOSURE_GUARD_URL")
            + "/api/v1/internal/account-lifecycle/grant-scope",
            headers={
                "X-Account-Lifecycle-Token": service_secret(
                    "ACCOUNT_CLOSURE_GUARD_TOKEN"
                ),
                "X-Tenant-ID": str(body.tenant_id),
            },
            json={
                "subject": body.subject,
                "tenant_id": str(body.tenant_id),
                "closed_at": body.closed_at.isoformat(),
            },
        ) as response,
    ):
        if response.status_code != 200:
            raise RuntimeError("Grant authority unavailable")
        payload = bytearray()
        async for chunk in response.aiter_bytes():
            payload.extend(chunk)
            if len(payload) > 16 * 1024 * 1024:
                raise RuntimeError("Grant authority response exceeds limit")
    return json.loads(payload)


async def require_grant_inventory(body):
    try:
        proof = await grant_snapshot(body)
        if not isinstance(proof, dict) or proof.get("allowed") is not True:
            raise ValueError()
        if any(
            not isinstance(proof.get(name), list)
            for name in ("key_ids", "fingerprints", "lease_ids")
        ):
            raise ValueError()
        keys = {uuid.UUID(value) for value in proof["key_ids"]}
        leases = {uuid.UUID(value) for value in proof["lease_ids"]}
        fingerprints = set(proof["fingerprints"])
    except Exception:
        raise HTTPException(503, "Canonical account grants unavailable") from None
    if (
        set(body.key_ids) != keys
        or set(body.lease_ids) != leases
        or set(body.fingerprints) != fingerprints
    ):
        raise HTTPException(
            409, "Grant denial scope conflicts with original account inventory"
        )


async def personal_owner(request: Request, name: str):
    ledger = getattr(request.app.state, "account_ledger", None)
    if ledger is None:
        raise HTTPException(503, "Account owner capability evidence unavailable")
    store = getattr(request.app.state, name + "_store", None)
    try:
        if store is not None:
            await asyncio.to_thread(ledger.configure_owner, name, True)
            return store
        if await asyncio.to_thread(ledger.owner_disabled, name):
            return None
    except LedgerUnavailable:
        pass
    raise HTTPException(503, "Configured account data owner unavailable")


@router.post("/close-owner")
async def close_owner(request: Request, response: Response, body: ClosureDelivery):
    response.headers["Cache-Control"] = "no-store"
    if not authorized_call(request.headers, mutation=True):
        raise HTTPException(403, "Account lifecycle authority required")
    if (
        not body.subject.strip()
        or body.subject.startswith("apikey:")
        or body.closed_at.tzinfo is None
        or body.closed_at > datetime.now(UTC)
        or request.headers.get("X-Tenant-ID") != str(body.tenant_id)
    ):
        raise HTTPException(422, "Exact account closure scope and timestamp required")
    try:
        await require_closure_permit(
            subject=body.subject, closed_at=body.closed_at, tenant_id=body.tenant_id
        )
    except RuntimeError:
        raise HTTPException(503, "Account closure permit unavailable") from None
    await verify_receiver(request, body)
    await require_grant_inventory(body)
    ledger = getattr(request.app.state, "account_ledger", None)
    history = await personal_owner(request, "history")
    training = await personal_owner(request, "training")
    if ledger is None:
        raise HTTPException(503, "Account closure owners unavailable")
    try:
        await asyncio.to_thread(
            ledger.retire,
            body.tenant_id,
            body.subject,
            key_ids=body.key_ids,
            fingerprints=body.fingerprints,
            leases=body.lease_ids,
        )
        if history is not None:
            await history.record_closure(
                body.tenant_id, body.subject, body.closed_at, "account-lifecycle"
            )
        if training is not None:
            await training.set_consent(body.tenant_id, body.subject, False)
            await training.delete_account(
                body.tenant_id, body.subject, "account-lifecycle"
            )
    except (ValueError, LedgerUnavailable):
        raise HTTPException(
            409, "Account closure evidence conflicts or is unavailable"
        ) from None
    except Exception:
        raise HTTPException(503, "Account closure owner effect unavailable") from None
    # Acknowledgement follows durable denial + independently committed owners.
    # Retries preserve history's original time; training deletion is repeatable.
    return {
        **receiver_receipt(request),
        "denial_persisted": True,
        "history_closure_recorded": True,
        "training_deleted": True,
    }


class PrincipalDelivery(BaseModel):
    model_config = ConfigDict(extra="forbid")
    tenant_id: uuid.UUID
    subject: str = Field(min_length=1, max_length=512)
    closed_at: datetime
    expected_gateway_id: uuid.UUID | None = None


async def global_authority(request, response, body, *, tenant_id=None):
    response.headers["Cache-Control"] = "no-store"
    if not authorized_call(request.headers, mutation=True):
        raise HTTPException(403, "Account lifecycle authority required")
    if (
        not body.subject.strip()
        or body.subject.startswith("apikey:")
        or body.closed_at.tzinfo is None
        or body.closed_at > datetime.now(UTC)
        or request.headers.get("X-Tenant-ID") != str(body.tenant_id)
    ):
        raise HTTPException(422, "Exact account closure scope and timestamp required")
    try:
        await require_closure_permit(
            subject=body.subject, closed_at=body.closed_at, tenant_id=tenant_id
        )
    except RuntimeError:
        raise HTTPException(503, "Account closure permit unavailable") from None

    await verify_receiver(request, body)


@router.post("/deny-principal")
async def deny_principal(request: Request, response: Response, body: PrincipalDelivery):
    """Deliver global JWT denial without inventing tenant-owned data records."""
    await global_authority(request, response, body)
    ledger = getattr(request.app.state, "account_ledger", None)
    if ledger is None:
        raise HTTPException(503, "Account denial owner unavailable")
    try:
        await asyncio.to_thread(
            ledger.retire,
            body.tenant_id,
            body.subject,
            key_ids=[],
            fingerprints=[],
            leases=[],
        )
    except (ValueError, LedgerUnavailable):
        raise HTTPException(503, "Account denial owner unavailable") from None
    return {**receiver_receipt(request), "denial_persisted": True}


@router.post("/owner-inventory")
async def owner_inventory(
    request: Request, response: Response, body: PrincipalDelivery
):
    await global_authority(request, response, body)
    ledger = getattr(request.app.state, "account_ledger", None)
    history = await personal_owner(request, "history")
    training = await personal_owner(request, "training")
    if ledger is None:
        raise HTTPException(503, "Account data owners unavailable")
    try:
        retired = await asyncio.to_thread(
            ledger.principal_retired, body.tenant_id, body.subject
        )
    except LedgerUnavailable:
        raise HTTPException(503, "Account denial evidence unavailable") from None
    if not retired:
        raise HTTPException(409, "Principal denial must precede owner discovery")
    try:
        saved = (
            await history.lifecycle_status(body.tenant_id, body.subject)
            if history is not None
            else {"present": False, "entries": 0, "disabled": True}
        )
        consent = (
            await training.lifecycle_status(body.tenant_id, body.subject)
            if training is not None
            else {"present": False, "entries": 0, "disabled": True}
        )
    except Exception:
        raise HTTPException(503, "Account data owner inventory unavailable") from None
    return {
        **receiver_receipt(request),
        "capabilities": {
            "history": "configured" if history is not None else "disabled",
            "training": "configured" if training is not None else "disabled",
        },
        "has_resources": saved["present"] or consent["present"],
        "history": saved,
        "training": consent,
    }


@router.post("/purge-owner")
async def purge_owner(request: Request, response: Response, body: PrincipalDelivery):
    from controlplane_identity.account_lifecycle import closure_scope

    await global_authority(request, response, body)
    ledger = getattr(request.app.state, "account_ledger", None)
    history = await personal_owner(request, "history")
    training = await personal_owner(request, "training")
    if ledger is None:
        raise HTTPException(503, "Account data owners unavailable")
    try:
        proof = await closure_scope(
            subject=body.subject, closed_at=body.closed_at, tenant_id=body.tenant_id
        )
        retired = await asyncio.to_thread(
            ledger.principal_retired, body.tenant_id, body.subject
        )
    except (RuntimeError, LedgerUnavailable):
        raise HTTPException(503, "Account erasure authority unavailable") from None
    if not proof["erasure_allowed"] or not retired:
        raise HTTPException(409, "Account erasure is not yet authorized")
    try:
        saved = (
            await history.purge_account(body.tenant_id, body.subject, body.closed_at)
            if history is not None
            else {"deleted": 0, "remaining": 0, "disabled": True}
        )
        consent = (
            await training.purge_account(body.tenant_id, body.subject)
            if training is not None
            else {"deleted": 0, "remaining": 0, "disabled": True}
        )
    except ValueError:
        raise HTTPException(
            409, "Original owner closure and retention boundary required"
        ) from None
    except Exception:
        raise HTTPException(503, "Account erasure owner unavailable") from None
    return {
        **receiver_receipt(request),
        "history": saved,
        "training": consent,
        "erasure_complete": True,
    }


@router.post("/deny-grants")
async def deny_grants(request: Request, response: Response, body: ClosureDelivery):
    """Persist only the closing account's canonical grants in its tenant."""
    await global_authority(request, response, body, tenant_id=body.tenant_id)
    await require_grant_inventory(body)
    ledger = getattr(request.app.state, "account_ledger", None)
    if ledger is None:
        raise HTTPException(503, "Account denial owner unavailable")
    try:
        await asyncio.to_thread(
            ledger.retire,
            body.tenant_id,
            body.subject,
            key_ids=body.key_ids,
            fingerprints=body.fingerprints,
            leases=body.lease_ids,
        )
    except (ValueError, LedgerUnavailable):
        raise HTTPException(503, "Account denial owner unavailable") from None
    return {**receiver_receipt(request), "denial_persisted": True}
