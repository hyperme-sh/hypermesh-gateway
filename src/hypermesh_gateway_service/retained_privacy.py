"""Account-scoped withdrawal, deletion, and retained-history closure purge."""
import argparse
import asyncio
from contextlib import asynccontextmanager
import json
import os
from uuid import UUID, uuid4

from fastapi import APIRouter, HTTPException, Request, Response
from pydantic import BaseModel, ConfigDict, StrictBool
from sqlalchemy import text

from hypermesh_gateway_service.renter_auth import jwt_tenant_id, require_renter_grant

router = APIRouter()


def account(request):
    grant = require_renter_grant(request)
    claims = grant.claims or {}
    tenant, subject = jwt_tenant_id(grant), claims.get("sub")
    if (tenant is None or not isinstance(subject, str) or not subject.strip() or len(subject) > 512
            or subject.startswith(("apikey:", "service-account-")) or claims.get("client_credentials")
            or any(claims.get(k) for k in ("api_key_id", "key_id"))
            or any(claims.get(k) == "api_key" for k in ("panopticon_auth", "spanopticon_auth"))):
        raise HTTPException(403, "An account access token is required")
    return tenant, subject


@asynccontextmanager
async def transaction(setting, tenant, subject, lock_prefix):
    from sqlalchemy.ext.asyncio import create_async_engine
    from sqlalchemy.pool import NullPool
    from controlplane_db.session import normalize_database_url

    url = os.environ.get(setting)
    if not url:
        raise HTTPException(503, "Privacy store unavailable")
    engine = create_async_engine(normalize_database_url(url), poolclass=NullPool, hide_parameters=True)
    try:
        async with engine.begin() as db:
            args = {"tenant": tenant, "subject": subject}
            await db.execute(text("SELECT set_config('app.current_tenant_id', :tenant, true)"), {"tenant": str(tenant)})
            await db.execute(text("SELECT pg_advisory_xact_lock(hashtextextended(:key,0))"),
                             {"key": f"{lock_prefix}:{tenant}:{subject}"})
            yield db, args
    finally:
        await engine.dispose()


class Withdrawal(BaseModel):
    model_config = ConfigDict(extra="forbid")
    enabled: StrictBool


@router.put("/v1/account/training-consent")
async def withdraw(request: Request, body: Withdrawal, response: Response):
    tenant, subject = account(request)
    if body.enabled:
        raise HTTPException(409, "Training enrollment unavailable")
    async with transaction("HYPERMESH_TRAINING_DATABASE_URL", tenant, subject, "training-account") as (db, args):
        await db.execute(text("""UPDATE public.hypermesh_training_consents
            SET enabled=false, consent_at=NULL, collect_after=now(), generation=generation+1
            WHERE tenant_id=:tenant AND subject=:subject AND enabled"""), args)
    response.headers["Cache-Control"] = "no-store"
    return {"enabled": False, "consent_at": None}


@router.delete("/v1/account/training-submissions")
async def delete_submissions(request: Request, response: Response):
    tenant, subject = account(request)
    async with transaction("HYPERMESH_TRAINING_DATABASE_URL", tenant, subject, "training-account") as (db, args):
        consent = (await db.execute(text("""SELECT enabled FROM public.hypermesh_training_consents
            WHERE tenant_id=:tenant AND subject=:subject FOR UPDATE"""), args)).scalar_one_or_none()
        if consent:
            raise HTTPException(409, "Withdraw training consent before deletion")
        removed = await db.execute(text("""DELETE FROM public.hypermesh_training_submissions
            WHERE tenant_id=:tenant AND subject=:subject"""), args)
        if removed.rowcount:
            await db.execute(text("""INSERT INTO public.hypermesh_training_deletions
                (id,tenant_id,subject,actor,deleted_count,created_at)
                VALUES (:id,:tenant,:subject,:subject,:count,now())"""), {**args, "id": uuid4(), "count": removed.rowcount})
    response.headers["Cache-Control"] = "no-store"
    return {"deleted": removed.rowcount}


async def purge_closed_history(tenant, subject):
    from controlplane_tenancy.account_profile import _closure_retention
    async with transaction("HYPERMESH_HISTORY_DATABASE_URL", tenant, subject, "saved-history-account") as (db, args):
        receipt = (await db.execute(text("""SELECT purged_at,closed_at IS NOT NULL AND
            closed_at <= now()-:period AND NOT enabled AS due FROM public.hypermesh_history_preferences
            WHERE tenant_id=:tenant AND subject=:subject FOR UPDATE"""), {**args, "period": _closure_retention()})).first()
        if not receipt or not receipt.due:
            raise ValueError("Original closed history preference must be due for purge")
        removed = await db.execute(text("""DELETE FROM public.hypermesh_history_entries
            WHERE tenant_id=:tenant AND subject=:subject"""), args)
        if receipt.purged_at is None or removed.rowcount:
            await db.execute(text("""UPDATE public.hypermesh_history_preferences
                SET purged_at=coalesce(purged_at,now()),generation=generation+1
                WHERE tenant_id=:tenant AND subject=:subject"""), args)
            await db.execute(text("""INSERT INTO public.hypermesh_history_audit
                (id,tenant_id,subject,actor,action,deleted_count,created_at)
                VALUES (:id,:tenant,:subject,'history-retention','closure_purge',:count,now())"""),
                {**args, "id": uuid4(), "count": removed.rowcount})
    return {"deleted": removed.rowcount}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Purge one due account from the retained saved-history store")
    parser.add_argument("--tenant", required=True, type=UUID)
    parser.add_argument("--subject", required=True)
    args = parser.parse_args()
    print(json.dumps(asyncio.run(purge_closed_history(args.tenant, args.subject))))
