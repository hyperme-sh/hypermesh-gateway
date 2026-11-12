"""Retained account data owner; no enrollment or payload collection."""
from contextlib import asynccontextmanager
from datetime import UTC, datetime
import uuid
from fastapi import HTTPException
from sqlalchemy import delete, func, select, text
from sqlalchemy.dialects.postgresql import insert
from controlplane_tenancy.account_profile import _closure_retention
from hypermesh_gateway_service.models import HistoryPreference, HistoryEntry, HistoryAudit, TrainingConsent, TrainingSubmission, TrainingDeletion

class TrainingStore:
    def __init__(self, maker, account_ledger=None):
        self.maker = maker
        self.account_ledger = account_ledger


    @asynccontextmanager
    async def transaction(self, tenant):
        async with self.maker.begin() as session:
            await session.execute(text("SELECT set_config('app.current_tenant_id', :t, true)"), {'t':str(tenant)})
            yield session


    async def locked(self, session, tenant, subject):
        await self.account_lock(session,tenant,subject)
        await session.execute(insert(TrainingConsent).values(tenant_id=tenant, subject=subject,
            enabled=False, generation=0).on_conflict_do_nothing())
        return (await session.execute(select(TrainingConsent).where(
            TrainingConsent.tenant_id==tenant, TrainingConsent.subject==subject).with_for_update())).scalar_one()


    async def account_lock(self,session,tenant,subject):
        await session.execute(text("SELECT pg_advisory_xact_lock(hashtextextended(:key,0))"),
                              {"key":f"training-account:{tenant}:{subject}"})


    async def lifecycle_status(self,tenant,subject):
        async with self.transaction(tenant) as session:
            await self.account_lock(session,tenant,subject)
            row=await session.get(TrainingConsent,(tenant,subject))
            count=await session.scalar(select(func.count()).select_from(TrainingSubmission).where(
                TrainingSubmission.tenant_id==tenant,TrainingSubmission.subject==subject))
            return {"present":bool(row or count),"entries":count,"enabled":bool(row and row.enabled)}


    async def set_consent(self, tenant, subject, enabled):
        if enabled:
            raise HTTPException(409, "Training enrollment unavailable")
        async with self.transaction(tenant) as session:
            row = await self.locked(session, tenant, subject)
            # Check while holding the same row lock as consent/deletion, so
            # an enable request authenticated before closure cannot win later.
            if enabled and self.account_ledger is not None and self.account_ledger.claims_blocked({'sub':subject, 'tenant_id':str(tenant)}):
                raise HTTPException(403, 'Account is unavailable')
            if row.enabled != enabled:
                row.generation += 1
                row.enabled = enabled
                row.collect_after = datetime.now(UTC)
                row.consent_at = row.collect_after if enabled else None
            return {'enabled': row.enabled, 'consent_at': row.consent_at}


    async def delete_account(self, tenant, subject, actor):
        if not subject.strip() or not actor.strip() or max(len(subject),len(actor)) > 512:
            raise ValueError('Exact account subject and operator actor required')
        async with self.transaction(tenant) as session:
            row = await self.locked(session, tenant, subject)
            row.generation += 1  # Fence requests already in flight, including off/on cycles.
            row.collect_after = datetime.now(UTC)
            result = await session.execute(delete(TrainingSubmission).where(
                TrainingSubmission.tenant_id==tenant, TrainingSubmission.subject==subject))
            session.add(TrainingDeletion(id=uuid.uuid4(), tenant_id=tenant, subject=subject,
                actor=actor, deleted_count=result.rowcount, created_at=datetime.now(UTC)))
            return result.rowcount


    async def purge_account(self,tenant,subject):
        async with self.transaction(tenant) as session:
            await self.account_lock(session,tenant,subject)
            removed=await session.execute(delete(TrainingSubmission).where(
                TrainingSubmission.tenant_id==tenant,TrainingSubmission.subject==subject))
            preference=await session.execute(delete(TrainingConsent).where(
                TrainingConsent.tenant_id==tenant,TrainingConsent.subject==subject))
            if removed.rowcount or preference.rowcount:
                session.add(TrainingDeletion(id=uuid.uuid4(),tenant_id=tenant,subject=subject,
                    actor="account-lifecycle",deleted_count=removed.rowcount,created_at=datetime.now(UTC)))
                await session.flush()
            total=await session.scalar(select(func.coalesce(func.sum(TrainingDeletion.deleted_count),0)).where(
                TrainingDeletion.tenant_id==tenant,TrainingDeletion.subject==subject,
                TrainingDeletion.actor=="account-lifecycle"))
            return {"deleted":int(total),"remaining":0}


