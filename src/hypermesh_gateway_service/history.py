"""Retained account data owner; no enrollment or payload collection."""
from contextlib import asynccontextmanager
from datetime import UTC, datetime
import uuid
from fastapi import HTTPException
from sqlalchemy import delete, func, select, text
from sqlalchemy.dialects.postgresql import insert
from controlplane_tenancy.account_profile import _closure_retention
from hypermesh_gateway_service.models import HistoryPreference, HistoryEntry, HistoryAudit, TrainingConsent, TrainingSubmission, TrainingDeletion

class HistoryStore:
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
        await session.execute(insert(HistoryPreference).values(tenant_id=tenant,subject=subject,
            enabled=False,generation=0).on_conflict_do_nothing())
        return (await session.execute(select(HistoryPreference).where(
            HistoryPreference.tenant_id==tenant,HistoryPreference.subject==subject).with_for_update())).scalar_one()


    async def account_lock(self,session,tenant,subject):
        await session.execute(text("SELECT pg_advisory_xact_lock(hashtextextended(:key,0))"),
                              {"key":f"saved-history-account:{tenant}:{subject}"})


    async def lifecycle_status(self,tenant,subject):
        async with self.transaction(tenant) as session:
            await self.account_lock(session,tenant,subject)
            row=await session.get(HistoryPreference,(tenant,subject))
            count=await session.scalar(select(func.count()).select_from(HistoryEntry).where(*self.owned(tenant,subject)))
            return {"present":bool(row or count),"entries":count,
                "closed_at":row.closed_at.isoformat() if row and row.closed_at else None,
                "purged_at":row.purged_at.isoformat() if row and row.purged_at else None}


    def audit(self, session, tenant, subject, actor, action, count=0):
        session.add(HistoryAudit(id=uuid.uuid4(),tenant_id=tenant,subject=subject,actor=actor,
            action=action,deleted_count=count,created_at=datetime.now(UTC)))


    def owned(self, tenant, subject):
        return (HistoryEntry.tenant_id==tenant,HistoryEntry.subject==subject)


    async def record_closure(self, tenant, subject, closed_at, actor):
        now=datetime.now(UTC)
        if closed_at.tzinfo is None or closed_at.utcoffset() is None or closed_at>now:
            raise ValueError('Actual, timezone-aware past closure time required')
        if not subject.strip() or not actor.strip() or max(len(subject),len(actor))>512:
            raise ValueError('Exact account and actor required')
        async with self.transaction(tenant) as session:
            row=await self.locked(session,tenant,subject)
            if row.closed_at:
                if row.closed_at != closed_at:
                    raise ValueError('Original closure time is immutable')
                return False
            row.closed_at=closed_at
            row.enabled=False
            row.generation+=1
            row.collect_after=now
            self.audit(session,tenant,subject,actor,'account_closed')
            return True


    async def purge_account(self,tenant,subject,closed_at):
        now=datetime.now(UTC)
        if closed_at.tzinfo is None or now<closed_at+_closure_retention():
            raise ValueError("History erasure is not yet due")
        async with self.transaction(tenant) as session:
            row=await self.locked(session,tenant,subject)
            if row.closed_at!=closed_at:
                raise ValueError("Original history closure receipt required")
            removed=await session.execute(delete(HistoryEntry).where(*self.owned(tenant,subject)))
            if row.purged_at is None or removed.rowcount:
                row.purged_at=row.purged_at or now
                row.generation+=1
                row.enabled=False
                self.audit(session,tenant,subject,"account-lifecycle","closure_purge",removed.rowcount)
                await session.flush()
            total=await session.scalar(select(func.coalesce(func.sum(HistoryAudit.deleted_count),0)).where(
                HistoryAudit.tenant_id==tenant,HistoryAudit.subject==subject,HistoryAudit.action=="closure_purge"))
            return {"deleted":int(total),"remaining":0,"purged_at":row.purged_at.isoformat()}


