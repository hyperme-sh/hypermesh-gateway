"""Gateway-owned private account stores. History and training remain separate."""
import uuid
from datetime import datetime
from sqlalchemy import Boolean, CheckConstraint, DateTime, ForeignKey, Index, Integer, LargeBinary, String
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column
from controlplane_db.base import Base
import controlplane_db.models as _platform_models  # noqa: F401


class TrainingConsent(Base):
    __tablename__ = 'hypermesh_training_consents'
    __table_args__ = (
        CheckConstraint('generation >= 0', name='ck_training_generation'),
        CheckConstraint('(enabled AND consent_at IS NOT NULL AND collect_after IS NOT NULL) OR (NOT enabled AND consent_at IS NULL)', name='ck_training_consent_time'),
    )
    tenant_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey('tenants.id', ondelete='RESTRICT'), primary_key=True)
    subject: Mapped[str] = mapped_column(String(512), primary_key=True)
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False)
    generation: Mapped[int] = mapped_column(Integer, nullable=False)
    consent_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    collect_after: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class TrainingSubmission(Base):
    __tablename__ = 'hypermesh_training_submissions'
    __table_args__ = (Index('ix_training_account', 'tenant_id', 'subject'),)
    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True)
    tenant_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey('tenants.id', ondelete='RESTRICT'), nullable=False)
    subject: Mapped[str] = mapped_column(String(512), nullable=False)
    consent_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    prompt: Mapped[dict] = mapped_column(JSONB, nullable=False)
    output: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    media_type: Mapped[str] = mapped_column(String(128), nullable=False)


class TrainingDeletion(Base):
    __tablename__ = 'hypermesh_training_deletions'
    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True)
    tenant_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey('tenants.id', ondelete='RESTRICT'), nullable=False)
    subject: Mapped[str] = mapped_column(String(512), nullable=False)
    actor: Mapped[str] = mapped_column(String(512), nullable=False)
    deleted_count: Mapped[int] = mapped_column(Integer, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class HistoryPreference(Base):
    __tablename__ = 'hypermesh_history_preferences'
    __table_args__ = (
        CheckConstraint('generation >= 0', name='ck_history_generation'),
        CheckConstraint('(NOT enabled) OR (consent_at IS NOT NULL AND collect_after IS NOT NULL AND closed_at IS NULL)', name='ck_history_enabled'),
        Index('ix_history_retention', 'tenant_id', 'closed_at', 'subject'),
    )
    tenant_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey('tenants.id', ondelete='RESTRICT'), primary_key=True)
    subject: Mapped[str] = mapped_column(String(512), primary_key=True)
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False)
    generation: Mapped[int] = mapped_column(Integer, nullable=False)
    consent_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    collect_after: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    closed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    purged_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class HistoryEntry(Base):
    __tablename__ = 'hypermesh_history_entries'
    __table_args__ = (Index('ix_history_owner', 'tenant_id', 'subject', 'created_at', 'id'),)
    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True)
    tenant_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey('tenants.id', ondelete='RESTRICT'), nullable=False)
    subject: Mapped[str] = mapped_column(String(512), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    prompt: Mapped[dict] = mapped_column(JSONB, nullable=False)
    output: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    media_type: Mapped[str] = mapped_column(String(128), nullable=False)


class HistoryAudit(Base):
    __tablename__ = 'hypermesh_history_audit'
    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True)
    tenant_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey('tenants.id', ondelete='RESTRICT'), nullable=False)
    subject: Mapped[str] = mapped_column(String(512), nullable=False)
    actor: Mapped[str] = mapped_column(String(512), nullable=False)
    action: Mapped[str] = mapped_column(String(32), nullable=False)
    deleted_count: Mapped[int] = mapped_column(Integer, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
