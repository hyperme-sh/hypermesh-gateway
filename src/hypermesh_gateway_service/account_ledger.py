"""Durable local account denial authority; paid requests never fetch a guard.

SQLite FULL/WAL transactions acknowledge only committed monotonic additions.
Each process reads the same durable store, rather than overwriting another
worker's in-memory snapshot. A tenant cannot serve before a complete bootstrap.
"""

from __future__ import annotations

import fcntl
import os
import re
import sqlite3
import stat
import uuid
from contextlib import closing
from pathlib import Path

from controlplane_identity.account_lifecycle import (
    enforcement_enabled,
    key_digest,
    subject_digest,
)

_DIGEST = re.compile(r"[0-9a-f]{64}\Z")
_KINDS = {
    "subjects": "subject",
    "keys": "key",
    "fingerprints": "fingerprint",
    "leases": "lease",
}
_MAX_SNAPSHOT = 100_000


class LedgerUnavailable(RuntimeError):
    def __init__(self):
        super().__init__("Account denial authority unavailable")


class AccountLedger:
    def __init__(self, path: str):
        self.path = Path(path)
        if not self.path.is_absolute() or not self.path.parent.is_dir():
            raise LedgerUnavailable()
        try:
            try:
                descriptor = os.open(
                    self.path, os.O_CREAT | os.O_EXCL | os.O_RDWR | os.O_NOFOLLOW, 0o600
                )
            except FileExistsError:
                descriptor = os.open(self.path, os.O_RDWR | os.O_NOFOLLOW)
            try:
                info = os.fstat(descriptor)
                if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o077:
                    raise LedgerUnavailable()
                # Serialize first initialization across gateway workers. This
                # lock is startup-only; authorization reads remain independent.
                fcntl.flock(descriptor, fcntl.LOCK_EX)
                self._initialize()
            finally:
                os.close(descriptor)
        except Exception:
            raise LedgerUnavailable() from None

    def _initialize(self):
        with closing(self._connect()) as db:
            if db.execute("PRAGMA quick_check").fetchone() != ("ok",):
                raise LedgerUnavailable()
            db.execute("PRAGMA journal_mode=WAL")
            db.execute("BEGIN IMMEDIATE")
            version = db.execute("PRAGMA user_version").fetchone()[0]
            if version not in (0, 1, 2, 3):
                raise LedgerUnavailable()
            if version == 0:
                if db.execute("SELECT count(*) FROM sqlite_master").fetchone()[0]:
                    raise LedgerUnavailable()
                db.execute(
                    "CREATE TABLE denials (tenant TEXT NOT NULL, kind TEXT NOT NULL, value TEXT NOT NULL, PRIMARY KEY(tenant,kind,value))"
                )
                db.execute("CREATE TABLE ready (tenant TEXT PRIMARY KEY NOT NULL)")
                db.execute("PRAGMA user_version=1")
            if version in (0, 1):
                db.execute(
                    "CREATE TABLE owner_capabilities (owner TEXT PRIMARY KEY NOT NULL CHECK(owner IN ('history','training')), ever_configured INTEGER NOT NULL CHECK(ever_configured IN (0,1)), never_configured_attested INTEGER NOT NULL DEFAULT 0 CHECK(never_configured_attested IN (0,1)))"
                )
            elif version == 2:
                # Old false rows were inferred from a missing URL, not historical
                # provenance. They stay unknown until explicitly reconciled.
                db.execute(
                    "ALTER TABLE owner_capabilities ADD COLUMN never_configured_attested INTEGER NOT NULL DEFAULT 0 CHECK(never_configured_attested IN (0,1))"
                )
            if version < 3:
                db.execute("PRAGMA user_version=3")
            db.commit()
            if [
                row[1] for row in db.execute("PRAGMA table_info(owner_capabilities)")
            ] != ["owner", "ever_configured", "never_configured_attested"]:
                raise LedgerUnavailable()
            # Check structure too; an unrelated versioned database must not
            # accidentally count as a complete, empty denial authority.
            if [row[1] for row in db.execute("PRAGMA table_info(denials)")] != [
                "tenant",
                "kind",
                "value",
            ]:
                raise LedgerUnavailable()
            if [row[1] for row in db.execute("PRAGMA table_info(ready)")] != ["tenant"]:
                raise LedgerUnavailable()
        descriptor = os.open(self.path.parent, os.O_DIRECTORY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)

    def _connect(self):
        db = sqlite3.connect(self.path, timeout=5, isolation_level=None)
        db.execute("PRAGMA synchronous=FULL")
        return db

    @staticmethod
    def _rows(tenant: uuid.UUID, snapshot: dict):
        if not isinstance(tenant, uuid.UUID) or not isinstance(snapshot, dict):
            raise LedgerUnavailable()
        if (
            type(snapshot.get("version")) is not int
            or snapshot["version"] != 1
            or snapshot.get("complete") is not True
        ):
            raise LedgerUnavailable()
        rows = []
        for field, kind in _KINDS.items():
            values = snapshot.get(field)
            if not isinstance(values, list) or len(rows) + len(values) > _MAX_SNAPSHOT:
                raise LedgerUnavailable()
            for value in values:
                if not isinstance(value, str):
                    raise LedgerUnavailable()
                if kind == "lease":
                    try:
                        if str(uuid.UUID(value)) != value:
                            raise ValueError()
                    except ValueError:
                        raise LedgerUnavailable() from None
                elif _DIGEST.fullmatch(value) is None:
                    raise LedgerUnavailable()
                rows.append((str(tenant), kind, value))
        return rows

    def configure_owner(
        self, owner: str, configured: bool, *, never_configured: bool = False
    ):
        if (
            owner not in {"history", "training"}
            or type(configured) is not bool
            or type(never_configured) is not bool
        ):
            raise LedgerUnavailable()
        if not configured and not never_configured:
            return  # Current absence is not historical proof.
        try:
            with closing(self._connect()) as db:
                db.execute("BEGIN IMMEDIATE")
                db.execute(
                    "INSERT INTO owner_capabilities VALUES (?,?,?) ON CONFLICT(owner) DO UPDATE SET ever_configured=max(ever_configured,excluded.ever_configured), never_configured_attested=max(never_configured_attested,excluded.never_configured_attested)",
                    (owner, int(configured), int(not configured and never_configured)),
                )
                db.commit()
        except Exception:
            raise LedgerUnavailable() from None

    def owner_disabled(self, owner: str) -> bool:
        if owner not in {"history", "training"}:
            raise LedgerUnavailable()
        try:
            with closing(self._connect()) as db:
                row = db.execute(
                    "SELECT ever_configured,never_configured_attested FROM owner_capabilities WHERE owner=?",
                    (owner,),
                ).fetchone()
            return row == (0, 1)
        except Exception:
            raise LedgerUnavailable() from None

    def apply_snapshot(self, tenant: uuid.UUID, snapshot: dict):
        self._write(tenant, snapshot, bootstrap=True)

    def retire(
        self,
        tenant: uuid.UUID,
        subject: str,
        *,
        key_ids: list[uuid.UUID],
        fingerprints: list[str],
        leases: list[uuid.UUID],
    ):
        self._write(
            tenant,
            {
                "version": 1,
                "complete": True,
                "subjects": [subject_digest(tenant, subject)],
                "keys": [key_digest(tenant, identifier) for identifier in key_ids],
                "fingerprints": fingerprints,
                "leases": [str(lease) for lease in leases],
            },
            bootstrap=False,
        )

    def _write(self, tenant: uuid.UUID, snapshot: dict, *, bootstrap: bool):
        rows = self._rows(tenant, snapshot)
        try:
            with closing(self._connect()) as db:
                db.execute("BEGIN IMMEDIATE")
                try:
                    db.executemany("INSERT OR IGNORE INTO denials VALUES (?,?,?)", rows)
                    if bootstrap:
                        db.execute(
                            "INSERT OR IGNORE INTO ready VALUES (?)", (str(tenant),)
                        )
                    db.commit()
                except Exception:
                    db.rollback()
                    raise
        except Exception:
            raise LedgerUnavailable() from None

    def _blocked(self, tenant: uuid.UUID, kind: str, value: str) -> bool:
        try:
            with closing(self._connect()) as db:
                # One read transaction covers readiness and denial, so a
                # concurrent writer cannot cause a torn authorization decision.
                db.execute("BEGIN")
                ready = db.execute(
                    "SELECT 1 FROM ready WHERE tenant=?", (str(tenant),)
                ).fetchone()
                denied = db.execute(
                    "SELECT 1 FROM denials WHERE tenant=? AND kind=? AND value=?",
                    (str(tenant), kind, value),
                ).fetchone()
                return not ready or bool(denied)
        except Exception:
            raise LedgerUnavailable() from None

    def tenant_ready(self, tenant: uuid.UUID) -> bool:
        try:
            with closing(self._connect()) as db:
                return bool(
                    db.execute(
                        "SELECT 1 FROM ready WHERE tenant=?", (str(tenant),)
                    ).fetchone()
                )
        except Exception:
            raise LedgerUnavailable() from None

    def principal_retired(self, tenant: uuid.UUID, subject: str) -> bool:
        """Prove an explicit durable denial, independently of bootstrap readiness."""
        try:
            with closing(self._connect()) as db:
                return bool(
                    db.execute(
                        "SELECT 1 FROM denials WHERE tenant=? AND kind='subject' AND value=?",
                        (str(tenant), subject_digest(tenant, subject)),
                    ).fetchone()
                )
        except Exception:
            raise LedgerUnavailable() from None

    def claims_blocked(self, claims: dict) -> bool:
        try:
            tenant = uuid.UUID(
                str(
                    claims.get("https://spanopticon.dev/tenant_id")
                    or claims.get("tenant_id")
                )
            )
            subject = claims.get("sub")
            if not isinstance(subject, str) or not subject or len(subject) > 512:
                return True
            if subject.startswith("apikey:"):
                return self._blocked(
                    tenant, "key", key_digest(tenant, uuid.UUID(subject[7:]))
                )
            return self._blocked(tenant, "subject", subject_digest(tenant, subject))
        except (ValueError, TypeError, AttributeError):
            return True

    def key_blocked(self, tenant: uuid.UUID, fingerprint: str) -> bool:
        return self._blocked(tenant, "fingerprint", fingerprint)

    def lease_blocked(self, tenant: uuid.UUID, lease: uuid.UUID) -> bool:
        return self._blocked(tenant, "lease", str(lease))


def resolve_ledger() -> AccountLedger | None:
    if not enforcement_enabled():
        return None
    path = os.environ.get("HYPERMESH_ACCOUNT_DENIAL_DATABASE", "")
    if not path:
        raise LedgerUnavailable()
    return AccountLedger(path)
