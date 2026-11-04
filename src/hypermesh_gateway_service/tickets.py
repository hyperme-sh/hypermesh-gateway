"""Cached signed lease tickets learned from hm_gw_ GET /gateway/tickets.

spanopticon is the broker. After a ticket is issued, chat uses this cache
and honor_ticket. Do not re-ask the control plane per completion.

Fingerprints are indexed back to a tenant so a bearer key can find its
tenant without X-Tenant-ID. A positive validate of that key is remembered
for at most ``key_ttl_s`` (default 60s) and purged when a pull drops it.
"""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field, replace
from datetime import datetime
from typing import Iterable

from hypermesh_ticket import TicketClaims, TicketNotReady, honor_ticket

PATH_B_GREEN = "green"
# Enrolled hosts stamp green via compact_cert; lab hosts via path_b. Same wire.
COMPACT_CERT_GREEN = PATH_B_GREEN


@dataclass(frozen=True)
class CachedTicket:
    lease_id: uuid.UUID
    ticket: str
    client_address: str
    assigned_gateway_id: uuid.UUID
    status: str
    exp: datetime | None = None
    device_id: uuid.UUID | None = None
    path_b_state: str = ""
    tunnel_id: uuid.UUID | None = None
    peer_public_key: str | None = None
    catalog_id: str | None = None
    catalog_origin: str | None = None
    catalog_admitted: bool = False
    activated_at: datetime | None = None

    @property
    def active(self) -> bool:
        return self.status == "active" and bool(self.ticket) and bool(self.client_address)


@dataclass
class TicketPull:
    tickets: list[CachedTicket]
    revoked_lease_ids: list[uuid.UUID]
    key_fingerprints: list[str] = field(default_factory=list)
    ir_key_fingerprints: list[str] = field(default_factory=list)
    revoked_key_fingerprints: list[str] = field(default_factory=list)


def _norm_fp(raw: str) -> str:
    return str(raw).strip().lower()


class TicketCache:
    def __init__(self, *, key_ttl_s: float = 60.0) -> None:
        self.key_ttl_s = key_ttl_s
        self._tickets: dict[tuple[uuid.UUID, uuid.UUID], CachedTicket] = {}
        self._revoked: dict[uuid.UUID, set[uuid.UUID]] = {}
        self._fingerprints: dict[uuid.UUID, set[str]] = {}
        self._ir_fingerprints: dict[uuid.UUID, set[str]] = {}
        self._fingerprint_tenant: dict[str, uuid.UUID] = {}
        self._ir_fingerprint_tenant: dict[str, uuid.UUID] = {}
        self._revoked_keys: dict[uuid.UUID, set[str]] = {}
        self._watched: set[uuid.UUID] = set()
        self._valid_until: dict[str, float] = {}
        self._valid_key_id: dict[str, uuid.UUID] = {}

    def watch(self, tenant_id: uuid.UUID) -> None:
        """Remember a tenant so the refresh hop can pull before any ticket lands."""

        self._watched.add(tenant_id)

    def known_tenants(self) -> list[uuid.UUID]:
        tenants = {tenant_id for tenant_id, _lease_id in self._tickets}
        tenants.update(self._revoked)
        tenants.update(self._watched)
        tenants.update(self._fingerprints)
        tenants.update(self._ir_fingerprints)
        return list(tenants)

    def replace_from_pull(
        self,
        tenant_id: uuid.UUID,
        pull: TicketPull,
        tunnels: Iterable[object] | None = None,
    ) -> None:
        by_lease: dict[uuid.UUID, object] = {}
        for tunnel in tunnels or []:
            lease_id = getattr(tunnel, "lease_id", None)
            if isinstance(lease_id, uuid.UUID):
                by_lease[lease_id] = tunnel
        stale = [key for key in self._tickets if key[0] == tenant_id]
        for key in stale:
            del self._tickets[key]
        self._revoked[tenant_id] = set(pull.revoked_lease_ids)
        self.replace_revoked_keys(tenant_id, pull.revoked_key_fingerprints)
        self.accept_keys(tenant_id, pull.key_fingerprints)
        self.accept_ir_keys(tenant_id, pull.ir_key_fingerprints)
        for ticket in pull.tickets:
            tunnel = by_lease.get(ticket.lease_id)
            enriched = ticket
            if tunnel is not None:
                enriched = replace(
                    ticket,
                    tunnel_id=getattr(tunnel, "tunnel_id", ticket.tunnel_id),
                    peer_public_key=getattr(tunnel, "peer_public_key", None)
                    or ticket.peer_public_key,
                    client_address=ticket.client_address
                    or str(getattr(tunnel, "client_address", "") or ""),
                )
            self._tickets[(tenant_id, ticket.lease_id)] = enriched

    def replace_revoked_keys(self, tenant_id: uuid.UUID, fingerprints: Iterable[str]) -> None:
        revoked = {_norm_fp(item) for item in fingerprints if _norm_fp(item)}
        self._revoked_keys[tenant_id] = revoked
        for fingerprint in revoked:
            self.purge_key(fingerprint)
            if self._fingerprint_tenant.get(fingerprint) == tenant_id:
                del self._fingerprint_tenant[fingerprint]
            if self._ir_fingerprint_tenant.get(fingerprint) == tenant_id:
                del self._ir_fingerprint_tenant[fingerprint]

    def accept_keys(self, tenant_id: uuid.UUID, fingerprints: Iterable[str]) -> set[str]:
        return self._accept(tenant_id, fingerprints, ir=False)

    def key_fingerprints(self, tenant_id: uuid.UUID) -> set[str]:
        return set(self._fingerprints.get(tenant_id, set()))

    def accept_ir_keys(self, tenant_id: uuid.UUID, fingerprints: Iterable[str]) -> set[str]:
        return self._accept(tenant_id, fingerprints, ir=True)

    def ir_key_fingerprints(self, tenant_id: uuid.UUID) -> set[str]:
        return set(self._ir_fingerprints.get(tenant_id, set()))

    def _accept(self, tenant_id: uuid.UUID, fingerprints: Iterable[str], *, ir: bool) -> set[str]:
        blocked = self._revoked_keys.get(tenant_id, set())
        new = {_norm_fp(item) for item in fingerprints if _norm_fp(item) and _norm_fp(item) not in blocked}
        table = self._ir_fingerprints if ir else self._fingerprints
        reverse = self._ir_fingerprint_tenant if ir else self._fingerprint_tenant
        old = table.get(tenant_id, set())
        removed = old - new
        for fingerprint, owner in list(reverse.items()):
            if owner == tenant_id and fingerprint not in new:
                del reverse[fingerprint]
                self.purge_key(fingerprint)
        for fingerprint in new:
            reverse[fingerprint] = tenant_id
        table[tenant_id] = new
        self.watch(tenant_id)
        return removed

    def note_key_index(self, entries: Iterable[tuple[uuid.UUID, str, str]]) -> None:
        """File a cross-tenant fingerprint index. Pulls remain authoritative."""

        for tenant_id, fingerprint, kind in entries:
            fp = _norm_fp(fingerprint)
            if not fp or fp in self._revoked_keys.get(tenant_id, set()):
                continue
            reverse = self._ir_fingerprint_tenant if kind == "ir" else self._fingerprint_tenant
            reverse.setdefault(fp, tenant_id)
            self.watch(tenant_id)

    def tenant_for_fingerprint(self, fingerprint: str, *, ir: bool = False) -> uuid.UUID | None:
        fp = _norm_fp(fingerprint)
        if not fp:
            return None
        reverse = self._ir_fingerprint_tenant if ir else self._fingerprint_tenant
        owner = reverse.get(fp)
        if owner is None:
            return None
        if fp in self._revoked_keys.get(owner, set()):
            return None
        return owner

    def remember_key(self, fingerprint: str, key_id: uuid.UUID | None) -> None:
        fp = _norm_fp(fingerprint)
        self._valid_until[fp] = time.monotonic() + self.key_ttl_s
        if key_id is not None:
            self._valid_key_id[fp] = key_id

    def key_is_fresh(self, fingerprint: str) -> bool:
        fp = _norm_fp(fingerprint)
        return time.monotonic() < self._valid_until.get(fp, 0.0)

    def key_id_for(self, fingerprint: str) -> uuid.UUID | None:
        return self._valid_key_id.get(_norm_fp(fingerprint))

    def purge_key(self, fingerprint: str) -> None:
        fp = _norm_fp(fingerprint)
        self._valid_until.pop(fp, None)
        self._valid_key_id.pop(fp, None)

    def put(self, tenant_id: uuid.UUID, ticket: CachedTicket) -> None:
        self._tickets[(tenant_id, ticket.lease_id)] = ticket

    def get(self, tenant_id: uuid.UUID, lease_id: uuid.UUID) -> CachedTicket | None:
        return self._tickets.get((tenant_id, lease_id))

    def leases_for_tenant(self, tenant_id: uuid.UUID) -> list[CachedTicket]:
        return [ticket for (tid, _lease_id), ticket in self._tickets.items() if tid == tenant_id]

    def honoring_leases(
        self, tenant_id: uuid.UUID, *, purposes: frozenset[str]
    ) -> list[CachedTicket]:
        """Tickets that honor for this tenant and purpose. Not paid/starting."""

        chosen: list[CachedTicket] = []
        for ticket in self.leases_for_tenant(tenant_id):
            try:
                claims = self.honor(tenant_id, ticket.lease_id)
            except TicketNotReady:
                continue
            if claims.purpose not in purposes:
                continue
            chosen.append(ticket)
        return chosen

    def revoked_lease_ids(self, tenant_id: uuid.UUID) -> set[uuid.UUID]:
        return set(self._revoked.get(tenant_id, set()))

    def honor(self, tenant_id: uuid.UUID, lease_id: uuid.UUID) -> TicketClaims:
        ticket = self.get(tenant_id, lease_id)
        if ticket is None or not ticket.active:
            raise TicketNotReady()
        claims = honor_ticket(
            ticket.ticket,
            gateway_id=ticket.assigned_gateway_id,
            revoked_lease_ids=self.revoked_lease_ids(tenant_id),
        )
        if claims.tenant_id is not None and claims.tenant_id != tenant_id:
            raise TicketNotReady()
        return claims

    def active_address(self, tenant_id: uuid.UUID, lease_id: uuid.UUID) -> str | None:
        try:
            return self.honor(tenant_id, lease_id).client_address
        except TicketNotReady:
            return None
