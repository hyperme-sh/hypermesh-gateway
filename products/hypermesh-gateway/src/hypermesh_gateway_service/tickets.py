"""Cached signed lease tickets learned from hm_gw_ GET /gateway/tickets.

Panopticon is the broker. After a ticket is issued, chat uses this cache
and honor_ticket. Do not re-ask the control plane per completion.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field, replace
from datetime import datetime
from typing import Iterable

from hypermesh_service.ticket import TicketClaims, TicketNotReady, honor_ticket

PATH_B_GREEN = "green"


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

    @property
    def active(self) -> bool:
        return self.status == "active" and bool(self.ticket) and bool(self.client_address)


@dataclass
class TicketPull:
    tickets: list[CachedTicket]
    revoked_lease_ids: list[uuid.UUID]
    key_fingerprints: list[str] = field(default_factory=list)
    ir_key_fingerprints: list[str] = field(default_factory=list)


class TicketCache:
    def __init__(self) -> None:
        self._tickets: dict[tuple[uuid.UUID, uuid.UUID], CachedTicket] = {}
        self._revoked: dict[uuid.UUID, set[uuid.UUID]] = {}
        self._fingerprints: dict[uuid.UUID, set[str]] = {}
        self._ir_fingerprints: dict[uuid.UUID, set[str]] = {}
        self._watched: set[uuid.UUID] = set()

    def watch(self, tenant_id: uuid.UUID) -> None:
        """Remember a tenant so the refresh hop can pull before any ticket lands."""

        self._watched.add(tenant_id)

    def known_tenants(self) -> list[uuid.UUID]:
        tenants = {tenant_id for tenant_id, _lease_id in self._tickets}
        tenants.update(self._revoked)
        tenants.update(self._watched)
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

    def accept_keys(self, tenant_id: uuid.UUID, fingerprints: Iterable[str]) -> None:
        self._fingerprints[tenant_id] = {
            str(item).strip().lower() for item in fingerprints if str(item).strip()
        }

    def key_fingerprints(self, tenant_id: uuid.UUID) -> set[str]:
        return set(self._fingerprints.get(tenant_id, set()))

    def accept_ir_keys(self, tenant_id: uuid.UUID, fingerprints: Iterable[str]) -> None:
        self._ir_fingerprints[tenant_id] = {
            str(item).strip().lower() for item in fingerprints if str(item).strip()
        }

    def ir_key_fingerprints(self, tenant_id: uuid.UUID) -> set[str]:
        return set(self._ir_fingerprints.get(tenant_id, set()))

    def put(self, tenant_id: uuid.UUID, ticket: CachedTicket) -> None:
        self._tickets[(tenant_id, ticket.lease_id)] = ticket

    def get(self, tenant_id: uuid.UUID, lease_id: uuid.UUID) -> CachedTicket | None:
        return self._tickets.get((tenant_id, lease_id))

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
