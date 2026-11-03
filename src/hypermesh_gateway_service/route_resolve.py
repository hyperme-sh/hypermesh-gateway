"""Key to lease resolution.

``resolve_route(key, requested_model)`` is the seam a later routing layer
can replace. Today every key is tenant-owned: the policy returns every
honoring ticket for the tenant, and ``auto`` is not a model. A later policy
can let one key span a subset of leases and can add a routing model id.

paid and starting leases are upcoming. They are not tickets that honor, so
they are not candidates. A key minted while a lease is still upcoming needs
no extra step; it routes on the pull after the lease is active.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Protocol

from hypermesh_gateway_service.tickets import CachedTicket, TicketCache

_EPOCH = datetime.min.replace(tzinfo=UTC)


class LeaseNotOwned(Exception):
    """The caller named a lease this tenant's cache does not hold."""


class ModelNotFound(Exception):
    """``model`` is set and no honoring lease serves that catalog id."""

    def __init__(self, requested: str, available: list[str]) -> None:
        super().__init__(requested)
        self.requested = requested
        self.available = available


class KeyPolicy(Protocol):
    def candidate_leases(
        self,
        cache: TicketCache,
        tenant_id: uuid.UUID,
        *,
        key: str | None,
        purposes: frozenset[str],
    ) -> list[CachedTicket]:
        """Leases this key may be routed to when the request omits a lease id."""


class TenantOwnedKeyPolicy:
    """All honoring tickets for the tenant. The key is not consulted.

    Keys are tenant-owned, never lease-owned. Swap this policy to narrow a
    key to some leases or to recognize a routing model such as ``auto``.
    This policy does not recognize ``auto``.
    """

    def candidate_leases(
        self,
        cache: TicketCache,
        tenant_id: uuid.UUID,
        *,
        key: str | None,
        purposes: frozenset[str],
    ) -> list[CachedTicket]:
        del key
        return cache.honoring_leases(tenant_id, purposes=purposes)


def resolve_route(
    cache: TicketCache,
    *,
    key: str | None,
    tenant_id: uuid.UUID,
    requested_model: str | None,
    requested_lease_id: uuid.UUID | None = None,
    purposes: frozenset[str],
    policy: KeyPolicy | None = None,
) -> CachedTicket | None:
    """Pick the lease for this key.

    An explicit lease id must already be in the tenant cache (else
    ``LeaseNotOwned``). When ``model`` is omitted, return the sole honoring
    lease or the most recently activated. When ``model`` is set, return only
    a lease whose catalog id matches (else ``ModelNotFound``). ``None``
    means there is no active paid lease.
    """

    chosen_policy = policy or TenantOwnedKeyPolicy()
    if requested_lease_id is not None:
        for ticket in cache.leases_for_tenant(tenant_id):
            if ticket.lease_id == requested_lease_id:
                return ticket
        raise LeaseNotOwned()
    candidates = chosen_policy.candidate_leases(
        cache, tenant_id, key=key, purposes=purposes
    )
    return select_lease(candidates, requested_model)


def select_lease(
    candidates: list[CachedTicket], requested_model: str | None
) -> CachedTicket | None:
    """Pick a lease. A set ``model`` never falls through to a different catalog."""

    if not candidates:
        return None
    model = (requested_model or "").strip()
    if not model:
        if len(candidates) == 1:
            return candidates[0]
        return _most_recent(candidates)
    matched = [ticket for ticket in candidates if (ticket.catalog_id or "") == model]
    if not matched:
        raise ModelNotFound(model, catalog_ids(candidates))
    if len(matched) == 1:
        return matched[0]
    return _most_recent(matched)


def catalog_ids(candidates: list[CachedTicket]) -> list[str]:
    """Distinct catalog ids, most recently activated first. No routing model."""

    ordered = sorted(candidates, key=_started, reverse=True)
    seen: list[str] = []
    for ticket in ordered:
        catalog_id = (ticket.catalog_id or "").strip()
        if catalog_id and catalog_id not in seen:
            seen.append(catalog_id)
    return seen


def _most_recent(tickets: list[CachedTicket]) -> CachedTicket:
    return max(tickets, key=_started)


def _started(ticket: CachedTicket) -> tuple[datetime, str]:
    started = ticket.activated_at or _EPOCH
    if started.tzinfo is None:
        started = started.replace(tzinfo=UTC)
    return (started, str(ticket.lease_id))
