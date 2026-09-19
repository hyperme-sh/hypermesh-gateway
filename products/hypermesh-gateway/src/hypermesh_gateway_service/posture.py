"""Fail-closed chat posture. No prompt body. Not an IdP.

Ticket valid, Path B green, WireGuard peer up, lease active. Revoked
ticket, Path B not green, or peer down cannot keep a session.
"""

from __future__ import annotations

import uuid

from hypermesh_gateway_service.tickets import PATH_B_GREEN, TicketCache
from hypermesh_service.ticket import TicketClaims, TicketNotReady


def require_chat_posture(
    cache: TicketCache,
    tenant_id: uuid.UUID,
    lease_id: uuid.UUID,
    *,
    peer_up: bool,
) -> TicketClaims:
    """Honor a cached ticket only when Path B is green and the host peer is up."""

    ticket = cache.get(tenant_id, lease_id)
    if ticket is not None and ticket.path_b_state != PATH_B_GREEN:
        raise TicketNotReady()
    if not peer_up:
        raise TicketNotReady()
    return cache.honor(tenant_id, lease_id)
