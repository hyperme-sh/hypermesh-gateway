"""Fail-closed chat posture. No prompt body. Not an IdP.

Ticket valid, compact-cert green (path_b_state), WireGuard peer up, lease
active. Uploaded catalog rows also need an allowed admission on the ticket
pull. Lab-discovered / seed rows (pack-v1 path) are not blocked for missing
admission.
"""

from __future__ import annotations

import uuid

from hypermesh_gateway_service.tickets import (
    COMPACT_CERT_GREEN,
    PATH_B_GREEN,
    TicketCache,
)
from hypermesh_ticket import TicketClaims, TicketNotReady

# Compact-cert green travels as path_b_state on the host. Same wire value.
assert COMPACT_CERT_GREEN == PATH_B_GREEN


def require_chat_posture(
    cache: TicketCache,
    tenant_id: uuid.UUID,
    lease_id: uuid.UUID,
    *,
    peer_up: bool,
    require_peer: bool = True,
) -> TicketClaims:
    """Honor a cached ticket only when compact-cert is green and the peer is up.

    Upload-origin catalog rows without an allowed admission fail closed.
    Seed / lab rows keep the existing certified pack-v1 path.
    ``require_peer`` false keeps the cert and honor checks and skips the
    WireGuard peer. Router verbs use that: they change this process's
    policy and do not need the host to be up.
    """

    ticket = cache.get(tenant_id, lease_id)
    if ticket is not None and ticket.path_b_state != COMPACT_CERT_GREEN:
        raise TicketNotReady()
    if ticket is not None and ticket.catalog_origin == "upload" and not ticket.catalog_admitted:
        raise TicketNotReady()
    if require_peer and not peer_up:
        raise TicketNotReady()
    return cache.honor(tenant_id, lease_id)
