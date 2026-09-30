from __future__ import annotations
from gateway_host_fixture import FYBER_AGX_DEVICE_ID
"""Door refuses non-green compact-cert and unadmitted uploads."""


import uuid
from datetime import UTC, datetime, timedelta

import pytest

from hypermesh_gateway_service.posture import require_chat_posture
from hypermesh_gateway_service.tickets import CachedTicket, TicketCache
from hypermesh_service.seed import (FYBER_TEST_GATEWAY_ID, MARKETPLACE_TENANT_ID)
from hypermesh_service.ticket import TicketClaims, TicketNotReady, issue_ticket


@pytest.fixture(autouse=True)
def _ticket_hmac(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("HYPERMESH_TICKET_HMAC_KEY", "test-plane-hypermesh-ticket-hmac")


def _ticket(
    lease_id: uuid.UUID,
    *,
    path_b_state: str = "green",
    catalog_origin: str | None = None,
    catalog_admitted: bool = False,
    catalog_id: str | None = None,
) -> CachedTicket:
    exp = datetime.now(UTC) + timedelta(hours=1)
    token = issue_ticket(
        TicketClaims(
            lease_id=lease_id,
            device_id=FYBER_AGX_DEVICE_ID,
            gateway_id=FYBER_TEST_GATEWAY_ID,
            client_address="10.77.0.2/32",
            status="active",
            exp=exp,
            purpose="renter",
            tenant_id=MARKETPLACE_TENANT_ID,
        )
    )
    return CachedTicket(
        lease_id=lease_id,
        ticket=token,
        client_address="10.77.0.2/32",
        assigned_gateway_id=FYBER_TEST_GATEWAY_ID,
        status="active",
        exp=exp,
        device_id=FYBER_AGX_DEVICE_ID,
        path_b_state=path_b_state,
        peer_public_key="peer-pub",
        catalog_id=catalog_id,
        catalog_origin=catalog_origin,
        catalog_admitted=catalog_admitted,
    )


def test_door_refuses_host_not_compact_cert_green():
    cache = TicketCache()
    lease_id = uuid.uuid4()
    cache.put(MARKETPLACE_TENANT_ID, _ticket(lease_id, path_b_state="suspended"))
    with pytest.raises(TicketNotReady):
        require_chat_posture(cache, MARKETPLACE_TENANT_ID, lease_id, peer_up=True)


def test_door_refuses_upload_without_allowed_admission():
    cache = TicketCache()
    lease_id = uuid.uuid4()
    cache.put(
        MARKETPLACE_TENANT_ID,
        _ticket(
            lease_id,
            catalog_id="upload-agx-large-aabb",
            catalog_origin="upload",
            catalog_admitted=False,
        ),
    )
    with pytest.raises(TicketNotReady):
        require_chat_posture(cache, MARKETPLACE_TENANT_ID, lease_id, peer_up=True)


def test_door_allows_seed_pack_v1_without_admission():
    cache = TicketCache()
    lease_id = uuid.uuid4()
    cache.put(
        MARKETPLACE_TENANT_ID,
        _ticket(
            lease_id,
            catalog_id="llama-3.1-8b-q4",
            catalog_origin="seed",
            catalog_admitted=False,
        ),
    )
    claims = require_chat_posture(cache, MARKETPLACE_TENANT_ID, lease_id, peer_up=True)
    assert claims.lease_id == lease_id


def test_door_allows_lab_discovered_without_admission():
    cache = TicketCache()
    lease_id = uuid.uuid4()
    cache.put(
        MARKETPLACE_TENANT_ID,
        _ticket(
            lease_id,
            catalog_id="hf-bartowski-llama",
            catalog_origin="lab",
            catalog_admitted=False,
        ),
    )
    claims = require_chat_posture(cache, MARKETPLACE_TENANT_ID, lease_id, peer_up=True)
    assert claims.lease_id == lease_id


def test_door_allows_admitted_upload():
    cache = TicketCache()
    lease_id = uuid.uuid4()
    cache.put(
        MARKETPLACE_TENANT_ID,
        _ticket(
            lease_id,
            catalog_id="upload-agx-large-aabb",
            catalog_origin="upload",
            catalog_admitted=True,
        ),
    )
    claims = require_chat_posture(cache, MARKETPLACE_TENANT_ID, lease_id, peer_up=True)
    assert claims.lease_id == lease_id
