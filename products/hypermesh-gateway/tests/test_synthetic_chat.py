"""Hermetic router chat synthetic: ticket pull → mock host completions.

Plane ``POST /renter/chat/completions`` is not the product. This suite
proxies one completion to ``http://127.0.0.1:<port>/v1/chat/completions``
using the ticket's ``client_address`` (no live WG / AGX).
"""

from __future__ import annotations

import logging
import uuid
from datetime import UTC, datetime, timedelta

import pytest

from hypermesh_gateway_service.chat import CHAT_PORT_ENV, INSTANCE_NOT_READY
from hypermesh_gateway_service.control_plane import GatewayTunnel
from hypermesh_gateway_service.tickets import CachedTicket, TicketPull
from hypermesh_service.seed import FYBER_AGX_DEVICE_ID, FYBER_TEST_ROUTER_ID
from hypermesh_service.ticket import TicketClaims, issue_ticket
from mock_host import MOCK_COMPLETION, MockHost


pytestmark = [pytest.mark.synthetic]

SECRET_PROMPT = "secret prompt must not be evented"
_TEST_TICKET_KEY = b"test-plane-hypermesh-ticket-hmac"


def _renter(tenant_headers: dict[str, str]) -> dict[str, str]:
    return {**tenant_headers, "Authorization": "Bearer pk_test.renter-key"}


def _router(tenant_headers: dict[str, str]) -> dict[str, str]:
    return {**tenant_headers, "Authorization": "Bearer hm_rtr_test"}


def _signed_ticket(
    lease_id: uuid.UUID,
    *,
    client_address: str,
    path_b_state: str = "green",
) -> CachedTicket:
    exp = datetime.now(UTC) + timedelta(hours=1)
    token = issue_ticket(
        TicketClaims(
            lease_id=lease_id,
            device_id=FYBER_AGX_DEVICE_ID,
            router_id=FYBER_TEST_ROUTER_ID,
            client_address=client_address,
            status="active",
            exp=exp,
        ),
        key=_TEST_TICKET_KEY,
    )
    return CachedTicket(
        lease_id=lease_id,
        ticket=token,
        client_address=client_address,
        assigned_router_id=FYBER_TEST_ROUTER_ID,
        status="active",
        exp=exp,
        device_id=FYBER_AGX_DEVICE_ID,
        path_b_state=path_b_state,
        peer_public_key="peer-pub-synthetic",
    )


def _allocated_tunnel(lease_id: uuid.UUID, client_address: str) -> GatewayTunnel:
    return GatewayTunnel(
        tunnel_id=uuid.uuid4(),
        lease_id=lease_id,
        status="allocated",
        endpoint="wg.test.hyperme.sh:51820",
        server_private_key="server-priv",
        server_public_key="server-pub",
        peer_public_key="peer-pub-synthetic",
        allowed_ips="10.77.0.0/24",
        client_address=client_address,
    )


def _plane_ticket_fixture(ticket: CachedTicket) -> dict:
    """Recorded GET /router/tickets row. Same lock fields as the plane."""

    return {
        "lease_id": str(ticket.lease_id),
        "device_id": str(ticket.device_id),
        "assigned_router_id": str(ticket.assigned_router_id),
        "client_address": ticket.client_address,
        "status": ticket.status,
        "ticket": ticket.ticket,
        "path_b_state": ticket.path_b_state,
    }


async def test_synthetic_router_chat_proxies_mock_host(
    http_client, tenant_headers, control_plane, monkeypatch, caplog
):
    host = MockHost().start()
    try:
        monkeypatch.setenv(CHAT_PORT_ENV, str(host.port))
        caplog.set_level(logging.INFO)
        lease_id = uuid.uuid4()
        ticket = _signed_ticket(lease_id, client_address=host.client_address)
        fixture = _plane_ticket_fixture(ticket)
        assert fixture["lease_id"] == str(lease_id)
        assert fixture["device_id"] == str(FYBER_AGX_DEVICE_ID)
        assert fixture["assigned_router_id"] == str(FYBER_TEST_ROUTER_ID)
        assert fixture["client_address"] == "127.0.0.1/32"
        assert "peer_private_key" not in fixture

        control_plane.tunnels.append(_allocated_tunnel(lease_id, host.client_address))
        control_plane.ticket_pull = TicketPull(tickets=[ticket], revoked_lease_ids=[])
        applied = await http_client.post(
            "/api/v1/hypermesh-gateway/tunnels/apply",
            headers=_router(tenant_headers),
        )
        assert applied.status_code == 200, applied.text
        assert control_plane.list_tickets_calls == 1
        assert control_plane.list_tunnels_calls == 1

        chat = await http_client.post(
            "/v1/chat/completions",
            headers=_renter(tenant_headers),
            json={
                "lease_id": str(lease_id),
                "model": "llama-3.1-8b-q4",
                "messages": [{"role": "user", "content": SECRET_PROMPT}],
            },
        )
        assert chat.status_code == 200, chat.text
        body = chat.json()
        assert body["object"] == "chat.completion"
        assert (
            body["choices"][0]["message"]["content"]
            == MOCK_COMPLETION["choices"][0]["message"]["content"]
        )
        assert host.hits == 1
        assert host.last_path == "/v1/chat/completions"
        assert host.last_content_length > 0
        assert control_plane.get_lease_calls == 0
        assert control_plane.list_tickets_calls == 1
        metric = control_plane.metrics[-1]
        dumped = str(metric) + " ".join(record.getMessage() for record in caplog.records)
        assert SECRET_PROMPT not in dumped
        assert "secret prompt" not in dumped
        assert "messages" not in str(metric)
    finally:
        host.stop()


async def test_synthetic_router_chat_not_ready_without_ticket(
    http_client, tenant_headers, control_plane
):
    lease_id = uuid.uuid4()
    control_plane.ticket_pull = TicketPull(tickets=[], revoked_lease_ids=[])
    await http_client.post(
        "/api/v1/hypermesh-gateway/tunnels/apply",
        headers=_router(tenant_headers),
    )
    refused = await http_client.post(
        "/v1/chat/completions",
        headers=_renter(tenant_headers),
        json={
            "lease_id": str(lease_id),
            "model": "llama-3.1-8b-q4",
            "messages": [{"role": "user", "content": SECRET_PROMPT}],
        },
    )
    assert refused.status_code == 409, refused.text
    assert refused.json()["detail"] == INSTANCE_NOT_READY
    assert control_plane.get_lease_calls == 0
    assert SECRET_PROMPT not in str(control_plane.metrics)
