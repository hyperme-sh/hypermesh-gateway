"""HTTPS hop to Panopticon with hm_gw_. Pull tickets/tunnels, post metrics.

This is not the chat path. After a ticket is issued, chat uses the cached
signed ticket and the standing WG peer. No WebSocket, no gateway mesh.
"""

from __future__ import annotations

import os
import uuid
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Protocol

import httpx

from hypermesh_gateway_service.tickets import CachedTicket, TicketPull

INSTANCE_NOT_READY = "instance not ready"


@dataclass(frozen=True)
class LeaseView:
    id: uuid.UUID
    status: str
    kind: str
    catalog_id: str | None


@dataclass(frozen=True)
class GatewayTunnel:
    tunnel_id: uuid.UUID
    lease_id: uuid.UUID
    status: str
    endpoint: str
    server_private_key: str | None
    server_public_key: str
    peer_public_key: str | None
    allowed_ips: str
    client_address: str


class ControlPlane(Protocol):
    async def list_tunnels(self, tenant_id: uuid.UUID) -> list[GatewayTunnel]: ...

    async def list_tickets(self, tenant_id: uuid.UUID) -> TicketPull: ...

    async def post_metrics(
        self,
        tenant_id: uuid.UUID,
        *,
        tunnel_id: uuid.UUID | None,
        lease_id: uuid.UUID | None,
        bytes_in: int,
        bytes_out: int,
        handshake_count: int,
        metric_id: uuid.UUID | None = None,
    ) -> None: ...


class HttpControlPlane:
    def __init__(self, base_url: str, service_secret: str) -> None:
        if not service_secret.strip():
            raise ValueError("Gateway service credential required")
        self._base = base_url.rstrip("/")
        self._secret = service_secret

    def _headers(self, tenant_id: uuid.UUID) -> dict[str, str]:
        return {
            "Authorization": f"Bearer {self._secret}",
            "X-Tenant-ID": str(tenant_id),
        }

    async def list_tunnels(self, tenant_id: uuid.UUID) -> list[GatewayTunnel]:
        async with httpx.AsyncClient(timeout=15.0) as client:
            response = await client.get(
                f"{self._base}/api/v1/hypermesh/gateway/tunnels",
                headers=self._headers(tenant_id),
            )
        if response.status_code == 401:
            raise PermissionError("Gateway service credential required")
        response.raise_for_status()
        out: list[GatewayTunnel] = []
        for row in response.json():
            out.append(
                GatewayTunnel(
                    tunnel_id=uuid.UUID(str(row["tunnel_id"])),
                    lease_id=uuid.UUID(str(row["lease_id"])),
                    status=str(row["status"]),
                    endpoint=str(row["endpoint"]),
                    server_private_key=row.get("server_private_key"),
                    server_public_key=str(row["server_public_key"]),
                    peer_public_key=row.get("peer_public_key"),
                    allowed_ips=str(row["allowed_ips"]),
                    client_address=str(row["client_address"]),
                )
            )
        return out

    async def list_tickets(self, tenant_id: uuid.UUID) -> TicketPull:
        async with httpx.AsyncClient(timeout=15.0) as client:
            response = await client.get(
                f"{self._base}/api/v1/hypermesh/gateway/tickets",
                headers=self._headers(tenant_id),
            )
        if response.status_code == 401:
            raise PermissionError("Gateway service credential required")
        response.raise_for_status()
        body = response.json()
        if not isinstance(body, dict):
            body = {}
        tickets: list[CachedTicket] = []
        for row in body.get("tickets", []):
            exp_raw = row.get("exp")
            exp = datetime.fromisoformat(str(exp_raw).replace("Z", "+00:00")) if exp_raw else None
            device_raw = row.get("device_id")
            tickets.append(
                CachedTicket(
                    lease_id=uuid.UUID(str(row["lease_id"])),
                    ticket=str(row["ticket"]),
                    client_address=str(row["client_address"]),
                    assigned_gateway_id=uuid.UUID(str(row["assigned_gateway_id"])),
                    status=str(row.get("status") or "active"),
                    exp=exp,
                    device_id=uuid.UUID(str(device_raw)) if device_raw else None,
                    path_b_state=str(row.get("path_b_state") or ""),
                )
            )
        revoked = [uuid.UUID(str(item)) for item in body.get("revoked_lease_ids", [])]
        fingerprints = [
            str(item).strip().lower()
            for item in body.get("key_fingerprints") or []
            if str(item).strip()
        ]
        return TicketPull(
            tickets=tickets,
            revoked_lease_ids=revoked,
            key_fingerprints=fingerprints,
        )

    async def post_metrics(
        self,
        tenant_id: uuid.UUID,
        *,
        tunnel_id: uuid.UUID | None,
        lease_id: uuid.UUID | None,
        bytes_in: int,
        bytes_out: int,
        handshake_count: int,
        metric_id: uuid.UUID | None = None,
    ) -> None:
        body: dict[str, Any] = {
            "tunnel_id": str(tunnel_id) if tunnel_id else None,
            "lease_id": str(lease_id) if lease_id else None,
            "bytes_in": bytes_in,
            "bytes_out": bytes_out,
            "handshake_count": handshake_count,
        }
        if metric_id is not None:
            body["id"] = str(metric_id)
        async with httpx.AsyncClient(timeout=15.0) as client:
            response = await client.post(
                f"{self._base}/api/v1/hypermesh/gateway/metrics",
                headers=self._headers(tenant_id),
                json=body,
            )
        if response.status_code == 401:
            raise PermissionError("Gateway service credential required")
        response.raise_for_status()


class FakeControlPlane:
    def __init__(
        self,
        *,
        leases: dict[uuid.UUID, LeaseView] | None = None,
        tunnels: list[GatewayTunnel] | None = None,
        service_secret: str = "hm_gw_test",
    ) -> None:
        self.leases = leases or {}
        self.tunnels = tunnels or []
        self.ticket_pull = TicketPull(tickets=[], revoked_lease_ids=[])
        self.service_secret = service_secret
        self.metrics: list[dict[str, Any]] = []
        self.require_secret = True
        self.get_lease_calls = 0
        self.list_tunnels_calls = 0
        self.list_tickets_calls = 0
        self.post_metrics_calls = 0
        self.fail_metrics = False

    async def get_lease(self, tenant_id: uuid.UUID, lease_id: uuid.UUID) -> LeaseView | None:
        self.get_lease_calls += 1
        return self.leases.get(lease_id)

    async def list_tunnels(self, tenant_id: uuid.UUID) -> list[GatewayTunnel]:
        self.list_tunnels_calls += 1
        if self.require_secret and not self.service_secret:
            raise PermissionError("Gateway service credential required")
        return list(self.tunnels)

    async def list_tickets(self, tenant_id: uuid.UUID) -> TicketPull:
        self.list_tickets_calls += 1
        if self.require_secret and not self.service_secret:
            raise PermissionError("Gateway service credential required")
        return TicketPull(
            tickets=list(self.ticket_pull.tickets),
            revoked_lease_ids=list(self.ticket_pull.revoked_lease_ids),
            key_fingerprints=list(self.ticket_pull.key_fingerprints),
        )

    async def post_metrics(
        self,
        tenant_id: uuid.UUID,
        *,
        tunnel_id: uuid.UUID | None,
        lease_id: uuid.UUID | None,
        bytes_in: int,
        bytes_out: int,
        handshake_count: int,
        metric_id: uuid.UUID | None = None,
    ) -> None:
        self.post_metrics_calls += 1
        if self.require_secret and not self.service_secret:
            raise PermissionError("Gateway service credential required")
        if self.fail_metrics:
            raise RuntimeError("metrics plane down")
        recorded: dict[str, Any] = {
            "tenant_id": tenant_id,
            "tunnel_id": tunnel_id,
            "lease_id": lease_id,
            "bytes_in": bytes_in,
            "bytes_out": bytes_out,
            "handshake_count": handshake_count,
        }
        if metric_id is not None:
            recorded["metric_id"] = metric_id
        self.metrics.append(recorded)


def resolve_control_plane(override: ControlPlane | None = None) -> ControlPlane:
    if override is not None:
        return override
    secret = os.environ.get("HYPERMESH_GATEWAY_SERVICE_SECRET", "").strip()
    base = os.environ.get("HYPERMESH_CONTROL_PLANE_URL", "http://hypermesh-service:8000")
    if not secret:
        return FakeControlPlane(service_secret="")
    return HttpControlPlane(base, secret)
