""" /ready is process health. The completions signal is per lease and rate-limited."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread

import pytest

from hypermesh_gateway_service.chat import CHAT_PORT_ENV
from hypermesh_gateway_service.completions_signal import SIGNAL_INTERVAL_ENV
from hypermesh_gateway_service.tickets import CachedTicket
from hypermesh_service.seed import (
    FYBER_AGX_DEVICE_ID,
    FYBER_TEST_GATEWAY_ID,
    MARKETPLACE_TENANT_ID,
)
from hypermesh_service.ticket import TicketClaims, issue_ticket

TEST_RENTER_KEY = "pk_test.renter-key"


def _gateway(tenant_headers: dict[str, str]) -> dict[str, str]:
    return {**tenant_headers, "Authorization": "Bearer hm_gw_test"}


def _renter(tenant_headers: dict[str, str]) -> dict[str, str]:
    return {**tenant_headers, "Authorization": f"Bearer {TEST_RENTER_KEY}"}


def _signed_ticket(lease_id: uuid.UUID, client_address: str, *, device_id: uuid.UUID) -> CachedTicket:
    exp = datetime.now(UTC) + timedelta(hours=1)
    token = issue_ticket(
        TicketClaims(
            lease_id=lease_id,
            device_id=device_id,
            gateway_id=FYBER_TEST_GATEWAY_ID,
            client_address=client_address,
            status="active",
            exp=exp,
            tenant_id=MARKETPLACE_TENANT_ID,
        )
    )
    return CachedTicket(
        lease_id=lease_id,
        ticket=token,
        client_address=client_address,
        assigned_gateway_id=FYBER_TEST_GATEWAY_ID,
        status="active",
        exp=exp,
        device_id=device_id,
        path_b_state="green",
        peer_public_key="peer-pub-signal",
    )


class _Host:
    def __init__(self) -> None:
        self.gets = 0
        self.posts = 0
        self._server: ThreadingHTTPServer | None = None
        self._thread: Thread | None = None

    @property
    def client_address(self) -> str:
        return "127.0.0.1/32"

    @property
    def port(self) -> int:
        if self._server is None:
            raise RuntimeError("host is not started")
        return int(self._server.server_address[1])

    def start(self) -> _Host:
        owner = self

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:
                if self.path != "/v1/chat/completions":
                    self.send_response(404)
                    self.end_headers()
                    return
                owner.gets += 1
                body = b'{"object":"chat.completion"}'
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_POST(self) -> None:
                length = int(self.headers.get("Content-Length") or 0)
                if length:
                    self.rfile.read(length)
                owner.posts += 1
                if self.path != "/v1/chat/completions":
                    self.send_response(404)
                    self.end_headers()
                    return
                body = (
                    b'{"object":"chat.completion","choices":[{"message":{"content":"ready"}}]}'
                )
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, format: str, *args: object) -> None:
                del format, args

        self._server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self._thread = Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()
        return self

    def stop(self) -> None:
        if self._server is not None:
            self._server.shutdown()
            self._server.server_close()
        if self._thread is not None:
            self._thread.join(timeout=2)
        self._server = None
        self._thread = None


@pytest.mark.asyncio
async def test_ready_stays_up_when_one_lease_host_is_down(
    http_client, tenant_headers, app, tenant_id, monkeypatch
):
    up = _Host().start()
    down = _Host().start()
    lease_up = uuid.uuid4()
    lease_down = uuid.uuid4()
    other_device = uuid.UUID("a6400000-0640-4000-8000-000000000099")
    try:
        monkeypatch.setenv(CHAT_PORT_ENV, str(up.port))
        monkeypatch.setenv(SIGNAL_INTERVAL_ENV, "60")
        app.state.ticket_cache.put(
            tenant_id, _signed_ticket(lease_up, up.client_address, device_id=FYBER_AGX_DEVICE_ID)
        )
        down_port = down.port
        down.stop()
        monkeypatch.setenv(CHAT_PORT_ENV, str(down_port))
        app.state.ticket_cache.put(
            tenant_id,
            _signed_ticket(lease_down, down.client_address, device_id=other_device),
        )

        ready = await http_client.get(
            "/api/v1/hypermesh-gateway/ready",
            headers=_gateway(tenant_headers),
        )
        assert ready.status_code == 200
        assert ready.json()["status"] == "ready"

        monkeypatch.setenv(CHAT_PORT_ENV, str(up.port))
        signal_up = await http_client.get(
            f"/api/v1/hypermesh-gateway/leases/{lease_up}/completions-signal",
            headers=_gateway(tenant_headers),
        )
        assert signal_up.status_code == 200, signal_up.text
        assert signal_up.json()["completions"] == "up"
        assert signal_up.json()["cached"] is False
        assert up.gets == 1
        assert up.posts == 0

        again = await http_client.get(
            f"/api/v1/hypermesh-gateway/leases/{lease_up}/completions-signal",
            headers=_gateway(tenant_headers),
        )
        assert again.json()["completions"] == "up"
        assert again.json()["cached"] is True
        assert up.gets == 1

        monkeypatch.setenv(CHAT_PORT_ENV, str(down_port))
        signal_down = await http_client.get(
            f"/api/v1/hypermesh-gateway/leases/{lease_down}/completions-signal",
            headers=_gateway(tenant_headers),
        )
        assert signal_down.status_code == 200, signal_down.text
        assert signal_down.json()["completions"] == "down"

        ready_again = await http_client.get(
            "/api/v1/hypermesh-gateway/ready",
            headers=_gateway(tenant_headers),
        )
        assert ready_again.status_code == 200
        assert ready_again.json()["status"] == "ready"

        monkeypatch.setenv(CHAT_PORT_ENV, str(up.port))
        chat = await http_client.post(
            "/v1/chat/completions",
            headers=_renter(tenant_headers),
            json={
                "lease_id": str(lease_up),
                "messages": [{"role": "user", "content": "Reply with the single word ready."}],
            },
        )
        assert chat.status_code == 200, chat.text
        assert chat.json()["choices"][0]["message"]["content"] == "ready"
        assert up.posts == 1
        assert "path_b" not in signal_up.text
        assert "path_b" not in signal_down.text
    finally:
        up.stop()
        down.stop()
