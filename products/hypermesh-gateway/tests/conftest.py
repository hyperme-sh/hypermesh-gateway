from __future__ import annotations

import uuid

import pytest

from api.core import config as api_config

from hypermesh_gateway_service.app import create_app
from hypermesh_gateway_service.control_plane import FakeControlPlane, GatewayTunnel, LeaseView
from hypermesh_gateway_service.tenants import MARKETPLACE_TENANT_ID


@pytest.fixture(autouse=True)
def _clear_ir_taxonomy_override(monkeypatch):
    monkeypatch.delenv("HYPERMESH_IR_TAXONOMY_PACK", raising=False)
    monkeypatch.delenv("AIUDITOR_SERVICE_URL", raising=False)
    monkeypatch.delenv("AIUDITOR_INTERNAL_TOKEN", raising=False)
    monkeypatch.setenv("HYPERMESH_IR_RECEIPT_PATH", "memory")
    monkeypatch.setenv("HYPERMESH_PORTAL_ORIGIN", "https://portal.test.hyperme.sh")
    monkeypatch.setenv("FASTAPI_ENV", "development")
    monkeypatch.delenv("HYPERMESH_REQUIRE_KEY_VALIDATE", raising=False)
    monkeypatch.setattr(
        api_config.settings,
        "api_key_exchange_jwt_secret",
        "test-api-key-exchange-secret-min-32-chars!!",
    )


def stub_api_key_validator(answers: uuid.UUID | None):
    """Stand in for api-keys-service. answers is the tenant it says owns the key.

    None means it refused the key. Assign to app.state.api_key_validator.
    """

    async def validate(
        *,
        base_url: str,
        api_key: str,
        tenant_id: uuid.UUID,
        timeout_s: float = 5.0,
    ) -> dict | None:
        if answers is None:
            return None
        return {"valid": True, "tenant_id": str(answers), "scopes": [], "purpose": "renter"}

    return validate


@pytest.fixture
def tenant_id() -> uuid.UUID:
    return MARKETPLACE_TENANT_ID


@pytest.fixture
def tenant_headers(tenant_id: uuid.UUID) -> dict[str, str]:
    return {"X-Tenant-ID": str(tenant_id)}


@pytest.fixture
def control_plane() -> FakeControlPlane:
    return FakeControlPlane(service_secret="hm_gw_test")


@pytest.fixture
def app(control_plane, monkeypatch):
    monkeypatch.setenv("HYPERMESH_WG_APPLY", "0")
    monkeypatch.setenv("HYPERMESH_ASSIGNMENT_REFRESH_S", "0")
    monkeypatch.setenv("HYPERMESH_TICKET_HMAC_KEY", "test-plane-hypermesh-ticket-hmac")
    return create_app(
        control_plane=control_plane,
        gateway_service_secret="hm_gw_test",
    )


@pytest.fixture
async def http_client(app, tenant_id):
    import httpx
    from asgi_lifespan import LifespanManager
    from hypermesh_service.ticket import renter_key_fingerprint

    async with LifespanManager(app):
        app.state.ticket_cache.accept_keys(
            tenant_id, [renter_key_fingerprint("pk_test.renter-key")]
        )
        app.state.ticket_cache.accept_ir_keys(
            tenant_id, [renter_key_fingerprint("pk_test.ir-key")]
        )
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            yield client
