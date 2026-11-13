"""Startup refuses invalid edge credentials before opening owner resources."""
from types import SimpleNamespace
import pytest
from controlplane_api import config
from hypermesh_gateway_service import app as module

@pytest.mark.asyncio
async def test_secret_guard_precedes_control_plane_and_owner_setup(monkeypatch):
    seen=[]
    def reject():
        seen.append('guard')
        raise ValueError('API_KEYS_INTERNAL_TOKEN is required')
    monkeypatch.setattr(config, 'settings', SimpleNamespace(require_edge_secrets=reject))
    monkeypatch.setattr(module, 'resolve_control_plane', lambda value: seen.append('owner'))
    app=module.create_app()
    with pytest.raises(ValueError, match='API_KEYS_INTERNAL_TOKEN'):
        async with app.router.lifespan_context(app):
            pytest.fail('Application accepted invalid secrets')
    assert seen == ['guard']


@pytest.mark.asyncio
@pytest.mark.parametrize("field,value", [("api_key_exchange_jwt_secret", ""),
    ("api_keys_internal_token", "short"),
    ("api_key_exchange_jwt_secret", "dev-" + "x" * 48)])
async def test_actual_guard_refuses_invalid_settings(monkeypatch, field, value):
    monkeypatch.setattr(config.settings, "edge_secrets_required", True)
    monkeypatch.setattr(config.settings, "api_key_exchange_jwt_secret", "a" * 48)
    monkeypatch.setattr(config.settings, "api_keys_internal_token", "b" * 48)
    monkeypatch.setattr(config.settings, field, value)
    app = module.create_app()
    with pytest.raises(ValueError, match=field.upper()):
        async with app.router.lifespan_context(app):
            pytest.fail("Application accepted invalid credentials")
