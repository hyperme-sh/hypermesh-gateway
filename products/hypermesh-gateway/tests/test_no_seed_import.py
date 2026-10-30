"""Gateway source and images use the family protocol without service internals."""

from __future__ import annotations

import ast
import importlib
import sys
from pathlib import Path

ROUTER_ROOT = Path(__file__).resolve().parents[1]
ROUTER_SRC = ROUTER_ROOT / "src" / "hypermesh_gateway_service"
ROUTER_DOCKERFILE = ROUTER_ROOT / "Dockerfile"


def _service_import_hits(path: Path) -> list[str]:
    tree = ast.parse(path.read_text(), filename=str(path))
    hits: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            module = node.module or ""
            if module == "hypermesh_service" or module.startswith("hypermesh_service."):
                hits.append(f"{path.name}:{node.lineno}")
        elif isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name == "hypermesh_service" or alias.name.startswith(
                    "hypermesh_service."
                ):
                    hits.append(f"{path.name}:{node.lineno}")
    return hits


def test_gateway_runtime_source_does_not_import_hypermesh_service():
    offenders: list[str] = []
    for path in ROUTER_SRC.rglob("*.py"):
        offenders.extend(_service_import_hits(path))
    assert offenders == [], f"gateway image does not ship Hypermesh service files: {offenders}"


def test_gateway_dockerfile_does_not_copy_hypermesh_service_seed():
    text = ROUTER_DOCKERFILE.read_text()
    assert "hypermesh_service/seed.py" not in text
    assert "hypermesh_service/ticket.py" not in text
    assert "COPY products/hypermesh " not in text
    assert "COPY products/hypermesh-ticket " in text


def test_routes_reload_does_not_load_hypermesh_service_seed():
    sys.modules.pop("hypermesh_service.seed", None)
    import hypermesh_gateway_service.routes as routes

    importlib.reload(routes)
    assert "hypermesh_service.seed" not in sys.modules
    from hypermesh_gateway_service.tenants import MARKETPLACE_TENANT_ID

    assert routes.MARKETPLACE_TENANT_ID == MARKETPLACE_TENANT_ID


def test_seed_watched_tenants_uses_in_gateway_marketplace_id(monkeypatch):
    sys.modules.pop("hypermesh_service.seed", None)
    from hypermesh_gateway_service.routes import seed_watched_tenants
    from hypermesh_gateway_service.tenants import MARKETPLACE_TENANT_ID
    from hypermesh_gateway_service.tickets import TicketCache

    monkeypatch.delenv("HYPERMESH_TENANT_IDS", raising=False)
    cache = TicketCache()
    seed_watched_tenants(cache)
    assert MARKETPLACE_TENANT_ID in cache.known_tenants()
    assert "hypermesh_service.seed" not in sys.modules


def test_seed_watched_tenants_honors_hypermesh_tenant_ids(monkeypatch):
    import uuid

    from hypermesh_gateway_service.routes import seed_watched_tenants
    from hypermesh_gateway_service.tenants import MARKETPLACE_TENANT_ID
    from hypermesh_gateway_service.tickets import TicketCache

    extra = uuid.UUID("11111111-1111-4111-8111-111111111111")
    monkeypatch.setenv("HYPERMESH_TENANT_IDS", f"{extra},")
    cache = TicketCache()
    seed_watched_tenants(cache)
    assert extra in cache.known_tenants()
    assert MARKETPLACE_TENANT_ID not in cache.known_tenants()


def test_create_app_does_not_import_hypermesh_service_seed(monkeypatch):
    monkeypatch.setenv("HYPERMESH_ASSIGNMENT_REFRESH_S", "0")
    monkeypatch.setenv("HYPERMESH_WG_APPLY", "0")
    sys.modules.pop("hypermesh_service.seed", None)
    import hypermesh_gateway_service.app as app_mod

    importlib.reload(app_mod)
    app_mod.create_app()
    assert "hypermesh_service.seed" not in sys.modules
