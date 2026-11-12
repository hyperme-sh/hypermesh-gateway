"""Async gateway callers preserve the adopted identity lifecycle enforcement."""
import threading

import pytest

from controlplane_identity import account_lifecycle
from hypermesh_gateway_service.renter_auth import require_tenant_bound_grant, RenterUnauthorized
from hypermesh_gateway_service.routes import _authorize_caller
from test_renter_auth import _AcceptJwt, _request


@pytest.mark.parametrize("path", ["renter", "auditor", "receipts"])
@pytest.mark.parametrize("blocked", [False, True, "unavailable"])
async def test_async_grants_enforce_account_state(monkeypatch, tenant_id, path, blocked):
    monkeypatch.setenv("ACCOUNT_CLOSURE_ENFORCEMENT_ENABLED", "true")
    monkeypatch.setenv("ACCOUNT_CLOSURE_GUARD_URL", "https://closure.invalid")
    monkeypatch.setenv("ACCOUNT_CLOSURE_GUARD_TOKEN", "g" * 40)
    thread = threading.get_ident()
    calls = []

    async def no_remote_guard(*args, **kwargs):
        pytest.fail("Authorization must use local state")

    monkeypatch.setattr(account_lifecycle, "_post_json", no_remote_guard)

    class Ledger:
        def tenant_ready(self, tenant):
            return True

        def claims_blocked(self, claims):
            from hypermesh_gateway_service.account_ledger import LedgerUnavailable
            assert threading.get_ident() != thread
            calls.append(claims)
            if blocked == "unavailable":
                raise LedgerUnavailable()
            return blocked

    class Validator(_AcceptJwt):
        def validate_sync(self, token):
            claims = super().validate_sync(token)
            account_lifecycle.require_open_account(claims)
            return claims

    request = _request(authorization="Bearer a.b.c", tenant_id=tenant_id,
                       validator=Validator("a.b.c", tenant_id, roles=["ir"]))

    request.app.state.account_ledger = Ledger()
    request.app.state.ticket_cache = object()

    async def authorize():
        if path == "receipts":
            return await require_tenant_bound_grant(request, tenant_id)
        grant, tenant, key = await _authorize_caller(request, ir=path == "auditor")
        assert tenant == tenant_id and key is None
        return grant

    if blocked is False:
        assert (await authorize()).kind == "jwt"
    else:
        with pytest.raises(RenterUnauthorized):
            await authorize()
    assert calls
