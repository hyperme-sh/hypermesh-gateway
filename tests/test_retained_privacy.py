from types import SimpleNamespace

from fastapi import HTTPException
import pytest
from hypermesh_gateway_service import retained_privacy as privacy
from hypermesh_gateway_service.renter_auth import RenterGrant


@pytest.mark.parametrize("extra", [{"spanopticon_auth":"api_key"}, {"key_id":"fixture"}, {"sub":"apikey:fixture"}])
def test_exchanged_key_cannot_withdraw_account_consent(monkeypatch, extra):
    claims = {"sub": "fixture", "tenant_id": "8a7e3eed-2eb4-42b9-a1ea-73e98b304946", **extra}
    monkeypatch.setattr(privacy, "require_renter_grant", lambda _: RenterGrant("jwt", "fixture", claims))
    with pytest.raises(HTTPException) as denied:
        privacy.account(SimpleNamespace())
    assert denied.value.status_code == 403


@pytest.mark.asyncio
@pytest.mark.parametrize("operation", ["withdraw", "delete_submissions"])
async def test_account_validation_runs_without_an_event_loop(monkeypatch, operation):
    import asyncio
    from fastapi import Response

    class Authenticated(Exception):
        pass

    def validate(request):
        with pytest.raises(RuntimeError, match="no running event loop"):
            asyncio.get_running_loop()
        raise Authenticated

    monkeypatch.setattr("hypermesh_gateway_service.renter_auth.require_renter_grant", validate)
    with pytest.raises(Authenticated):
        if operation == "withdraw":
            await privacy.withdraw(SimpleNamespace(), privacy.Withdrawal(enabled=False), Response())
        else:
            await privacy.delete_submissions(SimpleNamespace(), Response())
