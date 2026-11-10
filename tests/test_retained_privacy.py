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
