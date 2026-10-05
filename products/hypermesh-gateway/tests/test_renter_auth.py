"""Ticket-only chat access: JWT local verify or API key.

Purpose is a field on the signed ticket (slice 3), not a grant here.
API key stays format-only. Completions do not hop to api-keys-service.
"""

from __future__ import annotations

import uuid
from types import SimpleNamespace

import pytest
from jwt import InvalidTokenError
from starlette.requests import Request

from api.infrastructure.security.api_key_exchange_jwt import mint_api_key_session_jwt
from hypermesh_gateway_service.renter_auth import (
    AUDITOR_GRANT_REQUIRED,
    RENTER_AUTH_REQUIRED,
    RenterGrant,
    RenterUnauthorized,
    looks_like_api_key,
    looks_like_jwt,
    require_auditor_grant,
    require_renter_grant,
    require_ticket_bound_grant,
    verify_jwt_locally,
)
from hypermesh_ticket import renter_key_fingerprint


class _AcceptJwt:
    def __init__(
        self,
        token: str,
        tenant_id: uuid.UUID | None = None,
        *,
        roles: list[str] | None = None,
    ) -> None:
        self.token = token
        self.tenant_id = tenant_id
        self.roles = roles or []
        self.calls = 0

    def validate_sync(self, token: str) -> dict[str, object]:
        self.calls += 1
        if token != self.token:
            raise InvalidTokenError("rejected")
        claims: dict[str, object] = {"sub": "portal-user", "azp": "controlplane-frontend"}
        if self.tenant_id is not None:
            claims["https://panopticon.dev/tenant_id"] = str(self.tenant_id)
        if self.roles:
            claims["realm_access"] = {"roles": list(self.roles)}
            claims["groups"] = list(self.roles)
        return claims

    async def validate(self, token: str) -> dict[str, object]:
        return self.validate_sync(token)


def _request(
    *,
    authorization: str | None = None,
    api_key: str | None = None,
    tenant_id: uuid.UUID | None = None,
    validator: object | None = None,
) -> Request:
    headers: list[tuple[bytes, bytes]] = []
    if authorization is not None:
        headers.append((b"authorization", authorization.encode("ascii")))
    if api_key is not None:
        headers.append((b"x-api-key", api_key.encode("ascii")))
    if tenant_id is not None:
        headers.append((b"x-tenant-id", str(tenant_id).encode("ascii")))
    app = SimpleNamespace(state=SimpleNamespace(renter_jwt_validator=validator))
    scope = {
        "type": "http",
        "method": "POST",
        "path": "/v1/chat/completions",
        "headers": headers,
        "query_string": b"",
        "app": app,
    }
    return Request(scope)


def test_looks_like_jwt_and_api_key_do_not_invent_identities():
    assert looks_like_api_key("pk_test.renter-key") is True
    assert looks_like_jwt("pk_test.renter-key") is False
    assert looks_like_jwt("aaa.bbb.ccc") is True
    assert looks_like_api_key("aaa.bbb.ccc") is False
    assert looks_like_jwt("hm_gw_test") is False
    assert looks_like_api_key("hm_gw_test") is False
    assert looks_like_jwt("hm_dev_box-secret") is False
    assert looks_like_api_key("hm_dev_box-secret") is False
    assert looks_like_jwt("hm1.payload.sig") is False
    assert looks_like_api_key("hm1.payload.sig") is False
    assert looks_like_jwt("hm_site_cottage") is False
    assert looks_like_api_key("hm_site_cottage") is False
    assert looks_like_api_key("noperiod") is False


def test_verify_jwt_locally_honors_exchange_jwt(tenant_id):
    token = mint_api_key_session_jwt(
        key_record_id=uuid.uuid4(),
        tenant_id=tenant_id,
        scopes=[],
    )
    claims = verify_jwt_locally(token)
    assert claims is not None
    assert claims["panopticon_auth"] == "api_key"
    assert claims["https://panopticon.dev/tenant_id"] == str(tenant_id)


def test_verify_jwt_locally_uses_cached_jwks_not_token_endpoint(monkeypatch):
    from api.core import config

    monkeypatch.setattr(config.settings, "keycloak_jwks_url", "http://jwks.example/certs")
    monkeypatch.setattr(config.settings, "keycloak_issuer", "http://kc.example/realms/controlplane")

    class FakeValidator:
        def validate_sync(self, token: str) -> dict[str, object]:
            assert "openid-connect/token" not in token
            return {"sub": "kc-user", "azp": "controlplane-frontend"}

        async def validate(self, token: str) -> dict[str, object]:
            return self.validate_sync(token)

    monkeypatch.setattr(
        "api.infrastructure.security.keycloak_jwt.get_keycloak_jwt_validator",
        lambda: FakeValidator(),
    )
    claims = verify_jwt_locally("portal.jwt.token")
    assert claims is not None
    assert claims["sub"] == "kc-user"


def test_verify_jwt_locally_jwks_failure_is_none(monkeypatch):
    from api.core import config

    monkeypatch.setattr(config.settings, "keycloak_jwks_url", "http://jwks.example/certs")
    monkeypatch.setattr(config.settings, "keycloak_issuer", "http://kc.example/realms/controlplane")

    class FakeValidator:
        def validate_sync(self, token: str) -> dict[str, object]:
            raise InvalidTokenError("bad sig")

        async def validate(self, token: str) -> dict[str, object]:
            return self.validate_sync(token)

    monkeypatch.setattr(
        "api.infrastructure.security.keycloak_jwt.get_keycloak_jwt_validator",
        lambda: FakeValidator(),
    )
    assert verify_jwt_locally("portal.jwt.token") is None


def test_verify_jwt_locally_uses_injected_validator_not_keycloak():
    validator = _AcceptJwt("portal.jwt.token")
    claims = verify_jwt_locally("portal.jwt.token", validator=validator)
    assert claims is not None
    assert claims["sub"] == "portal-user"
    assert validator.calls == 1
    assert verify_jwt_locally("other.jwt.token", validator=validator) is None


def test_require_renter_grant_api_key_bearer():
    grant = require_renter_grant(_request(authorization="Bearer pk_test.renter-key"))
    assert grant.kind == "api_key"
    assert grant.subject == "pk_test"


def test_require_renter_grant_x_api_key_header():
    grant = require_renter_grant(_request(api_key="pk_test.renter-key"))
    assert grant.kind == "api_key"
    assert grant.subject == "pk_test"


def test_require_renter_grant_portal_jwt(tenant_id):
    validator = _AcceptJwt("portal.jwt.token", tenant_id)
    grant = require_renter_grant(
        _request(
            authorization="Bearer portal.jwt.token",
            tenant_id=tenant_id,
            validator=validator,
        )
    )
    assert grant.kind == "jwt"
    assert grant.subject == "portal-user"
    assert validator.calls == 1


def test_require_renter_grant_exchange_jwt(tenant_id):
    token = mint_api_key_session_jwt(
        key_record_id=uuid.uuid4(),
        tenant_id=tenant_id,
        scopes=["chat"],
    )
    grant = require_renter_grant(
        _request(authorization=f"Bearer {token}", tenant_id=tenant_id)
    )
    assert grant.kind == "jwt"


def test_require_renter_grant_rejects_jwt_without_tenant_claim(tenant_id):
    validator = _AcceptJwt("portal.jwt.token")
    with pytest.raises(RenterUnauthorized):
        require_renter_grant(
            _request(
                authorization="Bearer portal.jwt.token",
                tenant_id=tenant_id,
                validator=validator,
            )
        )


def test_require_renter_grant_rejects_jwt_with_neither_header_nor_claim():
    validator = _AcceptJwt("portal.jwt.token")
    with pytest.raises(RenterUnauthorized):
        require_renter_grant(
            _request(authorization="Bearer portal.jwt.token", validator=validator)
        )


def test_require_renter_grant_accepts_jwt_tenant_claim_without_header(tenant_id):
    validator = _AcceptJwt("portal.jwt.token", tenant_id)
    grant = require_renter_grant(
        _request(authorization="Bearer portal.jwt.token", validator=validator)
    )
    assert grant.kind == "jwt"
    assert grant.subject == "portal-user"


def test_require_renter_grant_rejects_wrong_identities_and_bad_jwt():
    validator = _AcceptJwt("good.jwt.token")
    cases = [
        _request(),
        _request(authorization="Bearer hm_gw_test"),
        _request(authorization="Bearer hm_dev_box-secret"),
        _request(authorization="Bearer hm1.payload.sig"),
        _request(authorization="Bearer hm_site_cottage"),
        _request(authorization="Bearer noperiod"),
        _request(authorization="Bearer bad.jwt.token", validator=validator),
        _request(api_key="hm_gw_test"),
    ]
    for request in cases:
        with pytest.raises(RenterUnauthorized) as exc:
            require_renter_grant(request)
        assert exc.value.status_code == 401
        assert exc.value.detail == RENTER_AUTH_REQUIRED


def test_require_renter_grant_rejects_exchange_jwt_for_other_tenant(tenant_id):
    token = mint_api_key_session_jwt(
        key_record_id=uuid.uuid4(),
        tenant_id=tenant_id,
        scopes=[],
    )
    other = uuid.uuid4()
    with pytest.raises(RenterUnauthorized):
        require_renter_grant(_request(authorization=f"Bearer {token}", tenant_id=other))


def test_require_auditor_grant_accepts_ir_purpose_jwt(tenant_id):
    token = mint_api_key_session_jwt(
        key_record_id=uuid.uuid4(),
        tenant_id=tenant_id,
        scopes=[],
        purpose="ir",
    )
    grant = require_auditor_grant(
        _request(authorization=f"Bearer {token}", tenant_id=tenant_id)
    )
    assert grant.kind == "jwt"


def test_require_auditor_grant_rejects_renter_jwt(tenant_id):
    token = mint_api_key_session_jwt(
        key_record_id=uuid.uuid4(),
        tenant_id=tenant_id,
        scopes=[],
        purpose="renter",
    )
    with pytest.raises(RenterUnauthorized) as exc:
        require_auditor_grant(
            _request(authorization=f"Bearer {token}", tenant_id=tenant_id)
        )
    assert exc.value.detail == AUDITOR_GRANT_REQUIRED


def test_require_auditor_grant_accepts_ir_role_session(tenant_id):
    validator = _AcceptJwt("good.jwt.token", tenant_id=tenant_id, roles=["ir"])
    grant = require_auditor_grant(
        _request(
            authorization="Bearer good.jwt.token",
            tenant_id=tenant_id,
            validator=validator,
        )
    )
    assert grant.kind == "jwt"


def test_ticket_bound_grant_accepts_matching_key_and_jwt(tenant_id):
    key = "pk_test.renter-key"
    grant = RenterGrant(kind="api_key", subject="pk_test")
    bound = require_ticket_bound_grant(
        grant,
        ticket_tenant_id=tenant_id,
        key_fingerprints=[renter_key_fingerprint(key)],
        presented_key=key,
    )
    assert bound.kind == "api_key"

    token = mint_api_key_session_jwt(
        key_record_id=uuid.uuid4(),
        tenant_id=tenant_id,
        scopes=[],
    )
    jwt_grant = require_renter_grant(
        _request(authorization=f"Bearer {token}", tenant_id=tenant_id)
    )
    require_ticket_bound_grant(
        jwt_grant,
        ticket_tenant_id=tenant_id,
        key_fingerprints=[],
        presented_key=None,
    )


def test_ticket_bound_grant_rejects_unknown_key_and_unbound_jwt(tenant_id):
    grant = RenterGrant(kind="api_key", subject="pk_test")
    with pytest.raises(RenterUnauthorized):
        require_ticket_bound_grant(
            grant,
            ticket_tenant_id=tenant_id,
            key_fingerprints=[renter_key_fingerprint("pk_test.renter-key")],
            presented_key="attacker.forged",
        )
    with pytest.raises(RenterUnauthorized):
        require_ticket_bound_grant(
            grant,
            ticket_tenant_id=tenant_id,
            key_fingerprints=[],
            presented_key="pk_test.renter-key",
        )
    with pytest.raises(RenterUnauthorized):
        require_ticket_bound_grant(
            RenterGrant(kind="jwt", subject="portal-user", claims={"sub": "portal-user"}),
            ticket_tenant_id=tenant_id,
            key_fingerprints=[],
            presented_key=None,
        )
