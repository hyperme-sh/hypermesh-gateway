"""Contextual access for renter chat. JWT local verify or API key.

Portal humans: OIDC JWT validated locally (cached JWKS, or the API-key
exchange JWT). Agents: API key. A paid, active, signed lease ticket is
still required. Purpose lives on that ticket, not here. Completions do
not call Keycloak or Panopticon. Not an IdP. Not a fourth identity:
renter key / JWT, host device_secret, router hm_rtr_, or site hm_site_.

API key is format-only on the completions path: the signed ticket carries the
tenant and the lease, so a forged key reaches nothing. Doors that read
tenant-wide history have no such ticket to bind against and must instead call
require_tenant_bound_grant, which resolves the caller's real tenant.
"""

from __future__ import annotations

import logging
import os
import uuid
from dataclasses import dataclass
from typing import Any, Literal, Protocol

from fastapi import HTTPException, Request

logger = logging.getLogger(__name__)

DEVICE_SECRET_HEAD = "hm_dev_"
ROUTER_SECRET_HEAD = "hm_rtr_"
SITE_TOKEN_HEAD = "hm_site_"
TICKET_PREFIX = "hm1."
RENTER_AUTH_REQUIRED = "API key or access token required"
TENANT_CLAIM = "https://panopticon.dev/tenant_id"


class RenterUnauthorized(HTTPException):
    def __init__(self) -> None:
        super().__init__(status_code=401, detail=RENTER_AUTH_REQUIRED)


@dataclass(frozen=True)
class RenterGrant:
    kind: Literal["jwt", "api_key"]
    subject: str
    claims: dict[str, Any] | None = None


class JwtValidator(Protocol):
    def validate_sync(self, token: str) -> dict[str, Any]: ...

    async def validate(self, token: str) -> dict[str, Any]: ...


def looks_like_jwt(token: str) -> bool:
    if token.startswith((ROUTER_SECRET_HEAD, DEVICE_SECRET_HEAD, SITE_TOKEN_HEAD, TICKET_PREFIX)):
        return False
    parts = token.split(".")
    return len(parts) == 3 and all(parts)


def looks_like_api_key(token: str) -> bool:
    if token.startswith((ROUTER_SECRET_HEAD, DEVICE_SECRET_HEAD, SITE_TOKEN_HEAD, TICKET_PREFIX)):
        return False
    if looks_like_jwt(token):
        return False
    if "." not in token:
        return False
    prefix, secret = token.split(".", 1)
    return bool(prefix) and bool(secret)


def _bearer(request: Request) -> str | None:
    raw = request.headers.get("Authorization")
    if not raw:
        return None
    scheme, _, token = raw.partition(" ")
    if scheme.lower() != "bearer" or not token.strip():
        return None
    return token.strip()


def _api_key_header(request: Request) -> str | None:
    raw = request.headers.get("X-Api-Key") or request.headers.get("x-api-key")
    if not raw or not raw.strip():
        return None
    return raw.strip()


def _forbidden_identity(token: str) -> bool:
    return token.startswith((ROUTER_SECRET_HEAD, DEVICE_SECRET_HEAD, SITE_TOKEN_HEAD, TICKET_PREFIX))


def verify_jwt_locally(
    token: str,
    *,
    validator: JwtValidator | None = None,
) -> dict[str, Any] | None:
    """Honor a portal or API-key-exchange JWT without an OIDC dance.

    Does not call the Keycloak token endpoint. Does not call Panopticon.
    JWKS (when used) is the cached local verify Keycloak already publishes.
    """

    from api.infrastructure.security.api_key_exchange_jwt import try_decode_api_key_session_jwt

    exchanged = try_decode_api_key_session_jwt(token)
    if exchanged is not None:
        return exchanged
    if validator is not None:
        try:
            return validator.validate_sync(token)
        except Exception:
            logger.info("renter jwt rejected")
            return None
    from api.core.config import settings

    if not (settings.keycloak_jwks_url and settings.keycloak_issuer):
        return None
    try:
        from api.infrastructure.security.keycloak_jwt import get_keycloak_jwt_validator

        return get_keycloak_jwt_validator().validate_sync(token)
    except Exception:
        logger.info("renter jwt rejected")
        return None


def _subject_from_jwt(claims: dict[str, Any]) -> str:
    for key in ("email", "preferred_username", "sub"):
        raw = claims.get(key)
        if raw:
            return str(raw)
    return "jwt"


def _subject_from_api_key(token: str) -> str:
    return token.split(".", 1)[0]


def _tenant_matches(claims: dict[str, Any], tenant_id: str | None) -> bool:
    if not tenant_id:
        return True
    raw = claims.get(TENANT_CLAIM) or claims.get("tenant_id")
    if raw is None:
        return True
    return str(raw) == tenant_id


def require_renter_grant(request: Request) -> RenterGrant:
    """JWT local verify or API key. Ticket / posture stay on the chat gate."""

    bearer = _bearer(request)
    header_key = _api_key_header(request)
    tenant_hdr = request.headers.get("X-Tenant-ID")
    validator = getattr(request.app.state, "renter_jwt_validator", None)

    if bearer:
        if _forbidden_identity(bearer):
            raise RenterUnauthorized()
        if looks_like_jwt(bearer):
            claims = verify_jwt_locally(bearer, validator=validator)
            if claims is None or not _tenant_matches(claims, tenant_hdr):
                raise RenterUnauthorized()
            return RenterGrant(kind="jwt", subject=_subject_from_jwt(claims), claims=claims)
        if looks_like_api_key(bearer):
            return RenterGrant(kind="api_key", subject=_subject_from_api_key(bearer))
        raise RenterUnauthorized()

    if header_key:
        if _forbidden_identity(header_key) or not looks_like_api_key(header_key):
            raise RenterUnauthorized()
        return RenterGrant(kind="api_key", subject=_subject_from_api_key(header_key))

    raise RenterUnauthorized()


def _api_keys_base_url() -> str:
    return os.environ.get("HYPERMESH_API_KEYS_URL", "http://api-keys-service:8000").strip()


def _tenant_claim_is(claims: dict[str, Any] | None, tenant_id: uuid.UUID) -> bool:
    """Strict tenant match. A payload with no tenant binds to no tenant."""

    if not claims:
        return False
    raw = claims.get(TENANT_CLAIM) or claims.get("tenant_id")
    if raw is None:
        return False
    try:
        return uuid.UUID(str(raw)) == tenant_id
    except (ValueError, AttributeError, TypeError):
        return False


async def require_tenant_bound_grant(request: Request, tenant_id: uuid.UUID) -> RenterGrant:
    """Prove the caller's credential belongs to tenant_id, not just that it parses.

    For a JWT the tenant claim must be present and match. For an API key the
    key is validated against api-keys-service, which refuses a key registered
    to another tenant. An unreachable or unconfigured api-keys-service denies.
    """

    grant = require_renter_grant(request)
    if grant.kind == "jwt":
        if not _tenant_claim_is(grant.claims, tenant_id):
            raise RenterUnauthorized()
        return grant

    raw = _bearer(request) or _api_key_header(request)
    base_url = _api_keys_base_url()
    if raw is None or not base_url:
        raise RenterUnauthorized()

    validate = getattr(request.app.state, "api_key_validator", None)
    if validate is None:
        from api.infrastructure.externals.api_keys_client import validate_api_key_remote

        validate = validate_api_key_remote

    data = await validate(base_url=base_url, api_key=raw, tenant_id=tenant_id)
    if data is None:
        raise RenterUnauthorized()
    if not _tenant_claim_is(data, tenant_id):
        raise RenterUnauthorized()
    return grant
