"""Contextual access for renter chat. JWT local verify or API key.

Portal humans: OIDC JWT validated locally (cached JWKS, or the API-key
exchange JWT). Agents: API key. A paid, active, signed lease ticket is
still required. Purpose lives on that ticket, not here. Completions do
not call Keycloak or (s)panopticon. Not an IdP. Not a fourth identity:
renter key / JWT, host device_secret, gateway hm_gw_, or site hm_site_.

API key format is only the first parse. Chat then binds the credential to the
signed ticket: JWT tenant claim must match the ticket tenant, and an API key
must hash to a fingerprint the plane pushed on GET /gateway/tickets. Doors
that read tenant-wide history have no ticket to bind against and must instead
call require_tenant_bound_grant, which resolves the caller's real tenant.
"""

from __future__ import annotations

import hmac
import logging
import os
import uuid
from collections.abc import Collection
from dataclasses import dataclass
from typing import Any, Literal, Protocol

from hypermesh_ticket import renter_key_fingerprint

from fastapi import HTTPException, Request

logger = logging.getLogger(__name__)

DEVICE_SECRET_HEAD = "hm_dev_"
GATEWAY_SECRET_HEAD = "hm_gw_"
SITE_TOKEN_HEAD = "hm_site_"
TICKET_PREFIX = "hm1."
RENTER_AUTH_REQUIRED = "API key or access token required"
AUDITOR_GRANT_REQUIRED = "IR purpose key or ir role JWT required"
TENANT_CLAIM = "https://spanopticon.dev/tenant_id"
AUDITOR_JWT_PURPOSES = frozenset({"ir"})
AUDITOR_JWT_ROLES = frozenset({"ir", "ir_export"})


class RenterUnauthorized(HTTPException):
    def __init__(self, detail: str = RENTER_AUTH_REQUIRED) -> None:
        super().__init__(status_code=401, detail=detail)


@dataclass(frozen=True)
class RenterGrant:
    kind: Literal["jwt", "api_key"]
    subject: str
    claims: dict[str, Any] | None = None


class JwtValidator(Protocol):
    def validate_sync(self, token: str) -> dict[str, Any]: ...

    async def validate(self, token: str) -> dict[str, Any]: ...


def looks_like_jwt(token: str) -> bool:
    if token.startswith((GATEWAY_SECRET_HEAD, DEVICE_SECRET_HEAD, SITE_TOKEN_HEAD, TICKET_PREFIX)):
        return False
    parts = token.split(".")
    return len(parts) == 3 and all(parts)


def looks_like_api_key(token: str) -> bool:
    if token.startswith((GATEWAY_SECRET_HEAD, DEVICE_SECRET_HEAD, SITE_TOKEN_HEAD, TICKET_PREFIX)):
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


def _reject_ambiguous_credentials(request: Request) -> None:
    # Reject even malformed/empty dual headers: never derive a subject from
    # one credential and authorize it using another credential.
    if "Authorization" in request.headers and "X-Api-Key" in request.headers:
        raise RenterUnauthorized()


def _forbidden_identity(token: str) -> bool:
    return token.startswith((GATEWAY_SECRET_HEAD, DEVICE_SECRET_HEAD, SITE_TOKEN_HEAD, TICKET_PREFIX))


def verify_jwt_locally(
    token: str,
    *,
    validator: JwtValidator | None = None,
) -> dict[str, Any] | None:
    """Honor a portal or API-key-exchange JWT without an OIDC dance.

    Does not call the Keycloak token endpoint. Does not call (s)panopticon.
    JWKS (when used) is the cached local verify Keycloak already publishes.
    """

    from controlplane_identity.security.api_key_exchange_jwt import try_decode_api_key_session_jwt

    exchanged = try_decode_api_key_session_jwt(token)
    if exchanged is not None:
        return exchanged
    if validator is not None:
        try:
            return validator.validate_sync(token)
        except Exception:
            logger.info("renter jwt rejected")
            return None
    from controlplane_api.config import settings

    if not (settings.keycloak_jwks_url and settings.keycloak_issuer):
        return None
    try:
        from controlplane_identity.security.keycloak_jwt import get_keycloak_jwt_validator

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
    """Missing tenant claim is a miss. A header-only tenant is not a grant."""

    if not tenant_id:
        raw = claims.get(TENANT_CLAIM) or claims.get("tenant_id")
        return raw is not None and str(raw).strip() != ""
    try:
        return _tenant_claim_is(claims, uuid.UUID(str(tenant_id)))
    except (ValueError, AttributeError, TypeError):
        return False


def _jwt_is_auditor(claims: dict[str, Any] | None) -> bool:
    """IR door grant. Purpose=ir exchange JWT or an ir / ir_export role."""

    if not claims:
        return False
    purpose = str(claims.get("purpose") or "").strip().lower()
    if purpose in AUDITOR_JWT_PURPOSES:
        return True
    roles: list[str] = []
    ra = claims.get("realm_access")
    if isinstance(ra, dict):
        raw_roles = ra.get("roles")
        if isinstance(raw_roles, list):
            roles.extend(str(item).strip() for item in raw_roles)
    groups = claims.get("groups")
    if isinstance(groups, list):
        roles.extend(str(item).strip() for item in groups)
    return any(role in AUDITOR_JWT_ROLES for role in roles)


def require_auditor_grant(request: Request, *, bind_tenant_header: bool = True) -> RenterGrant:
    """IR classify grant. A renter key or renter-only JWT is not enough."""

    grant = require_renter_grant(request, bind_tenant_header=bind_tenant_header)
    if grant.kind == "jwt" and not _jwt_is_auditor(grant.claims):
        raise RenterUnauthorized(AUDITOR_GRANT_REQUIRED)
    return grant


def require_renter_grant(request: Request, *, bind_tenant_header: bool = True) -> RenterGrant:
    """JWT local verify or API key. Ticket / posture stay on the chat gate.

    ``bind_tenant_header`` false lets the door compare X-Tenant-ID itself and
    answer 403 tenant_mismatch. The default still rejects a mismatched header.
    """

    _reject_ambiguous_credentials(request)
    bearer = _bearer(request)
    header_key = _api_key_header(request)
    tenant_hdr = request.headers.get("X-Tenant-ID") if bind_tenant_header else None
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


def presented_renter_key(request: Request) -> str | None:
    _reject_ambiguous_credentials(request)
    header_key = _api_key_header(request)
    if header_key and looks_like_api_key(header_key) and not _forbidden_identity(header_key):
        return header_key
    bearer = _bearer(request)
    if bearer and looks_like_api_key(bearer) and not _forbidden_identity(bearer):
        return bearer
    return None


def require_ticket_bound_grant(
    grant: RenterGrant,
    *,
    ticket_tenant_id: uuid.UUID,
    key_fingerprints: Collection[str],
    presented_key: str | None,
) -> RenterGrant:
    """Prove the caller owns a credential for the ticket's tenant. Local only."""

    if grant.kind == "jwt":
        if not _tenant_claim_is(grant.claims, ticket_tenant_id):
            raise RenterUnauthorized()
        return grant
    if not presented_key:
        raise RenterUnauthorized()
    fingerprint = renter_key_fingerprint(presented_key)
    accepted = [str(item).strip().lower() for item in key_fingerprints if str(item).strip()]
    if not accepted or not any(hmac.compare_digest(fingerprint, item) for item in accepted):
        raise RenterUnauthorized()
    return grant


def jwt_tenant_id(grant: RenterGrant) -> uuid.UUID | None:
    if grant.kind != "jwt":
        return None
    return _uuid_claim(grant.claims)


def _uuid_claim(claims: dict[str, Any] | None) -> uuid.UUID | None:
    if not claims:
        return None
    raw = claims.get(TENANT_CLAIM) or claims.get("tenant_id")
    if raw is None:
        return None
    try:
        return uuid.UUID(str(raw))
    except (ValueError, AttributeError, TypeError):
        return None


_LOCAL_ENVS = frozenset({"development", "dev", "local"})


def remote_key_validate_required() -> bool:
    """Remote api-keys validate is required on test and prod.

    ``HYPERMESH_REQUIRE_KEY_VALIDATE=1`` forces it on and ``=0`` forces it
    off. Unset, it is on unless this process is local/dev
    (``FASTAPI_ENV=development`` or ``HYPERMESH_DEV=1``).
    """

    flag = os.environ.get("HYPERMESH_REQUIRE_KEY_VALIDATE", "").strip().lower()
    if flag in {"1", "true", "yes", "on"}:
        return True
    if flag in {"0", "false", "no", "off"}:
        return False
    if os.environ.get("HYPERMESH_DEV", "").strip().lower() in {"1", "true", "yes", "on"}:
        return False
    raw = os.environ.get("FASTAPI_ENV")
    if raw is None or not raw.strip():
        from controlplane_api.config import settings

        raw = settings.fastapi_env
    return (raw or "development").strip().lower() not in _LOCAL_ENVS


def remote_key_validate_enabled(request: Request) -> bool:
    """True when validate must run, a validator is injected, or a token is set."""

    if getattr(request.app.state, "api_key_validator", None) is not None:
        return True
    if remote_key_validate_required():
        return True
    from controlplane_api.config import settings

    return bool(settings.usable_api_keys_internal_token())


async def confirm_api_key_live(
    request: Request,
    *,
    tenant_id: uuid.UUID,
    raw_key: str,
    fingerprint: str,
    cache: Any,
) -> uuid.UUID | None:
    """Re-check a key against api-keys-service at most once per TTL.

    Local/dev with no token trusts the fingerprint pull. Test and prod
    require api-keys-service. A check that fails, or a revoked key, is
    unauthorized. A fresh positive result is not asked again until
    ``cache.key_ttl_s`` (default 60s), so a revoked key stops working
    within 60 seconds. Returns the key id when the validator reported one.
    """

    if not remote_key_validate_enabled(request):
        return cache.key_id_for(fingerprint)
    if cache.key_is_fresh(fingerprint):
        return cache.key_id_for(fingerprint)
    data = await _validate_presented_key(request, raw_key=raw_key, tenant_id=tenant_id)
    if data is None or not _tenant_claim_is(data, tenant_id):
        cache.purge_key(fingerprint)
        raise RenterUnauthorized()
    key_id: uuid.UUID | None = None
    raw_id = data.get("key_id")
    if raw_id:
        try:
            key_id = uuid.UUID(str(raw_id))
        except (ValueError, AttributeError, TypeError):
            key_id = None
    cache.remember_key(fingerprint, key_id)
    return key_id


def _api_keys_base_url() -> str:
    return os.environ.get("HYPERMESH_API_KEYS_URL", "http://api-keys-service:8000").strip()


async def _validate_presented_key(
    request: Request, *, raw_key: str, tenant_id: uuid.UUID
) -> dict[str, Any] | None:
    base_url = _api_keys_base_url()
    if not raw_key or not base_url:
        return None
    validate = getattr(request.app.state, "api_key_validator", None)
    if validate is None:
        from controlplane_identity.api_keys_client import validate_api_key_remote

        validate = validate_api_key_remote
    return await validate(base_url=base_url, api_key=raw_key, tenant_id=tenant_id)


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
        from controlplane_identity.api_keys_client import validate_api_key_remote

        validate = validate_api_key_remote

    data = await validate(base_url=base_url, api_key=raw, tenant_id=tenant_id)
    if data is None:
        raise RenterUnauthorized()
    if not _tenant_claim_is(data, tenant_id):
        raise RenterUnauthorized()
    return grant
