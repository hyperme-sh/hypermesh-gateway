# Hypermesh gateway

Ticket-authorized renter chat and WireGuard gateway. Package
`hypermesh-gateway-service` 0.1.0; factory
`hypermesh_gateway_service.app.create_app`; entry point
`python -m hypermesh_gateway_service.main`.

The control plane assigns gateway/host peers and signed lease tickets. This
service caches and validates tickets, applies configured peer updates and proxies
authorized chat requests to the assigned host. Ticket contracts come from the
separate `hypermesh-ticket` package; no control-plane service internals are copied.
The bundled IR taxonomy JSON is included in both distributions.

Health is `/api/v1/health/`; version is `/version`; OpenAPI is `/openapi.json`.
`edge-routes.json` describes the routing contract. Authentication, tenant binding,
lease purpose, ticket expiry/revocation and host admission checks remain required.
Safety screening and request-body limits apply before forwarding.
Supply exactly one credential header: `Authorization` or `X-Api-Key`. Requests
containing both are rejected before authorization or approval lookup, including
when one header is empty or malformed.

## Development

Use Python 3.13 and uv 0.11.26 with read access to the eight pinned private
repositories named in `.github/workflows/package.yml`.

    uv sync --frozen
    bash scripts/check-package.sh

Checks run source tests, a normally installed wheel outside the checkout, and a
rebuilt source distribution. Wheel runtime and bundled resource bytes must match
source. Tests use fake control planes, mocked HTTP hosts and mocked command
execution; they do not qualify real WireGuard, host enrollment, upstream model
serving, deployment or consumer cutover.

For isolated development keep `HYPERMESH_WG_APPLY=0` and
`HYPERMESH_ASSIGNMENT_REFRESH_S=0`; inject a fake control plane. Real operation
requires explicitly configured gateway credentials, ticket signing trust,
control-plane access and host networking. Never reuse test credentials.

The main-only shared-runner workflow uses pinned actions, read-only contents and exact
repository credential headers. Actions remains disabled pending scoped
`DEPENDENCY_READ_TOKEN` access and shared-runner qualification. Standalone container and
network integration need separate qualification before deployment.
