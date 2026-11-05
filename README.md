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

## Release channels

Successful main-push validation retains the validated Python wheel and source distribution and publishes
an immutable `test-<commit>` GitHub prerelease. Push a `vMAJOR.MINOR.PATCH`
tag at that tested commit to promote the exact files to a stable release,
without rebuilding. Repository visibility applies to all package assets.
Package metadata versions are preserved; these are GitHub distribution snapshots,
not automatic PyPI publication or service deployment.

Promotion requires the original Actions artifact (90-day requested retention;
organization policy may shorten it). Expired evidence fails closed: validate a
new main revision. The publisher verifies the run, source, workflow and artifact
digest independently of release metadata. Repository immutable releases must be
enabled. See the [shared release contract](https://github.com/hyperme-sh/.github/blob/7749591fccd30d46ba9b0adabe82114001c9d0de/actions/release-channel/README.md).

The credential-attribution regressions adopted from Panopticon #702 exercise
both renter and IR chat paths, including edge-prefixed aliases. Dual-header
requests must stop before key validation, approval lookup, receipt creation,
safety attribution or host calls. A single valid IR key must own the approval,
receipt and safety subject. The equivalent runtime guard was already present
in the standalone import; these tests qualify that behavior without replacing it.
The source's retirement-aware bootstrap verifier is not yet adopted and remains
part of issue #18's separate closure work.

### Package preparation

`bash scripts/check-package.sh --fixtures` runs the existing source, fresh-wheel
and rebuilt-source-archive consumers without private Git credentials. Fixtures
are built from the exact clean Git revisions already pinned by this package;
the manifest records their digests and source provenance. The verifier checks
root metadata, the complete active lock graph and transitive wheel metadata.
Explicit private extras and unrecognized conditional pins fail closed.

The read-only pull-request workflow retains tested wheels, source archives and
an artifact-derived runtime inventory as Actions artifacts. It does not publish
releases. These are preparation evidence, not an accepted synchronized dependency
baseline: package version alignment, dependency adoption and comparison against
a qualified prior baseline remain separate work. Existing owner test boundaries
and live/provider qualification requirements continue to apply.
