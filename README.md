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

Main validation retains its exact qualified files in Actions artifacts. It does
not create GitHub releases or tags. Historical `test-<commit>` prereleases remain
qualification evidence and do not establish an accepted stable release.

Stable publication requires an explicit `vMAJOR.MINOR.PATCH` tag, the exact
successful main validation artifact, compatible declared contracts and an actual
immutable stable baseline. The publisher independently verifies that evidence;
successful caller jobs alone cannot establish acceptance. Missing evidence and
first-stable bootstrap remain closed. Package qualification, coordinated consumer
acceptance and runtime deployment remain separate.

### Package preparation

`bash scripts/check-package.sh --fixtures` runs the existing source, fresh-wheel
and rebuilt-source-archive consumers without private Git credentials. Fixtures
are verified existing 0.24 dependency artifacts; the manifest records their exact
source revisions, digests and original Actions provenance. The verifier checks
root metadata, the complete active lock graph and transitive wheel metadata.
Explicit private extras and unrecognized conditional pins fail closed.

The read-only pull-request workflow retains tested wheels, source archives and
artifact-derived runtime and installer contracts as Actions artifacts. It does
not publish releases. The private dependency graph is prepared on 0.24 using immutable Git pins and
matching artifacts. The owner version remains 0.1.0; coordinated owner-version
adoption and stable release acceptance remain unfinished.

`releases/qualification` records a verified prior immutable test snapshot and its
original Actions provenance. It is qualification evidence, not an accepted stable
release, and must not configure the stable release baseline variable.
`releases/prepared` identifies the exact prepared wheel by digest. Package tests
verify that binding and compare the rebuilt source archive's contract. Contracts
include runtime resources, Python constraints, dependencies, extras and entry
points. An explicit qualification-only transition lists the old and new private
pins and binds them to the complete 0.24 fixture graph. Runtime bytes, Python
constraints, registry requirements, extras and entry points must remain unchanged.
Source, installed-wheel and rebuilt-archive consumers qualify this exact graph;
this does not waive stable admission or authorize arbitrary dependency changes.
Existing owner test boundaries and live/provider qualification requirements apply.

## Test qualification and stable acceptance

GitHub `test-<commit>` prereleases are development snapshots. Their embedded
package version does not reserve a stable version. Artifact and consumer evidence
belongs under `releases/qualification`. Owning-package and artifact validation
remain separate from stable release admission. Future test receipts must carry
an explicit non-stable classification.

`releases/accepted` and `SPANOPTICON_RELEASE_BASELINE_SHA` are reserved for an
actual immutable stable GitHub release. The pinned shared guard verifies the live
release channel, stable tag source and asset digests; a test snapshot cannot
become accepted through a provenance label. No stable baseline is recorded until
that release exists. Stable publication remains closed without a valid baseline;
first stable bootstrap and coordinated release qualification remain separate.
No stable version, approval prerequisite or deployment is introduced here.

### Actions qualification and stable publication

Main merges and workflow completion do not publish GitHub test releases. Exact
qualification files remain in Actions artifacts with finite retention. The pinned
publisher independently verifies a real immutable stable baseline and refuses
qualification snapshots, even if a caller job reports success. Existing valid
stable records are retained; no release, version change, deployment or human
approval prerequisite is introduced by this correction.
