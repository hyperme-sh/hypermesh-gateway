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

## Router prompt verbs

A UI calls named verbs on this router. The same grant as customer chat: `Authorization: Bearer` (renter API key or portal JWT) or `X-Api-Key`, plus a paid active lease ticket whose purpose is `renter` or `service`. `lease_id` and `model` select the lease the same way chat does, including `X-Hypermesh-Lease-Id` / `X-Lease-Id`. Host `hm_dev_`, gateway `hm_gw_`, and site `hm_site_` keys are not verb credentials. The IR door's key is not this surface.

```http
POST /v1/router/verbs
Authorization: Bearer <renter API key>
Content-Type: application/json

{"verb": "pause", "lease_id": "<optional>", "model": "<optional catalog id>", "args": {}}
```

The sibling path is `POST /api/v1/hypermesh-gateway/v1/router/verbs`. `GET /v1/router/verbs` lists every verb and whether it is wired (auth required, no lease). `GET /v1/router/session` reads the caller session using the same routing preferences as chat and run control. When those preferences leave no eligible route, it still requires an owned valid ticket and returns preferences with `lease_id` and `run` set to null. `GET /v1/router/audit-overrides` lists override requests for the tenant.

The router interprets the verb and applies its own policy. It does not command the leased host. `recipient_ack` is `not_delivered` on a wired verb: delivery and any recipient acknowledgement stay a separate hop from this response. A `not_wired` verb is HTTP 200, changes nothing, and says so in `detail`.

Run control is per lease. `pause`, `drain`, and `cancel` make this process refuse new completions on both chat doors (`409` `run_paused`, `run_draining`, or `run_cancelled`). `resume` accepts them again. A completion already handed to the host is not revoked. `cancel` then `pause` or `drain` is rejected until `resume`. State is local to this gateway process. A restart drops it. Another replica does not see it. Pause and drain do not claim the host stopped.

Caller session (model pin, routing, prompt text, attachments, frames) is per tenant and credential subject: the signed JWT issuer and `sub` (never email or display username), or the API key prefix, scoped by credential kind. JWTs without a nonempty `sub` cannot access router state. It is also process-local.

| Family | Verb | Wired | What this process does |
| --- | --- | --- | --- |
| Run control | `pause`, `resume`, `drain`, `cancel` | yes | Gate new completions, as above |
| Model mix | `use_model` | yes | Pin a catalog id when a later completion omits `model`. An explicit `model` still wins. Unknown catalog is `404` `model_not_found` |
| Model mix | `mix_models`, `prefer_tier` | no | No blend and no tier on the ticket |
| Routing | `prefer_host` | yes | Prefer that device id when `lease_id` is omitted. Falls through if it cannot serve the model |
| Routing | `exclude_host` | yes | Drop that device. An explicit lease on it is `409` `host_excluded` |
| Routing | `affinity` | yes | Stick an omitted `lease_id` to one lease while that lease can serve the request |
| Routing | `route_hint` | no | Free-form hints are not applied |
| Prompt | `system_append`, `style`, `temperature_hint` | yes | Prepend system text, or set `temperature` only when the completion omits it. Screened with the outgoing request |
| Safety | `safety_context`, `op_class` | no | Not stored. Allow, hold, and deny are unchanged |
| Audit | `audit_override_request` | yes | Logged for the tenant and **denied**. `403`, `decision: denied`. No gate is bypassed. The reason is not written to logs |
| Attachments | `attach`, `detach`, `list_attachments` | yes | Inline text only. A `uri` or `url` is `400`. Nothing is fetched |
| Share / cache | `cache_put`, `cache_get`, `share`, `unshare` | yes | Process-local tenant cache. Private to the writer until `share`, then readable by other subjects in the tenant. A rewrite is private again. Default TTL 3600s, max 86400s |
| Stack frames | `frame_push`, `frame_next`, `frame_pop`, `think` | yes | Router preamble on later completions. Pop keeps the result and drops that frame from the preamble. `think` survives pop. The caller's own messages are not deleted |
| Skills | `skill_load`, `skill_unload`, `skill_list` | no | No skill catalog. `skill_list` returns `skills: []` and `wired: false` |

`args` for the wired verbs: `use_model` `{model}` or `{clear: true}`; `prefer_host` `{device_id}` or `{clear: true}`; `exclude_host` `{device_id}`, `{device_id, remove: true}`, or `{clear: true}`; `affinity` `{lease_id}` or `{clear: true}`; `system_append` `{text}` or `{clear: true}`; `style` `{text}` or `{clear: true}`; `temperature_hint` `{temperature}` (0 through 2) or `{clear: true}`; `audit_override_request` `{reason}`; `attach` `{name, text, media_type?}`; `detach` `{attachment_id}`; `cache_put` `{key, text, ttl_s?}`; `cache_get` / `share` / `unshare` `{key}`; `frame_push` `{name, goal?}`; `frame_next` `{result, name, goal?}`; `frame_pop` `{result?}`; `think` `{name, text}` or `{name, clear: true}`. `device_id` is the leased host's device id, not an IP.

## Development

Use Python 3.13 and uv 0.11.26. The pinned source dependencies are public;
no private credentials are needed. The gateway is licensed under Apache-2.0.

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

Private CI uses debrunners; public CI uses hosted Ubuntu. Main qualification uses
pinned actions, read-only contents and public Git without ambient credentials. Pull-request preparation uses verified
artifacts without private Git credentials. Package and container checks remain
separate from live WireGuard and caller acceptance before deployment.

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
are built from exact source revisions; the manifest records those revisions,
wheel digests and build provenance. The verifier checks
root metadata, the complete active lock graph and transitive wheel metadata.
Explicit private extras and unrecognized conditional pins fail closed.

The read-only pull-request workflow retains tested wheels, source archives and
artifact-derived runtime and installer contracts as Actions artifacts. It does
not publish releases. The dependency graph uses public repositories at immutable Git pins and
matching artifacts. The owner version remains 0.1.0; coordinated owner-version
adoption and stable release acceptance remain unfinished.

`releases/qualification` records a verified prior immutable test snapshot and its
original Actions provenance. It is qualification evidence, not an accepted stable
release, and must not configure the stable release baseline variable.
`releases/prepared` identifies the exact prepared wheel by digest. Package tests
verify that binding and compare the rebuilt source archive's contract. Contracts
include runtime resources, Python constraints, dependencies, extras and entry
points. An explicit qualification-only transition lists the old and new
pins and binds them to the complete fixture graph. Python
constraints, registry requirements, extras and entry points must remain unchanged.
Runtime byte changes are accepted only when that transition names the file, the
before and after digests, the reason, and a regression test. A new packaged
file needs the same record with its digest. Unrecorded runtime changes fail.
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

## Standalone runtime image

Use the owner Dockerfile and the package-qualified wheel inputs. The runtime
includes `iproute2` and `wireguard-tools`; its entrypoint refuses to start if
`ip` or `wg` cannot be found. A Python-only gateway image cannot implement the
allocated WireGuard peers and must not replace this runtime.

    export RELEASE_ARTIFACT_DIR="$(mktemp -d)"
    bash scripts/check-package.sh --fixtures
    bash scripts/check-runtime-image.sh

The image context contains the checked owner wheel, digest-verified existing
dependency artifacts from public owners matching the complete lock graph, hash-locked public
runtime requirements and an input manifest. No Git/deployment credentials or
source checkout enter the context. It installs wheels in a fresh container
interpreter; it does not copy an editable checkout or host virtual environment.
Source, wheel and rebuilt archive qualification still precede the container
checks. The owner Python runtime and its pinned dependency graph are unchanged.

CI runs both binaries' version commands, imports the installed gateway, and
checks that hiding the required tools makes startup fail. These checks are
networkless and have no NET_ADMIN or tun device; they never configure WireGuard
or contact hosts/providers. Real peer application, handshake and overlay traffic
remain post-deployment acceptance gates.

Main CI retains its tested runtime archive, archive SHA256, local image reference
and input manifest as Actions artifacts. It does not publish a registry image,
create a tag/release or deploy anything. Any subsequent approved publication must
load those exact retained bytes and verify the source label and archive checksum;
it must not rebuild or overwrite an existing published candidate. Normal gateway
deployment still supplies its existing NET_ADMIN, tun, credentials and port
configuration; this Dockerfile grants no host capabilities or ports.
