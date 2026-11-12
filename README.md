# Hypermesh gateway

`hypermesh-gateway-service` 0.1.0 is the Hypermesh data-plane gateway. It caches signed lease tickets from the control plane, keeps a WireGuard peer to each assigned host, and proxies renter chat to the host that ticket names. The Python package entry point is `python -m hypermesh_gateway_service.main`. The application factory is `hypermesh_gateway_service.app.create_app`.

## Why

A renter’s chat has to reach one leased host, and only that host, for as long as the lease is valid. The control plane decides the assignment and signs the lease ticket. This process is the hop that enforces the ticket and carries the traffic: it checks tenant, purpose, expiry, revocation, and host certification locally, then forwards the completion across a standing WireGuard tunnel. Putting that check on the gateway keeps lease authorization on the path that actually talks to the host.

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
| Routing | `exclude_host` | yes | Drop that device, at most 32. An explicit lease on it is `409` `host_excluded` |
| Routing | `affinity` | yes | Stick an omitted `lease_id` to one lease while that lease can serve the request |
| Routing | `route_hint` | no | Free-form hints are not applied |
| Prompt | `system_append`, `style`, `temperature_hint` | yes | Prepend system text, or set `temperature` only when the completion omits it. Screened with the outgoing request |
| Safety | `safety_context`, `op_class` | no | Not stored. Allow, hold, and deny are unchanged |
| Audit | `audit_override_request` | yes | Logged for the tenant and **denied**. `403`, `decision: denied`. No gate is bypassed. The reason is not written to logs |
| Attachments | `attach`, `detach`, `list_attachments` | yes | Inline text only. A `uri` or `url` is `400`. Nothing is fetched |
| Share / cache | `cache_put`, `cache_get`, `share`, `unshare` | yes | Process-local tenant cache. Private to the writer until `share`, then readable by other subjects in the tenant. A rewrite is private again. Default TTL 3600s, max 86400s |
| Stack frames | `frame_push`, `frame_next`, `frame_pop`, `think` | yes | Router preamble on later completions. Pop keeps the result and drops that frame from the preamble. `think` survives pop. The caller's own messages are not deleted |
| Skills | `skill_load`, `skill_unload`, `skill_list` | no | No skill catalog. `skill_list` returns `skills: []` and `wired: false` |

`args` for the wired verbs: `use_model` `{model}` or `{clear: true}`; `prefer_host` `{device_id}` or `{clear: true}`; `exclude_host` `{device_id}` (at most 32), `{device_id, remove: true}`, or `{clear: true}`; `affinity` `{lease_id}` or `{clear: true}`; `system_append` `{text}` or `{clear: true}`; `style` `{text}` or `{clear: true}`; `temperature_hint` `{temperature}` (0 through 2) or `{clear: true}`; `audit_override_request` `{reason}`; `attach` `{name, text, media_type?}`; `detach` `{attachment_id}`; `cache_put` `{key, text, ttl_s?}`; `cache_get` / `share` / `unshare` `{key}`; `frame_push` `{name, goal?}`; `frame_next` `{result, name, goal?}`; `frame_pop` `{result?}`; `think` `{name, text}` or `{name, clear: true}`. `device_id` is the leased host's device id, not an IP.


## How it works

The control plane assigns a gateway and a host, signs a lease ticket, and records the WireGuard tunnel. Ticket verification comes from the separate [`hypermesh-ticket`](https://github.com/hyperme-sh/hypermesh-ticket) package (the exact revision is pinned in `pyproject.toml`). This repository does not vendor control-plane service code.

On a timer the gateway pulls tickets and tunnels for each watched tenant, caches them, and applies one WireGuard peer per host on interface `wg-hm`. A completion request then:

1. Accepts either a portal access token or a renter API key.
2. Binds that credential to a tenant and selects a lease.
3. Honors the cached ticket (signature, purpose, expiry, revocation, tenant, host certification, and a live peer handshake).
4. Applies the body limit, per-lease rate limit, and safety screen.
5. Streams the OpenAI-shaped request to the host at `http://<overlay-ip>:8080/v1/chat/completions` and streams the host response back.

Usage counters are queued and posted back to the control plane. The bundled IR taxonomy pack (`src/hypermesh_gateway_service/packs/ir-taxonomy-v1.json`) ships in the wheel for the optional IR chat route.

This service is reached directly. `edge-routes.json` records that exposure.

### HTTP surface

| Method | Path | Caller |
| --- | --- | --- |
| GET | `/api/v1/health/` | anyone |
| GET | `/version` | anyone |
| GET | `/openapi.json` | anyone |
| GET | `/v1/models` | renter token or API key |
| POST | `/v1/chat/completions` | renter token or API key |
| POST | `/v1/ir/chat/completions` | IR key or IR-role token |
| GET | `/v1/ir/receipts` | tenant-bound IR credential |
| GET | `/api/v1/hypermesh-gateway/ready` | gateway service credential |
| GET | `/api/v1/hypermesh-gateway/tunnels` | gateway service credential |
| POST | `/api/v1/hypermesh-gateway/tunnels/apply` | gateway service credential |
| POST | `/api/v1/hypermesh-gateway/metrics` | gateway service credential |
| GET | `/api/v1/hypermesh-gateway/leases/{lease_id}/completions-signal` | gateway service credential |

The same handlers are also mounted at `/api/v1/hypermesh-gateway/v1/models`, `/api/v1/hypermesh-gateway/v1/chat/completions`, `/api/v1/hypermesh-gateway/v1/ir/chat/completions`, and `/api/v1/hypermesh-gateway/v1/ir/receipts`.

Send **one** credential header, `Authorization` or `X-Api-Key`. A request that includes both is rejected before any lookup, including when one of them is empty or malformed. Operator routes take `Authorization: Bearer $HYPERMESH_GATEWAY_SERVICE_SECRET` and require `X-Tenant-ID`.

## Practical use

Python 3.13 and [uv](https://docs.astral.sh/uv/) 0.11.26. Dependencies are public Git pins; `uv sync --frozen` needs network access to GitHub and no extra credentials.

```bash
git clone https://github.com/hyperme-sh/hypermesh-gateway.git
cd hypermesh-gateway
uv sync --frozen
```

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

### Process only

Leave the control-plane credential unset. The process starts with an in-process stand-in (empty ticket cache) and can serve health, version, and OpenAPI. Set the refresh interval to `0` so it does not poll that stand-in, and skip WireGuard commands:

```bash
export HYPERMESH_WG_APPLY=0
export HYPERMESH_ASSIGNMENT_REFRESH_S=0
uv run python -m hypermesh_gateway_service.main
```

```bash
curl -sS http://127.0.0.1:8000/api/v1/health/
curl -sS http://127.0.0.1:8000/version
curl -sS http://127.0.0.1:8000/openapi.json
```

The server listens on `HOST` (default `0.0.0.0`) and `PORT` (default `8000`).

### Control plane and WireGuard

Before startup, securely inject `HYPERMESH_TICKET_HMAC_KEY` from the deployment secret store. It must match the control plane ticket-signing key; the gateway service credential is not a substitute. Do not generate an independent gateway key or commit/log the value. Missing verification trust prevents valid tickets from authorizing chat.

Also securely inject `API_KEYS_INTERNAL_TOKEN`, matching the API-keys service internal-validation secret, and configure a reachable `HYPERMESH_API_KEYS_URL`. The operational example sets `FASTAPI_ENV=production` and forces live validation with `HYPERMESH_REQUIRE_KEY_VALIDATE=1`, so inherited development settings cannot bypass revocation checks. The ticket-verification key and gateway service credential do not replace this internal token. Missing/invalid validation credentials or an unavailable API-keys service fail closed when a live check is due.

Use the gateway credential the control plane issued for this deployment, the tenant ids this gateway should watch, and a host that has `/dev/net/tun`, `CAP_NET_ADMIN`, `ip`, and `wg`.

```bash
: "${HYPERMESH_TICKET_HMAC_KEY:?Inject the control plane ticket-verification key securely first}"
export HYPERMESH_TICKET_HMAC_KEY
: "${API_KEYS_INTERNAL_TOKEN:?Inject the API-keys internal-validation token securely first}"
export API_KEYS_INTERNAL_TOKEN
export FASTAPI_ENV=production
export HYPERMESH_REQUIRE_KEY_VALIDATE=1
export HYPERMESH_API_KEYS_URL=https://api-keys.example
export HOST=0.0.0.0
export PORT=8000
export HYPERMESH_CONTROL_PLANE_URL=https://control-plane.example
export HYPERMESH_GATEWAY_SERVICE_SECRET=hm_gw_replace_me
export HYPERMESH_TENANT_IDS=00000000-0000-0000-0000-000000000000
export HYPERMESH_ASSIGNMENT_REFRESH_S=30
export HYPERMESH_WG_APPLY=1
export HYPERMESH_WG_IFACE=wg-hm
export HYPERMESH_WG_LISTEN_PORT=51820
export HYPERMESH_WG_GATEWAY_ADDR=10.77.0.1/24
uv run python -m hypermesh_gateway_service.main
```

Replace both service URLs, the gateway secret, and the tenant id. `HYPERMESH_WG_APPLY` values `0`, `false`, and `no` skip `wg` and `ip`, as does a missing `/dev/net/tun`.

Pull the assignment by hand (the same pull the refresh loop performs):

```bash
curl -sS -X POST http://127.0.0.1:8000/api/v1/hypermesh-gateway/tunnels/apply \
  -H "Authorization: Bearer $HYPERMESH_GATEWAY_SERVICE_SECRET" \
  -H "X-Tenant-ID: $TENANT_ID"
```

### Chat

`model` is the lease catalog id. Omit `lease_id` to use the tenant’s active lease (the most recently activated when several honor). Set it in the JSON body or in `X-Hypermesh-Lease-Id` / `X-Lease-Id` to pin one lease.

```bash
curl -sS http://127.0.0.1:8000/v1/models \
  -H "Authorization: Bearer $RENTER_API_KEY"

curl -sS http://127.0.0.1:8000/v1/chat/completions \
  -H "Authorization: Bearer $RENTER_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "model": "catalog-id",
    "messages": [{"role": "user", "content": "Hello"}]
  }'
```

An API key may be sent as `X-Api-Key` instead of `Authorization`. An optional `X-Tenant-ID` must match the tenant on the credential. Outside local development the gateway rechecks API keys with the API-keys service (`HYPERMESH_API_KEYS_URL`, default `http://api-keys-service:8000`). Without an override, development mode and no internal token allow cached-fingerprint authorization. `HYPERMESH_REQUIRE_KEY_VALIDATE=1` forces live validation even when development settings are inherited; `=0` explicitly disables that requirement and must not be used for operational deployments. Successful validations are cached for the key TTL (default 60 seconds), so this is bounded revocation checking rather than a remote call on every request.

### Configuration

| Variable | Default | Role |
| --- | --- | --- |
| `FASTAPI_ENV` | `development` | Set `production` for operational deployments |
| `HYPERMESH_REQUIRE_KEY_VALIDATE` | unset | Set `1` operationally to require live API-key validation even with inherited development settings |
| `API_KEYS_INTERNAL_TOKEN` | empty | Secret matching the API-keys internal-validation endpoint; inject securely before startup |
| `HYPERMESH_API_KEYS_URL` | `http://api-keys-service:8000` | Reachable API-keys service base URL |
| `HYPERMESH_CONTROL_PLANE_URL` | `http://hypermesh-service:8000` | Control plane base URL |
| `HYPERMESH_TICKET_HMAC_KEY` | required for operational ticket verification | Secret matching the control plane ticket-signing key; inject securely before startup |
| `HYPERMESH_GATEWAY_SERVICE_SECRET` | empty | Bearer credential for pulls and operator routes. Empty selects the stand-in plane |
| `HYPERMESH_TENANT_IDS` | marketplace tenant | Comma-separated tenant UUIDs to pull on boot |
| `HYPERMESH_ASSIGNMENT_REFRESH_S` | `30` | Seconds between ticket and tunnel pulls. `0` disables the loop |
| `HYPERMESH_WG_APPLY` | `1` | `0`, `false`, or `no` skips WireGuard commands |
| `HYPERMESH_WG_IFACE` | `wg-hm` | WireGuard interface |
| `HYPERMESH_WG_LISTEN_PORT` | `51820` | UDP listen port |
| `HYPERMESH_WG_GATEWAY_ADDR` | `10.77.0.1/24` | Address on that interface |
| `HYPERMESH_WG_HANDSHAKE_STALE_S` | `180` | Handshake older than this counts the peer down |
| `HYPERMESH_CHAT_UPSTREAM_PORT` | `8080` | Host chat port on the overlay address |
| `HYPERMESH_CHAT_READ_TIMEOUT_S` | `1800` | Upstream read timeout. `none` waits with no read limit |
| `HYPERMESH_MAX_BODY_BYTES` | `8388608` | Request body cap (413 `request_too_large`) |
| `HYPERMESH_CHAT_RATE_LIMIT` | `60` | Requests per lease per window |
| `HYPERMESH_CHAT_RATE_WINDOW_S` | `60` | Rate-limit window in seconds |
| `HYPERMESH_CHAT_BYTES_QUOTA` | `0` | Per-lease byte cap. `0` sets no byte cap |
| `HYPERMESH_SAFETY_SCREENING` | `on` | `on` or `off`. Screens every chat request on both doors |
| `HYPERMESH_GATEWAY_CORS_ORIGINS` | hyperme.sh and local dev origins | Comma-separated browser origins |
| `AIUDITOR_SERVICE_URL` | unset | Where an IR classify hold files an approval |
| `HYPERMESH_IR_TAXONOMY_PACK` | bundled v1 pack | Override path for the IR taxonomy JSON |
| `HYPERMESH_DATA_DIR` | unset | Directory for IR receipts |
| `HOST` / `PORT` | `0.0.0.0` / `8000` | Bind address and port |

`HYPERMESH_SAFETY_ACTION_SELF_HARM`, `HYPERMESH_SAFETY_ACTION_MALWARE_INTRUSION`, and `HYPERMESH_SAFETY_ACTION_VIOLENT_EXTREMISM` are `allow` or `block` (both still record a flag). Child sexual abuse material is always blocked.

### Runtime image

Build the image from a qualified wheel. The Dockerfile expects the context produced by `scripts/prepare-runtime-context.py`, which `scripts/check-runtime-image.sh` prepares:

```bash
export RELEASE_ARTIFACT_DIR="$(mktemp -d)"
bash scripts/check-package.sh
bash scripts/check-runtime-image.sh
```

The image includes `iproute2` and `wireguard-tools`. Its entrypoint exits if `ip` or `wg` is missing. Deployment supplies `NET_ADMIN`, `/dev/net/tun`, the gateway credential, and published ports. See [Releasing](docs/releasing.md).

## How Hypermesh uses it

Hypermesh leases a host to a renter. The control plane is the broker: it assigns this gateway and that host, signs a lease ticket, and stores the tunnel (gateway private key, host public key, overlay address, public endpoint).

This gateway is the data plane for that lease.

1. **Lease tickets in.** Every `HYPERMESH_ASSIGNMENT_REFRESH_S` seconds, for each id in `HYPERMESH_TENANT_IDS` (the marketplace tenant when unset), the process calls:
   - `GET /api/v1/hypermesh/gateway/tickets`
   - `GET /api/v1/hypermesh/gateway/tunnels`

   Both use `Authorization: Bearer $HYPERMESH_GATEWAY_SERVICE_SECRET` and `X-Tenant-ID`. The cache stores the signed ticket, catalog id, host certification state, key fingerprints, and revoked lease and key ids. A cross-tenant key index (`GET /api/v1/hypermesh/internal/renter-key-index`) lets an API key find its tenant.

2. **Tunnel up.** For each tunnel with status `allocated`, the gateway installs one WireGuard peer per host on `wg-hm` (listen UDP `51820`, address `10.77.0.1/24` unless overridden). Lease start and lease stop leave that peer in place. The peer is removed when the tunnel status is `revoked` and no allocated tunnel still uses that host key, which covers host teardown such as failed certification or device revocation.

3. **Chat across the tunnel.** The renter (a portal JWT, or an application holding a renter API key) calls `POST /v1/chat/completions`. The gateway maps the credential to the tenant, picks the lease, and honors the cached ticket in process. Host certification on the ticket must be green, an uploaded catalog must be admitted, and the WireGuard handshake must be fresh. The completion is then proxied to the host’s overlay address on port `8080`. The host answers there; the renter never opens the host directly.

4. **Accounted back.** After the stream, queued byte and handshake counters are posted to `POST /api/v1/hypermesh/gateway/metrics`. A safety flag, when screening records one, is posted to `POST /api/v1/hypermesh/gateway/safety-flags`. A later ticket pull that lists the lease as revoked makes the next completion fail the local ticket check.

The IR door (`POST /v1/ir/chat/completions`) is the same tunnel and the same ticket cache, for IR purposes. It classifies the prompt with the taxonomy pack and can file an approval at `AIUDITOR_SERVICE_URL` when org policy holds the request. Receipts for that door are local to this process (`GET /v1/ir/receipts`).

## Develop and test

```bash
uv sync --frozen
uv run pytest
bash scripts/check-package.sh
```

`scripts/check-package.sh` runs the suite from the checkout, from a clean install of the built wheel, and from a wheel rebuilt out of the source distribution. Tests use a fake control plane, mocked HTTP hosts, and mocked command execution. They do not configure WireGuard, enroll hosts, or call upstream model servers. For a checkout you are editing by hand, keep `HYPERMESH_WG_APPLY=0` and `HYPERMESH_ASSIGNMENT_REFRESH_S=0`.

Package qualification, the runtime image, and stable tags are described in [Releasing](docs/releasing.md).

## Release and versioning

The package version is **0.1.0** (`pyproject.toml`). The release line in `release-policy.json` is **0.1**. A stable release is a `vMAJOR.MINOR.PATCH` tag admitted against an immutable baseline, then published from the exact artifacts the package workflow already tested. Day-to-day pushes to `main` retain those artifacts and do not publish a release. Details, including development `test-<commit>` snapshots and the runtime image, are in [Releasing](docs/releasing.md). The admission checklist is in [Release compatibility](docs/release-policy.md).

## License

Apache License 2.0. See [LICENSE](LICENSE).

### Retained privacy data

An authenticated renter can withdraw via `PUT /v1/account/training-consent`
with `{"enabled":false}`, then delete their submissions via
`DELETE /v1/account/training-submissions`. Both operations use the verified
account subject and tenant. Configure the training role through
`HYPERMESH_TRAINING_DATABASE_URL`. The gateway does not start collection.

For saved-history retention, run
`python -m hypermesh_gateway_service.retained_privacy --tenant UUID --subject SUBJECT`
with the separate `HYPERMESH_HISTORY_DATABASE_URL` role. This operator entry
checks the original closure receipt and retention interval before deleting
entries and recording the purge. Reruns preserve the original purge timestamp.

## Service-channel deployment overlay

The deployment owner can render the gateway image from the shared
`service-channels.json` contract without changing its base Compose settings:

```bash
python3 scripts/render_service_channel.py \
  --channels deployment/service-channels.example.json \
  --repositories deployment/service-repositories.json \
  --output gateway-channel.compose.json
```

Use the generated JSON as the last Compose overlay for `hypermesh-gateway`.
It contains only the approved image reference and `pull_policy: always`.
Credentials, tenant assignments, private URLs, WireGuard capabilities and ports
remain in the deployment-owned base configuration. Supply the generated asset
for the environment in place of the example. The repository policy is trusted
configuration, separate from that asset; the gateway accepts its owner GHCR
runtime repository or the existing ACR mirror. Missing or malformed settings
fail before output is written.

A complete shared asset may include independently updated plane and payment
channels when its trusted repository map includes those services. The renderer
validates the asset but emits only the gateway overlay. Peer patch tags need not
match. The gateway continues to authenticate its control-plane requests and
refuse a mismatched tenant; no peer build identity grants authorization.

The existing registered `hypermesh-gateway-installed` nightly adapter owns the
`gatewaychannel` case: a run-owned image alias passes through this renderer and
then the existing kernel transport/application checks. Its setup, readiness and
cleanup are checked into Infra. Combined registry-channel advancement and real
plane/payment peer scenarios remain tracked by
[Infra #922](https://github.com/FyberLabs/infra/issues/922). No deployed readiness
is inferred from the rendering contracts.
