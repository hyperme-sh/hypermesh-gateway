# Hypermesh gateway

`hypermesh-gateway-service` 0.1.0 is the Hypermesh data-plane gateway. It caches signed lease tickets from the control plane, keeps a WireGuard peer to each assigned host, and proxies renter chat to the host that ticket names. The Python package entry point is `python -m hypermesh_gateway_service.main`. The application factory is `hypermesh_gateway_service.app.create_app`.

## Why

A renter’s chat has to reach one leased host, and only that host, for as long as the lease is valid. The control plane decides the assignment and signs the lease ticket. This process is the hop that enforces the ticket and carries the traffic: it checks tenant, purpose, expiry, revocation, and host certification locally, then forwards the completion across a standing WireGuard tunnel. Putting that check on the gateway keeps lease authorization on the path that actually talks to the host.

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

Use the gateway credential the control plane issued for this deployment, the tenant ids this gateway should watch, and a host that has `/dev/net/tun`, `CAP_NET_ADMIN`, `ip`, and `wg`.

```bash
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

Replace the URL, secret, and tenant id. `HYPERMESH_WG_APPLY` values `0`, `false`, and `no` skip `wg` and `ip`, as does a missing `/dev/net/tun`.

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

An API key may be sent as `X-Api-Key` instead of `Authorization`. An optional `X-Tenant-ID` must match the tenant on the credential. Outside local development the gateway rechecks API keys with the API-keys service (`HYPERMESH_API_KEYS_URL`, default `http://api-keys-service:8000`). `HYPERMESH_DEV=1` or `FASTAPI_ENV=development` skips that live check; `HYPERMESH_REQUIRE_KEY_VALIDATE=1` forces it.

### Configuration

| Variable | Default | Role |
| --- | --- | --- |
| `HYPERMESH_CONTROL_PLANE_URL` | `http://hypermesh-service:8000` | Control plane base URL |
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
