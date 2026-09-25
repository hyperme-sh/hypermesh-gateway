# Hypermesh gateway (Fyber data plane)

Hypermesh (also Hyperme.sh) renter chat and WireGuard gateway. Folder is **`hypermesh-gateway`**. Never bare Hyperme.

Panopticon (`products/hypermesh`, :8010) is control. This service is the one test-plane gateway. It is not a third-party mesh, not MHS, not Solana.

## Test URLs

| Role | URL |
|------|-----|
| Control | https://api.test.hyperme.sh |
| Host enroll | https://api.test.hyperme.sh/api/v1/hypermesh |
| Renter chat | https://chat.test.hyperme.sh |
| Catalog | https://api.test.hyperme.sh/api/v1/hypermesh/catalog |
| Checkout | POST https://api.test.hyperme.sh/api/v1/hypermesh/leases (Stripe test) |

No host IPs on this page or in public OpenAPI.

## What it does

- Panopticon is the broker only: it assigns gateway + host + peer record + lease ticket. This gateway and the host do not negotiate with each other.
- Learns the #26 signed ticket over HTTPS with `hm_gw_…` (`GET /api/v1/hypermesh/gateway/tickets`) and applies the host peer from `GET /gateway/tunnels`. May POST ready/metrics the same way. No standing session, no WebSocket, no gateway mesh. Service Bus stays domain events, not this hop.
- Caches the ticket + `client_address` from the tickets pull and verifies with `honor_ticket`. Chat does **not** call Panopticon per completion.
- Ticket-only chat grant: portal JWT validated locally on this gateway (cached JWKS or API-key exchange JWT — no OIDC dance, no Keycloak token hop) **or** a renter API key (`Authorization: Bearer` or `X-Api-Key`), **plus** a paid, active, signed lease ticket. Ticket HMAC is the grant. Purpose is a field on that ticket (`renter` | `ir` | `service`), not a Keycloak role. The renter chat door accepts `renter` and `service` and rejects `ir`. The opt-in IR door (`/v1/ir/chat/completions`) accepts `ir` only. A versioned taxonomy pack (not the #36 keyword stub, not a detector / CASB) classifies a small set of authorized security prompt types and allow/hold. Default chat does not classify or store the prompt. Integrator note: [docs/ir-classifier-v0.md](docs/ir-classifier-v0.md). Host `device_secret` and gateway `hm_gw_` are not renter credentials. A bearer key is enough: the tenant comes from the fingerprint index. `X-Tenant-ID` and `lease_id` are optional overrides and must match that tenant.
- IR receipts stay on this door (`GET /v1/ir/receipts`): who, why, what left, class, allow/hold, time. Customer artifact. Not a Fyber product event. Receipts persist by default (`HYPERMESH_DATA_DIR/ir-receipts.json`, else `var/lib/hypermesh/ir-receipts.json`). Override the file with `HYPERMESH_IR_RECEIPT_PATH`. Set that to `memory` to keep rows in process only. Lock fields only. No prompt bodies on Azure Monitor / Service Bus / `hypermesh.*` events.
- Fail closed on a revoked ticket, Path B not green, or WireGuard peer down. Customer-readable chat error stays **instance not ready**. Completions never go to Keycloak or Panopticon.
- Reports tunnel/session metrics (`bytes_in`, `bytes_out`, `handshake_count`) to Panopticon with `hm_gw_`. No prompt body. Ever. A failed hop queues the counters on this door (`HYPERMESH_METER_QUEUE_PATH`) and retries; chat still returns. The door also rate-limits per lease (`HYPERMESH_CHAT_RATE_LIMIT`) so a caller who skips the edge still hits a ceiling.
- Applies the host WireGuard peer once (`wg`, `CAP_NET_ADMIN`, `/dev/net/tun`). Does not add or drop a peer on lease_start or lease_stop.
- Customer chat is `https://chat.test.hyperme.sh` on compose **8011** / container **:8000**: renter HTTPS → this gateway → `http://<client_address>:8080/v1/chat/completions` over the standing WG peer. Chat does not go through Keycloak. Do not move customer chat onto the host :8080. `POST /api/v1/hypermesh/renter/chat/completions` on the control plane is not the product.

Compose host port **8011**. Sibling prefix `/api/v1/hypermesh-gateway`. Customer chat also on `/v1/chat/completions` for `chat.test.hyperme.sh`.

Customer-readable chat error when the instance is not up: **instance not ready**.

## OpenAI-compatible door

`https://chat.test.hyperme.sh/v1` takes a base URL and `Authorization: Bearer <renter API key>`. Cursor, VS Code Copilot BYOK, Continue, and Cline do not send `X-Tenant-ID` or a lease id.

The tenant is the one that published `sha256(prefix.secret)`. The gateway learns that map from ticket pulls, and from `GET /api/v1/hypermesh/internal/renter-key-index` (internal token, no tenant header) so a renter tenant outside `HYPERMESH_TENANT_IDS` is pulled. A key the cache has never seen triggers one pull for that tenant. Otherwise the background refresh (`HYPERMESH_ASSIGNMENT_REFRESH_S`, default 30s) picks the fingerprint up.

Keys are tenant-owned, never lease-owned. There is no `scheduled` lease status. `paid` and `starting` are upcoming: a key minted then needs no extra step and routes on the next pull after the lease is active. Ending a lease does not delete keys. With no active lease the same key is `402 no_active_lease`, and it works again on the next active lease.

Lease choice when the request omits `lease_id` (`resolve_route(key, requested_model)` in `route_resolve.py`):

1. Honoring tickets for the tenant (signed, active, not revoked). Exactly one: use it.
2. Several: the ticket whose `catalog_id` equals the request `model`.
3. Still ambiguous (no model, the model matches none, or it matches several): the most recently started (`activated_at` on the ticket row).

`TenantOwnedKeyPolicy` is the seam. It ignores the key and returns every honoring ticket. A later routing layer can replace that policy so one key spans a subset of leases, and can add a routing model id such as `auto` on `GET /v1/models`. `auto` is not implemented and is not listed.

`GET /v1/models` (and `GET /api/v1/hypermesh-gateway/v1/models`) lists `{id, object: "model", owned_by: "hypermesh"}` from those catalog ids. No active lease is `200` with `data: []`, not an error. A bad key is `401`.

OpenAI error shape is only on `/v1/*`. Sibling `/api/v1/hypermesh-gateway/...` keeps `{"detail": ...}`.

| Status | code | When |
|--------|------|------|
| 401 | `invalid_api_key` | Missing, unknown, or revoked key |
| 402 | `no_active_lease` | Key is valid and no honoring lease is selected |
| 403 | `tenant_mismatch` | `X-Tenant-ID` does not match the key |
| 403 | `lease_not_owned` | `lease_id` is not in that tenant's cache |
| 409 | (detail) instance not ready | Ticket will not honor, or the host is down |
| 429 | (detail) | Quota or the usage queue is full |

Revoke removes the fingerprint (`POST /api/v1/hypermesh/internal/renter-key-fingerprints/revoke`, and the IR twin). The door also re-checks api-keys-service `POST /api/v1/internal/validate` when `API_KEYS_INTERNAL_TOKEN` is set, and remembers a positive result for at most 60s. A pull that drops the fingerprint purges that memory. A revoked key is not served for more than 60s.

Chat upstream timeout is `httpx.Timeout(connect=10, read=HYPERMESH_CHAT_READ_TIMEOUT_S or 600, write=60, pool=10)`. `none` disables the read limit. SSE is passed through unbuffered (`x-accel-buffering: no`). Empty `tool_calls[].id` values are filled with `call_<hex>`, stable per index for one stream.

The edge `timeout client` / `timeout server` in front of this process is owned by FyberLabs/infra (HAProxy). This repo does not change it. Host llama-server `--jinja` is owned by the host entrypoint, not this door.

`POST /api/v1/internal/touch` on api-keys-service records `last_used_at`, at most once per key per 60s.

## Run locally

```bash
docker compose up -d --build hypermesh-service hypermesh-gateway

# Or
cd products/hypermesh-gateway
uv run pytest -q
uv run python -m hypermesh_gateway_service.main

# Hermetic ticket + mock-host completions (no WG / AGX)
# make synthetic-hypermesh-gateway
# or: uv run pytest -m synthetic -q
```

- Health: http://localhost:8011/api/v1/health/
- OpenAPI: http://localhost:8011/docs
- CORS: `HYPERMESH_GATEWAY_CORS_ORIGINS` (hyperme.sh origins + localhost)

Shared local secret (not for production): `HYPERMESH_GATEWAY_SERVICE_SECRET`. Infra/Terraform stays in FyberLabs/infra.
