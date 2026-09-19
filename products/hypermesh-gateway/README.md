# Hypermesh router (Fyber data plane)

Hypermesh (also Hyperme.sh) renter chat and WireGuard gateway. Folder is **`hypermesh-gateway`**. Never bare Hyperme.

Panopticon (`products/hypermesh`, :8010) is control. This service is the one test-plane router. It is not a third-party mesh, not MHS, not Solana.

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

- Panopticon is the broker only: it assigns router + host + peer record + lease ticket. This router and the host do not negotiate with each other.
- Learns the #26 signed ticket over HTTPS with `hm_gw_…` (`GET /api/v1/hypermesh/router/tickets`) and applies the host peer from `GET /router/tunnels`. May POST ready/metrics the same way. No standing session, no WebSocket, no router mesh. Service Bus stays domain events, not this hop.
- Caches the ticket + `client_address` from the tickets pull and verifies with `honor_ticket`. Chat does **not** call Panopticon per completion.
- Ticket-only chat grant: portal JWT validated locally on this router (cached JWKS or API-key exchange JWT — no OIDC dance, no Keycloak token hop) **or** a renter API key (`Authorization: Bearer` or `X-Api-Key`), **plus** a paid, active, signed lease ticket. Ticket HMAC is the grant. Purpose is a field on that ticket (`renter` | `ir` | `service`), not a Keycloak role. The renter chat door accepts `renter` and `service` and rejects `ir`. The opt-in IR door (`/v1/ir/chat/completions`) accepts `ir` only. A versioned taxonomy pack (not the #36 keyword stub, not a detector / CASB) classifies a small set of authorized security prompt types and allow/hold. Default chat does not classify or store the prompt. Integrator note: [docs/ir-classifier-v0.md](docs/ir-classifier-v0.md). Host `device_secret` and router `hm_gw_` are not renter credentials. API key stays format-only on this path.
- IR receipts stay on this door (`GET /v1/ir/receipts`): who, why, what left, class, allow/hold, time. Customer artifact. Not a Fyber product event. Set `HYPERMESH_IR_RECEIPT_PATH` to persist sanitized rows across a bounce (JSON file, lock fields only). No prompt bodies on Azure Monitor / Service Bus / `hypermesh.*` events.
- Fail closed on a revoked ticket, Path B not green, or WireGuard peer down. Customer-readable chat error stays **instance not ready**. Completions never go to Keycloak or Panopticon.
- Reports tunnel/session metrics (`bytes_in`, `bytes_out`, `handshake_count`) to Panopticon with `hm_gw_`. No prompt body. Ever.
- Applies the host WireGuard peer once (`wg`, `CAP_NET_ADMIN`, `/dev/net/tun`). Does not add or drop a peer on lease_start or lease_stop.
- Customer chat is `https://chat.test.hyperme.sh` on compose **8011** / container **:8000**: renter HTTPS → this router → `http://<client_address>:8080/v1/chat/completions` over the standing WG peer. Chat does not go through Keycloak. Do not move customer chat onto the host :8080. `POST /api/v1/hypermesh/renter/chat/completions` on the control plane is not the product.

Compose host port **8011**. Sibling prefix `/api/v1/hypermesh-gateway`. Customer chat also on `/v1/chat/completions` for `chat.test.hyperme.sh`.

Customer-readable chat error: **instance not ready**.

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
