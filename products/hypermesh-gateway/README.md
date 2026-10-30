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
- Ticket-only chat grant: portal JWT validated locally on this gateway (cached JWKS or API-key exchange JWT — no OIDC dance, no Keycloak token hop) **or** a renter API key (`Authorization: Bearer` or `X-Api-Key`), **plus** a paid, active, signed lease ticket. Ticket HMAC is the grant. Purpose is a field on that ticket (`renter` | `ir` | `service`), not a Keycloak role. The renter chat door accepts `renter` and `service` and rejects `ir`. The opt-in IR door (`/v1/ir/chat/completions`) accepts `ir` only. A versioned taxonomy pack (not the #36 keyword stub, not a detector / CASB) classifies a small set of authorized security prompt types and allow/hold. Default chat does not run that taxonomy and does not store the prompt; see automated safety screening below. Integrator note: [docs/ir-classifier-v0.md](docs/ir-classifier-v0.md). Host `device_secret` and gateway `hm_gw_` are not renter credentials. A bearer key is enough: the tenant comes from the fingerprint index. `X-Tenant-ID` and `lease_id` are optional overrides and must match that tenant.
- IR receipts stay on this door (`GET /v1/ir/receipts`): who, why, what left, class, allow/hold, time. Customer artifact. Not a Fyber product event. Receipts persist by default (`HYPERMESH_DATA_DIR/ir-receipts.json`, else `var/lib/hypermesh/ir-receipts.json`). Override the file with `HYPERMESH_IR_RECEIPT_PATH`. Set that to `memory` to keep rows in process only. Defined fields only. No prompt bodies on Azure Monitor / Service Bus / `hypermesh.*` events.
- Fail closed on a revoked ticket, certification not green (`path_b_state`, to be renamed `cert_state`), or WireGuard peer down. Customer-readable chat error stays **instance not ready**. Completions never go to Keycloak or Panopticon.
- Reports tunnel/session metrics (`bytes_in`, `bytes_out`, `handshake_count`) to Panopticon with `hm_gw_`. No prompt body. Ever. A failed hop queues the counters on this door (`HYPERMESH_METER_QUEUE_PATH`) and retries; chat still returns. The door also rate-limits per lease (`HYPERMESH_CHAT_RATE_LIMIT`) so a caller who skips the edge still hits a ceiling.
- Applies the host WireGuard peer once (`wg`, `CAP_NET_ADMIN`, `/dev/net/tun`). Does not add or drop a peer on lease_start or lease_stop.
- Customer chat is `https://chat.test.hyperme.sh` on compose **8011** / container **:8000**: renter HTTPS → this gateway → `http://<client_address>:8080/v1/chat/completions` over the standing WG peer. Chat does not go through Keycloak. Do not move customer chat onto the host :8080. `POST /api/v1/hypermesh/renter/chat/completions` on the control plane is not the product.

Compose host port **8011**. Sibling prefix `/api/v1/hypermesh-gateway`. Customer chat also on `/v1/chat/completions` for `chat.test.hyperme.sh`.

Customer-readable chat error when the instance is not up: **instance not ready**.

`GET /api/v1/hypermesh-gateway/ready` takes the gateway service credential and reports process health only. It does not contact leased hosts. One host being down does not change it. The control-plane edge catalog probe (`GET /api/v1/hypermesh/catalog` from edge health) is a different check and stays as it is.

`GET /api/v1/hypermesh-gateway/leases/{lease_id}/completions-signal` reports that one lease. It GETs the host completions path on port 8080 and does not send a chat completion. The same lease is not probed again until `HYPERMESH_COMPLETIONS_SIGNAL_INTERVAL_S` (default 30 seconds). `completions` is `up` or `down` on that lease. The result does not change `/ready` and does not take the gateway out of service.

The signed lease protocol comes from the installed `hypermesh-ticket` family
package. This image contains no Hypermesh service source. The `hm1` wire format
and existing tenant, purpose, expiry and revocation checks are unchanged.

## OpenAI-compatible door

`https://chat.test.hyperme.sh/v1` takes a base URL and `Authorization: Bearer <renter API key>`. Cursor, VS Code Copilot BYOK, Continue, and Cline do not send `X-Tenant-ID` or a lease id.

The tenant is the one that published `sha256(prefix.secret)`. The gateway learns that map from ticket pulls, and from `GET /api/v1/hypermesh/internal/renter-key-index` (internal token, no tenant header) so a renter tenant outside `HYPERMESH_TENANT_IDS` is pulled. A key the cache has never seen triggers one pull for that tenant. Otherwise the background refresh (`HYPERMESH_ASSIGNMENT_REFRESH_S`, default 30s) picks the fingerprint up.

Keys are tenant-owned, never lease-owned. There is no `scheduled` lease status. `paid` and `starting` are upcoming: a key minted then needs no extra step and routes on the next pull after the lease is active. Ending a lease does not delete keys. With no active lease the same key is `402 no_active_lease`, and it works again on the next active lease.

Lease choice when the request omits `lease_id` (`resolve_route(key, requested_model)` in `route_resolve.py`):

When `model` is absent or empty:

1. Honoring tickets for the tenant (signed, active, not revoked). Exactly one: use it.
2. Several: the most recently started (`activated_at` on the ticket row).

When `model` is set:

1. Honoring tickets whose `catalog_id` equals `model`. One match: use it. Several matches: the most recently started among them.
2. No match: `404` `model_not_found`. The message lists the available catalog ids. The door does not serve a different model.

`TenantOwnedKeyPolicy` is the seam. It ignores the key and returns every honoring ticket. A later routing layer can replace that policy so one key spans a subset of leases, and can add a routing model id such as `auto` on `GET /v1/models`. `auto` is not implemented and is not listed.

`GET /v1/models` (and `GET /api/v1/hypermesh-gateway/v1/models`) lists `{id, object: "model", owned_by: "hypermesh"}` from those catalog ids. No active lease is `200` with `data: []`, not an error. A bad key is `401`.

OpenAI error shape is only on `/v1/*`. Sibling `/api/v1/hypermesh-gateway/...` keeps `{"detail": ...}`.

| Status | code | When |
|--------|------|------|
| 401 | `invalid_api_key` | Missing, unknown, or revoked key |
| 402 | `no_active_lease` | Key is valid and no honoring lease is selected. The catalog link uses `HYPERMESH_PORTAL_ORIGIN`. |
| 403 | `tenant_mismatch` | `X-Tenant-ID` does not match the key |
| 403 | `lease_not_owned` | `lease_id` is not in that tenant's cache and is not one of its revoked leases |
| 404 | `model_not_found` | `model` is set and no honoring lease has that catalog id |
| 409 | `instance_not_ready` | Ticket will not honor, including a lease id this tenant has revoked, or the host is down or still loading. See below. |
| 429 | (detail) | Quota or the usage queue is full |

`instance_not_ready` on `/v1/*` keeps the legacy `detail: "instance not ready"` and adds `error.reason` (also sent as `X-Hypermesh-Not-Ready`) and `error.retryable`. Reasons:

| reason | retryable | When |
|--------|-----------|------|
| `peer_down` | yes, `Retry-After: 5` | The host WireGuard peer has not handshaked recently |
| `host_unreachable` | yes, `Retry-After: 5` | Nothing answers on the host chat port yet, for example the container is starting |
| `host_status_5xx` | yes, `Retry-After: 5` | The host answered 5xx. llama-server answers 503 while it loads the model after `lease_start`. |
| `host_status_4xx` | no | The host refused the request |
| `not_honored` | no | The ticket is revoked, expired, not certified green, or for another purpose |
| `no_tunnel_address` | no | The ticket has no client address |

A lease is `active` once the host has started the container, which can be before the model has loaded. A client should retry a retryable `instance_not_ready` after `Retry-After`.

`DELETE /api/v1/api-keys/{id}` unpublishes the fingerprint before it marks the key revoked (`POST /api/v1/hypermesh/internal/renter-key-fingerprints/revoke`, and the IR twin). If that unpublish fails, the delete returns 502 and the key stays active. On test and prod the door requires api-keys-service `POST /api/v1/internal/validate` (`HYPERMESH_REQUIRE_KEY_VALIDATE`, default on outside local/dev). A positive result is remembered for at most 60s, and a pull that lists the fingerprint in `revoked_key_fingerprints` drops it. A revoked key stops working within 60 seconds.

Chat upstream timeout is `httpx.Timeout(connect=10, read=HYPERMESH_CHAT_READ_TIMEOUT_S or 1800, write=60, pool=10)`. The 1800s default matches the host `LLAMA_ARG_TIMEOUT=1800` and the HAProxy timeouts in FyberLabs/infra#130. `none` disables the read limit. SSE is passed through unbuffered (`x-accel-buffering: no`). Empty `tool_calls[].id` values are filled with `call_<hex>`, stable per index for one stream.

The edge `timeout client` / `timeout server` in front of this process is owned by FyberLabs/infra (HAProxy, infra#130). This repo does not change it. Host llama-server `--jinja` is owned by the host entrypoint, not this door.

`POST /api/v1/internal/touch` on api-keys-service records `last_used_at`, at most once per key per 60s.

## Automated safety screening

Every request on `/v1/chat/completions` and `/v1/ir/chat/completions` (and the sibling routes) is screened in process before it reaches the host (`safety.py`). Every string the door forwards is screened: message content, tool-call arguments, tool definitions, extra body fields and any dictionary key that is not a known request or JSON Schema field name, such as a tool-schema property name (data URLs are skipped, and so are structural fields such as a role or a tool-call id, but only when the value is a real role or a plain identifier that matches no CSAM pattern and no rule of a category set to block). The screen covers a small set of severe categories:

| Category | `category` | Default action |
|----------|------------|----------------|
| Child sexual abuse material | `csam` | block and record (fixed) |
| Credible self-harm risk | `self_harm` | allow and record |
| Malware or intrusion tooling aimed at others | `malware_intrusion` | allow and record |
| Violent extremism or terrorism | `violent_extremism` | allow and record |

- Nothing is stored or sent for a request that is not flagged.
- A flagged request is sent once to the control plane (`POST /api/v1/hypermesh/gateway/safety-flags`, gateway credential) with the category, action, rule id, classifier version, time, account (key prefix or token subject), lease, door and the flagged text (capped at 16 KiB around the match). Operators review it there.
- A blocked request returns `400` with code `content_policy_violation` on `/v1/*` and `{"detail": ...}` on sibling routes. The host is not called.
- `HYPERMESH_SAFETY_ACTION_SELF_HARM`, `HYPERMESH_SAFETY_ACTION_MALWARE_INTRUSION`, `HYPERMESH_SAFETY_ACTION_VIOLENT_EXTREMISM`: `allow` (default) or `block`. `csam` is always `block`.
- `HYPERMESH_MAX_BODY_BYTES` (default 8 MiB) caps the raw request body before it is parsed or decoded: a declared Content-Length over the cap is refused unread, and a streamed body is refused as soon as it passes the cap, with `413 request_too_large`.
- `HYPERMESH_SAFETY_TIMEOUT_MS` (default 250) is the base classification budget, plus 2 seconds per million characters. Every forwarded character is screened; a request whose screened text exceeds `HYPERMESH_SAFETY_MAX_CHARS` (default 1,048,576) is refused with `413 request_too_large` and never partly screened.
- Each turn is screened as one line (content parts and tool calls joined; consecutive messages from one role are one turn), and so is each entry of a top-level list such as `tools`. Proximity rules do not match across turns, fields or list entries. Explicit CSAM terms are also matched across line breaks, and both CSAM patterns (explicit terms and minor + sexual proximity) are checked across each role's turns read in order, across the whole conversation in order (system and developer turns included, since the caller writes them), and across every model-visible line of the request in order (messages, tools and other fields). The same split check covers the rules of any other category whose action is set to `block`. It also runs when the classifier fails, so a phrase cannot be split around a turn or field boundary. This errs toward flagging: unrelated turns that happen to form a match are blocked and recorded for review.
- Protective wording ("how do I report ...") suppresses a CSAM match only when it takes the match as its object and no turn in the whole request asks for material, a source for it or content about it ("where can I find ...", "provide ... URLs", "list", "write", "videos", "examples" and similar words void it). When several categories match, a blocking category wins.
- The classifier runs on a dedicated pool of `HYPERMESH_SAFETY_WORKERS` threads (default 4), not the shared executor. A slot is held until the work really finishes, so a classifier that overruns its budget cannot use more than the pool; when every slot is busy the screen fails at once instead of queueing.
- When the classifier errors, overruns its budget or finds the pool busy, the CSAM patterns, the rules of every category set to block and the split check still run inline (no protective wording honoured): a match is blocked and recorded (`csam.fallback`, or `<rule>.fallback` for another category) whatever the fail mode. Otherwise `HYPERMESH_SAFETY_FAIL_MODE` applies: `open` (default) serves the request unscreened and logs the failure without text; `closed` refuses with `503 safety_screening_unavailable`. Neither stores anything.
- `HYPERMESH_SAFETY_SCREENING=off` disables screening.
- If the control plane is unreachable, a record waits in process memory (never on disk) and is retried on the refresh loop. At most 1000 wait, with at most 100 per tenant. A tenant at its limit replaces only its own oldest pending record. If the queue is full and has no record from the incoming tenant, the incoming record is dropped; other tenants' evidence is preserved. Every drop is logged at error level with its id and category. A restart drops records still waiting. A record the control plane rejects outright (a 4xx other than 401, 403, 404, 408, 409, 425 or 429) is dropped and logged with its id, category and status so it cannot block the records behind it.
- Request text never goes to logs, metrics, telemetry or events. Log lines carry category, action, classifier version, lease id and record id only.
- The bundled classifier is a deterministic rules baseline (`safety-rules-v1`). `SafetyClassifier` is the seam for a model classifier later; pass one to `create_app(safety_classifier=...)`.

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
