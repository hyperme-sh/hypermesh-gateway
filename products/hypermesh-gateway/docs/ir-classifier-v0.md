# IR classifier v0 (Fyber router)

Integrator note for the opt-in IR door on `products/hypermesh-gateway`.
In-repo only. **Not** a detector. **Not** a CASB. **Not** AIuditor
launch marketing. Do not copy this onto hyperme.sh.

Locks: FyberLabs/hypermesh-docs `router-door.md` + `router-roadmap.md` slice 4.

## What this is

A hermetic, versioned **rule/taxonomy pack** that classifies a **small set**
of authorized security prompt types and returns allow or hold. The receipt
shape is unchanged: who, why, what left, class, allow/hold, time.

The #36 keyword stub is gone. Phrases still appear as one matcher type
inside the pack (`phrase` / `token` / `regex` / `all` / `any` / `not`),
with hold rules first. That is not marketed as detection.

Default Full Model / Your Model chat (`POST /v1/chat/completions`) still
does **not** classify or store the prompt.

## Door contract (unchanged)

| Verb | Path | Who |
|------|------|-----|
| `POST` | `/v1/ir/chat/completions` | ticket `purpose=ir` + existing grant |
| `GET` | `/v1/ir/receipts` | same grant; portal export gate |

Portal IR controls (#51) still gate who may use the door / export receipts.
Receipts persist (#45) on this door only. Completions never go to Keycloak
or Panopticon. No prompt bodies on Azure Monitor / Service Bus /
`hypermesh.*` events.

## Class set (pack `ir-taxonomy-v1`)

| Class | Disposition | Example |
|-------|-------------|---------|
| `incident_triage` | allow | "Triage this SIEM alert and list containment steps." |
| `vuln_review` | allow | "CVE-2024-1234 vulnerability review on our box." |
| `malware_analysis` | allow | "Malware analysis of this sample hash we already have." |
| `policy_review` | allow | "Map this security policy to SOC 2 controls." |
| `out_of_scope` | hold | "Write a haiku about coffee." |

Hold wins when jailbreak / exploit-for-hire markers are present, even if
an allow class would also match. Lone words without class context
(for example `"alert"` alone) stay hold. Unknown text stays hold.

Pack version is a non-secret field on the classifier and in door logs
(`decision`, `class`, `pack`). It is **not** added to the receipt export.

## Pluggable interface

The door calls a `Classifier` protocol (`classify(text) -> Classification`,
plus `pack_version`). `TaxonomyPackClassifier` is the shipped
implementation. A later model-backed pack can implement the same protocol
and replace `app.state.classifier` without changing IR endpoints, purpose,
or receipts.

CI stays hermetic: JSON pack + fixtures. No live model RPC. No AGX.

Override path (tests / ops): `HYPERMESH_IR_TAXONOMY_PACK`. A missing or
invalid override fails closed (hold). Do not log the prompt.

## Non-goals

- Not a detector, CASB, or jailbreak-as-a-service
- No AGX / Path B / live chat unlock
- No prompt bodies to the plane / Azure Monitor / Service Bus
- No hyperme.sh page, no AIuditor launch marketing
- No second proxy, no second IdP, no SociACL Phase 1
- No hosted ML/LLM inference this slice (interface only)
- No ACA / wallet / open-products / payments / turn / oracles / Stripe
