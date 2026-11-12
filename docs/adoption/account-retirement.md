# Account retirement adoption

This reconciles gateway issue #18 against source commit
`2cd00fd9a7ebb950999571a81be7cb0a24d9264e`. Work remains in this owner repository.

| Source change | Gateway implementation and regression coverage |
| --- | --- |
| #625 local retirement | `account_ledger.py`, signed-account/key/ticket checks, bootstrap-before-assignment; `test_account_ledger.py`, async authorization contracts |
| #633 authority fencing | Existing dependency-owned authority guards remain; durable gateway denials neither stop leases nor mutate host runtime |
| #638 owner operations | Authenticated closure, discovery, denial and erasure receiver; retained history/training owner adapters |
| #652 exact delivery targets | Credential-backed gateway identity and tenant checks; `test_closure_receiver_identity.py` |
| #653 durable owner effects | Durable denial precedes committed owner effects; retry after a failed owner; `test_account_owner_discovery.py` |
| #654 retained data deletion | Original closure time, retention and erasure authorization, repeated deletion counts; PostgreSQL cases in `test_retained_owners_postgres.py` run in nightly CI |
| #696 router verbs | Already adopted in #33 (`686e1f5b5bc4e1f123307eafe5bd56712a592b9e`); `test_router_verbs.py` |
| #702 credential attribution | Already adopted in #21 (`bbeb48d8f4780fc77348148a1f938888e846f57e`); `test_credential_attribution.py`; later organization boundary fixes in `da92a57` are preserved |

`28846a4` intentionally replaced the collection surface with account-scoped
withdrawal and deletion. The owner adapters retain only closure, inventory and
purge methods. They add no enrollment, capture, saved-history read routes or
payload writes. The canonical `spanopticon.dev` tenant claim and stricter service
account exclusions remain intact.

The existing pinned identity and tenancy packages supply the shared guard
contract; no dependency or package version advances. Enforcement stays disabled
by default. An enabled gateway requires a private durable denial database and a
complete snapshot from its ticket endpoint. Missing snapshots fail closed rather
than silently treating an older peer as an empty denial authority. Running peers
need compatible contracts, not matching revisions.

PR CI runs unit and contract checks. The central scheduled main batch provisions
an isolated database through infra's `gateway_database.py`, then runs the
PostgreSQL cases against source, wheel and rebuilt sdist. Its fixed synthetic
scopes and database setup belong to infra. No deployed environment is changed by
these checks.
