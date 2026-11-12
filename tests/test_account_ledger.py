import concurrent.futures
import os
import subprocess
import sys
import uuid

import pytest
from controlplane_identity.account_lifecycle import subject_digest
from hypermesh_gateway_service.account_ledger import AccountLedger, LedgerUnavailable


def snapshot(**updates):
    return {
        "version": 1,
        "complete": True,
        "subjects": [],
        "keys": [],
        "fingerprints": [],
        "leases": [],
        **updates,
    }


def test_uninitialized_denies_and_snapshot_is_tenant_scoped(tmp_path):
    ledger = AccountLedger(str(tmp_path / "denials.sqlite"))
    first, other = uuid.uuid4(), uuid.uuid4()
    claims = {"sub": "person", "tenant_id": str(first)}
    assert ledger.claims_blocked(claims)
    ledger.apply_snapshot(first, snapshot())
    assert not ledger.claims_blocked(claims)
    assert ledger.claims_blocked({**claims, "tenant_id": str(other)})
    assert ledger.claims_blocked({"sub": "person"})


def test_retirement_survives_stale_pull_restart_and_key_session_wrapping(tmp_path):
    path = str(tmp_path / "denials.sqlite")
    ledger = AccountLedger(path)
    tenant, key, lease = uuid.uuid4(), uuid.uuid4(), uuid.uuid4()
    ledger.apply_snapshot(tenant, snapshot())
    ledger.retire(
        tenant, "person", key_ids=[key], fingerprints=["f" * 64], leases=[lease]
    )
    ledger.apply_snapshot(tenant, snapshot())
    restored = AccountLedger(path)
    for principal in ("person", f"apikey:{key}"):
        assert restored.claims_blocked({"sub": principal, "tenant_id": str(tenant)})
    assert not restored.claims_blocked({"sub": "different", "tenant_id": str(tenant)})
    assert restored.key_blocked(tenant, "f" * 64)
    assert restored.lease_blocked(tenant, lease)
    assert not restored.lease_blocked(tenant, uuid.uuid4())


def test_partial_retirement_does_not_claim_complete_bootstrap(tmp_path):
    ledger = AccountLedger(str(tmp_path / "denials.sqlite"))
    tenant = uuid.uuid4()
    ledger.retire(tenant, "closed", key_ids=[], fingerprints=[], leases=[])
    assert ledger.claims_blocked({"sub": "unrelated", "tenant_id": str(tenant)})
    ledger.apply_snapshot(tenant, snapshot())
    assert not ledger.claims_blocked({"sub": "unrelated", "tenant_id": str(tenant)})
    assert ledger.claims_blocked({"sub": "closed", "tenant_id": str(tenant)})


@pytest.mark.parametrize(
    "invalid",
    [
        None,
        {},
        snapshot(complete=1),
        snapshot(version=True),
        snapshot(subjects=["raw-subject"]),
        snapshot(keys=[None]),
        snapshot(leases=["bad-uuid"]),
        snapshot(fingerprints="f" * 64),
    ],
)
def test_malformed_or_incomplete_snapshots_never_bootstrap(tmp_path, invalid):
    ledger = AccountLedger(str(tmp_path / "denials.sqlite"))
    tenant = uuid.uuid4()
    with pytest.raises(LedgerUnavailable):
        ledger.apply_snapshot(tenant, invalid)
    assert ledger.claims_blocked({"sub": "person", "tenant_id": str(tenant)})


def test_independent_writers_union_instead_of_losing_each_other(tmp_path):
    path = str(tmp_path / "denials.sqlite")
    first = AccountLedger(path)
    second = AccountLedger(path)
    tenant = uuid.uuid4()
    first.apply_snapshot(tenant, snapshot())

    def write(item):
        ledger, subject = item
        ledger.retire(tenant, subject, key_ids=[], fingerprints=[], leases=[])

    with concurrent.futures.ThreadPoolExecutor(2) as pool:
        list(pool.map(write, [(first, "one"), (second, "two")]))
    for principal in ("one", "two"):
        assert first.claims_blocked({"sub": principal, "tenant_id": str(tenant)})
        assert second.claims_blocked({"sub": principal, "tenant_id": str(tenant)})


def test_commit_survives_process_exit_without_close_and_has_no_raw_subject(tmp_path):
    path = tmp_path / "denials.sqlite"
    ledger = AccountLedger(str(path))
    tenant = uuid.uuid4()
    payload = snapshot(subjects=[subject_digest(tenant, "private-person-identifier")])
    code = (
        "import os, uuid; from hypermesh_gateway_service.account_ledger import AccountLedger; "
        f"AccountLedger({str(path)!r}).apply_snapshot(uuid.UUID({str(tenant)!r}), {payload!r}); os._exit(0)"
    )
    subprocess.run([sys.executable, "-c", code], check=True)
    assert ledger.claims_blocked(
        {"sub": "private-person-identifier", "tenant_id": str(tenant)}
    )
    assert all(
        b"private-person-identifier" not in file.read_bytes()
        for file in tmp_path.iterdir()
    )


def test_corruption_missing_configuration_and_unsafe_file_permissions_fail_closed(
    tmp_path, monkeypatch
):
    from hypermesh_gateway_service.account_ledger import resolve_ledger

    monkeypatch.setenv("ACCOUNT_CLOSURE_ENFORCEMENT_ENABLED", "true")
    monkeypatch.delenv("HYPERMESH_ACCOUNT_DENIAL_DATABASE", raising=False)
    with pytest.raises(LedgerUnavailable):
        resolve_ledger()
    path = tmp_path / "broken.sqlite"
    path.write_bytes(b"corrupt")
    os.chmod(path, 0o600)
    with pytest.raises(LedgerUnavailable):
        AccountLedger(str(path))
    path.unlink()
    path.touch(mode=0o644)
    with pytest.raises(LedgerUnavailable):
        AccountLedger(str(path))


def test_local_signed_token_checks_never_call_the_control_plane(tmp_path, monkeypatch):
    from controlplane_identity.account_lifecycle import require_open_account
    from controlplane_identity.security.api_key_exchange_jwt import (
        mint_api_key_session_jwt,
    )
    from controlplane_identity.security.tenant_session_jwt import (
        mint_tenant_session_jwt,
    )
    from hypermesh_gateway_service.renter_auth import verify_jwt_locally
    from jwt import InvalidTokenError

    monkeypatch.setenv("ACCOUNT_CLOSURE_ENFORCEMENT_ENABLED", "true")
    monkeypatch.delenv("ACCOUNT_CLOSURE_GUARD_URL", raising=False)
    tenant, identifier = uuid.uuid4(), uuid.uuid4()
    ledger = AccountLedger(str(tmp_path / "denials.sqlite"))
    ledger.apply_snapshot(tenant, snapshot())
    human = mint_tenant_session_jwt(claims={"sub": "person"}, tenant_id=tenant)
    exchanged = mint_api_key_session_jwt(
        key_record_id=identifier, tenant_id=tenant, scopes=[]
    )
    for token in (human, exchanged):
        assert verify_jwt_locally(token, ledger=ledger) is not None
        assert verify_jwt_locally(token) is None
    with pytest.raises(InvalidTokenError):
        require_open_account({"sub": "person"})
    ledger.retire(tenant, "person", key_ids=[identifier], fingerprints=[], leases=[])
    for token in (human, exchanged):
        assert verify_jwt_locally(token, ledger=ledger) is None
    assert verify_jwt_locally(human[:-8] + "tampered", ledger=ledger) is None


def test_stale_pull_cannot_reopen_raw_key_or_ticket(tmp_path, monkeypatch):
    from types import SimpleNamespace

    from hypermesh_gateway_service.renter_auth import (
        RenterUnauthorized,
        require_renter_grant,
    )
    from hypermesh_gateway_service.tickets import CachedTicket, TicketCache, TicketPull
    from hypermesh_ticket import TicketNotReady, renter_key_fingerprint
    from starlette.requests import Request

    monkeypatch.setenv("ACCOUNT_CLOSURE_ENFORCEMENT_ENABLED", "true")
    tenant, lease, gateway = uuid.uuid4(), uuid.uuid4(), uuid.uuid4()
    raw = "prefix.private-key"
    fp = renter_key_fingerprint(raw)
    ledger = AccountLedger(str(tmp_path / "denials.sqlite"))
    cache = TicketCache(account_ledger=ledger)
    ticket = CachedTicket(
        lease_id=lease,
        ticket="not-used-after-revocation",
        client_address="10.0.0.2",
        assigned_gateway_id=gateway,
        status="active",
    )
    pull = TicketPull(
        tickets=[ticket],
        revoked_lease_ids=[],
        key_fingerprints=[fp],
        closure_snapshot=snapshot(),
    )
    cache.replace_from_pull(tenant, pull)
    request = Request(
        {
            "type": "http",
            "headers": [(b"authorization", f"Bearer {raw}".encode())],
            "app": SimpleNamespace(
                state=SimpleNamespace(account_ledger=ledger, ticket_cache=cache)
            ),
        }
    )
    assert require_renter_grant(request).kind == "api_key"
    ledger.retire(tenant, "closed", key_ids=[], fingerprints=[fp], leases=[lease])
    cache.replace_from_pull(
        tenant, pull
    )  # An old complete pull cannot erase additions.
    with pytest.raises(RenterUnauthorized):
        require_renter_grant(request)
    with pytest.raises(TicketNotReady):
        cache.honor(tenant, lease)
    with pytest.raises(LedgerUnavailable):
        cache.replace_from_pull(tenant, TicketPull(tickets=[], revoked_lease_ids=[]))
    assert (
        cache.get(tenant, lease) == ticket
    )  # Incomplete pulls don't replace valid cache state.


@pytest.mark.parametrize("kind", ["key", "jwt"])
async def test_first_request_bootstraps_without_background_refresh_and_still_denies_retirement(
    tmp_path, monkeypatch, kind
):
    from types import SimpleNamespace
    from starlette.requests import Request
    from hypermesh_gateway_service.routes import _authorize_caller
    from hypermesh_gateway_service.control_plane import KeyIndexEntry
    from hypermesh_gateway_service.tickets import TicketCache, TicketPull
    from hypermesh_gateway_service.renter_auth import RenterUnauthorized
    from hypermesh_ticket import renter_key_fingerprint
    from controlplane_identity.security.tenant_session_jwt import (
        mint_tenant_session_jwt,
    )

    monkeypatch.setenv("ACCOUNT_CLOSURE_ENFORCEMENT_ENABLED", "true")
    monkeypatch.setenv("HYPERMESH_ASSIGNMENT_REFRESH_S", "0")
    monkeypatch.setenv("HYPERMESH_REQUIRE_KEY_VALIDATE", "0")
    monkeypatch.delenv("ACCOUNT_CLOSURE_GUARD_URL", raising=False)
    tenant = uuid.uuid4()
    ledger = AccountLedger(str(tmp_path / "denials.sqlite"))
    cache = TicketCache(account_ledger=ledger)
    raw = "new-key.private-secret"
    fp = renter_key_fingerprint(raw)

    class Plane:
        index_calls = ticket_calls = 0
        complete = False

        async def list_key_index(self):
            self.index_calls += 1
            return [KeyIndexEntry(fingerprint=fp, tenant_id=tenant)]

        async def list_tunnels(self, tenant):
            return []

        async def list_tickets(self, tenant):
            self.ticket_calls += 1
            return TicketPull(
                tickets=[],
                revoked_lease_ids=[],
                key_fingerprints=[fp],
                closure_snapshot=snapshot(complete=self.complete),
            )

    plane = Plane()

    async def validator(**kwargs):
        return {
            "valid": True,
            "tenant_id": str(tenant),
            "key_id": str(uuid.uuid4()),
            "purpose": "renter",
        }

    async def toucher(key_id):
        pass

    token = (
        raw
        if kind == "key"
        else mint_tenant_session_jwt(claims={"sub": "person"}, tenant_id=tenant)
    )
    state = SimpleNamespace(
        account_ledger=ledger,
        ticket_cache=cache,
        control_plane=plane,
        api_key_validator=validator,
        key_toucher=toucher,
    )

    def request():
        return Request(
            {
                "type": "http",
                "headers": [(b"authorization", f"Bearer {token}".encode())],
                "app": SimpleNamespace(state=state),
            }
        )

    with pytest.raises(RenterUnauthorized):
        await _authorize_caller(request(), ir=False)
    assert not ledger.tenant_ready(tenant)
    plane.complete = True
    grant, actual, _ = await _authorize_caller(request(), ir=False)
    assert actual == tenant
    assert grant.kind == ("api_key" if kind == "key" else "jwt")
    assert ledger.tenant_ready(tenant)
    previous = plane.ticket_calls
    await _authorize_caller(request(), ir=False)
    assert plane.ticket_calls == previous  # No guard/pull on the cached path.
    ledger.retire(tenant, "person", key_ids=[], fingerprints=[fp], leases=[])
    with pytest.raises(RenterUnauthorized):
        await _authorize_caller(request(), ir=False)


def test_concurrent_initialization_uses_one_complete_schema(tmp_path):
    path = str(tmp_path / "shared.sqlite")
    with concurrent.futures.ThreadPoolExecutor(4) as pool:
        ledgers = list(pool.map(lambda _: AccountLedger(path), range(4)))
    tenant = uuid.uuid4()
    ledgers[0].apply_snapshot(tenant, snapshot())
    assert all(ledger.tenant_ready(tenant) for ledger in ledgers)


async def test_bootstrap_preserves_the_standing_tunnel_peer_metadata(
    tmp_path, monkeypatch
):
    from types import SimpleNamespace
    from starlette.requests import Request
    from hypermesh_gateway_service.renter_auth import bootstrap_account_authority
    from hypermesh_gateway_service.tickets import CachedTicket, TicketCache, TicketPull

    monkeypatch.setenv("ACCOUNT_CLOSURE_ENFORCEMENT_ENABLED", "true")
    tenant, lease, gateway, tunnel = (
        uuid.uuid4(),
        uuid.uuid4(),
        uuid.uuid4(),
        uuid.uuid4(),
    )
    ledger = AccountLedger(str(tmp_path / "denials.sqlite"))
    cache = TicketCache(account_ledger=ledger)

    class Plane:
        async def list_tunnels(self, tenant):
            return [
                SimpleNamespace(
                    lease_id=lease,
                    tunnel_id=tunnel,
                    peer_public_key="standing-peer-key",
                    client_address="10.0.0.2",
                )
            ]

        async def list_tickets(self, tenant):
            return TicketPull(
                tickets=[
                    CachedTicket(
                        lease_id=lease,
                        ticket="signed-on-plane",
                        client_address="",
                        assigned_gateway_id=gateway,
                        status="active",
                    )
                ],
                revoked_lease_ids=[],
                closure_snapshot=snapshot(),
            )

    request = Request(
        {
            "type": "http",
            "headers": [],
            "app": SimpleNamespace(
                state=SimpleNamespace(
                    account_ledger=ledger, ticket_cache=cache, control_plane=Plane()
                )
            ),
        }
    )
    await bootstrap_account_authority(request, tenant)
    current = cache.get(tenant, lease)
    assert current.peer_public_key == "standing-peer-key"
    assert current.tunnel_id == tunnel and current.client_address == "10.0.0.2"


async def test_receipt_bootstrap_requires_a_verified_matching_credential(
    tmp_path, monkeypatch
):
    from types import SimpleNamespace
    from starlette.requests import Request
    from hypermesh_gateway_service.renter_auth import (
        RenterUnauthorized,
        require_tenant_bound_grant,
    )
    from hypermesh_gateway_service.tickets import TicketCache, TicketPull
    from controlplane_identity.security.tenant_session_jwt import (
        mint_tenant_session_jwt,
    )

    monkeypatch.setenv("ACCOUNT_CLOSURE_ENFORCEMENT_ENABLED", "true")
    ledger = AccountLedger(str(tmp_path / "denials.sqlite"))
    cache = TicketCache(account_ledger=ledger)

    class Plane:
        calls = 0

        async def list_tunnels(self, tenant):
            self.calls += 1
            return []

        async def list_tickets(self, tenant):
            self.calls += 1
            return TicketPull(
                tickets=[], revoked_lease_ids=[], closure_snapshot=snapshot()
            )

    plane = Plane()
    state = SimpleNamespace(
        account_ledger=ledger, ticket_cache=cache, control_plane=plane
    )
    token = mint_tenant_session_jwt(claims={"sub": "person"}, tenant_id=uuid.uuid4())
    for authorization in (None, f"Bearer {token}"):
        target = uuid.uuid4()
        request = Request(
            {
                "type": "http",
                "headers": []
                if authorization is None
                else [(b"authorization", authorization.encode())],
                "app": SimpleNamespace(state=state),
            }
        )
        with pytest.raises(RenterUnauthorized):
            await require_tenant_bound_grant(request, target)
        assert plane.calls == 0
        assert not ledger.tenant_ready(target)


async def test_ir_only_key_can_bootstrap_its_tenant_receipts(tmp_path, monkeypatch):
    from types import SimpleNamespace
    from starlette.requests import Request
    from hypermesh_gateway_service.renter_auth import require_tenant_bound_grant
    from hypermesh_gateway_service.control_plane import KeyIndexEntry
    from hypermesh_gateway_service.tickets import TicketCache, TicketPull
    from hypermesh_ticket import renter_key_fingerprint

    monkeypatch.setenv("ACCOUNT_CLOSURE_ENFORCEMENT_ENABLED", "true")
    tenant = uuid.uuid4()
    raw = "ir-only.private-secret"
    fp = renter_key_fingerprint(raw)
    ledger = AccountLedger(str(tmp_path / "denials.sqlite"))

    class Plane:
        async def list_key_index(self):
            return [KeyIndexEntry(fingerprint=fp, tenant_id=tenant, kind="ir")]

        async def list_tunnels(self, tenant):
            return []

        async def list_tickets(self, tenant):
            return TicketPull(
                tickets=[],
                revoked_lease_ids=[],
                ir_key_fingerprints=[fp],
                closure_snapshot=snapshot(),
            )

    async def validate(**kwargs):
        assert kwargs["api_key"] == raw and kwargs["tenant_id"] == tenant
        return {"valid": True, "tenant_id": str(tenant), "purpose": "ir"}

    cache = TicketCache(account_ledger=ledger)
    state = SimpleNamespace(
        account_ledger=ledger,
        ticket_cache=cache,
        control_plane=Plane(),
        api_key_validator=validate,
    )
    request = Request(
        {
            "type": "http",
            "headers": [(b"authorization", f"Bearer {raw}".encode())],
            "app": SimpleNamespace(state=state),
        }
    )
    assert (await require_tenant_bound_grant(request, tenant)).kind == "api_key"
    assert cache.key_fingerprints(tenant) == set()
    assert cache.ir_key_fingerprints(tenant) == {fp}


def test_legacy_capability_upgrade_preserves_denials_and_refuses_unknown_empty_owner(
    tmp_path,
):
    import sqlite3

    tenant = uuid.uuid4()
    path = str(tmp_path / "legacy-ledger.sqlite")
    ledger = AccountLedger(path)
    ledger.apply_snapshot(
        tenant,
        {
            "version": 1,
            "complete": True,
            "subjects": [],
            "keys": [],
            "fingerprints": [],
            "leases": [],
        },
    )
    ledger.retire(tenant, "already-retired", key_ids=[], fingerprints=[], leases=[])
    with sqlite3.connect(path) as db:
        db.execute("DROP TABLE owner_capabilities")
        db.execute("PRAGMA user_version=1")
    upgraded = AccountLedger(path)
    assert upgraded.tenant_ready(tenant)
    assert upgraded.principal_retired(tenant, "already-retired")
    for owner in ("history", "training"):
        upgraded.configure_owner(owner, False)
        assert not upgraded.owner_disabled(owner)
        upgraded.configure_owner(owner, False, never_configured=True)
        assert upgraded.owner_disabled(owner)


def test_unattested_old_false_capability_is_not_historical_provenance(tmp_path):
    import sqlite3

    path = str(tmp_path / "v2-capabilities.sqlite")
    AccountLedger(path)
    with sqlite3.connect(path) as db:
        db.execute("DROP TABLE owner_capabilities")
        db.execute(
            "CREATE TABLE owner_capabilities (owner TEXT PRIMARY KEY, ever_configured INTEGER NOT NULL)"
        )
        db.executemany(
            "INSERT INTO owner_capabilities VALUES (?,?)",
            [("history", 0), ("training", 1)],
        )
        db.execute("PRAGMA user_version=2")
    upgraded = AccountLedger(path)
    assert not upgraded.owner_disabled("history")
    upgraded.configure_owner("history", False)
    assert not upgraded.owner_disabled("history")
    upgraded.configure_owner("history", False, never_configured=True)
    assert upgraded.owner_disabled("history")
    upgraded.configure_owner("training", False, never_configured=True)
    assert not upgraded.owner_disabled("training")

@pytest.mark.parametrize("complete", [None, snapshot()])
async def test_ticket_transport_preserves_optional_denial_snapshot(monkeypatch, complete):
    import httpx
    from hypermesh_gateway_service.control_plane import HttpControlPlane

    class Client:
        def __init__(self, **kwargs):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            pass

        async def get(self, url, **kwargs):
            body = {"tickets": [], "revoked_lease_ids": []}
            if complete is not None:
                body["closure_snapshot"] = complete
            return httpx.Response(200, json=body, request=httpx.Request("GET", url))

    monkeypatch.setattr(httpx, "AsyncClient", Client)
    pull = await HttpControlPlane("https://plane.invalid", "fixture").list_tickets(uuid.uuid4())
    assert pull.closure_snapshot == complete


def test_incomplete_pull_does_not_replace_cached_assignments(tmp_path, monkeypatch):
    from hypermesh_gateway_service.tickets import TicketCache, TicketPull
    monkeypatch.setenv("ACCOUNT_CLOSURE_ENFORCEMENT_ENABLED", "true")
    tenant = uuid.uuid4()
    ledger = AccountLedger(str(tmp_path / "denials.sqlite"))
    cache = TicketCache(account_ledger=ledger)
    fingerprint = "a" * 64
    cache.replace_from_pull(tenant, TicketPull(tickets=[], revoked_lease_ids=[],
                            key_fingerprints=[fingerprint], closure_snapshot=snapshot()))
    with pytest.raises(LedgerUnavailable):
        cache.replace_from_pull(tenant, TicketPull(tickets=[], revoked_lease_ids=[]))
    assert cache.key_fingerprints(tenant) == {fingerprint}
