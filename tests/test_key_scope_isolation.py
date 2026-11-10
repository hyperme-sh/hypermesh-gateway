"""Same-tenant key scopes cannot route to another organization's paid ticket."""
from dataclasses import replace
from datetime import UTC,datetime
from types import SimpleNamespace
import uuid

import pytest
from starlette.requests import Request

from hypermesh_gateway_service.renter_auth import confirm_api_key_live,RenterUnauthorized
from hypermesh_gateway_service.route_resolve import TenantOwnedKeyPolicy,resolve_route,LeaseNotOwned
from hypermesh_gateway_service.tickets import TicketCache
from hypermesh_ticket import RENTER_CHAT_PURPOSES,renter_key_fingerprint
from test_hypermesh_gateway import _signed_ticket,TEST_RENTER_KEY,_ticket_pull


async def test_normal_models_and_explicit_foreign_lease_are_scope_bound(http_client,app,control_plane,tenant_id,monkeypatch):
    monkeypatch.setenv('HYPERMESH_REQUIRE_KEY_SCOPE','1')
    org,foreign=uuid.uuid4(),uuid.uuid4()
    own=replace(_signed_ticket(uuid.uuid4()),catalog_id='own-model',renter_organization_id=org,activated_at=datetime.now(UTC))
    other=replace(_signed_ticket(uuid.uuid4()),catalog_id='foreign-model',renter_organization_id=foreign,activated_at=datetime.now(UTC))
    control_plane.ticket_pull=_ticket_pull([own,other])
    app.state.ticket_cache.put(tenant_id,own)
    app.state.ticket_cache.put(tenant_id,other)
    async def validate(**kwargs):
        assert kwargs['tenant_id']==tenant_id
        return dict(valid=True,key_id=str(uuid.uuid4()),tenant_id=str(tenant_id),
                    scope_kind='organization',organization_id=str(org),purpose='renter')
    app.state.api_key_validator=validate
    headers={'Authorization':'Bearer '+TEST_RENTER_KEY}
    response=await http_client.get('/v1/models',headers=headers)
    assert response.status_code==200
    assert [row['id'] for row in response.json()['data']]==['own-model']
    response=await http_client.post('/v1/chat/completions',headers=headers,
        json={'lease_id':str(other.lease_id),'messages':[{'role':'user','content':'must refuse'}]})
    assert response.status_code==403


@pytest.mark.parametrize('data',[
    {},{'scope_kind':'organization','organization_id':'invalid','purpose':'renter'},
    {'scope_kind':'network','organization_id':None,'purpose':'service'},
    {'scope_kind':'organization','organization_id':str(uuid.uuid4()),'purpose':'ir'},
])
async def test_scope_and_purpose_cannot_fall_back_to_tenant_wide_authority(monkeypatch,data):
    monkeypatch.setenv('HYPERMESH_REQUIRE_KEY_SCOPE','1')
    tenant=uuid.uuid4();cache=TicketCache();fp=renter_key_fingerprint(TEST_RENTER_KEY)
    async def validate(**kwargs):return dict(valid=True,tenant_id=str(tenant),**data)
    app=SimpleNamespace(state=SimpleNamespace(api_key_validator=validate))
    request=Request({'type':'http','method':'GET','path':'/v1/models','headers':[],'app':app})
    with pytest.raises(RenterUnauthorized):
        await confirm_api_key_live(request,tenant_id=tenant,raw_key=TEST_RENTER_KEY,fingerprint=fp,cache=cache,ir=False)
    assert not cache.key_is_fresh(fp)


def test_explicit_lease_cannot_bypass_scope_or_unbound_ticket(monkeypatch):
    monkeypatch.setenv('HYPERMESH_REQUIRE_KEY_SCOPE','1')
    cache=TicketCache();tenant=uuid.uuid4();org=uuid.uuid4();fp=renter_key_fingerprint(TEST_RENTER_KEY)
    cache.remember_key_scope(fp,org,'renter')
    for bound in (uuid.uuid4(),None):
        ticket=replace(_signed_ticket(uuid.uuid4()),renter_organization_id=bound)
        cache.put(tenant,ticket)
        with pytest.raises(LeaseNotOwned):
            resolve_route(cache,key=TEST_RENTER_KEY,tenant_id=tenant,requested_model=None,
                          requested_lease_id=ticket.lease_id,purposes=RENTER_CHAT_PURPOSES)
    cache.purge_key(fp)
    assert cache.key_scope_for(fp) is None


def test_receipts_retain_org_scope_across_restart_and_hide_unbound_history(tmp_path):
    from hypermesh_gateway_service.receipts import ReceiptStore
    tenant,own,foreign=uuid.uuid4(),uuid.uuid4(),uuid.uuid4()
    path=tmp_path/'receipts.json';store=ReceiptStore(path)
    for org in (own,foreign,None):
        store.record(tenant_id=tenant,lease_id=uuid.uuid4(),organization_id=org,
            who='isolated-owner',why='ir',what_left='none',prompt_class='test',decision='allow')
    restored=ReceiptStore(path)
    assert len(restored.export_for(tenant))==3
    own_rows=restored.export_for(tenant,organization_id=own)
    assert len(own_rows)==1 and own_rows[0]['organization_id']==str(own)


async def test_ir_key_history_uses_validated_org_not_caller_header(http_client,app,tenant_id,monkeypatch):
    monkeypatch.setenv('HYPERMESH_REQUIRE_KEY_SCOPE','1')
    own,foreign=uuid.uuid4(),uuid.uuid4()
    for org in (own,foreign,None):
        app.state.receipt_store.record(tenant_id=tenant_id,lease_id=uuid.uuid4(),organization_id=org,
            who='isolated-owner',why='ir',what_left='none',prompt_class='test',decision='allow')
    async def validate(**kwargs):
        return dict(valid=True,tenant_id=str(tenant_id),scope_kind='organization',
            organization_id=str(own),purpose='ir',scopes=[])
    app.state.api_key_validator=validate
    response=await http_client.get('/v1/ir/receipts',headers={
        'Authorization':'Bearer pk_test.ir-key','X-Tenant-ID':str(tenant_id),'X-Organization-ID':str(foreign)})
    assert response.status_code==200,response.text
    assert [row['organization_id'] for row in response.json()['receipts']]==[str(own)]


async def test_key_scope_capability_reports_runtime_enforcement(http_client,monkeypatch):
    url='/api/v1/hypermesh-gateway/key-scope-capabilities'
    monkeypatch.setenv('HYPERMESH_REQUIRE_KEY_SCOPE','1')
    response=await http_client.get(url)
    assert response.status_code==200
    assert response.json()=={'api_key_scope_version':1,'require_key_scope':True}
    monkeypatch.setenv('HYPERMESH_REQUIRE_KEY_SCOPE','0')
    assert (await http_client.get(url)).json()['require_key_scope'] is False
