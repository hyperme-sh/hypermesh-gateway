"""The best-effort usage callback carries the already verified key tenant."""
import json
from types import SimpleNamespace
import uuid

import httpx
import pytest
from starlette.requests import Request
from controlplane_api.config import settings
from hypermesh_gateway_service import routes


@pytest.mark.asyncio
async def test_key_touch_uses_verified_tenant_not_untrusted_header(monkeypatch):
    tenant,key_id=uuid.uuid4(),uuid.uuid4();seen=[]
    request=Request({'type':'http','headers':[(b'x-tenant-id',str(uuid.uuid4()).encode())],
                     'app':SimpleNamespace(state=SimpleNamespace())})
    monkeypatch.setenv('HYPERMESH_API_KEYS_URL','https://api-keys.example.test')
    monkeypatch.setattr(settings,'api_keys_internal_token','synthetic-internal-fixture-token')
    original=httpx.AsyncClient
    def reply(request):
        seen.append(request)
        return httpx.Response(204)
    monkeypatch.setattr(httpx,'AsyncClient',lambda **kwargs:original(transport=httpx.MockTransport(reply),**kwargs))
    await routes._report_key_use(request,key_id,tenant_id=tenant)
    await routes._report_key_use(request,key_id,tenant_id=tenant)
    assert len(seen)==1
    assert seen[0].url.path=='/api/v1/internal/touch'
    assert seen[0].headers['X-Tenant-ID']==str(tenant)
    assert json.loads(seen[0].content)=={'key_id':str(key_id)}
