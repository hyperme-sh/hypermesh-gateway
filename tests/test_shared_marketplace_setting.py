"""The owning product honors the shared marketplace default and override."""
import os
import subprocess
import sys
import uuid

import pytest


@pytest.mark.parametrize("override", [False, True])
def test_product_uses_shared_marketplace_setting(override):
    env = dict(os.environ)
    env.pop("AIUDITOR_CRAWL_TENANT_ID", None)
    env.pop("MARKETPLACE_TENANT_ID", None)
    if override:
        env["MARKETPLACE_TENANT_ID"] = str(uuid.uuid4())
    env.pop("PYTHONPATH", None)
    subprocess.run([sys.executable, "-I", "-c", "from controlplane_tenancy.marketplace import MARKETPLACE_TENANT_ID as shared\n" + 'from hypermesh_gateway_service.tenants import MARKETPLACE_TENANT_ID as product\nassert shared == product'], env=env, check=True, capture_output=True, text=True)
