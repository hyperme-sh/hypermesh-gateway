"""Router-owned tenant ids.

The hypermesh-gateway image ships honor_ticket only (ticket.py). It does not
install hypermesh-service, so MARKETPLACE_TENANT_ID lives here — same UUID as
hypermesh_service.seed — and HYPERMESH_TENANT_IDS can override the watch list.
"""

from __future__ import annotations

import uuid

MARKETPLACE_TENANT_ID = uuid.UUID("8f8e8d8c-7b6a-4a59-8c3d-2e1f0a9b8c7d")
