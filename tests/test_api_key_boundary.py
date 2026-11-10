"""Key-management authorization stays outside the paid chat data path.

Ported from the API keys service's original source-boundary regression. Resolve
installed gateway source so the same check exercises source, wheel and sdist.
"""
from pathlib import Path

import hypermesh_gateway_service


def test_chat_and_routes_do_not_depend_on_key_management_authority():
    root=Path(hypermesh_gateway_service.__file__).resolve().parent
    chat=(root/'chat.py').read_text(encoding='utf-8')
    for forbidden in ('api_keys','portal_controls','Keycloak'):
        assert forbidden not in chat
    routes=(root/'routes.py').read_text(encoding='utf-8')
    for forbidden in ('api_keys_service','actor_can_mint_keys'):
        assert forbidden not in routes
