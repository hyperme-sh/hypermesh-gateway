"""Retain Panopticon's Docker boundary against the extracted wheel-only image."""
from pathlib import Path


def test_gateway_dockerfile_does_not_copy_hypermesh_service_seed():
    text = (Path(__file__).resolve().parents[1] / 'Dockerfile').read_text()
    assert 'hypermesh_service/seed.py' not in text
    assert 'hypermesh_service/ticket.py' not in text
    assert 'COPY products/hypermesh ' not in text
    # Extraction replaces the monorepo ticket COPY with verified owner wheels.
    assert 'COPY wheels/ /packages/wheels/' in text
    assert '--no-index --no-deps /packages/wheels/*.whl' in text
