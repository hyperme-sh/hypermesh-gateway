import importlib.util
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('boundary', ROOT/'scripts/check_open_boundary.py')
boundary = importlib.util.module_from_spec(spec)
spec.loader.exec_module(boundary)


def test_transitive_provider_dependency_and_dev_only_exclusion(tmp_path):
    (tmp_path/'pyproject.toml').write_text('[project]\nname="gateway"\n')
    lock = '\n'.join([
        '[[package]]', 'name="gateway"', 'dependencies=[{name="core"}]',
        '[package.dev-dependencies]', 'dev=[{name="stripe"}]',
        '[[package]]', 'name="core"', 'dependencies=[]',
        '[[package]]', 'name="stripe"',
    ])
    (tmp_path/'uv.lock').write_text(lock)
    assert boundary.runtime_violations(tmp_path) == []
    (tmp_path/'uv.lock').write_text(lock.replace('dependencies=[]', 'dependencies=[{name="stripe"}]'))
    assert 'stripe' in boundary.runtime_violations(tmp_path)[0]


def test_gateway_production_graph_excludes_provider():
    assert boundary.runtime_violations(ROOT) == []
