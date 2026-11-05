import importlib.util
from pathlib import Path
import shutil
from types import SimpleNamespace
import pytest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('environment_check', ROOT/'scripts/verify_preparation_environment.py')
check = importlib.util.module_from_spec(spec); spec.loader.exec_module(check)

@pytest.fixture
def root(tmp_path):
    for name in ['pyproject.toml', 'uv.lock']: shutil.copyfile(ROOT/name, tmp_path/name)
    return tmp_path

def test_real_public_metadata_is_fresh(root):
    assert check.verify_lock_metadata(root)

@pytest.mark.parametrize('scope', ['runtime', 'dev'])
def test_stale_public_requirement_rejected(root, scope):
    p = root/'pyproject.toml'; s=p.read_text()
    if scope == 'runtime': s=s.replace('dependencies = [', 'dependencies = ["httpx>=999.0.0",', 1)
    else: s=s.replace('dev = [', 'dev = ["pytest>=999.0.0",', 1)
    p.write_text(s)
    with pytest.raises(ValueError, match='locked metadata'): check.verify_lock_metadata(root)

def test_incompatible_transitive_public_requirement_rejected(monkeypatch):
    packages = {'owner':SimpleNamespace(version='1.0', requires=['child>=2']), 'child':SimpleNamespace(version='1.0', requires=[])}
    monkeypatch.setattr(check, 'distribution', packages.__getitem__)
    with pytest.raises(ValueError, match='does not satisfy'): check.verify_installed(['owner'])

def test_requested_extra_is_checked(monkeypatch):
    packages = {'owner':SimpleNamespace(version='1.0', requires=['child>=2; extra == "feature"']), 'child':SimpleNamespace(version='1.0', requires=[])}
    monkeypatch.setattr(check, 'distribution', packages.__getitem__)
    check.verify_installed(['owner'])
    with pytest.raises(ValueError, match='does not satisfy'): check.verify_installed(['owner[feature]'])


@pytest.mark.parametrize('scope', ['runtime', 'dev'])
def test_non_git_direct_reference_rejected(root, scope):
    p = root/'pyproject.toml'
    key = 'dependencies = [' if scope == 'runtime' else 'dev = ['
    p.write_text(p.read_text().replace(key, key + '"pytest @ https://example.invalid/pytest-999.whl",', 1))
    with pytest.raises(ValueError, match='non-Git direct reference'):
        check.verify_lock_metadata(root)


def test_locked_direct_reference_rejected():
    with pytest.raises(ValueError, match='non-Git direct reference'):
        check.locked_public_requirements([{'name': 'pytest', 'url': 'https://example.invalid/pytest.whl'}])


def test_transitive_direct_reference_rejected(monkeypatch):
    packages = {'owner': SimpleNamespace(version='1.0', requires=['child @ https://example.invalid/child.whl'])}
    monkeypatch.setattr(check, 'distribution', packages.__getitem__)
    with pytest.raises(ValueError, match='non-Git direct reference'):
        check.verify_installed(['owner'])
