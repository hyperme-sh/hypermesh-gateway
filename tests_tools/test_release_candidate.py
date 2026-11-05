import hashlib
import importlib.util
import json
from pathlib import Path
import pytest

spec = importlib.util.spec_from_file_location('verify_release_candidate', Path(__file__).resolve().parents[1] / 'scripts/verify_release_candidate.py')
verifier = importlib.util.module_from_spec(spec)
spec.loader.exec_module(verifier)


def fixture(tmp_path):
    contract = tmp_path / 'contract.json'; contract.write_text('{"real_api": "example test fixture"}\n')
    sha = hashlib.sha256(contract.read_bytes()).hexdigest()
    evidence = tmp_path / 'evidence.json'; evidence.write_text(json.dumps({'version': '0.24.0', 'wheel_sha256': 'a'*64, 'contract_sha256': sha}))
    manifest = tmp_path / 'release.json'
    data = {'schema_version': 1, 'line': '0.24', 'components': {'owner': {'version': '0.24.0', 'contract': 'contract.json', 'contract_sha256': sha, 'artifact': {'kind': 'package', 'sha256': 'a'*64, 'uri': 'urn:sha256:'+'a'*64}}}}
    return manifest, contract, evidence, data


def test_accepts_exact_built_candidate(tmp_path):
    manifest, contract, evidence, data = fixture(tmp_path)
    manifest.write_text(json.dumps(data))
    verifier.verify(manifest, contract, evidence, 'owner')


@pytest.mark.parametrize('change', ['version','artifact','contract','owner','line','uri'])
def test_rejects_mismatched_candidate(tmp_path, change):
    manifest, contract, evidence, data = fixture(tmp_path)
    c = data['components']['owner']
    if change == 'version': c['version'] = '0.24.1'
    if change == 'artifact': c['artifact']['sha256'] = 'b'*64
    if change == 'contract': c['contract_sha256'] = 'b'*64
    if change == 'owner': data['components']['other'] = data['components'].pop('owner')
    if change == 'line': data['line'] = '0.25'
    if change == 'uri': c['artifact']['uri'] = 'https://example.invalid/unverified'
    manifest.write_text(json.dumps(data))
    with pytest.raises(ValueError): verifier.verify(manifest, contract, evidence, 'owner')
