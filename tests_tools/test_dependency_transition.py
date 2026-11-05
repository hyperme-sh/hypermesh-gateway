import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import pytest

spec = importlib.util.spec_from_file_location('transition', Path(__file__).resolve().parents[1]/'scripts/verify_dependency_transition.py')
module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)

@pytest.fixture
def bundle(tmp_path):
    old = 'dep@ git+https://github.com/hyperme-sh/dep.git@' + 'a'*40
    new = 'dep@ git+https://github.com/hyperme-sh/dep.git@' + 'b'*40
    before = {'requires_dist': [old], 'requires_python': ['>=3.13'], 'entry_points': None, 'packaged_file_sha256': {'dep.py': 'abc'}}
    raw = json.dumps(before).encode()
    data = [before, dict(copy.deepcopy(before), requires_dist=[new]), {'schema_version':1, 'version_policy':'pre-0.24', 'dependency_versions':{'dep':'0.15.0'}, 'qualification_only':True, 'previous_contract_sha256':hashlib.sha256(raw).hexdigest(), 'requirements':[{'before':old,'after':new}]}, {'dependencies':[{'distribution':'dep','version':'0.15.0','dependency_revision':'b'*40}]}]
    paths = [tmp_path/str(i) for i in range(4)]
    def run():
        for p,d in zip(paths,data):p.write_text(json.dumps(d))
        module.verify(*paths)
    return data, run

def test_explicit_pin_transition(bundle):
    _,run = bundle;run()

@pytest.mark.parametrize('change', ['python','runtime','entry_points','registry','target','baseline','line','stable','shape'])
def test_unqualified_changes_rejected(bundle, change):
    d,run = bundle
    if change == 'python': d[1]['requires_python'] = ['>=3.14']
    if change == 'runtime': d[1]['packaged_file_sha256'] = {'dep.py':'changed'}
    if change == 'entry_points': d[1]['entry_points'] = 'new command'
    if change == 'registry': d[1]['requires_dist'].append('httpx>=99')
    if change == 'target': d[3]['dependencies'][0]['dependency_revision'] = 'c'*40
    if change == 'baseline': d[2]['previous_contract_sha256'] = '0'*64
    if change == 'line': d[3]['dependencies'][0]['version'] = '0.1.0'
    if change == 'stable': d[2]['qualification_only'] = False
    if change == 'shape': d[2]['requirements'][0]['after'] += '; python_version >= "3.13"'
    with pytest.raises(ValueError):run()

def test_independent_owner_versions_do_not_require_a_shared_release_line(bundle):
    data, run = bundle
    data[2]['dependency_versions']['dep'] = '0.1.0'
    data[3]['dependencies'][0]['version'] = '0.1.0'
    run()

def test_unauthorized_line_cannot_be_declared_as_a_transition(bundle):
    data, run = bundle
    data[2]['dependency_versions']['dep'] = '1.0.0'
    data[3]['dependencies'][0]['version'] = '1.0.0'
    with pytest.raises(ValueError, match='outside'):
        run()


def test_explicit_consumer_adaptation_is_bound_to_both_file_digests(bundle):
    data, run = bundle
    data[1]['packaged_file_sha256']['dep.py'] = 'd' * 64
    data[2]['consumer_adaptations'] = {'dep.py': {
        'before_sha256': 'abc', 'after_sha256': 'd' * 64,
        'reason': 'Async identity integration', 'regression_test': 'tests/test_async_lifecycle.py',
    }}
    run()


@pytest.mark.parametrize('tamper', ['source', 'target', 'extra_file', 'missing_reason', 'new_file'])
def test_consumer_adaptation_refuses_unrecorded_changes(bundle, tamper):
    data, run = bundle
    data[1]['packaged_file_sha256']['dep.py'] = 'd' * 64
    change = {'before_sha256': 'abc', 'after_sha256': 'd' * 64,
              'reason': 'Async integration', 'regression_test': 'tests/test_async_lifecycle.py'}
    data[2]['consumer_adaptations'] = {'dep.py': change}
    if tamper == 'source': change['before_sha256'] = 'wrong'
    if tamper == 'target': data[1]['packaged_file_sha256']['dep.py'] = 'e' * 64
    if tamper == 'extra_file': data[1]['packaged_file_sha256']['other.py'] = 'e' * 64
    if tamper == 'missing_reason': change.pop('reason')
    if tamper == 'new_file': data[2]['consumer_adaptations'] = {'unknown.py': change}
    with pytest.raises(ValueError):
        run()
