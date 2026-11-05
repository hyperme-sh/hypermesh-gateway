"""Qualify an explicit private-pin transition, never grant stable admission."""
import hashlib
import json
from pathlib import Path
import sys
from packaging.requirements import Requirement
from packaging.utils import canonicalize_name


def verify(before_path, after_path, transition_path, fixture_path):
    before_raw = Path(before_path).read_bytes()
    before = json.loads(before_raw)
    after = json.loads(Path(after_path).read_text())
    transition = json.loads(Path(transition_path).read_text())
    fixtures = json.loads(Path(fixture_path).read_text())['dependencies']
    def require(condition, message):
        if not condition:
            raise ValueError(message)
    require(transition.get('schema_version') == 1 and transition.get('release_line') == '0.24', 'Invalid transition line/schema')
    require(transition.get('qualification_only') is True, 'Transition must remain qualification only')
    require(transition['previous_contract_sha256'] == hashlib.sha256(before_raw).hexdigest(), 'Wrong previous contract')
    require(all(d['version'].rsplit('.', 1)[0] == '0.24' for d in fixtures), 'Mixed fixture release lines')
    records = {d['distribution']: d for d in fixtures}
    require(len(records) == len(fixtures), 'Duplicate fixture distribution')
    changes = transition['requirements']
    require(bool(changes), 'Empty dependency transition')
    expected = dict(before)
    requirements = list(before['requires_dist'])
    seen = set()
    for change in changes:
        old, new = Requirement(change['before']), Requirement(change['after'])
        name = canonicalize_name(old.name)
        require(name == canonicalize_name(new.name) and name not in seen, 'Changed or repeated dependency identity')
        seen.add(name)
        require(old.url and old.url.startswith('git+https://github.com/hyperme-sh/'), 'Only private Git pins can transition')
        require(old.extras == new.extras and str(old.marker) == str(new.marker) and old.specifier == new.specifier, 'Changed dependency shape')
        record = records[name]
        require(new.url == old.url.rsplit('@', 1)[0] + '@' + record['dependency_revision'], 'Target differs from qualified fixture revision')
        require(requirements.count(change['before']) == 1, 'Transition source missing or ambiguous')
        requirements[requirements.index(change['before'])] = change['after']
    expected['requires_dist'] = sorted(requirements)
    require(expected == after, 'Unexpected runtime or installer contract change')


if __name__ == '__main__':
    verify(*sys.argv[1:])
    print('Explicit private-pin transition qualified; stable admission remains separate')
