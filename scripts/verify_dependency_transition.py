"""Qualify an explicit dependency and consumer adaptation, never grant stable admission."""
import hashlib
import json
from pathlib import Path
import sys
from packaging.requirements import Requirement
from packaging.utils import canonicalize_name
from packaging.version import Version


def verify(before_path, after_path, transition_path, fixture_path):
    before_raw = Path(before_path).read_bytes()
    before = json.loads(before_raw)
    after = json.loads(Path(after_path).read_text())
    transition = json.loads(Path(transition_path).read_text())
    fixtures = json.loads(Path(fixture_path).read_text())['dependencies']
    def require(condition, message):
        if not condition:
            raise ValueError(message)
    require(transition.get('schema_version') == 1 and transition.get('version_policy') == 'pre-0.24', 'Invalid transition line/schema')
    require(transition.get('qualification_only') is True, 'Transition must remain qualification only')
    require(transition['previous_contract_sha256'] == hashlib.sha256(before_raw).hexdigest(), 'Wrong previous contract')
    require(transition.get('dependency_versions') == {d['distribution']: d['version'] for d in fixtures}, 'Fixture versions differ from the declared transition')
    require(all(Version(d['version']) < Version('0.24.0') for d in fixtures), 'Fixture version is outside the authorized pre-0.24 policy')
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
    # Consumer adaptations are explicit, byte-bound preparation evidence. They
    # neither grant stable compatibility nor allow unrecorded runtime changes.
    runtime = dict(before['packaged_file_sha256'])
    for path, change in transition.get('consumer_adaptations', {}).items():
        require(path in runtime, 'Consumer adaptation must name an existing file')
        require(change.get('reason') and change.get('regression_test'), 'Consumer adaptation requires rationale and regression evidence')
        require(runtime[path] == change['before_sha256'], 'Wrong consumer adaptation source')
        digest = change['after_sha256']
        require(len(digest) == 64 and all(c in '0123456789abcdef' for c in digest), 'Invalid consumer adaptation digest')
        runtime[path] = digest
    for path, change in transition.get('added_files', {}).items():
        parts = Path(path).parts
        require(
            bool(parts) and not path.startswith('/') and '..' not in parts and path not in runtime,
            'Added file is unsafe or already in the baseline',
        )
        require(change.get('reason') and change.get('regression_test'), 'Added file requires rationale and regression evidence')
        digest = change.get('sha256')
        require(
            isinstance(digest, str) and len(digest) == 64 and all(c in '0123456789abcdef' for c in digest),
            'Invalid added file digest',
        )
        runtime[path] = digest
    expected['packaged_file_sha256'] = runtime
    require(expected == after, 'Unexpected runtime or installer contract change')


if __name__ == '__main__':
    verify(*sys.argv[1:])
    print('Explicit private-pin transition qualified; stable admission remains separate')
