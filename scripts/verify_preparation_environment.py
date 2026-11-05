"""Check public lock freshness and the active installed requirement graph."""
from importlib.metadata import distribution
from pathlib import Path
import sys
import tomllib
from packaging.requirements import Requirement
from packaging.specifiers import SpecifierSet
from packaging.utils import canonicalize_name


def public_requirements(requirements):
    parsed = [Requirement(r) for r in requirements]
    if any(r.url and not r.url.startswith('git+') for r in parsed):
        raise ValueError('Unsupported non-Git direct reference')
    return {r for r in parsed if not r.url}


def locked_public_requirements(records):
    result = []
    for r in records:
        if 'url' in r:
            raise ValueError('Unsupported non-Git direct reference in lock metadata')
        if 'git' in r: continue
        value = r['name']
        if r.get('extras'): value += '[' + ','.join(r['extras']) + ']'
        value += r.get('specifier', '')
        if r.get('marker'): value += '; ' + r['marker']
        result.append(value)
    return public_requirements(result)


def verify_lock_metadata(root):
    root = Path(root)
    project = tomllib.loads((root/'pyproject.toml').read_text())
    lock = tomllib.loads((root/'uv.lock').read_text())
    owner, = [p for p in lock['package'] if p['name'] == project['project']['name'] and 'editable' in p['source']]
    metadata = owner['metadata']
    requirements = project['project']['dependencies']
    dev = project.get('dependency-groups', {}).get('dev', [])
    if public_requirements(requirements) != locked_public_requirements(metadata.get('requires-dist', [])):
        raise ValueError('Public project requirements differ from locked metadata')
    if public_requirements(dev) != locked_public_requirements(metadata.get('requires-dev', {}).get('dev', [])):
        raise ValueError('Public development requirements differ from locked metadata')
    if SpecifierSet(project['project']['requires-python']) != SpecifierSet(lock['requires-python']):
        raise ValueError('Python requirement differs from locked metadata')
    return requirements + dev


def verify_installed(requirements):
    pending = [Requirement(r) for r in requirements]
    seen = set()
    while pending:
        requirement = pending.pop()
        if requirement.marker and not requirement.marker.evaluate({'extra': ''}): continue
        if requirement.url and not requirement.url.startswith('git+'):
            raise ValueError('Unsupported non-Git direct reference')
        package = distribution(requirement.name)
        if requirement.specifier and not requirement.specifier.contains(package.version, prereleases=True):
            raise ValueError(f'Installed {requirement.name} {package.version} does not satisfy {requirement.specifier}')
        key = (canonicalize_name(requirement.name), frozenset(requirement.extras))
        if key in seen: continue
        seen.add(key)
        for raw in package.requires or []:
            child = Requirement(raw)
            if child.marker and not any(child.marker.evaluate({'extra': e}) for e in {'', *requirement.extras}): continue
            # The edge has been evaluated in its parent's extras context.
            child.marker = None
            pending.append(child)


if __name__ == '__main__':
    verify_installed(verify_lock_metadata(sys.argv[1]))
    print('Public lock metadata and active installed requirements verified')
