"""Reject provider-specific symbols on the declared open runtime surface.

Pass one or more runtime/package paths explicitly; missing inputs fail closed.
Scan code, schemas, templates and dependency metadata, not prose or test evidence.
The caller must enumerate its complete shipped surface (including generated SDKs).
"""
from __future__ import annotations

import argparse
from pathlib import Path
import re
import tomllib

PROVIDER = re.compile(r'stripe', re.IGNORECASE)
EXTENSIONS = {'.py','.pyi','.go','.rs','.js','.jsx','.ts','.tsx','.proto','.sql',
              '.json','.yaml','.yml','.toml','.jinja','.j2','.h','.hpp','.c','.cpp',
              '.kt','.kts','.java','.swift','.cs','.mod','.sum'}


def violations(paths):
    found = []
    for root in paths:
        if not root.exists():
            raise ValueError(f'missing open surface: {root}')
        files = [root] if root.is_file() else sorted(root.rglob('*'))
        for path in files:
            if not path.is_file() or path.suffix not in EXTENSIONS:
                continue
            for line, value in enumerate(path.read_text(encoding='utf-8').splitlines(), 1):
                if PROVIDER.search(value):
                    found.append(f'{path}:{line}: provider-specific symbol in open surface')
    return found


def runtime_violations(root):
    """Walk locked production edges, including requested extras; omit dev groups."""
    project = tomllib.loads((root / 'pyproject.toml').read_text())['project']['name']
    packages = tomllib.loads((root / 'uv.lock').read_text())['package']
    by_name = {}
    for package in packages:
        by_name.setdefault(package['name'], []).append(package)
    pending = [(project, ())]
    seen, found = set(), []
    while pending:
        name, extras = pending.pop()
        key = (name, tuple(sorted(extras)))
        if key in seen:
            continue
        seen.add(key)
        candidates = by_name.get(name, [])
        if not candidates:
            raise ValueError(f'missing runtime dependency: {name}')
        if PROVIDER.search(name):
            found.append(f'{root}/uv.lock: provider runtime dependency: {name}')
        # Conservatively inspect every platform variant admitted by the lock.
        for package in candidates:
            edges = list(package.get('dependencies', []))
            for extra in extras:
                edges.extend(package.get('optional-dependencies', {}).get(extra, []))
            pending.extend((edge['name'], tuple(edge.get('extra', []))) for edge in edges)
    return found


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('paths', nargs='+', type=Path)
    parser.add_argument('--runtime-project', type=Path)
    args = parser.parse_args()
    try:
        failures = violations(args.paths)
        if args.runtime_project:
            failures.extend(runtime_violations(args.runtime_project))
    except (ValueError, OSError, UnicodeError) as exc:
        parser.exit(2, str(exc) + '\n')
    if failures:
        parser.exit(1, '\n'.join(failures) + '\n')


if __name__ == '__main__':
    main()
