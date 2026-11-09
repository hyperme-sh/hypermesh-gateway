"""Prepare a credential-free image context from checked owner/dependency wheels."""
from __future__ import annotations

import argparse
import email.parser
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
import tomllib
import zipfile

from verify_dependency_fixtures import verify
from check_open_boundary import runtime_violations


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--artifacts', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--source-sha', required=True)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    if not re.fullmatch('[0-9a-f]{40}', args.source_sha):
        parser.error('A full source commit is required')
    actual = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=root, text=True).strip()
    if actual != args.source_sha:
        parser.error('Selected commit differs from the checkout')
    subprocess.run(['git', 'ls-files', '--error-unmatch', 'Dockerfile',
                    'docker-entrypoint.sh', 'scripts/prepare-runtime-context.py',
                    'pyproject.toml', 'uv.lock', 'tests_artifacts/dependencies/manifest.json'],
                   cwd=root, check=True, stdout=subprocess.DEVNULL)
    changed = subprocess.check_output(
        ['git', 'status', '--porcelain', '--untracked-files=all', '--', 'src',
         'pyproject.toml', 'uv.lock', 'Dockerfile', 'docker-entrypoint.sh',
         'scripts', 'tests_artifacts'], cwd=root, text=True)
    if changed:
        raise SystemExit('Runtime inputs include changes outside the selected source commit')
    if runtime_violations(root):
        raise SystemExit('Provider dependency in production runtime graph')
    dependencies = verify(root)
    wheel, = args.artifacts.glob('*.whl')
    subprocess.run(['python3', str(root/'scripts/verify_wheel.py'), str(args.artifacts)], check=True)
    project = tomllib.loads((root/'pyproject.toml').read_text())['project']
    with zipfile.ZipFile(wheel) as archive:
        [metadata] = [name for name in archive.namelist() if name.endswith('.dist-info/METADATA')]
        info = email.parser.BytesParser().parsebytes(archive.read(metadata))
    normalize = lambda value: re.sub(r'\s+', '', value)
    if (info.get_all('Name') != [project['name']]
            or info.get_all('Version') != [project['version']]
            or info.get_all('Requires-Python') != [project['requires-python']]
            or sorted(map(normalize, info.get_all('Requires-Dist', [])))
                != sorted(map(normalize, project['dependencies']))):
        raise SystemExit('Owner wheel metadata differs from the selected source')
    args.output.mkdir(parents=True, exist_ok=False)
    with zipfile.ZipFile(args.output/'tested-dist.zip', 'w') as packages:
        for path in sorted(args.artifacts.iterdir()):
            if not path.is_file() or path.is_symlink():
                raise ValueError("Expected flat release package files")
            packages.write(path, path.name)
    wheels = args.output/'wheels'
    wheels.mkdir()
    inputs = {}
    for source in [wheel, *dependencies]:
        target = wheels/source.name
        if target.exists():
            raise SystemExit('Ambiguous runtime wheel name')
        shutil.copyfile(source, target)
        inputs[source.name] = hashlib.sha256(source.read_bytes()).hexdigest()
    options = []
    locked = tomllib.loads((root/'uv.lock').read_text())['package']
    for package in locked:
        if package['source'].get('git'):
            options.extend(['--no-emit-package', package['name']])
    requirements = args.output/'requirements.txt'
    subprocess.run(['uv', 'export', '--frozen', '--no-dev', '--group', 'image', '--no-emit-project',
                    *options, '--format', 'requirements-txt', '--output-file', str(requirements)],
                   cwd=root, check=True, stdout=subprocess.DEVNULL)
    if 'git+' in requirements.read_text():
        raise SystemExit('Private Git references must not enter the image context')
    for name in ('Dockerfile', 'docker-entrypoint.sh'):
        shutil.copyfile(root/name, args.output/name)
    manifest = {'source_sha': args.source_sha, 'wheels': inputs,
                'lock_sha256': hashlib.sha256((root/'uv.lock').read_bytes()).hexdigest(),
                'requirements_sha256': hashlib.sha256(requirements.read_bytes()).hexdigest()}
    (args.output/'runtime-inputs.json').write_text(json.dumps(manifest, indent=2)+'\n')
    print('Prepared runtime context from source-matching owner and verified dependency bytes')


if __name__ == '__main__':
    main()
