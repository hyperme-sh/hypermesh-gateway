"""Validate the isolated shipped-command configuration without starting Docker."""
from pathlib import Path
import os
import re
import runpy
import subprocess
import sys

from hypermesh_gateway_service.ticket_verifier import validate_verifier


def test_shipped_command_has_public_only_verifier(monkeypatch, tmp_path):
    root = Path(__file__).resolve().parents[1]
    source = (root/'scripts/check-runtime-image.sh').read_text()
    write = runpy.run_path(str(root/'scripts/runtime-qualification-env.py'))['write_environment']
    path = tmp_path/'runtime.env'
    write(path)
    assert path.stat().st_mode & 0o777 == 0o600
    other = tmp_path/'another.env'
    write(other)
    assert path.read_text() != other.read_text()
    assert 'python3 scripts/runtime-qualification-env.py "$scratch/runtime.env"' in source
    command = re.search(r'server=\$\(docker run -d .*?\n.*?\)', source, re.S).group()
    shell = 'set -euo pipefail\nci_labels=()\nimage=unit-fixture\ndocker() { printf "%s\\n" "$@"; }\n'
    result = subprocess.run(['bash', '-c', shell + command + '\nprintf "%s\\n" "$server"'],
                            env={'PATH':os.environ['PATH'], 'scratch':str(tmp_path)},
                            capture_output=True, text=True, check=True, timeout=5)
    args = result.stdout.splitlines()
    assert args[args.index('--env-file')+1] == str(path)
    env = dict(line.split('=', 1) for line in path.read_text().splitlines())
    env.update(dict(args[i+1].split('=', 1) for i, arg in enumerate(args) if arg in ('-e', '--env')))
    for name in tuple(os.environ):
        if name.startswith('HYPERMESH_TICKET_') or name == 'HYPERMESH_DEV':
            monkeypatch.delenv(name)
    for name, value in env.items():
        monkeypatch.setenv(name, value)
    assert set(name for name in env if name.startswith('HYPERMESH_TICKET_')) == {'HYPERMESH_TICKET_ED25519_PUBLIC_KEY'}
    assert env['HYPERMESH_WG_APPLY'] == env['HYPERMESH_ASSIGNMENT_REFRESH_S'] == '0'
    validate_verifier()
    # Load settings in a clean process, without module-global test settings.
    subprocess.run([sys.executable, '-c', 'from controlplane_api.config import settings; settings.require_edge_secrets()'],
                   env=env, check=True, capture_output=True, timeout=10)
