"""Write ephemeral configuration for the credential-free, network-isolated probe."""
import os
from pathlib import Path
import secrets
import sys


def write_environment(path):
    values = {
        'API_KEY_EXCHANGE_JWT_SECRET': secrets.token_urlsafe(48),
        'API_KEYS_INTERNAL_TOKEN': secrets.token_urlsafe(48),
        # RFC 8032 test-vector public key; no ticket signer is present.
        'HYPERMESH_TICKET_ED25519_PUBLIC_KEY': '11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo=',
    }
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'w') as output:
        for name, value in values.items():
            output.write(f'{name}={value}\n')


if __name__ == '__main__':
    write_environment(Path(sys.argv[1]))
