"""Render the gateway image overlay from a validated shared channel asset."""
import argparse
import json
from pathlib import Path

from service_channels import ASSET, document, validate

SERVICE = 'hypermesh-gateway'
APPROVED_REPOSITORIES = (
    'ghcr.io/hyperme-sh/hypermesh-gateway/runtime',
    'acrfybercg47.azurecr.io/hypermesh-gateway',
)


def render(raw, repositories):
    policy = document(repositories)
    if not isinstance(policy, dict) or policy.get(SERVICE) not in APPROVED_REPOSITORIES:
        raise ValueError('Gateway repository policy is missing or unsupported')
    channels = validate({ASSET: raw}, repositories)
    # An overlay changes only the owned image and refresh policy. Environment,
    # trust, networking, capabilities and independently deployed peers stay in
    # the deployment owner's base composition.
    return {'services': {SERVICE: {'image': channels[SERVICE], 'pull_policy': 'always'}}}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--channels', type=Path, required=True)
    parser.add_argument('--repositories', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    result = render(args.channels.read_bytes(), args.repositories.read_text())
    args.output.write_text(json.dumps(result, indent=2) + '\n')


if __name__ == '__main__':
    main()
