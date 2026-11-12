"""Validate runtime references independently of immutable package provenance."""
import json
import re

ASSET = 'service-channels.json'
NAME = r'[a-z0-9]+(?:[._-][a-z0-9]+)*'
REPOSITORY = rf'[a-z0-9]+(?:[.-][a-z0-9]+)*(?::[0-9]{{1,5}})?/{NAME}(?:/{NAME})*'
TAG = r'[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}'


def document(raw):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError('Duplicate service configuration key')
            result[key] = value
        return result
    return json.loads(raw, object_pairs_hook=unique)


def reference(value, repository):
    """Return the configured tag unchanged. Never resolve it to a digest."""
    if not isinstance(repository, str) or not re.fullmatch(REPOSITORY, repository):
        raise ValueError('Invalid approved registry/repository')
    registry = repository.split('/')[0]
    if ':' in registry and not 1 <= int(registry.rsplit(':', 1)[1]) <= 65535:
        raise ValueError('Invalid registry port')
    if not isinstance(value, str) or not re.fullmatch(re.escape(repository) + ':' + TAG, value):
        raise ValueError('Service must use an approved repository and explicit tag')
    return value


def validate(files, repositories):
    """Check an optional tested asset against trusted action configuration.

    An opted-in caller must provide the asset and every configured service.
    Package-only callers remain compatible. An asset without policy fails closed.
    """
    policy = document(repositories)
    if not isinstance(policy, dict) or any(
        not isinstance(key, str) or not re.fullmatch(NAME, key) for key in policy
    ):
        raise ValueError('Invalid service repository policy')
    if not policy and ASSET not in files:
        return {}
    if not policy or ASSET not in files:
        raise ValueError('Service asset and repository policy are both required')
    raw = files[ASSET]
    if not isinstance(raw, bytes) or len(raw) > 65536:
        raise ValueError('Invalid service asset size')
    data = document(raw)
    if (not isinstance(data, dict) or set(data) != {'schema', 'services'}
            or type(data['schema']) is not int or data['schema'] != 1
            or not isinstance(data['services'], dict)
            or set(data['services']) != set(policy)):
        raise ValueError('Service asset does not match configured services')
    return {name: reference(value, policy[name]) for name, value in data['services'].items()}
