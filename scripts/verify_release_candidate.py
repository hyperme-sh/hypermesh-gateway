"""Bind a declared release candidate to the artifact built by package CI."""
import argparse
import hashlib
import json
from pathlib import Path


def verify(manifest, contract, evidence, owner):
    manifest, contract, evidence = map(Path, (manifest, contract, evidence))
    bundle = json.loads(manifest.read_text())
    built = json.loads(evidence.read_text())
    def require(condition, message):
        if not condition:
            raise ValueError(message)
    require(bundle.get('schema_version') == 1, 'Unsupported candidate schema')
    require(set(bundle.get('components', {})) == {owner}, 'Wrong candidate component')
    candidate = bundle['components'][owner]
    require(candidate['version'] == built['version'], 'Candidate version differs from built wheel')
    require(bundle['line'] == built['version'].rsplit('.', 1)[0], 'Candidate line differs from built wheel')
    artifact = candidate['artifact']
    require(artifact['kind'] == 'package' and artifact['sha256'] == built['wheel_sha256'], 'Candidate artifact differs from built wheel')
    require(artifact['uri'] == 'urn:sha256:' + built['wheel_sha256'], 'Candidate must identify exact built bytes by digest')
    expected = (manifest.parent / candidate['contract']).resolve()
    require(expected.is_relative_to(manifest.parent.resolve()), 'Candidate contract escapes its bundle')
    actual = contract.read_bytes()
    require(expected.read_bytes() == actual, 'Candidate contract differs from built wheel export')
    digest = hashlib.sha256(actual).hexdigest()
    require(candidate['contract_sha256'] == digest == built['contract_sha256'], 'Candidate contract digest mismatch')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ['manifest', 'contract', 'evidence', 'owner']:
        parser.add_argument(name)
    args = parser.parse_args()
    verify(args.manifest, args.contract, args.evidence, args.owner)
    print('Candidate matches the exact built wheel and exported contract')
