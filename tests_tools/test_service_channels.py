"""Offline shared channel and deployment-overlay contracts."""
import hashlib
import json
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT/'scripts'))
from render_service_channel import render
from service_channels import reference

VECTORS = json.loads((ROOT/'tests_tools/service-reference-vectors.json').read_text())
GATEWAY = 'ghcr.io/hyperme-sh/hypermesh-gateway/runtime'


class ServiceChannelTests(unittest.TestCase):
    def test_shared_vectors(self):
        for image in VECTORS['accepted']:
            self.assertEqual(reference(image, VECTORS['repository']), image)
        for image in VECTORS['rejected']:
            with self.subTest(image=image), self.assertRaises(ValueError):
                reference(image, VECTORS['repository'])

    def test_independent_peer_patches_do_not_change_gateway_overlay(self):
        policy = {'hypermesh-gateway': GATEWAY, 'plane': 'ghcr.io/hyperme-sh/hypermesh-plane/runtime',
                  'payment': 'ghcr.io/hyperme-sh/payment-service/runtime'}
        for plane, payment in [('0.1.0', '0.3.2'), ('0.1.1', '0.3.2'), ('0.1.1', '0.3.3')]:
            channels = {key: repo+':'+tag for (key, repo), tag in zip(policy.items(), ['test', plane, payment])}
            output = render(json.dumps({'schema': 1, 'services': channels}).encode(), json.dumps(policy))
            self.assertEqual(output, {'services': {'hypermesh-gateway': {'image': GATEWAY+':test', 'pull_policy': 'always'}}})

    def test_bad_or_missing_configuration_is_refused(self):
        policy = json.dumps({'hypermesh-gateway': GATEWAY})
        for document in ({}, {'schema': 2, 'services': {'hypermesh-gateway': GATEWAY+':test'}},
                         {'schema': 1, 'services': {}},
                         {'schema': 1, 'services': {'hypermesh-gateway': GATEWAY+'@sha256:'+'a'*64}},
                         {'schema': 1, 'services': {'hypermesh-gateway': GATEWAY+':test\n'}}):
            with self.subTest(document=document), self.assertRaises(ValueError):
                render(json.dumps(document).encode(), policy)
        for policy in ({}, {'hypermesh-gateway': 'evil.test/gateway'}):
            with self.assertRaises(ValueError):
                render(b'{}', json.dumps(policy))

    def test_example_and_vendored_source(self):
        result = render((ROOT/'deployment/service-channels.example.json').read_bytes(),
                        (ROOT/'deployment/service-repositories.json').read_text())
        self.assertEqual(result['services']['hypermesh-gateway']['image'], GATEWAY+':test')
        recorded = json.loads((ROOT/'scripts/service-channels-source.json').read_text())
        for path in (ROOT/'scripts/service_channels.py', ROOT/'tests_tools/service-reference-vectors.json'):
            self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), recorded['sha256'][path.name])
