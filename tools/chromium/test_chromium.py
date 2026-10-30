import copy
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

import audit_chromium as audit
import releases_chromium as releases
import update_chromium as update

REPO = Path(__file__).resolve().parents[2]


class ChromiumContracts(unittest.TestCase):
    def test_official_https_hosts_only(self):
        for url in ['http://edgeupdates.microsoft.com/a', 'https://edgeupdates.microsoft.com.evil.test/a',
                    'https://user@edgeupdates.microsoft.com/a', 'https://storage.googleapis.com:444/a']:
            with self.subTest(url=url), self.assertRaises(ValueError):
                releases.checked_url(url)
        releases.checked_url('https://storage.googleapis.com/chrome-for-testing-public/version/win64/chrome-win64.zip')

    def test_release_selection_is_stable_product_and_full_version(self):
        raw = json.dumps([dict(Product='Stable', Releases=[dict(Platform='Windows', Architecture='x64', ProductVersion='156.0.1.2',
            Artifacts=[dict(ArtifactName='msi', HashAlgorithm='SHA256', Hash='a' * 64, SizeInBytes=20,
                            Location='https://msedge.sf.dl.delivery.mp.microsoft.com/browser.msi')])])]).encode()
        with patch.object(releases, 'fetch', return_value=raw):
            value, _ = releases.discover('edge', '156.0.1.2')
            self.assertEqual(value['archive_sha256'], 'a' * 64)
            for version in ['156', '156.0.1.3', '../version', '156.0.1.2-beta']:
                with self.assertRaises(ValueError):
                    releases.discover('edge', version)

    def test_bcj2_truncated_or_oversized_inputs_rejected(self):
        for data in [b'', b'\0' * 20, b'\xff' * 20]:
            with self.assertRaises(ValueError):
                releases.unbcj2(data)

    def test_unknown_extension_cannot_be_silently_projected(self):
        hello = dict(record_version=769, legacy_version=771, cipher_suites=[4865], extensions=[dict(id=60000, payload_hex='')])
        with self.assertRaises(ValueError):
            audit.project_tls(hello)

    def test_shuffle_normalization_retains_membership_and_values(self):
        hello = dict(record_version=769, legacy_version=771, cipher_suites=[4865], extensions=[
            dict(id=13, payload_hex='00020403'), dict(id=23, payload_hex='')])
        events = [dict(type='tls.client_hello', data=hello), dict(type='http1.headers', data=dict(headers=[dict(name='Host', value='localhost')]))]
        original = audit.normalize(events, 'tls13-h1')
        changed = copy.deepcopy(events); changed[0]['data']['extensions'].reverse()
        self.assertEqual(original, audit.normalize(changed, 'tls13-h1'))
        changed[0]['data']['extensions'][1]['payload_hex'] = '00020804'
        self.assertNotEqual(original, audit.normalize(changed, 'tls13-h1'))
        changed[0]['data']['extensions'].pop()
        self.assertNotEqual(original, audit.normalize(changed, 'tls13-h1'))

    def test_no_change_requires_exact_build_mode_platform_and_replay(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.assertFalse(update.known_build({}, root, 'chrome', '156.0.1.2'))
            fields = update.FIELDS
            catalog = {'chrome/156/windows': dict(match=dict(verified_fields=fields), spec=dict(evidence=[
                dict(product_version='156.0.1.2', platform='windows', transport=s, verified_fields=fields) for s in audit.SCENARIOS]))}
            observation = dict(browser='chrome', version='156.0.1.2', platform='windows-x64', locale='en-US', mode='headed-minimized', runtime_replay=dict(tls_and_headers_match=True))
            path = root / 'testdata/chrome/windows.json'
            audit.dump(path, dict(observations=[observation]))
            self.assertTrue(update.known_build(catalog, root, 'chrome', '156.0.1.2'))
            for key, value in [('mode', 'headless'), ('version', '156.0.1.3'), ('platform', 'linux-x64'), ('runtime_replay', {})]:
                changed = {**observation, key: value}
                audit.dump(path, dict(observations=[changed]))
                self.assertFalse(update.known_build(catalog, root, 'chrome', '156.0.1.2'))

    def test_shared_entry_preserves_firefox_and_product_arguments(self):
        spec = importlib.util.spec_from_file_location('browser_entry', REPO / 'tools/browser_update.py')
        module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
        arguments = ['--version', '156.0.1.2', '--output', 'out']
        self.assertEqual(Path(module.command('firefox', arguments)[1]).parts[-2:], ('firefox', 'update.py'))
        self.assertEqual(module.command('edge', arguments)[2:4], ['--browser', 'edge'])
        with self.assertRaises(ValueError):
            module.command('unknown', arguments)


if __name__ == '__main__':
    unittest.main()
