import copy
import importlib.util
import io
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
    def test_range_rejects_wrong_identity_and_truncation(self):
        class Response(io.BytesIO):
            status = 206
            url = releases.CHROME_MSI
        for fault in ('etag', 'range', 'short', 'status'):
            with tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                def response(request, timeout):
                    start, end = map(int, request.get_header('Range').split('=')[1].split('-'))
                    value = Response(b'x' * (end - start + (0 if fault == 'short' else 1)))
                    value.headers = {'Content-Range': 'wrong' if fault == 'range' else f'bytes {start}-{end}/16', 'ETag': 'wrong' if fault == 'etag' else 'pin'}
                    if fault == 'status': value.status = 200
                    return value
                with patch.object(releases.urllib.request, 'build_opener') as opener:
                    opener.return_value.open.side_effect = response
                    with self.assertRaises(ValueError):
                        releases.ranged_download(dict(size=16, etag='pin', url=releases.CHROME_MSI), root / 'browser.msi')
                self.assertFalse((root / 'browser.msi').exists())

    def test_unsigned_msi_never_reaches_extractor(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); archive = root / 'browser.msi'; archive.write_bytes(b'unsigned')
            manifest = dict(browser='chrome', version='156.0.1.2', archive_sha256=None, size=8)
            with patch.object(releases, 'publisher', side_effect=ValueError('NotSigned')), patch.object(releases.subprocess, 'run') as execute:
                with self.assertRaises(ValueError):
                    releases.extract_archive(manifest, archive, root)
                execute.assert_not_called()

    def make_run(self, root):
        version = '156.0.1.2'
        audit.dump(root / 'downloads/builds.json', [dict(browser='chrome', version=version, executable_sha256='a' * 64, source='official')])
        audit.dump(root / 'run.json', dict(expected_samples_per_scenario=5, mode='headed-minimized', scope='synthetic unit fixture'))
        samples, batches = [], {'12': [], '13': []}
        for scenario in audit.SCENARIOS:
            suffix = '12' if scenario == 'tls12-h1' else '13'
            for index in range(5):
                connection = scenario + '-' + str(index)
                events = [dict(type='tls.client_hello', data=dict(record_version=769, legacy_version=771, cipher_suites=[4865], extensions=[dict(id=13, payload_hex='00020403')])),
                    dict(type='tls.negotiated', data=dict(version=771 if suffix == '12' else 772, alpn='h2' if scenario.endswith('h2') else 'http/1.1', resumed=False)),
                    dict(type='http2.headers' if scenario.endswith('h2') else 'http1.headers', data=dict(headers=[dict(name='User-Agent', value='Chrome/156.0.0.0')]))]
                if scenario.endswith('h2'):
                    events.append(dict(type='http2.settings', data=[dict(id=2, value=0)]))
                for item in events:
                    item.update(run_id='capture' + suffix, connection_id=connection)
                batches[suffix].extend(events)
                samples.append(dict(browser='chrome', version=version, browser_version=version, browser_identity=dict(product='Chrome/' + version),
                    executable_sha256='a' * 64, scenario=scenario, sample=index, time='2026-10-30T00:00:00Z', mode='headed-minimized', status='observed', events=events))
        audit.dump(root / 'browser-samples.json', samples)
        for suffix, events in batches.items():
            audit.dump(root / f'capture{suffix}/management-events.json', events)

    def test_projection_accepts_collector_settings_list_and_preserves_source(self):
        catalog = audit.read(REPO / 'browser-specs.json')
        previous = copy.deepcopy(catalog)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); self.make_run(root)
            observations, candidates = audit.audit(root, catalog, 'chrome')
            self.assertEqual(len(observations['observations'][0]['cases']), 3)
            self.assertEqual(candidates['chrome/156/windows']['spec']['http2']['settings'], [dict(id=2, value=0)])
            self.assertEqual(candidates['chrome/156/windows']['match']['verified_fields'], [])
            self.assertEqual(catalog, previous)

    def test_missing_duplicate_reused_or_resumed_samples_are_blocked(self):
        catalog = audit.read(REPO / 'browser-specs.json')
        for change in ('missing', 'duplicate', 'reused', 'resumed'):
            with tempfile.TemporaryDirectory() as directory:
                root = Path(directory); self.make_run(root)
                samples = audit.read(root / 'browser-samples.json')
                if change == 'missing': samples.pop()
                if change == 'duplicate': samples[1]['sample'] = samples[0]['sample']
                if change == 'reused': samples[1]['events'] = samples[0]['events']
                if change == 'resumed':
                    events = audit.read(root / 'capture12/management-events.json')
                    next(e['data'] for e in events if e['type'] == 'tls.negotiated')['resumed'] = True
                    audit.dump(root / 'capture12/management-events.json', events)
                audit.dump(root / 'browser-samples.json', samples)
                with self.subTest(change=change), self.assertRaises(ValueError):
                    audit.audit(root, catalog, 'chrome')

    def test_official_https_hosts_only(self):
        for url in ['http://edgeupdates.microsoft.com/a', 'https://edgeupdates.microsoft.com.evil.test/a',
                    'https://user@edgeupdates.microsoft.com/a', 'https://storage.googleapis.com:444/a']:
            with self.subTest(url=url), self.assertRaises(ValueError):
                releases.checked_url(url)
        releases.checked_url(releases.CHROME_MSI)

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

    def test_reviewed_trust_anchor_bytes_preserved_and_malformed_vectors_rejected(self):
        raw = '000403822101'
        hello = dict(record_version=769, legacy_version=771, cipher_suites=[4865], extensions=[dict(id=51764, payload_hex=raw)])
        self.assertEqual(audit.project_tls(hello)['extensions'], [dict(id='0xca34', raw_hex=raw)])
        for payload in ['00', '00010201', '00020000', '00020180', '000403808100', '000401010101']:
            with self.subTest(payload=payload), self.assertRaises(ValueError):
                audit.trust_anchor_ids(bytes.fromhex(payload))

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
