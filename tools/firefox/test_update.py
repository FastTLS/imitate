import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import audit
import releases

REPO = Path(__file__).resolve().parents[2]


class ReleaseTests(unittest.TestCase):
    def test_stable_selection_excludes_esr_beta_and_nonzero_minor(self):
        data = {
            'firefox_versions.json': {'LATEST_FIREFOX_VERSION': '158.0.1'},
            'firefox_history_stability_releases.json': {'157.0.1': '', '158.0.1': '', '158.4.0': '', '158.0b9': '', '158.0.2esr': ''},
            'firefox_history_major_releases.json': {'157.0': '', '158.0': ''},
        }
        with patch.object(releases, 'fetch', lambda url: json.dumps(data[url.rsplit('/', 1)[-1]]).encode()):
            self.assertEqual(releases.discover(157, 158)['versions'], ['157.0.1', '158.0.1'])
            with self.assertRaises(ValueError):
                releases.discover(156, 158)


class EvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.catalog = audit.read(REPO / 'browser-specs.json')
        cls.fixture = audit.read(REPO / 'testdata/firefox/windows.json')

    def make_run(self, root):
        observation = next(o for o in self.fixture['observations'] if o['version'] == '158.0.1')
        audit.dump(root / 'downloads/builds.json', [observation['build']])
        audit.dump(root / 'downloads/discovery.json', {'versions': ['158.0.1'], 'source': releases.API})
        audit.dump(root / 'run.json', {'expected_samples_per_scenario': 5, 'mode': 'headless', 'scope': 'test fixture'})
        samples, batches = [], {'12': [], '13': []}
        for scenario, case in observation['cases'].items():
            for index in range(5):
                events = copy.deepcopy(case['raw_events'])
                for e in events:
                    e['connection_id'] = scenario + str(index)
                batches['12' if scenario == 'tls12-h1' else '13'].extend(events)
                samples.append({'version': observation['version'], 'browser_version': observation['version'], 'scenario': scenario,
                                'sample': index, 'mode': 'headless', 'time': case['samples'][0]['captured_at'], 'status': 'observed', 'events': events})
        audit.dump(root / 'browser-samples.json', samples)
        for suffix, events in batches.items():
            audit.dump(root / f'capture{suffix}/management-events.json', events)

    def test_complete_input_preserved_and_ja3_is_auxiliary(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.make_run(root)
            observations, catalog, summary = audit.audit(root, self.catalog)
            self.assertEqual(summary['valid_samples'], 15)
            spec = catalog['firefox/158/windows']['spec']
            self.assertTrue(any(e['id'] == '0x001b' for e in spec['tls']['extensions']))
            self.assertEqual(catalog['firefox/158/windows']['match']['verified_fields'], [])
            hello = observations['observations'][0]['cases']['tls13-h2']['hello']
            changed = copy.deepcopy(hello)
            signature = next(e for e in changed['extensions'] if e['id'] == 13)
            signature['payload_hex'] = signature['payload_hex'].replace('0804', '0807')
            self.assertEqual(audit.ja3(hello), audit.ja3(changed))
            self.assertNotEqual(audit.tls(hello), audit.tls(changed))

    def test_missing_or_duplicate_sample_rejected(self):
        for duplicate in (False, True):
            with self.subTest(duplicate=duplicate), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                self.make_run(root)
                samples = audit.read(root / 'browser-samples.json')
                if duplicate:
                    samples[1]['sample'] = samples[0]['sample']
                else:
                    samples.pop()
                audit.dump(root / 'browser-samples.json', samples)
                with self.assertRaises(ValueError):
                    audit.audit(root, self.catalog)

    def test_resumed_connection_and_unstable_headers_rejected(self):
        for kind in ('tls.negotiated', 'http1.headers'):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                self.make_run(root)
                path = root / 'capture12/management-events.json'
                events = audit.read(path)
                e = next(e for e in events if e['type'] == kind)
                if kind == 'tls.negotiated':
                    e['data']['resumed'] = True
                else:
                    e['data']['headers'][1]['value'] = 'wrong identity'
                audit.dump(path, events)
                with self.assertRaises(ValueError):
                    audit.audit(root, self.catalog)

    def test_unknown_tls_extension_blocks_projection(self):
        hello = copy.deepcopy(self.fixture['observations'][-1]['cases']['tls13-h2']['hello'])
        hello['extensions'].append({'id': 12345, 'payload_hex': ''})
        with self.assertRaises(ValueError):
            audit.project_tls(hello)

    def test_all_requested_windows_majors_have_independent_evidence(self):
        # Historical observations are not assertions about the active catalog.
        self.assertEqual({int(o['version'].split('.')[0]) for o in self.fixture['observations'] if int(o['version'].split('.')[0]) <= 158}, set(range(144,159)))
        for observation in self.fixture['observations']:
            self.assertEqual(set(observation['cases']), set(audit.SCENARIOS))
            for case in observation['cases'].values():
                self.assertEqual(len(case['samples']), 5)
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory); self.make_run(root)
            _, candidate, _=audit.audit(root,self.catalog)
            item=candidate['firefox/158/windows']
            self.assertEqual(len(item['spec']['evidence']),3)
            self.assertEqual(item['match']['method'],'compatible')
            self.assertIn('http.headers.protocol.v1',item['spec']['capabilities']['required_features'])
            self.assertEqual(item['match']['verified_fields'],[])


if __name__ == '__main__':
    unittest.main()
