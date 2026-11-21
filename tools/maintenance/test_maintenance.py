import copy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import maintain
import publish

REPO = Path(__file__).resolve().parents[2]
SHA = 'a' * 40


class AdoptionTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.repo = self.root / 'repo'
        self.repo.mkdir()
        self.inputs = self.root / 'inputs'
        self.run = self.inputs / 'browser-profile-candidate-firefox'
        self.catalog = maintain.read(REPO / 'browser-specs.json')
        self.identifier = 'firefox/159/windows'
        entry = copy.deepcopy(self.catalog[self.identifier])
        verified = sorted(maintain.fields('firefox'))
        entry['match']['verified_fields'] = verified
        observation = next(o for o in maintain.read(REPO / 'testdata/firefox/windows.json')['observations'] if o['version'] == '159.0')
        observation['runtime_replay'] = {'tls_and_headers_match': True, 'whole_profile_match': True}
        entry['spec']['http2'].update(maintain.audit.project_h2_stream(observation['cases']['tls13-h2']['raw_events']))
        entry['spec']['capabilities']['required_features'].append('http2.stream.v1')
        for evidence in entry['spec']['evidence']:
            evidence['verified_fields'] = verified
        proposed = copy.deepcopy(self.catalog)
        proposed[self.identifier] = entry
        raw = json.dumps(entry['spec'], sort_keys=True, separators=(',', ':'))
        sha = hashlib.sha256(raw.encode()).hexdigest()
        maintain.write(self.run / 'candidate/browser-specs.json', proposed)
        maintain.write(self.run / 'candidate/testdata/firefox/windows.json', {'schema_version': 1, 'observations': [observation]})
        maintain.write(self.run / 'bundles/firefox-windows.json', {'schema_version': 1, 'profile_id': self.identifier, 'spec_json': raw, 'sha256': sha})
        report = {'status': 'candidate', 'browser_version': '159.0', 'scope': 'synthetic adoption unit test using recorded observations',
            'sources': {'imitate': {'commit': SHA}}, 'bundle': {'path': 'bundles/firefox-windows.json', 'sha256': sha}}
        maintain.write(self.run / 'update-report.json', report)
        rows = [{'selector': self.identifier, 'mode': mode, 'scenario': scenario, 'status': 200, 'differences': [],
            'actual': maintain.audit.normalize(case['raw_events'], scenario)}
            for mode in ('online', 'offline') for scenario, case in observation['cases'].items()]
        maintain.write(self.run / 'replay/comparison.json', {'results': rows})
        maintain.write(self.run / 'replay/catalog-check.json', {'catalog': [{'id': self.identifier, 'spec': entry['spec']}]})
        maintain.write(self.repo / 'browser-specs.json', self.catalog)
        (self.repo / 'provider.go').write_text('const DataRevision = "before"\n')

    def change(self, path, edit):
        target = self.run / path
        data = maintain.read(target)
        edit(data)
        maintain.write(target, data)

    def verify(self):
        return maintain.verify(self.run, self.catalog, 'firefox', SHA)

    def test_exact_evidence_accepts_and_preserves_other_profiles(self):
        result = maintain.stage(self.repo, self.inputs, SHA, 'https://example.test/run', ['firefox'])
        self.assertTrue(result['changed'])
        self.assertFalse(result['blocked'])
        current = maintain.read(self.repo / 'browser-specs.json')
        self.assertEqual({k:v for k,v in current.items() if k != self.identifier}, {k:v for k,v in self.catalog.items() if k != self.identifier})
        self.assertIn('browser-', (self.repo / 'provider.go').read_text())

    def test_unrelated_profile_edit_is_rejected(self):
        self.change('candidate/browser-specs.json', lambda c: c.pop('chrome/155/windows'))
        with self.assertRaisesRegex(ValueError, 'unrelated'): self.verify()

    def test_missing_and_duplicate_replay_modes_are_rejected(self):
        for fault in ('missing', 'duplicate'):
            with self.subTest(fault=fault):
                path = self.run / 'replay/comparison.json'
                previous = path.read_bytes()
                self.change('replay/comparison.json', lambda c: c['results'].pop() if fault == 'missing' else c['results'].__setitem__(0, copy.deepcopy(c['results'][1])))
                with self.assertRaisesRegex(ValueError, 'six unique'): self.verify()
                path.write_bytes(previous)

    def test_replay_claim_cannot_hide_actual_difference(self):
        self.change('replay/comparison.json', lambda c: c['results'][0]['actual']['headers'].clear())
        with self.assertRaisesRegex(ValueError, 'sealed'): self.verify()

    def test_modified_observation_cannot_reuse_digest(self):
        self.change('candidate/testdata/firefox/windows.json', lambda c: c['observations'][0]['cases']['tls12-h1']['raw_events'][0].update(connection_id='tampered'))
        with self.assertRaisesRegex(ValueError, 'digest'): self.verify()

    def test_other_source_commit_is_rejected(self):
        self.change('update-report.json', lambda c: c['sources']['imitate'].update(commit='b' * 40))
        with self.assertRaisesRegex(ValueError, 'source commit'): self.verify()

    def test_tls_only_candidate_is_not_automatically_adopted(self):
        self.change('candidate/browser-specs.json', lambda c: c[self.identifier]['match']['verified_fields'].remove('http2.initial_frames.cold'))
        with self.assertRaisesRegex(ValueError, 'requires TLS'): self.verify()

    def test_replayed_spec_must_equal_candidate(self):
        self.change('replay/catalog-check.json', lambda c: c['catalog'][0]['spec']['tls']['cipher_suites'].reverse())
        with self.assertRaisesRegex(ValueError, 'Replayed Spec'): self.verify()

    def test_bundle_content_and_path_are_bound(self):
        self.change('bundles/firefox-windows.json', lambda c: c.update(sha256='0' * 64))
        with self.assertRaisesRegex(ValueError, 'Bundle bytes'): self.verify()
        self.change('update-report.json', lambda c: c['bundle'].update(path='../other'))
        with self.assertRaisesRegex(ValueError, 'bundle path'): self.verify()

    def test_missing_product_does_not_discard_successful_product(self):
        result = maintain.stage(self.repo, self.inputs, SHA, 'https://example.test/run', ['firefox', 'edge'])
        self.assertTrue(result['blocked'])
        self.assertTrue(result['changed'])
        self.assertEqual(result['products']['edge']['status'], 'blocked')

    def test_false_no_change_cannot_skip_verification(self):
        self.change('update-report.json', lambda c: c.update(status='no_change'))
        result = maintain.stage(self.repo, self.inputs, SHA, 'https://example.test/run', ['firefox'])
        self.assertTrue(result['blocked'])
        self.assertFalse(result['changed'])

    def test_adopted_full_build_can_be_no_change(self):
        current = maintain.read(self.run / 'candidate/browser-specs.json')
        maintain.write(self.repo / 'browser-specs.json', current)
        self.change('update-report.json', lambda c: c.update(status='no_change'))
        result = maintain.stage(self.repo, self.inputs, SHA, 'https://example.test/run', ['firefox'])
        self.assertFalse(result['blocked'])
        self.assertFalse(result['changed'])

    def test_old_build_cannot_downgrade_verified_profile(self):
        for e in self.catalog[self.identifier]['spec']['evidence']: e['product_version'] = '159.0.1'
        with self.assertRaisesRegex(ValueError, 'downgrade'): self.verify()

    def test_old_archive_can_recover_from_bound_raw_observations(self):
        fixture = self.run / 'candidate/testdata/firefox/windows.json'
        observations = maintain.read(fixture)
        observations['observations'][0].pop('runtime_replay')
        maintain.write(self.run / 'observations.json', observations)
        fixture.unlink()
        identifier, entry, observation, record = self.verify()
        self.assertEqual(identifier, self.identifier)
        self.assertTrue(observation['runtime_replay']['whole_profile_match'])

    def test_reuse_rejects_any_capture_or_generator_input_change(self):
        for path in ['provider.go', 'browser-specs.json', 'tools/chromium/capture.mjs', 'tools/firefox/audit.py', 'go.sum']:
            with self.subTest(path=path), patch.object(maintain.subprocess, 'run'), patch.object(maintain.subprocess, 'check_output', return_value=path):
                with self.assertRaisesRegex(ValueError, 'identical generator'):
                    maintain.validate_reuse(self.repo, SHA, 'b' * 40)

    def test_reuse_accepts_only_adoption_tooling_and_documentation(self):
        with patch.object(maintain.subprocess, 'run'), patch.object(maintain.subprocess, 'check_output', return_value='tools/maintenance/maintain.py\n.github/workflows/browser-update.yml\nREADME.md'):
            maintain.validate_reuse(self.repo, SHA, 'b' * 40)


class PublicationTests(unittest.TestCase):
    def test_advanced_default_branch_prevents_publication(self):
        with tempfile.TemporaryDirectory() as directory:
            repo = Path(directory)
            maintain.write(repo / 'maintenance-result.json', {'source_commit': SHA, 'changed': True, 'products': {}})
            with patch.object(publish, 'execute', side_effect=['browser-specs.json', SHA, 'b' * 40 + '\trefs/heads/v2']) as execute:
                with self.assertRaisesRegex(ValueError, 'advanced'):
                    publish.publish(repo, 'FastTLS/imitate', SHA, 'v2')
                self.assertFalse(any('push' in call.args or 'merge' in call.args for call in execute.call_args_list))

    def test_unexpected_source_edit_prevents_publication(self):
        with tempfile.TemporaryDirectory() as directory:
            repo = Path(directory)
            maintain.write(repo / 'maintenance-result.json', {'source_commit': SHA, 'changed': True, 'products': {}})
            with patch.object(publish, 'execute', return_value='provider_test.go'):
                with self.assertRaisesRegex(ValueError, 'Unexpected tracked'):
                    publish.publish(repo, 'FastTLS/imitate', SHA, 'v2')


if __name__ == '__main__':
    unittest.main()
