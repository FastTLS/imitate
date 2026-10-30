import copy
import unittest
from pathlib import Path
import audit


class StreamProjectionTests(unittest.TestCase):
    def setUp(self):
        fixture = audit.read(Path(__file__).resolve().parents[2] / 'testdata/firefox/windows.json')
        self.events = next(o for o in fixture['observations'] if o['version'] == '159.0')['cases']['tls13-h2']['raw_events']

    def test_observed_stream_behavior(self):
        self.assertEqual(audit.project_h2_stream(self.events), {'first_stream_id': 3, 'stream_window_increment': 12451840})

    def test_unsupported_sequence_is_rejected(self):
        update = next(e for e in self.events if e['type'] == 'http2.window_update' and e['data']['stream_id'] != 0)
        for change in ('duplicate', 'before_headers', 'different_stream', 'even_stream', 'overflow'):
            events = copy.deepcopy(self.events)
            if change == 'duplicate': events.append(copy.deepcopy(update))
            elif change == 'before_headers':
                events.remove(update); events.insert(0, copy.deepcopy(update))
            elif change == 'different_stream':
                next(e for e in events if e == update)['data']['stream_id'] = 5
            elif change == 'even_stream':
                next(e for e in events if e['type'] == 'http2.headers')['data']['stream_id'] = 2
            else:
                next(e for e in events if e == update)['data']['increment'] = 0x80000000
            with self.subTest(change=change), self.assertRaises(ValueError): audit.project_h2_stream(events)

    def test_default_stream_has_no_new_requirement(self):
        events = [{'type': 'http2.headers', 'data': {'stream_id': 1}}]
        self.assertEqual(audit.project_h2_stream(events), {})

    def test_stream_id_comparison_does_not_depend_on_priority(self):
        events = [e for e in self.events if e['type'] != 'http2.header_priority']
        original = audit.normalize(events, 'tls13-h2')
        changed = copy.deepcopy(events)
        next(e for e in changed if e['type'] == 'http2.headers')['data']['stream_id'] = 1
        actual = audit.normalize(changed, 'tls13-h2')
        self.assertEqual(original['http2'], actual['http2'])
        self.assertNotEqual(original['http2_stream_id'], actual['http2_stream_id'])


if __name__ == '__main__': unittest.main()
