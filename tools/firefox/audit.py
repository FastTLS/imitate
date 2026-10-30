"""Validate complete Firefox observations and project supported fields to full Specs.

JA3 remains a derived diagnostic. It is never an input to the projection.
Random ECH bytes and ephemeral key bytes are excluded from equality, not their
extension positions or key-share groups. Navigation is Windows x64 / zh-CN.
"""
import argparse
import base64
import collections
import copy
import hashlib
import json
from pathlib import Path
import re

SCENARIOS = ('tls12-h1', 'tls13-h1', 'tls13-h2')


def read(path):
    return json.loads(path.read_text(encoding='utf-8'))


def dump(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def grease(value):
    return value & 0x0f0f == 0x0a0a and value >> 8 == value & 255


def norm(value):
    return 'GREASE' if grease(value) else value


def event(events, kind):
    values = [e['data'] for e in events if e['type'] == kind]
    if len(values) != 1:
        raise ValueError(f'Expected one {kind}, got {len(values)}')
    return values[0]


def words(data):
    if len(data) % 2:
        raise ValueError('Malformed TLS vector')
    return [int.from_bytes(data[i:i+2], 'big') for i in range(0, len(data), 2)]


def tls(hello):
    extensions = []
    for extension in hello['extensions']:
        identifier = extension['id']
        data = bytes.fromhex(extension['payload_hex'])
        if identifier in (10, 13, 34, 50):
            value = [norm(v) for v in words(data[2:])]
        elif identifier == 43:
            value = [norm(v) for v in words(data[1:])]
        elif identifier == 51:
            value = [norm(v) for v in extension['key_share_groups']]
        elif identifier == 65037 or grease(identifier):
            value = '<randomized>'
        else:
            value = data.hex()
        extensions.append({'id': norm(identifier), 'value': value})
    return {'record_version': hello['record_version'], 'legacy_version': hello['legacy_version'],
            'cipher_suites': [norm(v) for v in hello['cipher_suites']], 'extensions': extensions}


def ja3(hello):
    extensions = {e['id']: bytes.fromhex(e['payload_hex']) for e in hello['extensions']}
    groups = words(extensions.get(10, b'\0\0')[2:])
    points = list(extensions.get(11, b'\0')[1:])
    join = lambda values: '-'.join(str(v) for v in values if not grease(v))
    text = ','.join([str(hello['legacy_version']), join(hello['cipher_suites']), join(e['id'] for e in hello['extensions']), join(groups), join(points)])
    return {'text': text, 'md5': hashlib.md5(text.encode(), usedforsecurity=False).hexdigest()}


def headers(events, scenario):
    return event(events, 'http2.headers' if scenario.endswith('h2') else 'http1.headers')['headers']


def normalize(events, scenario):
    hs = headers(events, scenario)
    hs = [{**h, 'value': '<authority>' if h['name'].lower() in ('host', ':authority') else '<path>' if h['name'] == ':path' else h['value']} for h in hs]
    frames = [{'type': e['type'], 'data': e['data']} for e in events if e['type'].startswith('http2.') and e['type'] not in ('http2.headers', 'http2.error')]
    return {'tls': tls(event(events, 'tls.client_hello')), 'headers': hs, 'http2': frames}


def code(value):
    return f'0x{value:04x}'


def project_tls(hello):
    extensions = []
    for extension in hello['extensions']:
        identifier = extension['id']
        data = bytes.fromhex(extension['payload_hex'])
        item = {'id': code(identifier)}
        if identifier in (10, 13, 34, 50):
            item['groups' if identifier == 10 else 'signature_algorithms'] = [code(v) for v in words(data[2:])]
        elif identifier == 43:
            item['versions'] = [code(v) for v in words(data[1:])]
        elif identifier == 51:
            item['key_shares'] = [code(v) for v in extension['key_share_groups']]
        elif identifier == 27:
            item['compression_algorithms'] = [code(v) for v in words(data[1:])]
        elif identifier in (11, 45):
            item['point_formats' if identifier == 11 else 'psk_modes'] = base64.b64encode(data[1:]).decode()
        elif identifier == 16:
            offset, protocols = 2, []
            while offset < len(data):
                size = data[offset]
                protocols.append(data[offset+1:offset+1+size].decode('ascii'))
                offset += size + 1
            item['alpn'] = protocols
        elif identifier == 65037:
            item['strategy'] = 'grease-ech'
        elif identifier == 28:
            item['raw_hex'] = data.hex()
        elif identifier not in (0, 5, 18, 23, 35, 65281):
            raise ValueError(f'Unreviewed Firefox extension {identifier}; retain evidence, do not project')
        extensions.append(item)
    return {'min_version': '0x0303', 'max_version': '0x0304', 'record_version': code(hello['record_version']),
            'legacy_version': code(hello['legacy_version']), 'cipher_suites': [code(v) for v in hello['cipher_suites']],
            'extensions': extensions, 'extension_order': 'fixed', 'grease_policy': 'per-connection', 'session_policy': 'disabled'}


def project_headers(h1, h2):
    def values(hs):
        return {h['name'].lower(): h['value'] for h in hs if h['name'].lower() not in ('host', 'user-agent') and not h['name'].startswith(':')}
    a, b = values(h1), values(h2)
    common = {k: v for k, v in a.items() if b.get(k) == v}
    make = lambda items: [{'name': k, 'values': [v]} for k, v in items.items()]
    return {'defaults': make(common), 'http1_defaults': make({k: v for k, v in a.items() if k not in common}),
            'http2_defaults': make({k: v for k, v in b.items() if k not in common}),
            'http1_order': [h['name'] for h in h1], 'order': [h['name'] for h in h2 if not h['name'].startswith(':')],
            'pseudo_order': [h['name'] for h in h2 if h['name'].startswith(':')], 'extra_order': 'sorted'}


def audit(root, catalog):
    run = read(root / 'run.json')
    samples = read(root / 'browser-samples.json')
    builds = read(root / 'downloads/builds.json')
    discovery = read(root / 'downloads/discovery.json')
    if {b['version'] for b in builds} != set(discovery['versions']):
        raise ValueError('Incomplete official builds manifest')
    all_events = []
    for suffix in ('12', '13'):
        all_events.extend(read(root / f'capture{suffix}/management-events.json'))
    connections = collections.defaultdict(list)
    for e in all_events:
        connections[(e['run_id'], e['connection_id'])].append(e)
    grouped = collections.defaultdict(list)
    for sample in samples:
        if sample['status'] != 'observed' or sample['browser_version'] != sample['version']:
            raise ValueError('Browser capture failed or identity mismatch')
        first = sample['events'][0]
        sample['events'] = connections[(first['run_id'], first['connection_id'])]
        if any(e['type'].endswith('.error') or e['type'] == 'capture.incomplete' for e in sample['events']):
            raise ValueError('Incomplete/error connection: ' + sample['version'])
        negotiation = event(sample['events'], 'tls.negotiated')
        expected = 771 if sample['scenario'] == 'tls12-h1' else 772
        alpn = 'h2' if sample['scenario'].endswith('h2') else 'http/1.1'
        if negotiation != {**negotiation, 'version': expected, 'alpn': alpn, 'resumed': False}:
            raise ValueError('Unexpected TLS negotiation')
        grouped[(sample['version'], sample['scenario'])].append(sample)
    observations, candidates, changes = [], copy.deepcopy(catalog), []
    for build in builds:
        version = build['version']
        major = version.split('.')[0]
        identifier = f'firefox/{major}/windows'
        cases = {}
        for scenario in SCENARIOS:
            batch = grouped[(version, scenario)]
            if len(batch) != run['expected_samples_per_scenario'] or len({s['sample'] for s in batch}) != len(batch):
                raise ValueError('Missing/duplicate samples: ' + version + ' ' + scenario)
            normalized = [normalize(s['events'], scenario) for s in batch]
            if len({digest(n) for n in normalized}) != 1:
                raise ValueError('Unstable full input: ' + version + ' ' + scenario)
            cases[scenario] = {'normalized': normalized[0], 'hello': event(batch[0]['events'], 'tls.client_hello'),
                               'raw_events': batch[0]['events'], 'ja3': ja3(event(batch[0]['events'], 'tls.client_hello')),
                               'samples': [{'captured_at': s['time'], 'sha256': digest(s['events'])} for s in batch]}
        if any(cases[scenario]['normalized']['tls'] != cases['tls13-h2']['normalized']['tls'] for scenario in SCENARIOS):
            raise ValueError('Scenario-dependent ClientHello requires separate profiles: ' + version)
        h1 = headers(cases['tls13-h1']['raw_events'], 'tls13-h1')
        h2 = headers(cases['tls13-h2']['raw_events'], 'tls13-h2')
        ua = next(h['value'] for h in h1 if h['name'].lower() == 'user-agent')
        if not re.search(r'Firefox/' + re.escape(major) + r'\.0(?:\s|$)', ua):
            raise ValueError('Unexpected UA identity')
        baseline = copy.deepcopy(catalog.get(identifier, catalog['firefox/158/windows']))
        spec = baseline['spec']
        before = copy.deepcopy(catalog.get(identifier))
        spec['id'] = identifier
        spec['metadata']['product_version'] = major
        engine = re.search(r'\brv:([0-9]+)\.', ua)
        if not engine or engine.group(1) != major:
            raise ValueError('Unexpected Firefox engine identity')
        spec['metadata']['engine_version'] = engine.group(1)
        spec['tls'] = project_tls(cases['tls13-h2']['hello'])
        spec['headers'] = project_headers(h1, h2)
        spec['identity'] = {'user_agent': ua}
        frames = cases['tls13-h2']['normalized']['http2']
        settings = next(f['data'] for f in frames if f['type'] == 'http2.settings')
        # Collector stores SETTINGS as an ordered list under settings.
        settings = settings['settings'] if isinstance(settings, dict) else settings
        spec['http2'] = {'settings': settings,
                         'connection_flow': sum(f['data']['increment'] for f in frames if f['type'] == 'http2.window_update' and f['data']['stream_id'] == 0),
                         'priority_frames': [f['data'] for f in frames if f['type'] == 'http2.priority']}
        priority = next((f['data'] for f in frames if f['type'] == 'http2.header_priority'), None)
        if priority:
            spec['http2']['header_priority'] = {**priority, 'stream_id': 0}
        limitations = ['Windows x64 zh-CN ' + run['mode'] + ' navigation only; other platforms and headed/headless equivalence are unverified.',
                       'Cold connections only; resumption, opaque ECH bytes and ephemeral keys are not verified.',
                       'Observed H2 initial stream ID and stream WINDOW_UPDATE are retained in the full input; current backend cannot express these fields. Whole-profile equivalence is unverified.']
        spec['capabilities']['required_features'] = ['tls.ordered.v1', 'http1.ordered.v1', 'http2.ordered.v1', 'http.headers.protocol.v1']
        spec['capabilities']['limitations'] = limitations
        source = f'testdata/firefox/windows.json#{version}'
        spec['evidence'] = [{'source': source + '-' + scenario, 'captured_at': cases[scenario]['samples'][0]['captured_at'],
                             'product_version': version, 'platform': 'windows', 'verified_fields': [], 'transport': scenario,
                             'sample_sha256': cases[scenario]['samples'][0]['sha256']} for scenario in SCENARIOS]
        match = baseline['match']
        match.update(profile_id=identifier, selector=identifier, product_version=major, user_agent=ua,
                     baseline_id='Firefox' + version, method='compatible', verified_fields=[], compatibility_notes=limitations,
                     source={'path': 'testdata/firefox/windows.json'})
        # Runtime replay, not browser observation alone, establishes verified fields.
        candidates[identifier] = baseline
        changes.append({'id': identifier, 'version': version, 'previously_present': before is not None,
                        'tls_changed': before is None or before['spec']['tls'] != spec['tls'],
                        'headers_changed': before is None or before['spec']['headers'] != spec['headers'],
                        'whole_profile_verified': False})
        observations.append({'version': version, 'platform': 'windows-x64', 'locale': 'zh-CN', 'mode': run['mode'],
                             'build': {k: v for k, v in build.items() if k != 'executable'}, 'cases': cases})
    expected = len(builds) * len(SCENARIOS) * run['expected_samples_per_scenario']
    if len(samples) != expected:
        raise ValueError('Unexpected extra samples')
    return {'schema_version': 1, 'source': discovery['source'], 'scope': run['scope'], 'observations': observations}, candidates, {
        'versions': discovery['versions'], 'valid_samples': len(samples), 'scenarios': list(SCENARIOS), 'mode': run['mode'], 'changes': changes,
        'whole_profile_verified': False, 'limitations': limitations}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run', required=True, type=Path)
    parser.add_argument('--repo', required=True, type=Path)
    parser.add_argument('--apply', action='store_true')
    args = parser.parse_args()
    catalog_path = args.repo / 'browser-specs.json'
    observations, candidates, summary = audit(args.run, read(catalog_path))
    dump(args.run / 'observations.json', observations)
    dump(args.run / 'audit-summary.json', summary)
    dump(args.run / 'candidate-browser-specs.json', candidates)
    if args.apply:
        destination = args.repo / 'testdata/firefox/windows.json'
        previous = read(destination) if destination.exists() else {'schema_version': 1, 'observations': []}
        updated = {o['version']: o for o in previous['observations']}
        updated.update({o['version']: o for o in observations['observations']})
        observations['observations'] = sorted(updated.values(), key=lambda o: tuple(map(int, o['version'].split('.'))))
        dump(destination, observations)
        dump(catalog_path, candidates)
        provider = args.repo / 'provider.go'
        content = provider.read_text(encoding='utf-8')
        date = max(s['captured_at'] for o in observations['observations'] for c in o['cases'].values() for s in c['samples'])[:10].replace('-', '')
        content, count = re.subn(r'const DataRevision = "[^"]+"', 'const DataRevision = "firefox-' + date + '.1"', content)
        if count != 1:
            raise ValueError('DataRevision declaration missing')
        provider.write_text(content, encoding='utf-8')
    print(json.dumps(summary, ensure_ascii=False, indent=2))


if __name__ == '__main__':
    main()
