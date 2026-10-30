"""Project Chromium observations without discarding static TLS/header/H2 differences."""
import base64
import collections
import copy
from pathlib import Path
import re
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'firefox'))
import audit as firefox

SCENARIOS = firefox.SCENARIOS
read, dump, digest, event = firefox.read, firefox.dump, firefox.digest, firefox.event


def normalize(events, scenario):
    value = firefox.normalize(events, scenario)
    # Chromium shuffles ordinary extension positions. Preserve membership,
    # multiplicity and parameters; raw per-sample orders remain in the evidence.
    value['tls']['extensions'] = sorted(value['tls']['extensions'], key=lambda e: (str(e['id']), str(e['value'])))
    return value


def project_tls(hello):
    result = copy.deepcopy(hello)
    ordinary, special, positions = [], [], []
    for index, extension in enumerate(result['extensions']):
        number = extension['id']
        if firefox.grease(number):
            special.append({'id': '0x0a0a'}); positions.append(index)
        elif number in (17513, 17613):
            data = bytes.fromhex(extension['payload_hex'])
            if len(data) < 3 or int.from_bytes(data[:2], 'big') != len(data) - 2:
                raise ValueError('Malformed application settings extension')
            offset, protocols = 2, []
            while offset < len(data):
                size = data[offset]; offset += 1
                if not size or offset + size > len(data):
                    raise ValueError('Malformed application protocol vector')
                protocols.append(data[offset:offset + size].decode('ascii')); offset += size
            special.append({'id': firefox.code(number), 'alpn': protocols}); positions.append(index)
        else:
            ordinary.append(extension)
    result['extensions'] = ordinary
    spec = firefox.project_tls(result)
    for index, item in zip(positions, special):
        spec['extensions'].insert(index, item)
    for field in ('cipher_suites',):
        spec[field] = ['0x0a0a' if firefox.grease(int(v, 16)) else v for v in spec[field]]
    for extension in spec['extensions']:
        for field in ('groups', 'versions', 'key_shares', 'signature_algorithms'):
            if field in extension:
                extension[field] = ['0x0a0a' if firefox.grease(int(v, 16)) else v for v in extension[field]]
    spec['extension_order'] = 'shuffle-chrome'
    return spec


def audit(root, catalog, browser):
    if browser not in ('chrome', 'edge'):
        raise ValueError('Unsupported Chromium product')
    run, samples = read(root / 'run.json'), read(root / 'browser-samples.json')
    builds = read(root / 'downloads/builds.json')
    if len(builds) != 1 or builds[0]['browser'] != browser or run['expected_samples_per_scenario'] < 5:
        raise ValueError('Expected one pinned product and at least five independent samples')
    build = builds[0]; version = build['version']; major = version.split('.')[0]
    connections = collections.defaultdict(list)
    for suffix in ('12', '13'):
        for row in read(root / f'capture{suffix}/management-events.json'):
            connections[(row['run_id'], row['connection_id'])].append(row)
    grouped = collections.defaultdict(list)
    used_connections = set()
    for sample in samples:
        if (sample['status'] != 'observed' or sample['browser'] != browser or sample['version'] != version or
                sample['browser_version'] != version or sample['mode'] != run['mode'] or
                sample.get('browser_identity', {}).get('product') != ('Edg/' if browser == 'edge' else 'Chrome/') + version or
                sample['executable_sha256'] != build['executable_sha256']):
            raise ValueError('Wrong product/build/mode or failed sample')
        first = sample['events'][0]
        connection = (first['run_id'], first['connection_id'])
        if connection in used_connections:
            raise ValueError('Samples must use independent cold connections')
        used_connections.add(connection)
        events = connections[(first['run_id'], first['connection_id'])]
        if not events or any(e['type'].endswith('.error') or e['type'] == 'capture.incomplete' for e in events):
            raise ValueError('Incomplete/error connection')
        sample['events'] = events
        negotiation = event(events, 'tls.negotiated')
        if (negotiation['version'] != (771 if sample['scenario'] == 'tls12-h1' else 772) or
                negotiation['alpn'] != ('h2' if sample['scenario'].endswith('h2') else 'http/1.1') or negotiation['resumed']):
            raise ValueError('Unexpected cold TLS negotiation')
        grouped[sample['scenario']].append(sample)
    cases = {}
    for scenario in SCENARIOS:
        batch = grouped[scenario]
        if len(batch) != run['expected_samples_per_scenario'] or {s['sample'] for s in batch} != set(range(run['expected_samples_per_scenario'])):
            raise ValueError('Missing/duplicate browser samples')
        values = [normalize(s['events'], scenario) for s in batch]
        if len({digest(value) for value in values}) != 1:
            raise ValueError('Unstable static TLS, headers or H2 parameters: ' + scenario)
        cases[scenario] = dict(normalized=values[0], hello=event(batch[0]['events'], 'tls.client_hello'),
            raw_events=batch[0]['events'], ja3_samples=[firefox.ja3(event(s['events'], 'tls.client_hello')) for s in batch],
            extension_orders=[[firefox.norm(e['id']) for e in event(s['events'], 'tls.client_hello')['extensions']] for s in batch],
            samples=[dict(captured_at=s['time'], sha256=digest(s['events'])) for s in batch])
    if len(samples) != len(SCENARIOS) * run['expected_samples_per_scenario']:
        raise ValueError('Unexpected extra samples/scenarios')
    if any(cases[s]['normalized']['tls'] != cases['tls13-h2']['normalized']['tls'] for s in SCENARIOS):
        raise ValueError('Scenario-dependent ClientHello requires distinct profiles')
    identifier = f'{browser}/{major}/windows'
    available = [k for k in catalog if re.fullmatch(browser + r'/[0-9]+/windows', k)]
    if not available:
        raise ValueError('No reviewed product template')
    baseline = copy.deepcopy(catalog.get(identifier, catalog[max(available, key=lambda k: int(k.split('/')[1]))]))
    spec = baseline['spec']
    h1 = firefox.headers(cases['tls13-h1']['raw_events'], 'tls13-h1')
    h2 = firefox.headers(cases['tls13-h2']['raw_events'], 'tls13-h2')
    ua = next(h['value'] for h in h1 if h['name'].lower() == 'user-agent')
    engine = re.search(r'\bChrome/([0-9]+)\.', ua)
    if not engine or (browser == 'edge' and not re.search(r'\bEdg/' + re.escape(major) + r'\.', ua)) or (browser == 'chrome' and ('Edg/' in ua or engine.group(1) != major)):
        raise ValueError('Unexpected browser UA identity')
    spec['id'] = identifier
    spec['metadata'].update(kind='browser', family=browser, product=browser, product_version=major, engine_version=engine.group(1), platform='windows')
    spec['tls'] = project_tls(cases['tls13-h2']['hello'])
    spec['headers'] = firefox.project_headers(h1, h2)
    spec['identity'] = dict(user_agent=ua)
    frames = cases['tls13-h2']['normalized']['http2']
    settings = next(f['data'] for f in frames if f['type'] == 'http2.settings')
    settings = settings['settings'] if isinstance(settings, dict) else settings
    spec['http2'] = dict(settings=settings,
        connection_flow=sum(f['data']['increment'] for f in frames if f['type'] == 'http2.window_update' and f['data']['stream_id'] == 0),
        priority_frames=[f['data'] for f in frames if f['type'] == 'http2.priority'])
    priority = [f['data'] for f in frames if f['type'] == 'http2.header_priority']
    if priority:
        if len(priority) != 1:
            raise ValueError('Unexpected multiple header priorities')
        spec['http2']['header_priority'] = {**priority[0], 'stream_id': 0}
    limitations = ['Windows x64 en-US ' + run['mode'] + ' cold navigation only; other modes, contexts and platforms unverified.',
        'Extension membership/parameters verified separately from randomized order; no distributional shuffle, resumption, ECH or ephemeral-key equivalence claim.',
        'H2 initial stream IDs and stream WINDOW_UPDATE remain explicit comparison fields; current backend cannot configure all stream-level behavior.']
    advertised = [v for e in spec['tls']['extensions'] for v in e.get('signature_algorithms', []) if v in ('0x0904', '0x0905', '0x0906')]
    if advertised:
        limitations.append('ML-DSA signature schemes are advertised only; the backend cannot verify ML-DSA CertificateVerify.')
    spec['capabilities'].update(required_features=['tls.ordered.v1', 'http1.ordered.v1', 'http2.ordered.v1',
        'http.headers.protocol.v1', 'tls.shuffle-chrome.v1'] + (['tls.signature-advertised.v1'] if advertised else []),
        advertised_only=advertised, limitations=limitations)
    fixture = f'testdata/{browser}/windows.json'
    spec['evidence'] = [dict(source=fixture + '#' + version + '-' + scenario, captured_at=cases[scenario]['samples'][0]['captured_at'],
        product_version=version, platform='windows', verified_fields=[], transport=scenario, sample_sha256=cases[scenario]['samples'][0]['sha256']) for scenario in SCENARIOS]
    baseline['match'].update(profile_id=identifier, selector=identifier, product=browser, product_version=major, engine_version=engine.group(1),
        user_agent=ua, baseline_id=browser + '-' + version, method='compatible', verified_fields=[], compatibility_notes=limitations, source={'path': fixture})
    candidates = copy.deepcopy(catalog); candidates[identifier] = baseline
    observations = dict(schema_version=1, source=build['source'], scope=run['scope'], observations=[dict(browser=browser, version=version,
        platform='windows-x64', locale='en-US', mode=run['mode'], build={k:v for k,v in build.items() if k != 'executable'}, cases=cases)])
    dump(root / 'observations.json', observations)
    dump(root / 'audit-summary.json', dict(browser=browser, version=version, valid_samples=len(samples), limitations=limitations))
    return observations, candidates
