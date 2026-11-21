"""Verify same-run evidence before staging bounded catalog updates."""
import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'chromium'))
import audit_chromium
import audit

PRODUCTS = ('edge', 'chrome', 'firefox')
SCENARIOS = set(audit.SCENARIOS)


def read(path):
    return json.loads(path.read_text(encoding='utf-8'))


def write(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode()).hexdigest()


def protocol(spec):
    result = copy.deepcopy(spec)
    result.pop('evidence', None)
    return result


def fields(browser):
    return {'http2.initial_frames.cold', 'tls.static_client_hello.cold' if browser == 'firefox' else 'tls.static_client_hello.cold.chromium',
            'http.headers.navigation.zh-CN' if browser == 'firefox' else 'http.headers.navigation.en-US'}


def verify(root, current, browser, source_sha):
    report = read(root / 'update-report.json')
    if report.get('sources', {}).get('imitate', {}).get('commit') != source_sha:
        raise ValueError('Candidate source commit differs from this workflow')
    if report.get('status') != 'candidate':
        raise ValueError('Only a verified candidate can be adopted')
    version = report.get('browser_version', '')
    pattern = r'[1-9][0-9]*\.[0-9]+(?:\.[0-9]+)?' if browser == 'firefox' else r'[1-9][0-9]*(?:\.[0-9]+){3}'
    if not re.fullmatch(pattern, version):
        raise ValueError('Malformed full browser version')
    identifier = f'{browser}/{version.split(".")[0]}/windows'
    candidate = read(root / 'candidate/browser-specs.json')
    # The producer can change exactly one Windows profile, not siblings or code.
    if set(candidate) - {identifier} != set(current) - {identifier} or any(
            candidate[key] != current[key] for key in current if key != identifier):
        raise ValueError('Candidate changed unrelated profiles')
    entry = candidate[identifier]
    spec = entry['spec']
    previous_versions = [e.get('product_version', '0') for e in current.get(identifier, {}).get('spec', {}).get('evidence') or []]
    if any(tuple(map(int, v.split('.'))) > tuple(map(int, version.split('.'))) for v in previous_versions):
        raise ValueError('Refusing to downgrade an already verified build')
    if spec['id'] != identifier or entry['match']['selector'] != identifier or entry['match']['product'] != browser:
        raise ValueError('Profile identity mismatch')
    required = fields(browser)
    if not required.issubset(entry['match'].get('verified_fields', [])):
        raise ValueError('Automatic adoption requires TLS, headers and H2 replay')
    evidence = spec.get('evidence') or []
    if len(evidence) != 3 or {e['transport'] for e in evidence} != SCENARIOS or any(
            e.get('product_version') != version or e.get('platform') != 'windows' or
            not required.issubset(e.get('verified_fields', [])) for e in evidence):
        raise ValueError('Incomplete exact-build evidence')
    fixture_path = root / f'candidate/testdata/{browser}/windows.json'
    # Older uploads omitted the staged fixture. Sealed raw observations and six
    # independently rechecked replay rows establish the same bounded evidence.
    observations = read(fixture_path if fixture_path.exists() else root / 'observations.json')
    selected = [o for o in observations['observations'] if o['version'] == version]
    if len(selected) != 1:
        raise ValueError('Expected exactly one exact-build observation')
    observation = selected[0]
    locale, mode = ('zh-CN', 'headless') if browser == 'firefox' else ('en-US', audit_chromium.MODES[browser])
    if observation['platform'] != 'windows-x64' or observation['locale'] != locale or observation['mode'] != mode:
        raise ValueError('Observation scope mismatch')
    if set(observation['cases']) != SCENARIOS:
        raise ValueError('Missing transport scenario')
    normalizer = audit.normalize if browser == 'firefox' else audit_chromium.normalize
    expected = {}
    for scenario, case in observation['cases'].items():
        if len(case['samples']) != 5 or len({s['sha256'] for s in case['samples']}) != 5:
            raise ValueError('Expected five independent samples per scenario')
        if audit.digest(case['raw_events']) != case['samples'][0]['sha256']:
            raise ValueError('Observation digest mismatch')
        record = next(e for e in evidence if e['transport'] == scenario)
        if record['sample_sha256'] != case['samples'][0]['sha256']:
            raise ValueError('Spec evidence does not bind observed bytes')
        expected[scenario] = normalizer(case['raw_events'], scenario)
    comparison = read(root / 'replay/comparison.json')
    rows = [row for row in comparison['results'] if row['selector'] == identifier]
    if len(rows) != 6 or {(row['mode'], row['scenario']) for row in rows} != {
            (mode, scenario) for mode in ('online', 'offline') for scenario in SCENARIOS}:
        raise ValueError('Expected six unique online/offline replay comparisons')
    if any(row.get('error') or row.get('status') != 200 or row['differences'] or
           row['actual'] != expected[row['scenario']] for row in rows):
        raise ValueError('Replay does not match sealed browser observations')
    observation['runtime_replay'] = {'tls_and_headers_match': True, 'whole_profile_match': True, 'online_offline_pairs': 3}
    checked = read(root / 'replay/catalog-check.json')['catalog']
    checked = [e for e in checked if e['id'] == identifier]
    if len(checked) != 1 or 'validation_error' in checked[0] or protocol(checked[0]['spec']) != protocol(spec):
        raise ValueError('Replayed Spec differs from proposed Spec')
    bundle_path = report.get('bundle', {}).get('path')
    if bundle_path != f'bundles/{browser}-windows.json':
        raise ValueError('Unexpected bundle path')
    bundle = read(root / bundle_path)
    sha = hashlib.sha256(bundle['spec_json'].encode()).hexdigest()
    if bundle['schema_version'] != 1 or bundle['profile_id'] != identifier or bundle['sha256'] != sha or report['bundle']['sha256'] != sha or json.loads(bundle['spec_json']) != spec:
        raise ValueError('Bundle bytes or identity mismatch')
    return identifier, entry, observation, {'version': version, 'profile_id': identifier, 'spec_sha256': sha,
        'source_commit': source_sha, 'verified_fields': sorted(required), 'scope': report['scope']}


def stage(repo, inputs, source_sha, run_url, browsers):
    if not browsers or len(set(browsers)) != len(browsers) or any(b not in PRODUCTS for b in browsers):
        raise ValueError('Unsupported or duplicate products')
    catalog = read(repo / 'browser-specs.json')
    state_path = repo / 'maintenance-state.json'
    state = read(state_path) if state_path.exists() else {'schema_version': 1, 'products': {}}
    result = {'source_commit': source_sha, 'run_url': run_url, 'products': {}, 'changed': False, 'blocked': False}
    pending = []
    for browser in browsers:
        root = inputs / ('browser-profile-candidate-' + browser)
        try:
            report = read(root / 'update-report.json')
            if report.get('sources', {}).get('imitate', {}).get('commit') != source_sha:
                raise ValueError('Candidate source commit differs from workflow')
            if report.get('status') == 'no_change':
                version = report['browser_version']
                identifier = f'{browser}/{version.split(".")[0]}/windows'
                current = catalog.get(identifier, {})
                evidence = current.get('spec', {}).get('evidence') or []
                if len(evidence) != 3 or {e['transport'] for e in evidence} != SCENARIOS or any(
                        e.get('product_version') != version or not fields(browser).issubset(e.get('verified_fields', [])) for e in evidence):
                    raise ValueError('no_change lacks adopted exact-build evidence')
                result['products'][browser] = {'status': 'no_change', 'version': version}
                continue
            identifier, entry, observation, record = verify(root, catalog, browser, source_sha)
            record['run_url'] = run_url
            pending.append((browser, identifier, entry, observation, record))
            result['products'][browser] = {'status': 'validated', **record}
        except (ValueError, KeyError, TypeError, OSError) as error:
            result['blocked'] = True
            result['products'][browser] = {'status': 'blocked', 'error': str(error)}
    # Validate every input against the original base before combining products.
    for browser, identifier, entry, observation, record in pending:
        catalog[identifier] = entry
        fixture = repo / f'testdata/{browser}/windows.json'
        previous = read(fixture) if fixture.exists() else {'schema_version': 1, 'observations': []}
        history = {o['version']: o for o in previous['observations']}
        history[observation['version']] = observation
        previous['observations'] = sorted(history.values(), key=lambda o: tuple(map(int, o['version'].split('.'))))
        write(fixture, previous)
        state['products'][browser] = record
    if pending:
        write(repo / 'browser-specs.json', catalog)
        write(state_path, state)
        provider = repo / 'provider.go'
        content, count = re.subn(r'const DataRevision = "[^"]+"', 'const DataRevision = "browser-' + digest(catalog)[:16] + '"', provider.read_text(encoding='utf-8'))
        if count != 1:
            raise ValueError('Missing unique DataRevision')
        provider.write_text(content, encoding='utf-8')
        result['changed'] = True
    write(repo / 'maintenance-result.json', result)
    return result


def validate_reuse(repo, capture_sha, source_sha):
    if capture_sha == source_sha:
        return
    subprocess.run(['git', '-C', str(repo), 'merge-base', '--is-ancestor', capture_sha, source_sha], check=True)
    changed = subprocess.check_output(['git', '-C', str(repo), 'diff', '--name-only', capture_sha, source_sha], text=True).splitlines()
    if any(not (p.startswith('tools/maintenance/') or p.startswith('.github/workflows/') or p.endswith('/README.md') or p in ('README.md', '.gitignore')) for p in changed):
        raise ValueError('Capture reuse requires identical generator, catalog and collector tool inputs')
    workflow = '.github/workflows/browser-update.yml'
    if workflow in changed:
        before, after = [subprocess.check_output(['git', '-C', str(repo), 'show', sha + ':' + workflow], text=True)
                         for sha in (capture_sha, source_sha)]
        # Archive manifests may be repaired without changing the collector,
        # backend pins, toolchain or invocation used for the original evidence.
        marker = '      - uses: actions/upload-artifact@'
        if marker not in before or marker not in after or before.split(marker)[0] != after.split(marker)[0]:
            raise ValueError('Capture workflow production inputs changed')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('repo', 'inputs'):
        parser.add_argument('--' + name, type=Path, required=True)
    for name in ('source-sha', 'run-url', 'browsers'):
        parser.add_argument('--' + name, required=True)
    parser.add_argument('--capture-sha', help='Reuse a completed same-repository capture after tooling-only changes')
    args = parser.parse_args()
    if subprocess.check_output(['git', '-C', str(args.repo), 'rev-parse', 'HEAD'], text=True).strip() != args.source_sha:
        raise ValueError('Checkout differs from capture source')
    capture_sha = args.capture_sha or args.source_sha
    validate_reuse(args.repo, capture_sha, args.source_sha)
    result = stage(args.repo, args.inputs, capture_sha, args.run_url, json.loads(args.browsers))
    result.update(source_commit=args.source_sha, capture_source_commit=capture_sha)
    write(args.repo / 'maintenance-result.json', result)
    print(json.dumps(result, ensure_ascii=False, indent=2))
    if os.environ.get('GITHUB_OUTPUT'):
        with open(os.environ['GITHUB_OUTPUT'], 'a', encoding='utf-8') as output:
            for key in ('changed', 'blocked'):
                print(f'{key}={str(result[key]).lower()}', file=output)
    if os.environ.get('GITHUB_STEP_SUMMARY'):
        with open(os.environ['GITHUB_STEP_SUMMARY'], 'a', encoding='utf-8') as summary:
            print('Browser maintenance: validated is pending adoption; no_change means an exact build was already verified.\n', file=summary)
            for browser, product in result['products'].items():
                print(f'- {browser}: {product["status"]} {product.get("version", "")} {product.get("error", "")}', file=summary)


if __name__ == '__main__':
    main()
