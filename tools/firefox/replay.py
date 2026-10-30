"""Replay every Firefox Spec online/offline, then compare observed wire fields.

Source checkouts are explicit inputs. This build is isolated from the generator
module and never adds transport dependencies to its public API.
"""
import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import time
import urllib.request
from audit import read, dump, normalize, event, digest


def wait_json(path, child):
    for _ in range(200):
        if child.poll() is not None:
            raise RuntimeError('Collector exited')
        if path.exists():
            try:
                return read(path)
            except (ValueError, OSError):
                pass
        time.sleep(.1)
    raise TimeoutError('Collector start timeout')


def replay(run, repo, core, transport, gate=True, *, family='firefox', normalizer=normalize, verified_fields=None, selector=None):
    if family not in ('firefox', 'chrome', 'edge'):
        raise ValueError('Unsupported browser product')
    output = run / 'replay'
    output.mkdir(exist_ok=False)
    build = output / 'build'
    build.mkdir()
    shutil.copyfile(Path(__file__).with_name('probe.go.txt'), build / 'main.go')
    (build / 'go.mod').write_text('module firefox-replay\n\ngo 1.26.0\n\nrequire (\n github.com/FastTLS/fastls v0.1.0\n github.com/FastTLS/imitate v0.1.0\n github.com/FastTLS/fastls/profile v0.1.0\n)\n', encoding='utf-8')
    env = {**os.environ, 'GOWORK': 'off'}
    for name, source in [('fastls', core), ('fastls/profile', core / 'profile'), ('imitate', repo), ('ftransport', transport)]:
        subprocess.run(['go', 'mod', 'edit', '-replace=github.com/FastTLS/' + name + '=' + str(source.resolve())], cwd=build, env=env, check=True)
    subprocess.run(['go', 'mod', 'tidy'], cwd=build, env=env, check=True)
    executable = output / 'probe.exe'
    subprocess.run(['go', 'build', '-o', str(executable.resolve()), '.'], cwd=build, env=env, check=True)
    labs = []
    all_events = []
    try:
        for suffix in ('13', '12'):
            directory = output / ('capture' + suffix)
            child = subprocess.Popen([str((run / ('lab' + suffix + '.exe')).resolve()), '-output', str(directory.resolve())], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            labs.append((child, directory, wait_json(directory / 'lab-manifest.json', child)))
        subprocess.run([str(executable.resolve()), str((labs[0][1] / 'lab-manifest.json').resolve()), str((labs[1][1] / 'lab-manifest.json').resolve()), str((output / 'catalog-check.json').resolve())], env={**env, 'FASTLS_REPLAY_FAMILY': family, 'FASTLS_REPLAY_SELECTOR': selector or ''}, check=True, timeout=600)
    finally:
        for child, directory, manifest in labs:
            try:
                with urllib.request.urlopen(manifest['management'] + '/events', timeout=20) as response:
                    events = json.load(response)
                dump(directory / 'management-events.json', events)
                all_events.extend(events)
            finally:
                subprocess.run(['taskkill', '/PID', str(child.pid), '/T', '/F'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    audit = read(output / 'catalog-check.json')
    if any('validation_error' in entry for entry in audit['catalog']):
        raise ValueError('Backend profile validation failed')
    observed = read(run / 'observations.json')
    expected = {(f"{family}/{o['version'].split('.')[0]}/windows", scenario): case['normalized'] for o in observed['observations'] for scenario, case in o['cases'].items()}
    results, parity = [], {}
    for row in audit['requests']:
        if row.get('error') or row['status'] != 200:
            raise ValueError('Replay request failed: ' + str(row))
        head = next((e for e in all_events if e['type'] in ('http1.headers', 'http2.headers') and row['token'] in json.dumps(e['data'])), None)
        if not head:
            raise ValueError('Replay capture missing')
        events = [e for e in all_events if (e['run_id'], e['connection_id']) == (head['run_id'], head['connection_id'])]
        negotiation = event(events, 'tls.negotiated')
        if negotiation['resumed'] or negotiation['version'] != (771 if row['scenario'] == 'tls12-h1' else 772) or negotiation['alpn'] != ('h2' if row['scenario'].endswith('h2') else 'http/1.1'):
            raise ValueError('Replay negotiation mismatch')
        value = normalizer(events, row['scenario'])
        key = (row['selector'], row['scenario'])
        if key in parity and parity[key] != digest(value):
            raise ValueError('Online/offline wire mismatch: ' + str(key))
        parity[key] = digest(value)
        if key in expected:
            differences = [field for field in value if value[field] != expected[key][field]]
            results.append({**row, 'differences': differences, 'actual': value})
    expected_rows = len(expected) * 2
    if len(results) != expected_rows:
        raise ValueError('Missing observed profile replay')
    summary = {'requests': len(audit['requests']), 'online_offline_pairs': len(parity), 'observed_comparisons': len(results),
               'tls_matches': sum('tls' not in r['differences'] for r in results), 'header_matches': sum('headers' not in r['differences'] for r in results),
               'whole_profile_matches': sum(not r['differences'] for r in results), 'results': results}
    dump(output / 'comparison.json', summary)
    print(json.dumps({k: v for k, v in summary.items() if k != 'results'}, indent=2))
    if gate and any('tls' in r['differences'] or 'headers' in r['differences'] for r in results):
            raise ValueError('TLS/header replay differs from actual browser; candidate rejected')
    if gate:
        catalog_path = repo / 'browser-specs.json'
        catalog = read(catalog_path)
        fixture_path = repo / f'testdata/{family}/windows.json'
        fixture = read(fixture_path)
        active_versions = {o['version'] for o in observed['observations']}
        for observation in fixture['observations']:
            if observation['version'] not in active_versions:
                continue
            identifier = f"{family}/{observation['version'].split('.')[0]}/windows"
            rows = [r for r in results if r['selector'] == identifier]
            if not rows:
                continue
            if len(rows) != 6:
                raise ValueError('Incomplete online/offline replay for ' + identifier)
            fields = verified_fields or ['tls.static_client_hello.cold', 'http.headers.navigation.zh-CN']
            catalog[identifier]['match']['verified_fields'] = fields
            for evidence in catalog[identifier]['spec']['evidence']:
                evidence['verified_fields'] = fields
            observation['runtime_replay'] = {'tls_and_headers_match': True, 'online_offline_pairs': 3,
                                             'whole_profile_match': all(not r['differences'] for r in rows)}
        dump(fixture_path, fixture)
        dump(catalog_path, catalog)
    # H2 differences remain explicit in comparison.json and profile limitations.
    return summary


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('run', 'repo', 'core', 'transport'):
        parser.add_argument('--' + name, required=True, type=Path)
    parser.add_argument('--report-only', action='store_true')
    args = parser.parse_args()
    replay(args.run, args.repo, args.core, args.transport, not args.report_only)
