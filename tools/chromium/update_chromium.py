"""Manual, read-only Chrome/Edge capture and replay; output candidates never activate."""
import argparse
from contextlib import contextmanager
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time

import audit_chromium as audit
import releases_chromium as releases
import prepare_lab
import replay
import update as firefox

FIELDS = ['tls.static_client_hello.cold.chromium', 'http.headers.navigation.en-US']


def known_build(catalog, repo, browser, version):
    entry = catalog.get(f'{browser}/{version.split(".")[0]}/windows', {})
    evidence = entry.get('spec', {}).get('evidence', [])
    fixture = repo / f'testdata/{browser}/windows.json'
    if not fixture.is_file() or not evidence or not set(FIELDS).issubset(entry.get('match', {}).get('verified_fields', [])):
        return False
    return (len(evidence) == len(audit.SCENARIOS) and {e.get('transport') for e in evidence} == set(audit.SCENARIOS) and all(
        e.get('product_version') == version and e.get('platform') == 'windows' and set(FIELDS).issubset(e.get('verified_fields', [])) for e in evidence)
        and any(o.get('version') == version and o.get('browser') == browser and o.get('platform') == 'windows-x64' and
                o.get('locale') == 'en-US' and o.get('mode') == 'headed-minimized' and o.get('runtime_replay', {}).get('tls_and_headers_match') is True
                for o in audit.read(fixture).get('observations', [])))


def collectors(source, output, cache=None):
    env = {**os.environ, 'GOWORK': 'off'}
    identity = dict(source=firefox.source_identity(source), adapter_sha256=hashlib.sha256(Path(prepare_lab.__file__).read_bytes()).hexdigest(),
        toolchain=subprocess.check_output(['go', 'version'], env=env, text=True).strip(),
        configuration=json.loads(subprocess.check_output(['go', 'env', '-json', 'GOOS', 'GOARCH', 'GOEXPERIMENT', 'GOFLAGS', 'CGO_ENABLED', 'CGO_CFLAGS', 'CGO_LDFLAGS', 'CC'], env=env, text=True)))
    if cache and (cache / 'collector-inputs.json').is_file():
        record = audit.read(cache / 'collector-inputs.json')
        if record['inputs'] != identity:
            raise ValueError('Collector cache source/configuration mismatch')
        for suffix in ('12', '13'):
            name = 'lab' + suffix + '.exe'
            if releases.digest(cache / name) != record['sha256'][name]:
                raise ValueError('Collector cache byte mismatch')
            shutil.copyfile(cache / name, output / name)
        return
    prepare_lab.prepare(source, output)
    if cache:
        cache.mkdir(parents=True, exist_ok=False)
        record = dict(inputs=identity, sha256={})
        for suffix in ('12', '13'):
            name = 'lab' + suffix + '.exe'
            shutil.copyfile(output / name, cache / name)
            record['sha256'][name] = releases.digest(cache / name)
        audit.dump(cache / 'collector-inputs.json', record)


def run(args, *, prepared=None):
    if sys.platform != 'win32':
        raise ValueError('Chromium capture requires Windows x64')
    sources = dict(imitate=args.repo, core=args.core, transport=args.transport, collector=args.lab)
    output = args.output.resolve()
    if output.exists() or any(output.is_relative_to(p.resolve()) for p in sources.values()):
        raise ValueError('Use a fresh output directory outside source checkouts')
    output.mkdir(parents=True)
    identities = {name: firefox.source_identity(path) for name, path in sources.items()}
    report = dict(status='preparing', started_at=datetime.now(timezone.utc).isoformat(), browser=args.browser,
        scope='Windows x64 en-US headed-minimized; cold H1/H2 navigation', writes_source_catalog=False,
        automatic_activation=False, sources=identities, durations_seconds={})
    phase = 'discovery'
    @contextmanager
    def timed(name):
        nonlocal phase
        phase = name; started = time.monotonic()
        try:
            yield
        finally:
            report['durations_seconds'][name] = round(time.monotonic() - started, 3)
    try:
        with timed('discovery'):
            manifest, raw = releases.discover(args.browser, args.version)
            report['browser_version'] = manifest['version']
            downloads = output / 'downloads'; downloads.mkdir()
            (downloads / 'official-manifest.json').write_bytes(raw)
            audit.dump(downloads / 'discovery.json', dict(versions=[manifest['version']], source=manifest['source'], browser=args.browser))
            catalog = audit.read(args.repo / 'browser-specs.json')
        if known_build(catalog, args.repo, args.browser, manifest['version']) and not args.force_capture:
            if identities != {name: firefox.source_identity(path) for name, path in sources.items()}:
                raise ValueError('Source inputs changed during discovery')
            report.update(status='no_change', verification_scope='Existing exact build/platform/mode/fields only; no new backend certification')
            return report
        with timed('download_and_publisher'):
            if prepared is None:
                build = releases.download(manifest, downloads / 'build', args.sevenzip, args.archive_cache)
            else:
                # An in-process caller may continue a recorded download after a
                # local verifier fix; recheck every identity instead of trusting it.
                for key in ('browser', 'version', 'url', 'manifest_sha256'):
                    if prepared.get(key) != manifest[key]:
                        raise ValueError('Prepared download differs from official release identity')
                build = dict(prepared)
                if releases.digest(Path(build['archive'])) != build['archive_sha256'] or manifest.get('archive_sha256') and build['archive_sha256'] != manifest['archive_sha256']:
                    raise ValueError('Prepared browser archive checksum mismatch')
                signature = releases.publisher(Path(build['executable']), args.browser)
                build['installer_publisher'] = releases.publisher(Path(build['archive']), args.browser)
                if signature['product_version'] != build['version'] or releases.digest(Path(build['executable'])) != build['executable_sha256']:
                    raise ValueError('Prepared browser executable changed')
                build['publisher'] = signature
            audit.dump(downloads / 'builds.json', [build])
        with timed('collector_build'):
            collectors(args.lab, output, getattr(args, 'collector_cache', None))
        with timed('capture'):
            subprocess.run(['node', str(Path(__file__).with_name('capture.mjs')), str(output), '5'], check=True, timeout=600)
        with timed('projection'):
            observations, candidate = audit.audit(output, catalog, args.browser)
            stage = output / 'candidate'
            shutil.copytree(args.repo, stage, ignore=shutil.ignore_patterns('.git', '__pycache__', '.cache', 'go.work*'))
            audit.dump(stage / 'browser-specs.json', candidate)
            audit.dump(stage / f'testdata/{args.browser}/windows.json', observations)
        with timed('backend_replay'):
            identifier = f'{args.browser}/{manifest["version"].split(".")[0]}/windows'
            comparison = replay.replay(output, stage, args.core, args.transport, family=args.browser,
                normalizer=audit.normalize, verified_fields=FIELDS, selector=identifier)
        if identities != {name: firefox.source_identity(path) for name, path in sources.items()}:
            raise ValueError('Source inputs changed during capture/replay')
        candidate = audit.read(stage / 'browser-specs.json')
        differences = firefox.semantic_diff(catalog.get(identifier), candidate[identifier])
        audit.dump(output / 'semantic-diff.json', dict(profile_id=identifier, changed_paths=differences))
        spec_json = json.dumps(candidate[identifier]['spec'], ensure_ascii=False, sort_keys=True, separators=(',', ':'))
        sha = hashlib.sha256(spec_json.encode('utf-8')).hexdigest()
        bundle_path = f'bundles/{args.browser}-windows.json'
        audit.dump(output / bundle_path, dict(schema_version=1, profile_id=identifier, spec_json=spec_json, sha256=sha,
            source=f'{args.browser} {manifest["version"]}; Windows x64 en-US; {manifest["source"]}'))
        report.update(status='candidate' if differences else 'no_change', changed_paths=differences,
            bundle=dict(profile_id=identifier, sha256=sha, path=bundle_path),
            whole_profile_verified=all(not r['differences'] for r in comparison['results']),
            limitations=candidate[identifier]['spec']['capabilities']['limitations'],
            replay_summary={k:v for k,v in comparison.items() if k != 'results'})
        return report
    except BaseException as error:
        report.update(status='blocked', phase=phase, error=type(error).__name__ + ': ' + str(error))
        raise
    finally:
        report['finished_at'] = datetime.now(timezone.utc).isoformat()
        audit.dump(output / 'update-report.json', report)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--browser', choices=['chrome', 'edge'], required=True)
    for name in ('repo', 'core', 'transport', 'lab', 'output'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--version')
    parser.add_argument('--sevenzip', default='7z')
    parser.add_argument('--force-capture', action='store_true')
    parser.add_argument('--archive-cache', type=Path)
    parser.add_argument('--collector-cache', type=Path)
    result = run(parser.parse_args())
    print(json.dumps(result, ensure_ascii=False, indent=2))


if __name__ == '__main__':
    main()
