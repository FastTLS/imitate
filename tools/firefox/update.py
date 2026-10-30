"""Manual Firefox Windows capture -> semantic diff -> validated offline candidates.

Never edits the source catalog, installs profiles, opens a PR, or publishes.
The output directory must be new. Official HTTPS checksums bind downloaded bytes;
they do not replace producer signature verification.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
from datetime import datetime, timezone

import audit
import prepare_lab
import releases
import replay


def source_identity(path):
    path = path.resolve()
    files = subprocess.check_output(['git', 'ls-files', '-c', '-o', '--exclude-standard', '-z'], cwd=path).decode().split('\0')
    digest = hashlib.sha256()
    for name in sorted(set(files) - {''}):
        file = path / name
        if file.is_file():
            digest.update(name.encode() + b'\0' + file.read_bytes() + b'\0')
    return dict(commit=subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=path, text=True).strip(), tree_sha256=digest.hexdigest())


def semantic_diff(previous, candidate, path=''):
    """Object key order is irrelevant; array order and null/absence are not."""
    if type(previous) is not type(candidate):
        return [path or '/']
    if isinstance(previous, dict):
        result = []
        for key in sorted(previous.keys() | candidate.keys()):
            child = path + '/' + key.replace('~', '~0').replace('/', '~1')
            result += [child] if key not in previous or key not in candidate else semantic_diff(previous[key], candidate[key], child)
        return result
    if isinstance(previous, list):
        return [] if previous == candidate else [path or '/']
    return [] if previous == candidate else [path or '/']


def known_build(catalog, version):
    entry = catalog.get('firefox/' + version.split('.')[0] + '/windows', {})
    required = {'tls.static_client_hello.cold', 'http.headers.navigation.zh-CN', 'http2.initial_frames.cold'}
    return bool(entry.get('spec', {}).get('evidence')) and required.issubset(entry.get('match', {}).get('verified_fields', [])) and all(
        e.get('product_version') == version and required.issubset(e.get('verified_fields', [])) for e in entry['spec']['evidence'])


def write_bundles(directory, catalog, version, provenance):
    identifier = 'firefox/' + version.split('.')[0] + '/windows'
    spec = catalog[identifier]['spec']
    # These bytes use the shared ProfileBundle v1 envelope. Consumers validate
    # native support again and require the caller's explicit digest pin.
    raw = json.dumps(spec, ensure_ascii=False, sort_keys=True, separators=(',', ':'))
    digest = hashlib.sha256(raw.encode('utf-8')).hexdigest()
    bundle = dict(schema_version=1, profile_id=identifier, spec_json=raw, sha256=digest,
                  source='Mozilla Firefox ' + version + '; Windows x64 zh-CN; ' + provenance)
    directory.mkdir()
    audit.dump(directory / 'firefox-windows.json', bundle)
    return dict(profile_id=identifier, sha256=digest, path='bundles/firefox-windows.json')


def run(args):
    if sys.platform != 'win32':
        raise ValueError('Firefox capture currently requires Windows x64')
    if args.output.exists():
        raise ValueError('Use a fresh output directory')
    for source in (args.repo, args.core, args.transport, args.lab):
        if args.output.resolve().is_relative_to(source.resolve()):
            raise ValueError('Output must be outside all source checkouts')
    args.output.mkdir(parents=True)
    report = dict(status='preparing', started_at=datetime.now(timezone.utc).isoformat(),
                  scope='Firefox stable; Windows x64 zh-CN; headless cold navigation',
                  writes_source_catalog=False, automatic_activation=False,
                  sources={name: source_identity(path) for name, path in
                           [('imitate', args.repo), ('core', args.core), ('transport', args.transport), ('collector', args.lab)]})
    phase = 'discovery'
    try:
        catalog = audit.read(args.repo / 'browser-specs.json')
        manifest = releases.discover() if not args.version else dict(latest=None, source=releases.ARCHIVE,
                                                                    platform='windows-x64', locale='zh-CN')
        version = args.version or manifest['latest']
        if not releases.STABLE.fullmatch(version):
            raise ValueError('Expected a full ordinary stable Firefox version')
        manifest['versions'] = [version]
        downloads = args.output / 'downloads'
        downloads.mkdir()
        audit.dump(downloads / 'discovery.json', manifest)
        report['browser_version'] = version
        if known_build(catalog, version) and not args.force_capture:
            report['status'] = 'no_change'
            return report
        phase = 'download'
        print('Downloading verified Firefox ' + version, flush=True)
        build = releases.download(version, downloads.resolve(), args.sevenzip, getattr(args, 'archive_cache', None))
        audit.dump(downloads / 'builds.json', [build])
        phase = 'collector'
        print('Building independent collectors', flush=True)
        prepare_lab.prepare(args.lab, args.output)
        phase = 'capture'
        print('Capturing 15 fresh browser samples', flush=True)
        subprocess.run(['node', str(Path(__file__).with_name('capture.mjs')), str(args.output.resolve()), '5'], check=True, timeout=600)
        phase = 'projection'
        # The staging repository is an output, never the input checkout.
        stage = args.output / 'candidate'
        shutil.copytree(args.repo, stage, ignore=shutil.ignore_patterns('.git', '__pycache__', '.cache', 'go.work*'))
        subprocess.run([sys.executable, str(Path(__file__).with_name('audit.py')), '--run', str(args.output.resolve()), '--repo', str(stage.resolve()), '--apply'], check=True, timeout=90)
        phase = 'backend_replay'
        print('Validating supported fields with online/offline replay', flush=True)
        comparison = replay.replay(args.output, stage, args.core, args.transport)
        candidate = audit.read(stage / 'browser-specs.json')
        final_sources = {name: source_identity(path) for name, path in
                        [('imitate', args.repo), ('core', args.core), ('transport', args.transport), ('collector', args.lab)]}
        if final_sources != report['sources']:
            raise ValueError('Source inputs changed during collection; candidate rejected')
        identifier = 'firefox/' + version.split('.')[0] + '/windows'
        paths = semantic_diff(catalog.get(identifier), candidate[identifier])
        audit.dump(args.output / 'semantic-diff.json', dict(profile_id=identifier, changed_paths=paths))
        report['bundle'] = write_bundles(args.output / 'bundles', candidate, version, build['checksum_source'])
        report.update(status='candidate' if paths else 'no_change', changed_paths=paths,
                      whole_profile_verified=all(not row['differences'] for row in comparison['results']),
                      limitations=candidate[identifier]['spec']['capabilities']['limitations'],
                      replay_summary={k:v for k,v in comparison.items() if k != 'results'})
        return report
    except BaseException as error:
        report.update(status='blocked', phase=phase, error=type(error).__name__ + ': ' + str(error))
        raise
    finally:
        report['finished_at'] = datetime.now(timezone.utc).isoformat()
        audit.dump(args.output / 'update-report.json', report)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    for name in ('repo', 'core', 'transport', 'lab', 'output'):
        p.add_argument('--' + name, required=True, type=Path)
    p.add_argument('--version', help='Pin a full stable version instead of selecting the current stable')
    p.add_argument('--sevenzip', default='7z')
    p.add_argument('--force-capture', action='store_true')
    p.add_argument('--archive-cache', type=Path, help='Reuse only archives matching the freshly fetched official SHA512')
    args = p.parse_args()
    result = run(args)
    print(json.dumps(result, ensure_ascii=False, indent=2))


if __name__ == '__main__':
    main()
