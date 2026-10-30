"""Discover and download official Firefox Windows x64 releases without installing.

Only regular stable X.0[.Y] builds are selected; ESR/beta/nightly never qualify.
The archive SHA512SUMS is fetched over HTTPS and checked before extraction.
"""
import argparse
import concurrent.futures
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import urllib.parse
import urllib.request

API = 'https://product-details.mozilla.org/1.0/'
ARCHIVE = 'https://archive.mozilla.org/pub/firefox/releases/'
STABLE = re.compile(r'^([1-9][0-9]*)\.0(?:\.([0-9]+))?$')


def fetch(url, limit=256 * 1024 * 1024):
    with urllib.request.urlopen(url, timeout=180) as response:
        if urllib.parse.urlparse(response.url).scheme != 'https':
            raise ValueError('HTTPS redirect required')
        body = response.read(limit + 1)
        if len(body) > limit:
            raise ValueError('Official download exceeds size budget')
        return body


def discover(first=None, last=None):
    current = json.loads(fetch(API + 'firefox_versions.json'))['LATEST_FIREFOX_VERSION']
    versions = set(json.loads(fetch(API + 'firefox_history_stability_releases.json')))
    versions.update(json.loads(fetch(API + 'firefox_history_major_releases.json')))
    versions.add(current)
    if not STABLE.fullmatch(current):
        raise ValueError('Unexpected stable release: ' + current)
    first = first if first is not None else int(current.split('.')[0])
    last = last if last is not None else int(current.split('.')[0])
    selected = []
    for major in range(first, last + 1):
        candidates = [v for v in versions if STABLE.fullmatch(v) and int(v.split('.')[0]) == major]
        if not candidates:
            raise ValueError('No official stable release for major ' + str(major))
        selected.append(max(candidates, key=lambda v: tuple(map(int, v.split('.')))))
    return {'latest': current, 'versions': selected, 'platform': 'windows-x64', 'locale': 'zh-CN', 'source': API}


def download(version, output, sevenzip, archive_cache=None):
    if not STABLE.fullmatch(version):
        raise ValueError('Invalid version')
    relative = f'win64/zh-CN/Firefox Setup {version}.exe'
    base = ARCHIVE + version + '/'
    sums = fetch(base + 'SHA512SUMS', 8 * 1024 * 1024).decode('utf-8')
    matching = [line.split()[0] for line in sums.splitlines() if line.split(maxsplit=1)[-1].lstrip('*') == relative]
    if len(matching) != 1 or not re.fullmatch(r'[0-9a-fA-F]{128}', matching[0]):
        raise ValueError('Missing or ambiguous official SHA512: ' + relative)
    target = output / version
    target.mkdir(parents=True, exist_ok=True)
    installer = target / 'installer.exe'
    expected = matching[0].lower()
    if archive_cache is not None and not installer.exists():
        cached = Path(archive_cache) / version / 'installer.exe'
        if cached.is_file() and cached.stat().st_size <= 256 * 1024 * 1024 and hashlib.sha512(cached.read_bytes()).hexdigest() == expected:
            import shutil
            shutil.copyfile(cached, installer)
    if not installer.exists() or hashlib.sha512(installer.read_bytes()).hexdigest() != expected:
        installer.write_bytes(fetch(base + urllib.parse.quote(relative)))
    if hashlib.sha512(installer.read_bytes()).hexdigest() != expected:
        raise ValueError('SHA512 mismatch: ' + version)
    (target / 'SHA512SUMS').write_text(sums, encoding='utf-8')
    executable = target / 'core' / 'firefox.exe'
    # Re-extract from the verified archive even when a browser cache exists.
    subprocess.run([sevenzip, 'x', str(installer), '-o' + str(target), '-y'], check=True, stdout=subprocess.DEVNULL)
    if not executable.is_file():
        raise ValueError('Extracted Firefox missing: ' + version)
    return {'version': version, 'url': base + urllib.parse.quote(relative), 'sha512': expected,
            'executable_sha256': hashlib.sha256(executable.read_bytes()).hexdigest(),
            'executable': str(executable.resolve()), 'checksum_source': base + 'SHA512SUMS'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--first', type=int)
    parser.add_argument('--last', type=int)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--download', action='store_true')
    parser.add_argument('--skip-known', type=Path, help='Skip a default latest-only run already collected and replayed')
    parser.add_argument('--sevenzip', default='7z')
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    manifest = discover(args.first, args.last)
    (args.output / 'discovery.json').write_text(json.dumps(manifest, indent=2), encoding='utf-8')
    print(json.dumps(manifest), flush=True)
    known = False
    if args.skip_known and args.first is None and args.last is None and args.skip_known.exists():
        records = json.loads(args.skip_known.read_text(encoding='utf-8'))['observations']
        known = any(o['version'] == manifest['latest'] and o.get('runtime_replay', {}).get('tls_and_headers_match') is True for o in records)
    if os.environ.get('GITHUB_OUTPUT'):
        with open(os.environ['GITHUB_OUTPUT'], 'a', encoding='utf-8') as output:
            output.write('update_required=' + ('false' if known else 'true') + '\n')
    if known:
        print('Latest stable build already collected and replayed; no update needed.', flush=True)
        return
    if args.download:
        with concurrent.futures.ThreadPoolExecutor(max_workers=3) as pool:
            jobs = [pool.submit(download, version, args.output.resolve(), args.sevenzip) for version in manifest['versions']]
            builds = []
            for job in concurrent.futures.as_completed(jobs):
                result = job.result()
                builds.append(result)
                print('Verified archive: ' + result['version'], flush=True)
                (args.output / 'builds.json').write_text(json.dumps(sorted(builds, key=lambda b: tuple(map(int, b['version'].split('.')))), indent=2), encoding='utf-8')


if __name__ == '__main__':
    main()
