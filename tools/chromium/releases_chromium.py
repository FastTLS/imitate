"""Official Windows x64 release discovery and isolated extraction; never installs."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import struct
import subprocess
import tarfile
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor

CHROME = 'https://versionhistory.googleapis.com/v1/chrome/platforms/win64/channels/stable/versions/all/releases?filter=endtime=none'
CHROME_MSI = 'https://dl.google.com/dl/chrome/install/googlechromestandaloneenterprise64.msi'
EDGE = 'https://edgeupdates.microsoft.com/api/products?view=enterprise'
VERSION = re.compile(r'[1-9][0-9]*\.[0-9]+\.[0-9]+\.[0-9]+')
HOSTS = {'versionhistory.googleapis.com', 'dl.google.com', 'edgeupdates.microsoft.com',
         'msedge.sf.dl.delivery.mp.microsoft.com'}
MAX_ARCHIVE = 512 * 1024 * 1024


def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def checked_url(url):
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme != 'https' or parsed.hostname not in HOSTS or parsed.username or parsed.password or parsed.port not in (None, 443):
        raise ValueError('Unapproved browser release URL')
    return url


class Redirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        checked_url(newurl)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def fetch(url, maximum=8 * 1024 * 1024):
    with urllib.request.build_opener(Redirects()).open(checked_url(url), timeout=60) as response:
        checked_url(response.url)
        data = response.read(maximum + 1)
    if len(data) > maximum:
        raise ValueError('Release response exceeds size limit')
    return data


def discover(browser, version=None):
    if browser not in ('chrome', 'edge') or version is not None and not VERSION.fullmatch(version):
        raise ValueError('Expected browser and full four-component version')
    url = CHROME if browser == 'chrome' else EDGE
    raw = fetch(url)
    data = json.loads(raw)
    if browser == 'chrome':
        stable = [r['version'] for r in data['releases'] if r.get('pinnable') is True and r.get('fraction', 0) > 0 and VERSION.fullmatch(r.get('version', ''))]
        if not stable:
            raise ValueError('No pinned ordinary stable Chrome release in the official feed')
        selected = max(stable, key=lambda value: tuple(map(int, value.split('.'))))
        if version and version != selected:
            raise ValueError('Chrome enterprise MSI serves the current pinned stable build only; historical versions require a separately verified official archive')
        request = urllib.request.Request(CHROME_MSI, method='HEAD')
        with urllib.request.build_opener(Redirects()).open(request, timeout=30) as response:
            checked_url(response.url)
            size, etag = int(response.headers['Content-Length']), response.headers.get('ETag')
            ranges = response.headers.get('Accept-Ranges') == 'bytes'
        if not 0 < size <= MAX_ARCHIVE or not etag:
            raise ValueError('Missing bounded Chrome download identity')
        result = dict(browser=browser, version=selected, url=CHROME_MSI, archive_sha256=None, checksum_source=None,
            size=size, etag=etag, ranges=ranges, distribution='enterprise-stable',
            integrity='Official HTTPS MSI; pinned HTTP size/ETag; valid installer and executable Authenticode; locally recorded SHA256, not a vendor checksum.')
    else:
        releases = [r for p in data if p['Product'] == 'Stable' for r in p['Releases']
                    if r['Platform'] == 'Windows' and r['Architecture'] == 'x64' and
                    (version is None or r['ProductVersion'] == version)]
        if not releases:
            raise ValueError('Requested Edge stable version is unavailable in the official feed')
        selected = max(releases, key=lambda r: tuple(map(int, r['ProductVersion'].split('.'))))
        matches = [a for a in selected['Artifacts'] if a['ArtifactName'] == 'msi' and a['HashAlgorithm'] == 'SHA256']
        if len(matches) != 1 or not re.fullmatch(r'[0-9a-fA-F]{64}', matches[0]['Hash']):
            raise ValueError('Expected one checksum-bound official Edge x64 MSI')
        result = dict(browser=browser, version=selected['ProductVersion'], url=matches[0]['Location'],
                      archive_sha256=matches[0]['Hash'].lower(), checksum_source=EDGE, size=matches[0]['SizeInBytes'],
                      integrity='Official feed SHA256 and executable Authenticode')
    if not VERSION.fullmatch(result['version']):
        raise ValueError('Malformed discovered browser version')
    checked_url(result['url'])
    result.update(source=url, manifest_sha256=hashlib.sha256(raw).hexdigest(), platform='windows-x64', locale='en-US')
    return result, raw


def unbcj2(data):
    """Decode the four BCJ2 streams in the MSI's LZMA payload, with bounded reads.

    Adapted from the workspace's independently written Edge extraction helper;
    no downloaded decoder executable is run.
    """
    if len(data) < 20:
        raise ValueError('Short BCJ2 header')
    size, *lengths = struct.unpack_from('<5I', data)
    if not 0 < size <= 1024 * 1024 * 1024 or sum(lengths) + 20 != len(data):
        raise ValueError('Invalid BCJ2 lengths')
    streams, at = [], 20
    for length in lengths:
        streams.append(memoryview(data)[at:at + length]); at += length
    positions = [0] * 4
    def take(index, count):
        start = positions[index]; positions[index] += count
        if positions[index] > len(streams[index]):
            raise ValueError('Truncated BCJ2 stream')
        return streams[index][start:positions[index]]
    code = 0
    for value in take(3, 5):
        code = ((code << 8) | value) & 0xffffffff
    span, probabilities, previous, output = 0xffffffff, [1024] * 258, 0, bytearray()
    while len(output) < size:
        if span < 1 << 24:
            span <<= 8; code = ((code << 8) | take(3, 1)[0]) & 0xffffffff
        value = take(0, 1)[0]; output.append(value)
        index = previous + 2 if value == 0xe8 else 1 if value == 0xe9 else 0 if previous == 0x0f and 0x80 <= value <= 0x8f else -1
        previous = value
        if index < 0:
            continue
        bound = (span >> 11) * probabilities[index]
        if code < bound:
            span = bound; probabilities[index] += (2048 - probabilities[index]) >> 5
            continue
        span -= bound; code -= bound; probabilities[index] -= probabilities[index] >> 5
        address = int.from_bytes(take(1 if value == 0xe8 else 2, 4), 'big')
        relative = (address - len(output) - 4) & 0xffffffff
        output.extend(relative.to_bytes(4, 'little')); previous = relative >> 24
    if len(output) != size:
        raise ValueError('BCJ2 output size mismatch')
    return output


def publisher(executable, browser):
    if os.name != 'nt':
        raise ValueError('Browser verification requires Windows x64')
    script = "$ErrorActionPreference='Stop'; $s=Get-AuthenticodeSignature -LiteralPath $env:FASTLS_BROWSER_EXE; $v=(Get-Item -LiteralPath $env:FASTLS_BROWSER_EXE).VersionInfo; @{status=[string]$s.Status; subject=$s.SignerCertificate.Subject; thumbprint=$s.SignerCertificate.Thumbprint; product_version=$v.ProductVersion} | ConvertTo-Json -Compress"
    output = subprocess.check_output([shutil.which('pwsh') or 'powershell.exe', '-NoProfile', '-NonInteractive', '-Command', script],
        env={**os.environ, 'FASTLS_BROWSER_EXE': str(executable)}, text=True, encoding='utf-8')
    value = json.loads(output)
    expected = 'Google LLC' if browser == 'chrome' else 'Microsoft Corporation'
    if value['status'] != 'Valid' or not re.search(r'(?:^|,\s*)O=' + re.escape(expected) + r'(?:,|$)', value['subject'] or ''):
        raise ValueError('Browser executable publisher verification failed')
    return value


def download(manifest, output, sevenzip='7z', archive_cache=None):
    output.mkdir(parents=True, exist_ok=False)
    browser, version = manifest['browser'], manifest['version']
    archive = output / 'browser.msi'
    expected = manifest['archive_sha256']
    # Only a producer checksum makes an external archive cache admissible.
    cached = archive_cache / (version + '.msi') if archive_cache and browser == 'edge' else None
    if cached and cached.is_file() and digest(cached) == expected:
        shutil.copyfile(cached, archive)
    elif browser == 'chrome' and manifest.get('ranges'):
        ranged_download(manifest, archive)
    else:
        with urllib.request.build_opener(Redirects()).open(checked_url(manifest['url']), timeout=90) as response, archive.open('xb') as target:
            checked_url(response.url)
            count = 0
            while chunk := response.read(1024 * 1024):
                count += len(chunk)
                if count > MAX_ARCHIVE:
                    raise ValueError('Browser archive exceeds size limit')
                target.write(chunk)
    return extract_archive(manifest, archive, output, sevenzip)


def ranged_download(manifest, archive):
    """Bounded parallel ranges, all bound to the same official size and ETag."""
    size, etag = manifest['size'], manifest['etag']
    if not 0 < size <= MAX_ARCHIVE or not isinstance(etag, str) or not etag:
        raise ValueError('Invalid range download identity')
    directory = archive.parent / 'ranges'
    identity = dict(url=checked_url(manifest['url']), size=size, etag=etag)
    if directory.exists():
        if json.loads((directory / 'identity.json').read_text(encoding='utf-8')) != identity:
            raise ValueError('Partial download identity changed')
    else:
        directory.mkdir()
        (directory / 'identity.json').write_text(json.dumps(identity), encoding='utf-8')
    def fetch_part(index):
        start, end = size * index // 8, size * (index + 1) // 8 - 1
        target = directory / f'{index}.part'
        ledger = directory / f'{index}.json'
        if target.exists():
            record = json.loads(ledger.read_text(encoding='utf-8'))
            if record != dict(start=start, end=end, bytes=target.stat().st_size, sha256=digest(target)):
                raise ValueError('Partial browser bytes changed')
        elif ledger.exists():
            raise ValueError('Missing partial browser bytes')
        if target.exists() and target.stat().st_size > end - start + 1:
            raise ValueError('Oversized partial browser range')
        for attempt in range(3):
            offset = target.stat().st_size if target.exists() else 0
            if offset == end - start + 1:
                return
            position = start + offset
            request = urllib.request.Request(identity['url'], headers={'Range': f'bytes={position}-{end}', 'If-Match': etag})
            with urllib.request.build_opener(Redirects()).open(request, timeout=90) as response:
                checked_url(response.url)
                if response.status != 206 or response.headers.get('Content-Range') != f'bytes {position}-{end}/{size}' or response.headers.get('ETag') != etag:
                    raise ValueError('Chrome range identity mismatch')
                with target.open('ab') as stream:
                    try:
                        while chunk := response.read(1024 * 1024):
                            if stream.tell() + len(chunk) > end - start + 1:
                                raise ValueError('Chrome range exceeds declared size')
                            stream.write(chunk)
                    finally:
                        stream.flush()
                        ledger.write_text(json.dumps(dict(start=start, end=end, bytes=target.stat().st_size, sha256=digest(target))), encoding='utf-8')
            # Early EOF resumes only missing bytes, with the same pinned identity.
            # A mismatching identity is never retried. No partial archive is used.
        if target.stat().st_size != end - start + 1:
            raise ValueError('Truncated Chrome range after bounded continuation')
    with ThreadPoolExecutor(max_workers=4) as pool:
        list(pool.map(fetch_part, range(8)))
    with archive.open('xb') as stream:
        for index in range(8):
            with (directory / f'{index}.part').open('rb') as source:
                shutil.copyfileobj(source, stream)


def extract_archive(manifest, archive, output, sevenzip='7z'):
    browser, version, expected = manifest['browser'], manifest['version'], manifest['archive_sha256']
    actual = digest(archive)
    if expected and actual != expected or manifest.get('size') and archive.stat().st_size != manifest['size']:
        raise ValueError('Official browser archive checksum/size mismatch')
    extracted = output / 'browser'
    archive_signature = publisher(archive, browser)
    def seven(source, destination, *names):
        subprocess.run([sevenzip, 'x', str(source), '-o' + str(destination), *names, '-y'], check=True, stdout=subprocess.DEVNULL, timeout=180)
    if browser == 'chrome':
        seven(archive, output / 'outer', 'Binary.GoogleChromeInstaller')
        seven(output / 'outer/Binary.GoogleChromeInstaller', output / 'wrapper')
        wrappers = list((output / 'wrapper').rglob('updater.7z'))
        if len(wrappers) != 1:
            raise ValueError('Unexpected signed Chrome MSI wrapper')
        seven(wrappers[0], output / 'updater')
        installers = list((output / 'updater').rglob('*_chrome_installer.exe'))
        if len(installers) != 1:
            raise ValueError('Expected one pinned Chrome installer')
        publisher(installers[0], browser)
        seven(installers[0], output / 'installer')
        payloads = list((output / 'installer').rglob('chrome.7z'))
        if len(payloads) != 1:
            raise ValueError('Unexpected signed Chrome payload')
        seven(payloads[0], extracted)
        matches = list(extracted.rglob('chrome.exe'))
        if len(matches) != 1:
            raise ValueError('Expected one signed Chrome executable')
        executable = matches[0]
    else:
        seven(archive, output / 'outer', 'Binary.MicrosoftEdgeInstaller')
        seven(output / 'outer/Binary.MicrosoftEdgeInstaller', output / 'lzma')
        streams = list((output / 'lzma').rglob('102~'))
        if len(streams) != 1:
            raise ValueError('Unknown Edge MSI payload; retain archive for review')
        decoded = output / 'decoded.tar'
        decoded.write_bytes(unbcj2(streams[0].read_bytes()))
        with tarfile.open(decoded) as tar:
            members = [m for m in tar if m.isfile() and m.name.startswith('MicrosoftEdge_X64_')]
            if len(members) != 1 or members[0].size > MAX_ARCHIVE:
                raise ValueError('Unexpected Edge installer payload')
            installer = output / 'browser-installer.exe'
            with tar.extractfile(members[0]) as source, installer.open('xb') as target:
                shutil.copyfileobj(source, target)
        seven(installer, output / 'installer')
        payloads = list((output / 'installer').rglob('msedge.7z')) + list((output / 'installer').rglob('chrome.7z'))
        if len(payloads) != 1:
            raise ValueError('Unexpected Edge browser payload')
        seven(payloads[0], extracted)
        matches = list(extracted.rglob('msedge.exe'))
        if len(matches) != 1:
            raise ValueError('Expected one extracted Edge browser')
        executable = matches[0]
    signature = publisher(executable, browser)
    if signature['product_version'] != version:
        raise ValueError('Extracted browser full version mismatch')
    return {**manifest, 'archive_sha256': actual, 'archive': str(archive.resolve()), 'executable': str(executable.resolve()),
            'executable_sha256': digest(executable), 'publisher': signature, 'installer_publisher': archive_signature}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--browser', choices=['chrome', 'edge'], required=True)
    parser.add_argument('--version')
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--sevenzip', default='7z')
    args = parser.parse_args()
    manifest, raw = discover(args.browser, args.version)
    args.output.mkdir(parents=True, exist_ok=False)
    (args.output / 'discovery.json').write_bytes(raw)
    result = download(manifest, args.output / 'downloads', args.sevenzip)
    (args.output / 'build.json').write_text(json.dumps(result, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(result, indent=2))
