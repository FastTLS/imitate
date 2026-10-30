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
import zipfile

CHROME = 'https://googlechromelabs.github.io/chrome-for-testing/'
EDGE = 'https://edgeupdates.microsoft.com/api/products?view=enterprise'
VERSION = re.compile(r'[1-9][0-9]*\.[0-9]+\.[0-9]+\.[0-9]+')
HOSTS = {'googlechromelabs.github.io', 'storage.googleapis.com', 'edgeupdates.microsoft.com',
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
    url = CHROME + (version + '.json' if version else 'last-known-good-versions-with-downloads.json') if browser == 'chrome' else EDGE
    raw = fetch(url)
    data = json.loads(raw)
    if browser == 'chrome':
        selected = data if version else data['channels']['Stable']
        if version and selected['version'] != version:
            raise ValueError('Chrome manifest version mismatch')
        matches = [v for v in selected['downloads']['chrome'] if v['platform'] == 'win64']
        if len(matches) != 1:
            raise ValueError('Expected one official Chrome win64 archive')
        result = dict(browser=browser, version=selected['version'], url=matches[0]['url'],
                      archive_sha256=None, checksum_source=None,
                      integrity='Official HTTPS archive; locally recorded SHA256; executable Authenticode required. No vendor archive checksum is advertised.')
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
    archive = output / ('browser.zip' if browser == 'chrome' else 'browser.msi')
    expected = manifest['archive_sha256']
    # Only a producer checksum makes an external archive cache admissible.
    cached = archive_cache / (version + '.msi') if archive_cache and browser == 'edge' else None
    if cached and cached.is_file() and digest(cached) == expected:
        shutil.copyfile(cached, archive)
    else:
        with urllib.request.build_opener(Redirects()).open(checked_url(manifest['url']), timeout=90) as response, archive.open('xb') as target:
            checked_url(response.url)
            count = 0
            while chunk := response.read(1024 * 1024):
                count += len(chunk)
                if count > MAX_ARCHIVE:
                    raise ValueError('Browser archive exceeds size limit')
                target.write(chunk)
    actual = digest(archive)
    if expected and actual != expected or manifest.get('size') and archive.stat().st_size != manifest['size']:
        raise ValueError('Official browser archive checksum/size mismatch')
    extracted = output / 'browser'
    if browser == 'chrome':
        with zipfile.ZipFile(archive) as zipped:
            if sum(i.file_size for i in zipped.infolist()) > 2 * 1024**3:
                raise ValueError('Browser extraction exceeds size limit')
            for info in zipped.infolist():
                if '\\' in info.filename or not (extracted / info.filename).resolve().is_relative_to(extracted.resolve()) or (info.external_attr >> 16) & 0o170000 == 0o120000:
                    raise ValueError('Unsafe archive member')
            zipped.extractall(extracted)
        executable = extracted / 'chrome-win64/chrome.exe'
    else:
        def seven(source, destination, *names):
            subprocess.run([sevenzip, 'x', str(source), '-o' + str(destination), *names, '-y'], check=True, stdout=subprocess.DEVNULL, timeout=180)
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
            'executable_sha256': digest(executable), 'publisher': signature}


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
