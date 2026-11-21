"""Bind an offline export to exact bytes, source commit and module identity."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess


def manifest(bundle, run_url):
    raw = bundle.read_bytes()
    data = json.loads(raw)
    records = data['records']
    ids = [r['match']['selector'] for r in records]
    if len(ids) != len(set(ids)) or any(not r.get('spec') or r.get('legacy') for r in records):
        raise ValueError('Export must contain unique complete Specs')
    source = subprocess.check_output(['git', 'rev-parse', 'HEAD'], text=True).strip()
    version = re.search(r'const Version = "([^"]+)"', Path('provider.go').read_text()).group(1)
    revision = re.search(r'const DataRevision = "([^"]+)"', Path('provider.go').read_text()).group(1)
    if data['provider_version'] != version or data['data_revision'] != revision:
        raise ValueError('Export identity differs from generator source')
    state = json.loads(Path('maintenance-result.json').read_text()) if Path('maintenance-result.json').exists() else {}
    dirty = bool(subprocess.check_output(['git', 'diff', '--name-only'], text=True).strip())
    source_commit = state.get('adopted_commit') or (None if dirty else source)
    return {'schema_version': 1, 'artifact': bundle.name, 'sha256': hashlib.sha256(raw).hexdigest(),
            'records': len(records), 'complete_specs': len(records), 'provider_version': version, 'data_revision': revision,
            'source_commit': source_commit, 'capture_source_commit': state.get('capture_source_commit', state.get('source_commit', source)),
            'catalog_sha256': hashlib.sha256(Path('browser-specs.json').read_bytes()).hexdigest(),
            'run_url': run_url, 'published_module': False,
            'note': 'This artifact is an explicit offline snapshot; it does not replace installed SDK profiles.'}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--bundle', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--run-url', required=True)
    args = parser.parse_args()
    args.output.write_text(json.dumps(manifest(args.bundle, args.run_url), indent=2) + '\n', encoding='utf-8')
