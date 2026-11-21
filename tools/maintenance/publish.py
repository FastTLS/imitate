"""Publish only validated profile data through a normal fast-forward push."""
import argparse
import json
from pathlib import Path
import re
import subprocess


def execute(*args, **kwargs):
    return subprocess.check_output(args, text=True, **kwargs).strip()


def publish(repo, repository, source_sha, base):
    result = json.loads((repo / 'maintenance-result.json').read_text())
    if result['source_commit'] != source_sha or not result['changed']:
        raise ValueError('No validated update for this source')
    allowed = {'browser-specs.json', 'provider.go', 'maintenance-state.json'}
    allowed.update(f'testdata/{browser}/windows.json' for browser, p in result['products'].items() if p['status'] == 'validated')
    # Local output files are never committed. Restrict the tracked diff as well.
    changed = set(execute('git', 'diff', '--name-only', cwd=repo).splitlines())
    if changed - allowed:
        raise ValueError('Unexpected tracked changes: ' + str(changed - allowed))
    if execute('git', 'rev-parse', 'HEAD', cwd=repo) != source_sha:
        raise ValueError('Checkout moved since capture')
    remote = execute('git', 'ls-remote', 'origin', f'refs/heads/{base}', cwd=repo).split()[0]
    if remote != source_sha:
        raise ValueError('Default branch advanced; rerun maintenance on the new source')
    original = execute('git', 'show', source_sha + ':provider.go', cwd=repo)
    actual = (repo / 'provider.go').read_text(encoding='utf-8').strip()
    scrub = lambda value: re.sub(r'const DataRevision = "[^"]+"', 'const DataRevision = "<revision>"', value).strip()
    if scrub(original) != scrub(actual):
        raise ValueError('Provider changes exceed the data revision')
    execute('git', 'config', 'user.name', 'github-actions[bot]', cwd=repo)
    execute('git', 'config', 'user.email', '41898282+github-actions[bot]@users.noreply.github.com', cwd=repo)
    execute('git', 'add', '--', *sorted(allowed), cwd=repo)
    execute('git', 'commit', '-m', 'data: adopt verified browser profile updates', cwd=repo)
    head = execute('git', 'rev-parse', 'HEAD', cwd=repo)
    # Ordinary fast-forward push: concurrent changes and branch protection reject it.
    # No force push, admin override, organization setting change, or extra token.
    execute('git', 'push', 'origin', f'HEAD:refs/heads/{base}', cwd=repo)
    adopted = execute('git', 'ls-remote', 'origin', f'refs/heads/{base}', cwd=repo).split()[0]
    if adopted != head:
        raise ValueError('Remote adoption identity differs from validated commit')
    result.update(adopted=True, adopted_commit=head)
    (repo / 'maintenance-result.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(result, indent=2))
    return result


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--repo', type=Path, required=True)
    for name in ('repository', 'source-sha', 'base'):
        parser.add_argument('--' + name, required=True)
    args = parser.parse_args()
    publish(args.repo, args.repository, args.source_sha, args.base)
