"""Publish only staged profile data, then request policy-respecting PR merge."""
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
    remote = execute('gh', 'api', f'repos/{repository}/git/ref/heads/{base}', '--jq', '.object.sha', cwd=repo)
    if remote != source_sha:
        raise ValueError('Default branch advanced; rerun maintenance on the new source')
    branch = 'automation/browser-profiles-' + execute('git', 'hash-object', 'browser-specs.json', cwd=repo)[:16]
    execute('git', 'config', 'user.name', 'github-actions[bot]', cwd=repo)
    execute('git', 'config', 'user.email', '41898282+github-actions[bot]@users.noreply.github.com', cwd=repo)
    execute('git', 'checkout', '-b', branch, cwd=repo)
    execute('git', 'add', '--', *sorted(allowed), cwd=repo)
    execute('git', 'commit', '-m', 'data: adopt verified browser profile updates', cwd=repo)
    head = execute('git', 'rev-parse', 'HEAD', cwd=repo)
    execute('git', 'push', 'origin', f'HEAD:refs/heads/{branch}', cwd=repo)
    body = repo / 'maintenance-pr-body.txt'
    products = ', '.join(f'{b} {p["version"]}' for b, p in result['products'].items() if p['status'] == 'validated')
    body.write_text(f'Adopt independently captured Windows profiles: {products}.\n\n'
        'Validation: official distribution integrity, 15 independent cold samples per product, six matching online/offline TLS/header/H2 replays, combined Go catalog tests and vet, and a complete offline export with SHA-256.\n\n'
        f'Evidence and exact scope: {result["run_url"]}\n\n'
        'Existing evidence and other platforms remain unchanged. This does not publish a Go module or update installed SDK stores.\n', encoding='utf-8')
    pr = execute('gh', 'pr', 'create', '--repo', repository, '--base', base, '--head', branch,
                 '--title', 'data: adopt verified browser profiles', '--body-file', str(body.resolve()), cwd=repo)
    print('Candidate PR:', pr, flush=True)
    if execute('gh', 'api', f'repos/{repository}/git/ref/heads/{base}', '--jq', '.object.sha', cwd=repo) != source_sha:
        raise ValueError('Default branch advanced after publication; PR retained for a fresh validation')
    # This uses normal repository protections. No admin override or self approval.
    execute('gh', 'pr', 'merge', pr, '--repo', repository, '--squash', '--match-head-commit', head, cwd=repo)
    state = json.loads(execute('gh', 'pr', 'view', pr, '--repo', repository, '--json', 'state,mergeCommit,url', cwd=repo))
    if state['state'] != 'MERGED':
        raise ValueError('PR remains pending; the active catalog has not been updated')
    result.update(adopted=True, pull_request=state['url'], adopted_commit=state['mergeCommit']['oid'])
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
