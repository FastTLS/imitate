"""Test the generator against an explicit profile checkout without changing go.mod/sum."""
import argparse
import os
from pathlib import Path
import shutil
import subprocess
import tempfile


def check(repo, profile):
    with tempfile.TemporaryDirectory(prefix='firefox-generator-check-') as directory:
        mod = Path(directory) / 'check.mod'
        shutil.copyfile(repo / 'go.mod', mod)
        if (repo / 'go.sum').exists():
            shutil.copyfile(repo / 'go.sum', mod.with_suffix('.sum'))
        env = {**os.environ, 'GOWORK': 'off'}
        subprocess.run(['go', 'mod', 'edit', '-modfile=' + str(mod), '-replace=github.com/FastTLS/fastls/profile=' + str(profile.resolve())], cwd=repo, env=env, check=True)
        for command in [('test', './...'), ('vet', './...')]:
            subprocess.run(['go', command[0], '-mod=mod', '-modfile=' + str(mod), command[1]], cwd=repo, env=env, check=True)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--repo', required=True, type=Path)
    parser.add_argument('--profile', required=True, type=Path)
    args = parser.parse_args()
    check(args.repo, args.profile)
