"""Build isolated cold-connection collectors from the pinned fastls-lab source."""
import argparse
import os
from pathlib import Path
import shutil
import subprocess


def prepare(source, output):
    output.mkdir(parents=True, exist_ok=True)
    for suffix, maximum in [('12', 'tls.VersionTLS12'), ('13', 'tls.VersionTLS13')]:
        target = output / ('collector' + suffix)
        target.mkdir(exist_ok=True)
        for item in source.iterdir():
            if item.is_file() and (item.suffix == '.go' or item.name in ('go.mod', 'go.sum', 'LICENSE')):
                shutil.copy2(item, target / item.name)
        server = target / 'server.go'
        text = server.read_text(encoding='utf-8')
        old = 'MinVersion: tls.VersionTLS12, MaxVersion: tls.VersionTLS13, NextProtos:'
        if text.count(old) != 1:
            raise ValueError('Collector source changed; review TLS adapter')
        server.write_text(text.replace(old, 'SessionTicketsDisabled: true, MinVersion: tls.VersionTLS12, MaxVersion: ' + maximum + ', NextProtos:'), encoding='utf-8')
        h2 = target / 'http2.go'
        text = h2.read_text(encoding='utf-8')
        old = 'MinVersion: tls.VersionTLS12, NextProtos:'
        if text.count(old) != 1:
            raise ValueError('Collector source changed; review H2 adapter')
        h2.write_text(text.replace(old, 'SessionTicketsDisabled: true, MinVersion: tls.VersionTLS12, NextProtos:'), encoding='utf-8')
        subprocess.run(['go', 'build', '-o', str(output.resolve() / ('lab' + suffix + '.exe')), '.'], cwd=target, env={**os.environ, 'GOWORK': 'off'}, check=True)


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--source', required=True, type=Path)
    p.add_argument('--output', required=True, type=Path)
    a = p.parse_args()
    prepare(a.source, a.output)
