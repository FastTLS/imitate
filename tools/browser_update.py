"""One manual entry point; browser-specific collectors keep their own contracts."""
import argparse
from pathlib import Path
import subprocess
import sys


def command(browser, arguments):
    root = Path(__file__).resolve().parent
    if browser == 'firefox':
        return [sys.executable, str(root / 'firefox/update.py'), *arguments]
    if browser in ('chrome', 'edge'):
        return [sys.executable, str(root / 'chromium/update_chromium.py'), '--browser', browser, *arguments]
    raise ValueError('Unsupported browser')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__, add_help=False)
    parser.add_argument('--browser', choices=['firefox', 'chrome', 'edge'], default='firefox')
    selected, remaining = parser.parse_known_args()
    raise SystemExit(subprocess.run(command(selected.browser, remaining)).returncode)
