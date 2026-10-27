#!/usr/bin/env python3
"""RFC-0020 §5: select GPU parity from actual Git changes for push and PR events."""
import json
import os
from pathlib import Path
import re
import subprocess
import sys


def git(*arguments):
    return subprocess.check_output(['git', *arguments])


def commit(value):
    if not isinstance(value, str) or not re.fullmatch(r'[0-9a-f]{40}', value):
        raise ValueError('event contains an invalid commit id')
    return value


def gpu_changed(event):
    if 'pull_request' in event:
        pr = event['pull_request']
        head = commit(pr['head']['sha'])
        base = git('merge-base', commit(pr['base']['sha']), head).decode().strip()
    else:
        base, head = commit(event['before']), commit(event['after'])
        if base == '0' * 40:
            base = git('hash-object', '-t', 'tree', os.devnull).decode().strip()
    paths = git('diff', '--no-renames', '--name-only', '-z', base, head).split(b'\0')
    return any(path.startswith((b'crates/stele-gpu/', b'crates/stele-kernels/')) for path in paths)


def main():
    try:
        event = json.loads(Path(os.environ['GITHUB_EVENT_PATH']).read_text())
        print(f'gpu={str(gpu_changed(event)).lower()}')
    except (OSError, ValueError, KeyError, subprocess.CalledProcessError) as error:
        print(f'CI scope failed: {error}', file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
