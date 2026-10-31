#!/usr/bin/env python3
"""RFC-0020 §5: select expensive checks from actual push/PR changes."""
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


def changed_paths(event):
    if 'pull_request' in event:
        pr = event['pull_request']
        head = commit(pr['head']['sha'])
        base = git('merge-base', commit(pr['base']['sha']), head).decode().strip()
    else:
        base, head = commit(event['before']), commit(event['after'])
        if base == '0' * 40:
            base = git('hash-object', '-t', 'tree', os.devnull).decode().strip()
    return git('diff', '--no-renames', '--name-only', '-z', base, head).split(b'\0')


def scopes(paths):
    # Shared dependencies invalidate both campaigns; native gate edits do not
    # alter Python research proofs or the independent table arithmetic oracle.
    shared = any(path.startswith((b'.github/actions/', b'.cargo/', b'Cargo.',
                                  b'rust-toolchain', b'uv.lock', b'pyproject.toml'))
                 for path in paths)
    routing = any(path in (b'.github/workflows/ci.yml', b'scripts/ci_scope.py',
                          b'scripts/ci_result.py') for path in paths)
    return {
        'gpu': any(path.startswith((b'crates/stele-gpu/', b'crates/stele-kernels/'))
                   for path in paths),
        'tables': shared or routing or any(path.startswith((b'crates/stele-field/', b'crates/stele-poly/',
                                                b'crates/stele-simd/', b'crates/stele-cqis/'))
                                for path in paths),
        'research': shared or routing or any(
            (path.startswith((b'research/', b'harness/', b'formal/')) and path not in (
                # The mandatory native gate executes this exact locked oracle.
                b'research/merkle-oracle/check_field_wire.py',
                b'research/merkle-oracle/check_field_wire.py.lock')) or path in (
                b'.github/workflows/exhaustive.yml', b'scripts/research_ci.py',
                b'scripts/research-checks.json', b'scripts/research-full-checks.json')
            for path in paths),
    }


def main():
    try:
        event = json.loads(Path(os.environ['GITHUB_EVENT_PATH']).read_text())
        for name, required in scopes(changed_paths(event)).items():
            print(f'{name}={str(required).lower()}')
    except (OSError, ValueError, KeyError, subprocess.CalledProcessError) as error:
        print(f'CI scope failed: {error}', file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
