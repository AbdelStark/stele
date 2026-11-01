#!/usr/bin/env python3
"""RFC-0020 §5: execute the selected research inventory with failure propagation."""
import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / 'scripts/research-checks.json'
FULL_MANIFEST = ROOT / 'scripts/research-full-checks.json'


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f'duplicate research group: {key}')
        result[key] = value
    return result


def load_groups(path=MANIFEST):
    groups = json.loads(path.read_text(), object_pairs_hook=unique_object)
    if not isinstance(groups, dict) or not groups:
        raise ValueError('research inventory must be a nonempty object')
    seen = set()
    for name, commands in groups.items():
        if not re.fullmatch(r'[a-z][a-z0-9-]*', name):
            raise ValueError(f'invalid research group: {name}')
        if not isinstance(commands, list) or not commands:
            raise ValueError(f'empty or invalid research group: {name}')
        for command in commands:
            if not isinstance(command, str) or not command.strip() or command in seen:
                raise ValueError(f'empty, invalid or duplicate command in {name}')
            seen.add(command)
    return groups


def run_group(name, groups):
    commands = groups[name]
    if any('$RUNNER_TEMP' in command for command in commands):
        directory = Path(os.environ.get('RUNNER_TEMP', ''))
        if not directory.is_absolute() or not directory.is_dir():
            raise ValueError('RUNNER_TEMP must name an existing absolute directory')
    # Commands are repository-owned CI code. Preserve their shell quoting and
    # environment, including the ordered pinned-checkpoint download sequences.
    for command in commands:
        print(f'RUN {command}', flush=True)
        subprocess.run(['bash', '--noprofile', '--norc', '-e', '-o', 'pipefail',
                        '-c', command], cwd=ROOT, check=True)


def main(argv=None):
    try:
        parser = argparse.ArgumentParser(description=__doc__)
        parser.add_argument('--full', action='store_true', help='exhaustive scheduled/manual inventory')
        parser.add_argument('--selection', choices=('all', 'native', 'stacked', 'native-stacked', 'none'), default='all',
                            help='normal matrix selection; defaults to the complete inventory')
        mode = parser.add_mutually_exclusive_group(required=True)
        mode.add_argument('--matrix', action='store_true')
        mode.add_argument('--group')
        args = parser.parse_args(argv)
        groups = load_groups(FULL_MANIFEST if args.full else MANIFEST)
        if args.selection != 'all' and (args.full or not args.matrix):
            parser.error('selection applies only to the normal matrix')
        subsets = {'native': ('native-comparisons',), 'stacked': ('stacked-gkr',),
                   'native-stacked': ('native-comparisons', 'stacked-gkr')}
        if args.selection in subsets:
            selected = subsets[args.selection]
            for name in selected:
                if not groups.get(name):
                    raise ValueError(f'missing {name} research group')
            groups = {name: commands for name, commands in groups.items() if name in selected}
        elif args.selection == 'none':
            groups = {}
        if args.group is not None and args.group not in groups:
            parser.error('unknown research group: ' + args.group)
        if args.matrix:
            print('matrix=' + json.dumps({'group': list(groups)}, separators=(',', ':')))
        else:
            run_group(args.group, groups)
    except subprocess.CalledProcessError as error:
        print(f'Research CI failed: {error}', file=sys.stderr)
        return error.returncode
    except (OSError, ValueError) as error:
        print(f'Research CI failed: {error}', file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
