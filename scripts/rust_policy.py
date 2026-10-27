#!/usr/bin/env python3
"""RFC-0020 §4 / INV-12: reject float tokens missed by Clippy's type lint."""
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
# Comments and quoted data are not Rust expressions. Rust checks full syntax in CI.
TOKENS = re.compile(
    r'(?P<line>//[^\n]*)|(?P<block>/\*)|'
    r'(?P<raw>(?:br|cr|r)(?P<hashes>\#*)")|'
    r'(?P<string>(?:b|c)?"(?:\\.|[^"\\])*")|'
    r"(?P<char>b?'(?:\\(?:u\{[0-9a-fA-F_]+\}|x[0-9a-fA-F]{2}|.)|[^'\\\n])')|"
    r'(?P<base>0(?:x[0-9a-fA-F_]+|o[0-7_]+|b[01_]+)(?:[iu][0-9]+|[iu]size)?)|'
    r'(?P<number>[0-9][0-9_]*(?:\.(?![.a-zA-Z_])[0-9_]*)?(?:[eE][+-]?[0-9_]+)?(?:[a-zA-Z][a-zA-Z0-9_]*)?)|'
    r'(?P<ident>[^\W\d]\w*)', re.DOTALL)


def violations(source):
    """Return offsets of direct float types/literals, skipping nested Rust comments."""
    position = 0
    while match := TOKENS.search(source, position):
        position = match.end()
        if match.group('block'):
            depth = 1
            while depth:
                boundary = re.search(r'/\*|\*/', source[position:])
                if boundary is None:
                    raise ValueError('unterminated block comment')
                depth += 1 if boundary[0] == '/*' else -1
                position += boundary.end()
        elif match.group('raw'):
            terminator = '"' + match.group('hashes')
            end = source.find(terminator, position)
            if end < 0:
                raise ValueError('unterminated raw string')
            position = end + len(terminator)
        elif match.group('number'):
            token = match[0]
            if '.' in token or re.search(r'[eE][+-]?[0-9_]', token) or token.endswith(('f32', 'f64')):
                yield match.start(), token
        elif match.group('ident') in {'f32', 'f64'}:
            yield match.start(), match[0]


def check(root):
    errors = []
    files = sorted(file for directory in ('crates', 'tests/negative-controls')
                   for file in (root / directory).rglob('*.rs'))
    if not files:
        raise ValueError('no Rust sources found')
    for file in files:
        source = file.read_text()
        for offset, token in violations(source):
            line = source.count('\n', 0, offset) + 1
            errors.append(f'{file.relative_to(root)}:{line}: forbidden float token {token}')
    return errors


if __name__ == '__main__':
    try:
        errors = check(ROOT)
        if errors:
            print('\n'.join(errors), file=sys.stderr)
            sys.exit(1)
        print('gate rust-policy: no direct float types or literals')
    except (OSError, ValueError) as error:
        print(f'gate rust-policy: {error}', file=sys.stderr)
        sys.exit(1)
