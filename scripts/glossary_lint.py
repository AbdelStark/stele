#!/usr/bin/env python3
"""RFC-0020 §4: reject new forbidden synonyms without rewriting Accepted RFCs."""
from collections import Counter
import json
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
DIRECTORIES = ('docs', 'agents', 'crates', 'tests', 'harness', 'bench', 'scripts', 'formal', 'research')


def occurrences(root):
    glossary = (root / 'agents/context/glossary.md').read_text()
    section = glossary.split('Forbidden synonyms:', 1)
    if len(section) != 2:
        raise ValueError('glossary is missing its forbidden synonyms list')
    terms = re.findall(r'"([^"]+)"', section[1])
    if not terms:
        raise ValueError('glossary has no forbidden synonyms')
    patterns = [re.escape(term).replace(r'\ ', r'\s+').replace(r'\-', '[-‑– ]')
                + ('' if term.endswith('randomness') else 's?') for term in terms]
    pattern = re.compile(r'\b(?:' + '|'.join(patterns) + r')\b', re.IGNORECASE)
    files = set(root.glob('*.md'))
    for directory in DIRECTORIES:
        files.update((root / directory).rglob('*.md'))
    found = Counter()
    for file in sorted(files):
        if not file.resolve().is_relative_to(root.resolve()):
            raise ValueError(f'document path escapes the repository: {file}')
        source = file.read_text()
        spans = set()
        for match in pattern.finditer(source):
            start = source.rfind('\n', 0, match.start()) + 1
            end = source.find('\n', match.end())
            spans.add((start, len(source) if end < 0 else end))
        for start, end in spans:
            found[(str(file.relative_to(root)), source[start:end])] += 1
    return found


def check(root):
    rows = json.loads((root / 'scripts/gates/glossary-exceptions.json').read_text())
    exceptions = Counter()
    for row in rows:
        key = (row['path'], row['text'])
        if key in exceptions or not row['reason'] or type(row['count']) is not int or row['count'] <= 0:
            raise ValueError('invalid or duplicate glossary exception')
        exceptions[key] = row['count']
    found = occurrences(root)
    errors = [f'{path}: new forbidden wording: {text}' for path, text in found - exceptions]
    errors += [f'{path}: stale glossary exception: {text}' for path, text in exceptions - found]
    return errors


if __name__ == '__main__':
    try:
        errors = check(ROOT)
        if errors:
            print('\n'.join(errors), file=sys.stderr)
            sys.exit(1)
        print('gate glossary-lint: no new forbidden wording; exact legacy exceptions checked')
    except (OSError, ValueError, KeyError, TypeError) as error:
        print(f'gate glossary-lint: {error}', file=sys.stderr)
        sys.exit(1)
