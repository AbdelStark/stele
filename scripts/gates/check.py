#!/usr/bin/env python3
"""RFC-0020 §5: fail closed until each protocol gate has its real producer.

The hashes identify empty scaffolds only. They are not proof reference digests.
Replace a guard with the actual validator in the task named in its diagnostic.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys
import tomllib
from urllib.parse import unquote, urlsplit

ROOT = Path(__file__).resolve().parents[2]
# Guard only crates that can introduce the corresponding proof obligations.
SCOPES = {
    'digest': ('prover', 'proof'),
    'negative-controls': ('sumcheck', 'gkr', 'lookup', 'pcs', 'verifier', 'reductions'),
    'soundness-accounting': ('sumcheck', 'gkr', 'lookup', 'pcs', 'verifier'),
    'parity': ('gpu', 'kernels'),
}
OWNERS = {
    'digest': 'E8-06', 'negative-controls': 'E0-03',
    'soundness-accounting': 'E2-01 / E8-05', 'parity': 'E10-01',

}
ARTIFACTS = {
    'digest': ('tests/digests',),
    'negative-controls': (),
    'soundness-accounting': ('tests/soundness',),
    'parity': ('tests/parity',),
}


def bootstrap_guard(root, gate):
    """An absent implementation may pass; an unvalidated implementation may not."""
    baseline = json.loads((root / 'scripts/gates/bootstrap-sources.json').read_text())
    for name in SCOPES.get(gate, ()):
        crate = root / f'crates/stele-{name}'
        expected = baseline[f'stele-{name}']
        actual = {str(p.relative_to(crate)): hashlib.sha256(p.read_bytes()).hexdigest()
                  for p in crate.rglob('*') if p.is_file()}
        if actual != expected:
            raise ValueError(f'{gate}: validator not wired for changed {crate.relative_to(root)}; '
                             f'implement the gate with its producer (task {OWNERS[gate]})')
    for directory in ARTIFACTS[gate]:
        for file in (root / directory).rglob('*'):
            if file.is_file() and file.name not in {'catalog.md', 'README.md', '.gitkeep'}:
                raise ValueError(f'{gate}: validator not wired for {file.relative_to(root)} '
                                 f'(task {OWNERS[gate]})')
    print(f'gate {gate}: remaining scaffold guards verified (task {OWNERS[gate]})')


def transcript_registry(root):
    """Compare the real validated registry producer with the RFC/accounting inventory."""
    command = ['cargo', 'run', '-q', '-p', 'stele-hash', '--example', 'registry', '--locked', '--offline']
    result = subprocess.run(command, cwd=root, text=True, capture_output=True)
    if result.returncode:
        raise ValueError(f'transcript registry producer failed: {result.stderr}')
    actual = [line.split('\t') for line in result.stdout.splitlines()]
    expected = json.loads((root / 'docs/security/transcript-labels.json').read_text())
    if actual != expected:
        raise ValueError('transcript registry mapping mismatch against soundness inventory')
    result = subprocess.run(['cargo', 'test', '-p', 'stele-hash', '--lib', '--all-features', '--locked', '--offline'],
                            cwd=root, text=True, capture_output=True)
    if result.returncode:
        raise ValueError(f'transcript primitive tests failed: {result.stdout}\n{result.stderr}')
    print(f'gate transcript: validated {len(actual)} registry entries; no profile budget certified')


def controls_layout(root):
    """Every standalone control source must be a declared Cargo test target."""
    suite = root / 'tests/negative-controls'
    manifest = tomllib.loads((suite / 'Cargo.toml').read_text())
    allowed = {'src/lib.rs', 'src/catalog.rs', 'src/main.rs', 'Cargo.toml'}
    for target in manifest.get('test', []):
        path = Path(target['path'])
        if path.is_absolute() or '..' in path.parts or path.suffix != '.rs':
            raise ValueError('invalid control test path')
        allowed.add(str(path))
    actual = {str(p.relative_to(suite)) for p in suite.rglob('*') if p.is_file()
              and p.suffix != '.md' and p.name != '.gitkeep'}
    if actual != allowed:
        raise ValueError(f'negative-controls: sources not wired to Cargo targets: {sorted(actual ^ allowed)}')


def rfc_status(root):
    """Code citations must resolve uniquely to an Accepted RFC."""
    statuses = {}
    for file in sorted((root / 'docs/rfcs').glob('RFC-*.md')):
        match = re.match(r'RFC-([0-9]{4})-', file.name)
        if not match:
            raise ValueError(f'malformed RFC filename: {file}')
        key = match[1]
        if key in statuses:
            raise ValueError(f'duplicate RFC-{key}')
        status = re.search(r'^Status: ([A-Za-z]+)', file.read_text(), re.MULTILINE)
        if not status:
            raise ValueError(f'RFC-{key} has no status')
        statuses[key] = status[1]
    references = 0
    sources = sorted(file for directory in ('crates', 'tests/negative-controls')
                     for file in (root / directory).rglob('*.rs'))
    if not sources:
        raise ValueError('no Rust sources found')
    for file in sources:
        for key in re.findall(r'RFC-([0-9]{4})', file.read_text()):
            if statuses.get(key) != 'Accepted':
                raise ValueError(f'{file.relative_to(root)} references RFC-{key}: '
                                 f'{statuses.get(key, "missing")}')
            references += 1
    print(f'gate rfc-status: checked {references} Accepted RFC references')


def docs_links(root):
    """Check local Markdown link file targets, without network requests."""
    files = [root / 'README.md']
    for directory in ('docs', 'agents'):
        files.extend((root / directory).rglob('*.md'))
    count = 0
    for file in files:
        # Inline Markdown links only; fenced examples are not document links.
        text = re.sub(r'```.*?```', '', file.read_text(), flags=re.DOTALL)
        for target in re.findall(r'\]\(([^)]+)\)', text):
            target = target.strip().split(' "', 1)[0].strip('<>')
            url = urlsplit(target)
            if url.scheme or url.netloc or not url.path:
                continue
            path = unquote(url.path)
            resolved = (root / path.lstrip('/') if path.startswith('/') else file.parent / path)
            if not resolved.exists():
                raise ValueError(f'{file.relative_to(root)}: broken local link {target}')
            count += 1
    print(f'gate docs-links: checked {count} local file targets')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('gate', choices=(*OWNERS, 'rfc-status', 'docs-links'))
    args = parser.parse_args()
    try:
        if args.gate == 'rfc-status':
            rfc_status(ROOT)
        elif args.gate == 'docs-links':
            docs_links(ROOT)
        else:
            if args.gate == 'negative-controls':
                controls_layout(ROOT)
            bootstrap_guard(ROOT, args.gate)
            if args.gate in ('negative-controls', 'soundness-accounting'):
                transcript_registry(ROOT)
    except (OSError, ValueError, KeyError) as error:
        print(f'gate {args.gate}: {error}', file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
