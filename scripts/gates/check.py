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
    'negative-controls': ('gkr', 'lookup', 'pcs', 'verifier', 'reductions'),
    'soundness-accounting': ('gkr', 'lookup', 'pcs', 'verifier'),
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


def sumcheck_corpus(root):
    """Compare real Rust/Python decisions and each accepted instance's SC record."""
    path = 'research/sumcheck/corpus.jsonl'
    commands = [
        ['cargo', 'run', '-q', '-p', 'stele-sumcheck', '--example', 'corpus', '--locked', '--offline', '--', path],
        ['uv', 'run', '--locked', '--script', 'research/sumcheck/check_sumcheck.py', '--verify-corpus', path],
    ]
    outputs = []
    for command in commands:
        result = subprocess.run(command, cwd=root, text=True, capture_output=True)
        if result.returncode:
            raise ValueError(f'sumcheck corpus producer failed: {result.stdout} {result.stderr}')
        outputs.append([json.loads(line) for line in result.stdout.splitlines()])
    cases = [json.loads(line) for line in (root / path).read_text().splitlines()]
    if not cases or outputs[0] != outputs[1] or len(outputs[0]) != len(cases):
        raise ValueError('sumcheck corpus decisions/accounting mismatch')
    for case, result in zip(cases, outputs[0]):
        if result['name'] != case['name'] or result.get('error', 'accept') != case['expected']:
            raise ValueError('sumcheck corpus expected rejection mismatch')
        if case['expected'] == 'accept':
            if len(result['receipts']) != len(case['instances']):
                raise ValueError('sumcheck instance enumeration mismatch')
            for record, receipt in zip(case['instances'], result['receipts']):
                i = record['instance']
                degree = max((len(t['factors']) for t in i['terms']), default=0)
                expected = dict(id=i['id'], m=i['m'], degree=degree, field_degree=case['field_degree'], numerator=i['m']*degree)
                if receipt['sc'] != expected or len(receipt['point']) != i['m']:
                    raise ValueError('sumcheck SC record/challenge count mismatch')
    print(f'gate sumcheck: {len(cases)} actual corpus decisions and SC records; no profile budget certified')


def batch_instances(root):
    """Real instance-batch bytes/records and both-mode production controls."""
    commands = [
        ('matches_reference_batch_bytes_and_accounting', ['cargo', 'test', '-p', 'stele-sumcheck', '--test', 'batch', '--locked', '--offline']),
        ('batching::rejects_batch_binding_tampers', ['cargo', 'test', '-p', 'stele-negative-controls', '--lib', 'batching::', '--locked', '--offline']),
        ('', ['uv', 'run', '--locked', '--script', 'research/batching/check_batching.py', '--instance-vectors']),
    ]
    for test, command in commands:
        result = subprocess.run(command, cwd=root, text=True, capture_output=True)
        if result.returncode or (test and f'test {test} ... ok' not in result.stdout):
            raise ValueError(f'batch instance checks failed: {result.stdout} {result.stderr}')
    expected = (root / 'crates/stele-sumcheck/tests/fixtures/batch-instances.jsonl').read_text()
    if result.stdout != expected:
        raise ValueError('batch instance byte/accounting oracle mismatch')
    print('gate batching: instance bytes/SC/RLC and both-mode controls checked; E3-02 remains incomplete')


def batch_claims(root):
    """Check the separate mode-1 prover/verifier and sparse/direct coefficient agreement."""
    tests = ['matches_reference_claim_bytes_and_accounting',
             'matches_reference_coefficients_at_ten_thousand_points_per_field']
    result = subprocess.run(['cargo', 'test', '-p', 'stele-sumcheck', '--test', 'claim_batch', '--locked', '--offline'],
                            cwd=root, text=True, capture_output=True)
    if result.returncode or any(f'test {name} ... ok' not in result.stdout for name in tests):
        raise ValueError(f'claim batch checks failed: {result.stdout} {result.stderr}')
    result = subprocess.run(['uv', 'run', '--locked', '--script', 'research/batching/check_batching.py', '--claim-vectors'],
                            cwd=root, text=True, capture_output=True)
    expected = (root / 'crates/stele-sumcheck/tests/fixtures/batch-claims.jsonl').read_text()
    if result.returncode or result.stdout != expected:
        raise ValueError(f'claim batch byte/accounting oracle mismatch: {result.stderr}')
    print('gate claim batching: bytes/SC/RLC and 10000 coefficient points per field checked; no profile certified')



def batch_corpus(root):
    """Compare actual closed-statement decisions, every obligation, and both loss records."""
    path = 'research/batching/corpus.jsonl'
    outputs = []
    for command in [
        ['cargo', 'run', '-q', '-p', 'stele-sumcheck', '--example', 'batch_corpus', '--locked', '--offline', '--', path],
        ['uv', 'run', '--locked', '--script', 'research/batching/check_batching.py', '--verify-corpus', path],
    ]:
        result = subprocess.run(command, cwd=root, text=True, capture_output=True)
        if result.returncode:
            raise ValueError(f'batch corpus producer failed: {result.stdout} {result.stderr}')
        outputs.append([json.loads(line) for line in result.stdout.splitlines()])
    cases = [json.loads(line) for line in (root / path).read_text().splitlines()]
    if not cases or outputs[0] != outputs[1] or len(outputs[0]) != len(cases):
        raise ValueError('batch corpus decisions/obligations/accounting mismatch')
    for case, result in zip(cases, outputs[0]):
        if result['name'] != case['name'] or result.get('error', 'accept') != case['expected']:
            raise ValueError('batch corpus expected rejection mismatch')
        if case['expected'] == 'accept':
            b, d = case['batch'], case['degree']
            if b['mode']:
                m, degree, count, claims = b['m'], 2, len(b['claims']), 1
            else:
                members = b['instances']; m = max(i['m'] for i in members)
                degree = max([int(any(i['m'] != m for i in members))] +
                             [len(factors) for i in members for _, factors in i['terms']])
                count, claims = len(members), sum(len(i['ids']) for i in members)
            if (result['sc'] != dict(id=b['id'], m=m, degree=degree, field_degree=d, numerator=m*degree) or
                result['rlc'] != dict(id=b['id'], t=count, field_degree=d, numerator=count) or
                len(result['point']) != m or len(result['claims']) != claims):
                raise ValueError('batch corpus descriptor/accounting mismatch')
    print(f'gate batching: {len(cases)} shared decisions, all obligations and SC/RLC checked; no profile certified')


def zerocheck(root):
    """Actual A3 bytes, all slice claims, SC phases and one-value controls."""
    for test, command in [
        ('matches_reference_zerocheck_bytes_and_accounting', ['cargo', 'test', '-p', 'stele-sumcheck', '--test', 'zerocheck', '--locked', '--offline']),
        ('zerocheck::rejects_zerocheck_binding_tampers', ['cargo', 'test', '-p', 'stele-negative-controls', '--lib', 'zerocheck::', '--locked', '--offline']),
        ('', ['uv', 'run', '--locked', '--script', 'research/zerocheck/check_zerocheck.py']),
    ]:
        result = subprocess.run(command, cwd=root, text=True, capture_output=True)
        if result.returncode or (test and f'test {test} ... ok' not in result.stdout):
            raise ValueError(f'zerocheck bytes/claims/accounting/control mismatch: {result.stdout} {result.stderr}')
    print('gate zerocheck: 130 both-field vectors, all slice claims, three SC phases and actual controls; no profile certified')


def zero_corpus(root):
    """Actual A3 public decisions, all original claims and ordered SC phases."""
    path = 'research/zerocheck/corpus.jsonl'
    outputs = []
    for command in [
        ['cargo', 'run', '-q', '-p', 'stele-sumcheck', '--example', 'zero_corpus', '--locked', '--offline', '--', path],
        ['uv', 'run', '--locked', '--script', 'research/zerocheck/check_zerocheck.py', '--verify-corpus', path],
    ]:
        result = subprocess.run(command, cwd=root, text=True, capture_output=True)
        if result.returncode:
            raise ValueError(f'zerocheck corpus producer failed: {result.stdout} {result.stderr}')
        outputs.append([json.loads(line) for line in result.stdout.splitlines()])
    cases = [json.loads(line) for line in (root / path).read_text().splitlines()]
    if not cases or outputs[0] != outputs[1] or len(outputs[0]) != len(cases):
        raise ValueError('zerocheck corpus decisions/claims/accounting mismatch')
    for case, result in zip(cases, outputs[0]):
        if result['name'] != case['name'] or result.get('error', 'accept') != case['expected']:
            raise ValueError('zerocheck corpus expected rejection mismatch')
        if case['expected'] == 'accept':
            i, d = case['instance'], case['field']
            delta = max([0] + [len(factors) for _, factors in i['terms']])
            j, s = i['m']-i['k'], 2**i['k']
            records = [dict(id=i['id'], phase=p, m=m, degree=degree, field_degree=d, numerator=m*degree)
                       for p, (m, degree) in enumerate([(j, 1), (int(i['k'] > 0), delta*(s-1)), (j, delta)])]
            if result['sc'] != records or len(result['claims']) != len(i['ids'])*s:
                raise ValueError('zerocheck corpus descriptor/accounting mismatch')
    print(f'gate zerocheck corpus: {len(cases)} shared decisions, all original claims and SC phases checked')


def merkle_vectors(root):
    """Execute actual authentication/KATs and check the independent candidate oracle."""
    for command in [
        ['cargo', 'test', '-p', 'stele-hash', '--test', 'merkle', '--locked', '--offline'],
        ['uv', 'run', '--locked', '--script', 'research/merkle/check_merkle.py'],
    ]:
        result = subprocess.run(command, cwd=root, text=True, capture_output=True)
        if result.returncode:
            raise ValueError(f'Merkle authentication/vector checks failed: {result.stdout} {result.stderr}')
    print('gate Merkle: actual roots, paths, batches and byte vectors checked; no PCS/profile certification')


def controls_layout(root):
    """Every standalone control source must be a declared Cargo test target."""
    suite = root / 'tests/negative-controls'
    manifest = tomllib.loads((suite / 'Cargo.toml').read_text())
    allowed = {'src/lib.rs', 'src/catalog.rs', 'src/main.rs', 'src/sumcheck.rs', 'src/batching.rs', 'src/zerocheck.rs', 'Cargo.toml'}
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
                sumcheck_corpus(ROOT)
                batch_instances(ROOT)
                batch_claims(ROOT)
                batch_corpus(ROOT)
                zerocheck(ROOT)
                zero_corpus(ROOT)
                if args.gate == 'negative-controls':
                    merkle_vectors(ROOT)
    except (OSError, ValueError, KeyError) as error:
        print(f'gate {args.gate}: {error}', file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
