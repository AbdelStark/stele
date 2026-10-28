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
    'negative-controls': ('pcs', 'verifier', 'reductions'),
    'soundness-accounting': ('pcs', 'verifier'),
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


def fraction_reductions(root):
    """Actual A3 tree/selected-product producers and consumers; full lookup stays guarded."""
    crate = root / 'crates/stele-lookup'
    allowed = {'Cargo.toml', 'src/lib.rs', 'src/fraction.rs', 'tests/codec.rs',
               'tests/fixtures/fraction-codec.jsonl', 'src/tree.rs', 'tests/tree.rs',
               'src/leaf_codec.rs', 'tests/leaf_codec.rs', 'tests/fixtures/leaf-codec.jsonl',
               'src/selected.rs', 'tests/selected.rs'}
    actual = {str(p.relative_to(crate)) for p in crate.rglob('*') if p.is_file()}
    library = ('//! Conditional fraction primitives governed by RFC-0008 A3.\n//!\n'
               '//! Tree and selected-product arithmetic return conditional claims; full lookup is absent.\n'
               '//! ```compile_fail\n//! use stele_lookup::fraction::verify_lookup;\n//! ```\n'
               '#![forbid(unsafe_code)]\n#![no_std]\n'
               '#![cfg_attr(not(test), deny(clippy::float_arithmetic))]\n\n'
               'extern crate alloc;\npub mod fraction;\n')
    manifest = tomllib.loads((crate / 'Cargo.toml').read_text())
    dependencies = {f'stele-{name}': {'path': f'../stele-{name}'} for name in ('gkr','hash','sumcheck','poly')}
    if (actual != allowed or (crate / 'src/lib.rs').read_text() != library
            or manifest.get('dependencies') != dependencies
            or manifest.get('dev-dependencies') != {'stele-field': {'path': '../stele-field'}, 'serde_json': '1.0'}
            or any(key in manifest for key in ('build-dependencies','target','features'))
            or 'build' in manifest.get('package', {})):
        raise ValueError('fraction engine/lookup validator not wired; only A3 conditional reductions/codecs admitted (E3-07a)')
    result = subprocess.run(['cargo','test','-p','stele-lookup','--locked','--offline'],
                            cwd=root,text=True,capture_output=True)
    names = ('matches_reference_qm31_fraction_codec','matches_reference_om31_fraction_codec',
             'rejects_fraction_codec_boundaries','accepts_maximum_verifier_shape_without_domain_allocation',
             'accepts_qm31_fraction_tree_original_consumers','accepts_om31_fraction_tree_original_consumers',
             'rejects_fraction_tree_source_shape_and_poles', 'rejects_qm31_leaf_codec_boundaries',
             'rejects_om31_leaf_codec_boundaries', 'matches_reference_qm31_selected_product_codec',
             'matches_reference_om31_selected_product_codec',
             'accepts_qm31_selected_product_original_consumers','accepts_om31_selected_product_original_consumers',
             'rejects_selected_product_context_and_source_shapes')
    if result.returncode or any(f'test {name} ... ok' not in result.stdout for name in names):
        raise ValueError(f'fraction codec checks failed: {result.stdout} {result.stderr}')
    result = subprocess.run(['uv','run','--locked','--script',
                             'research/logup-characteristic/check_fraction.py','--codec'],
                            cwd=root,text=True,capture_output=True)
    if result.returncode or '12 both-field native codec fixtures match' not in result.stdout:
        raise ValueError(f'fraction codec reference drift: {result.stdout} {result.stderr}')
    result = subprocess.run(['uv','run','--locked','--script',
                             'research/logup-characteristic/check_fraction.py','--leaf-codec'],
                            cwd=root,text=True,capture_output=True)
    if result.returncode or '12 both-field selected-product codec fixtures match' not in result.stdout:
        raise ValueError(f'selected-product codec reference drift: {result.stdout} {result.stderr}')
    result = subprocess.run(['cargo','test','-p','stele-negative-controls','--lib',
                             'fraction_transcript::','--locked','--offline'],
                            cwd=root,text=True,capture_output=True)
    names = ('rejects_fraction_challenge_order_tampers','rejects_fraction_missing_final_continuations')
    if result.returncode or any(f'fraction_transcript::{name} ... ok' not in result.stdout for name in names):
        raise ValueError(f'fraction transcript controls failed: {result.stdout} {result.stderr}')
    print('gate fraction reductions: tree/selected-product proofs, original consumers, scoped SC/RLC and continuation match Python; no full lookup/profile credit')


def public_coefficients(root):
    """A7 arithmetic only; keep all unwired stage/consumer code fail-closed."""
    crate = root / 'crates/stele-gkr'
    allowed = {'Cargo.toml', 'src/lib.rs', 'src/public_mle.rs', 'tests/public_mle.rs'}
    actual = {str(p.relative_to(crate)) for p in crate.rglob('*') if p.is_file()}
    library = ('//! Stacked reduction primitives governed by RFC-0006 A7.\n'
               '#![forbid(unsafe_code)]\n#![no_std]\n'
               '#![cfg_attr(not(test), deny(clippy::float_arithmetic))]\n\n'
               'extern crate alloc;\npub mod public_mle;\n')
    manifest = tomllib.loads((crate / 'Cargo.toml').read_text())
    if (actual != allowed or (crate / 'src/lib.rs').read_text() != library
            or manifest.get('dependencies') != {'stele-field': {'path': '../stele-field'}}
            or any(key in manifest for key in ('build-dependencies', 'dev-dependencies', 'target', 'features'))
            or 'build' in manifest.get('package', {})):
        raise ValueError('GKR stage/source validator not wired; only A7 arithmetic admitted (E3-06)')
    tests = ('matches_reference_qm31_all_kinds', 'matches_reference_om31_all_kinds',
             'rejects_invalid_descriptors_and_resource_limits',
             'accepts_large_masks_and_scalar_axes_without_domain_allocation')
    result = subprocess.run(['cargo', 'test', '-p', 'stele-gkr', '--test', 'public_mle',
                             '--locked', '--offline'], cwd=root, text=True, capture_output=True)
    if result.returncode or any(f'test {name} ... ok' not in result.stdout for name in tests):
        raise ValueError(f'public coefficient arithmetic checks failed: {result.stdout} {result.stderr}')
    print('gate public coefficients: 10000 points/kind/field; no stage, source or NC-0203 credit')


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


def native_encoder(root):
    """Actual A4 codeword digests and full-byte differential corpus, not PCS proofs."""
    generated = subprocess.run(
        ['uv', 'run', '--locked', '--script', 'research/code-provenance/check_native.py', '--vectors'],
        cwd=root, capture_output=True)
    expected = (root / 'crates/stele-code/tests/encoder-vectors.txt').read_bytes()
    if generated.returncode or generated.stdout != expected:
        raise ValueError(f'native encoder reference digests drift: {generated.stderr.decode()}')
    commands = [
        (['cargo', 'test', '-p', 'stele-code', '--locked', '--offline'],
         ['test matches_reference_materialized_codeword_digests ... ok',
          'test matches_reference_complete_work_and_capacity_all_fields ... ok',
          'test encoder::tests::rejects_outer_inner_and_late_sampling_exhaustion ... ok']),
        (['uv', 'run', '--locked', '--script', 'research/code-provenance/check_native.py'],
         [f'native d={d}: 1006 full words and ordered queries; {{3: 900, 4: 90, 5: 10}} seeds'
          for d in (1, 4, 8)] + ['native corpus: malformed adapter inputs reject; no PCS/profile or NC credit']),
    ]
    for command, receipts in commands:
        result = subprocess.run(command, cwd=root, text=True, capture_output=True)
        if result.returncode or any(receipt not in result.stdout for receipt in receipts):
            raise ValueError(f'native encoder gate failed: {result.stdout} {result.stderr}')
    print('gate digest: native encoder digests, sealed API and full-byte corpus checked; no PCS proof claim')


def sumcheck_corpus(root, path='research/sumcheck/corpus.jsonl', features=()):
    """Compare real Rust/Python decisions, all claims and every SC record."""
    commands = [
        ['cargo', 'run', '-q', '-p', 'stele-sumcheck', '--example', 'corpus', '--locked', '--offline']
        + (['--features', ','.join(features)] if features else []) + ['--', path],
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
                if (receipt['sc'] != expected or len(receipt['point']) != i['m'] or
                    [claim[0] for claim in receipt['claims']] != i['ids']):
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


def small_corpus(root):
    for test, command in [
        ('', ['uv', 'run', '--locked', '--script', 'research/small-value/check_small_value.py', '--check-corpus']),
        ('tests::rejects_small_corpus_unchecked_narrowing', ['cargo', 'test', '-p', 'stele-sumcheck', '--example', 'corpus', '--locked', '--offline']),
    ]:
        result = subprocess.run(command, cwd=root, text=True, capture_output=True)
        if result.returncode or (test and f'test {test} ... ok' not in result.stdout):
            raise ValueError(f'small corpus drift or adapter failure: {result.stdout} {result.stderr}')
    sumcheck_corpus(root, 'research/small-value/corpus.jsonl')


def small_strategy(root):
    """A5 directed/seeded parity and actual original-value consumer rejection."""
    for package, target, tests in [
        ('stele-sumcheck', 'small', ('matches_reference_small_qm31',
         'matches_reference_small_om31', 'rejects_small_constructor_and_cached_instance',
         'matches_reference_small_zero_one_folds')),
        ('stele-sumcheck', 'small_reference', ('matches_reference_naive_small_qm31',
         'matches_reference_naive_small_om31')),
        ('stele-negative-controls', 'nc-0204', ('rejects_nc_0204',)),
    ]:
        result = subprocess.run(['cargo', 'test', '-p', package, '--test', target,
                                 '--locked', '--offline'], cwd=root, text=True, capture_output=True)
        if result.returncode or any(f'test {test} ... ok' not in result.stdout for test in tests):
            raise ValueError(f'small strategy parity/control mismatch: {result.stdout} {result.stderr}')
    print('gate small strategy: 1000 direct-reference cases per degree/field and NC-0204; independent decisions and measured costs pending')


def buffered_engine(root):
    """A6 engine buffers retain A1 bytes, consumers, capacities and preflight errors."""
    tests = ('matches_reference_buffered_qm31', 'matches_reference_buffered_om31',
             'accepts_empty_inputs_and_reuses_proof_and_byte_buffers',
             'rejects_buffer_shapes_before_mutating_transcript',
             'matches_reference_payloads_and_rejects_short_buffers_without_partial_writes',
             'rejects_buffered_false_sum_and_invalid_descriptor',
             'rejects_buffered_unused_final_value')
    result = subprocess.run(['cargo', 'test', '-p', 'stele-sumcheck', '--test', 'buffers',
                             '--locked', '--offline'], cwd=root, text=True, capture_output=True)
    if result.returncode or any(f'test {test} ... ok' not in result.stdout for test in tests):
        raise ValueError(f'buffered A1 parity/consumer mismatch: {result.stdout} {result.stderr}')
    print('gate buffered A1: 1000 cases per degree/field, unchanged capacities, consumers and continuations')


def streaming_strategy(root):
    """A6 generic source/arena behavior; complete pipeline evidence remains open."""
    tests = ('matches_reference_streaming_qm31', 'matches_reference_streaming_om31',
             'accepts_workspace_smaller_than_dense_input', 'rejects_source_failures_and_capacity_overrun',
             'rejects_cached_instance_even_without_rounds', 'accepts_no_inputs_without_source_access',
             'rejects_source_failure_during_window_transition', 'matches_reference_zero_and_one_challenges',
             'matches_reference_window_suffix_contributions')
    result = subprocess.run(['cargo', 'test', '-p', 'stele-sumcheck', '--test', 'streaming',
                             '--locked', '--offline'], cwd=root, text=True, capture_output=True)
    if result.returncode or any(f'test {test} ... ok' not in result.stdout for test in tests):
        raise ValueError(f'streaming A1 source/arena mismatch: {result.stdout} {result.stderr}')
    print('gate streaming A1: 1000 cases per degree/field; source visits, errors and arena limits')


def file_source(root):
    """Execute the opt-in file adapter and actual source-substitution control."""
    tests = ('matches_reference_file_source_qm31', 'matches_reference_file_source_om31',
             'rejects_malformed_files_and_preserves_existing_paths',
             'rejects_changed_length_on_replay_and_short_rows',
             'rejects_extra_bytes_after_open_and_keeps_original_handles',
             'accepts_empty_file_source_without_size_overflow')
    for command, names in [
        (['cargo', 'test', '-p', 'stele-sumcheck', '--features', 'std', '--test', 'file_source'], tests),
        (['cargo', 'test', '-p', 'stele-negative-controls', '--test', 'nc-0210'], ('rejects_nc_0210',)),
    ]:
        result = subprocess.run(command + ['--locked', '--offline'], cwd=root, text=True, capture_output=True)
        if result.returncode or any(f'test {name} ... ok' not in result.stdout for name in names):
            raise ValueError(f'streaming file/control mismatch: {result.stdout} {result.stderr}')
    print('gate streaming files: canonical preparation/reads, preserved originals and NC-0210 in both fields')


def streaming_corpus(root):
    for test, command in [
        ('', ['uv', 'run', '--locked', '--script', 'research/streaming/check_windows.py', '--check-corpus']),
        ('tests::matches_reference_streaming_corpus_source_receipt',
         ['cargo', 'test', '-p', 'stele-sumcheck', '--features', 'std', '--example', 'corpus', '--locked', '--offline']),
    ]:
        result = subprocess.run(command, cwd=root, text=True, capture_output=True)
        if result.returncode or (test and f'test {test} ... ok' not in result.stdout):
            raise ValueError(f'streaming corpus drift or adapter failure: {result.stdout} {result.stderr}')
    sumcheck_corpus(root, 'research/streaming/corpus.jsonl', features=('std',))


def zerocheck(root):
    """Actual A3 bytes, all slice claims, SC phases and one-value controls."""
    for test, command in [
        ('matches_reference_zerocheck_bytes_and_accounting', ['cargo', 'test', '-p', 'stele-sumcheck', '--test', 'zerocheck', '--locked', '--offline']),
        ('matches_reference_naive_zerocheck_qm31', ['cargo', 'test', '-p', 'stele-sumcheck', '--test', 'zerocheck_reference', 'matches_reference_naive_zerocheck_qm31', '--locked', '--offline']),
        ('matches_reference_naive_zerocheck_om31', ['cargo', 'test', '-p', 'stele-sumcheck', '--test', 'zerocheck_reference', 'matches_reference_naive_zerocheck_om31', '--locked', '--offline']),
        ('zerocheck::rejects_zerocheck_binding_tampers', ['cargo', 'test', '-p', 'stele-negative-controls', '--lib', 'zerocheck::', '--locked', '--offline']),
        ('', ['uv', 'run', '--locked', '--script', 'research/zerocheck/check_zerocheck.py']),
    ]:
        result = subprocess.run(command, cwd=root, text=True, capture_output=True)
        if result.returncode or (test and f'test {test} ... ok' not in result.stdout):
            raise ValueError(f'zerocheck bytes/claims/accounting/control mismatch: {result.stdout} {result.stderr}')
    print('gate zerocheck: 130 both-field vectors, 1000 reference cases per degree/field, all slice claims, three SC phases and actual controls; no profile certified')


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
    allowed = {'src/lib.rs', 'src/catalog.rs', 'src/main.rs', 'src/sumcheck.rs', 'src/batching.rs', 'src/zerocheck.rs', 'src/small.rs', 'src/streaming.rs', 'src/fraction.rs', 'src/fraction_transcript.rs', 'Cargo.toml'}
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
            if args.gate == 'digest':
                native_encoder(ROOT)
            if args.gate in ('negative-controls', 'soundness-accounting'):
                public_coefficients(ROOT)
                transcript_registry(ROOT)
                sumcheck_corpus(ROOT)
                fraction_reductions(ROOT)
                small_strategy(ROOT)
                small_corpus(ROOT)
                batch_instances(ROOT)
                batch_claims(ROOT)
                batch_corpus(ROOT)
                zerocheck(ROOT)
                zero_corpus(ROOT)
                buffered_engine(ROOT)
                streaming_strategy(ROOT)
                file_source(ROOT)
                streaming_corpus(ROOT)
                if args.gate == 'negative-controls':
                    merkle_vectors(ROOT)
    except (OSError, ValueError, KeyError) as error:
        print(f'gate {args.gate}: {error}', file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
