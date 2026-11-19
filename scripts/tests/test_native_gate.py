"""RFC-0020 §5: combined execution retains gate coverage without duplicate work."""
from contextlib import ExitStack, redirect_stderr
import importlib.util
import io
import json
import os
import shlex
import shutil
import subprocess
import sys
import tempfile
import tomllib
from pathlib import Path
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location('native_gate', ROOT / 'scripts/gates/check.py')
gate = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(gate)
VALIDATORS = ('controls_layout', 'field_source_codec', 'field_sources', 'bootstrap_guard', 'native_encoder',
              'development_digests', 'public_coefficients', 'transcript_registry', 'sumcheck_corpus',
              'fraction_reductions', 'small_strategy', 'small_corpus', 'batch_instances', 'batch_claims',
              'batch_corpus', 'zerocheck', 'zero_corpus', 'buffered_engine', 'streaming_strategy', 'file_source',
              'streaming_corpus', 'merkle_vectors', 'accounting_admission')


class NativeGateTests(unittest.TestCase):
    def test_accepts_checked_coverage_commands_and_rejects_failures(self):
        profile = tomllib.loads((ROOT / 'Cargo.toml').read_text())['profile']['test']
        self.assertIs(profile['debug-assertions'], True)
        self.assertIs(profile['overflow-checks'], True)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            log = root / 'commands.jsonl'
            helper = root / 'capture.py'
            helper.write_text('''import json, os, sys
from pathlib import Path
command = [Path(sys.argv[1]).name, *sys.argv[2:]]
with Path(os.environ['STELE_GATE_COMMAND_LOG']).open('a') as output:
    output.write(json.dumps(command) + '\\n')
phase = command[0] if command[0] == 'python3' else command[1]
sys.exit(37 if phase == os.environ['STELE_GATE_FAIL_PHASE'] else 0)
''')
            stub = '#!/bin/sh\nexec ' + shlex.quote(sys.executable) + ' ' + shlex.quote(str(helper)) + ' "$0" "$@"\n'
            for name in ('python3', 'cargo'):
                path = root / name
                path.write_text(stub)
                path.chmod(0o755)
            for name, arguments in [('native', []), ('negative-controls', []),
                                    ('negative-controls', ['--coverage'])]:
                expected = [
                    ['python3', str(ROOT / 'scripts/gates/check.py'), name],
                    ['cargo', 'test', '-p', 'stele-negative-controls', '--all-features', '--locked', '--offline'],
                    ['cargo', 'run', '--profile', 'test', '-p', 'stele-negative-controls', '--all-features',
                     '--bin', 'stele-controls', '--locked', '--offline', '--', '--coverage'],
                ]
                for failure, count in [('', 3), ('python3', 1), ('test', 2), ('run', 3)]:
                    with self.subTest(gate=name, arguments=arguments, failure=failure):
                        log.write_text('')
                        env = dict(os.environ, PATH=directory + os.pathsep + os.environ['PATH'],
                                   STELE_GATE_COMMAND_LOG=str(log), STELE_GATE_FAIL_PHASE=failure)
                        result = subprocess.run(['bash', str(ROOT / 'scripts/gates' / f'{name}.sh'), *arguments],
                                                cwd='/', env=env, text=True, capture_output=True)
                        self.assertEqual(result.returncode, 37 if failure else 0, result.stderr)
                        self.assertEqual([json.loads(line) for line in log.read_text().splitlines()], expected[:count])

    def run_gate(self, name, fail=None):
        calls = []
        def validator(label):
            def run(*args):
                calls.append((label, args))
                if label == fail:
                    raise ValueError('synthetic validator failure')
            return run
        with ExitStack() as stack:
            for label in VALIDATORS:
                stack.enter_context(patch.object(gate, label, side_effect=validator(label)))
            stack.enter_context(patch('sys.argv', ['check.py', name]))
            stack.enter_context(redirect_stderr(io.StringIO()))
            code = gate.main()
        return code, calls

    def test_matches_reference_standalone_union_once(self):
        standalone = set()
        for name in ('digest', 'negative-controls', 'soundness-accounting'):
            code, calls = self.run_gate(name)
            self.assertEqual(code, 0)
            standalone.update(calls)
        code, combined = self.run_gate('native')
        self.assertEqual(code, 0)
        self.assertEqual(set(combined), standalone)
        self.assertEqual(len(combined), len(standalone))

    def test_rejects_every_validator_failure(self):
        for validator in VALIDATORS:
            with self.subTest(validator=validator):
                code, calls = self.run_gate('native', fail=validator)
                self.assertNotEqual(code, 0)
                self.assertEqual(calls[-1][0], validator)

    def test_rejects_missing_accounting_receipt_and_unadmitted_verifier_surface(self):
        # E8-02f1: the replay's unit checks, the two dumps and the parity test, whose
        # stderr names both honest windows and both forged rejections.
        lines = ([f'test accounting::tests::{n} ... ok' for n in gate.ACCOUNTING['tests']]
                 + [f'test {n} ... ok' for n in gate.ACCOUNTING['parity']]
                 + [f'test {n} ... ok' for n in gate.ACCOUNTING['replay']]
                 + [f'test {n} ... ok' for n in gate.ACCOUNTING['registered']]
                 + [f'test {n} ... ok' for n in gate.ACCOUNTING['registered_units']]
                 + ['test dumps_byte5 ... ok', 'test dumps_forged ... ok',
                    'test matches_reference_registered_cli_windows ... ok',
                    'test matches_reference_request_layout_variants ... ok', 'A16 reference vectors match',
                    'test matches_reference_verify_dev_on_byte5_windows_and_tampers ... ok'])
        output = '\n'.join(lines)
        stderr = ('one-layer: 42 tampers rejected\neight-layer: 42 tampers rejected\n'
                  'forged-table: forged Err(TableDenominatorMismatch)\n'
                  'forged-public: forged Err(PublicMismatch)\n'
                  'A16 registered one-layer: accepted pinned proof\n'
                  'A16 registered eight-layer: accepted pinned proof\n')
        stderr += ''.join(f'A16 declaration {rung}-{sign}-{i}: request/template matched\n'
                          for rung in ('one-layer', 'eight-layer')
                          for sign in ('positive', 'negative') for i in range(3))
        stderr += ''.join(f'A16 CLI {rung}: published pinned entry, identical proof, registered acceptance, wrong entry rejected\n'
                          for rung in ('one-layer', 'eight-layer'))
        stderr += 'STELE_REGISTERED_CLI_PASSED\n'
        def fixtures(command, **kwargs):
            env = kwargs.get('env', {})
            if 'matches_reference_request_layout_variants' in command:
                declaration = Path(env['STELE_DUMP_DIR']) / 'one-layer-positive-0'
                declaration.mkdir()
                (declaration / 'relation.bin').write_bytes(b'declaration only')
            if 'development_replay' in command:
                # Replay reads every relation-bearing directory as a complete proof.
                for relation in Path(env['STELE_DEV_REPLAY_DIR']).glob('*/relation.bin'):
                    self.assertTrue(relation.with_name('proof.bin').is_file())
                    self.assertTrue(relation.with_name('public.bin').is_file())
            return subprocess.CompletedProcess([], 0, output, stderr)
        with patch.object(gate.subprocess, 'run', side_effect=fixtures):
            gate.accounting_admission(ROOT)
        missing = [stderr.replace(line + '\n', '') for line in stderr.splitlines()]
        for code, text, err in ([(1, output, stderr)] + [(0, output.replace(line, ''), stderr) for line in lines]
                                + [(0, output, e) for e in missing]):
            with self.subTest(code=code, output=text, stderr=err), patch.object(gate.subprocess, 'run',
                    return_value=subprocess.CompletedProcess([], code, text, err)):
                with self.assertRaisesRegex(ValueError, 'accounting admission'):
                    gate.accounting_admission(ROOT)
        crate = ROOT / 'crates/stele-verifier'
        expected = json.loads((ROOT / 'scripts/gates/bootstrap-sources.json').read_text())['stele-verifier']
        actual = {'src/lib.rs': 'changed', **gate.ACCOUNTING['pins']}
        self.assertEqual(gate.accounting_surface(crate, actual, expected), expected)
        for extra in ({'src/other.rs': 'y'}, {'Cargo.toml': 'changed'}, {'src/accounting.rs': 'edited'},
                      {'src/sumcheck.rs': 'edited'}, {'src/registered.rs': 'edited'},
                      {'src/registered/tests.rs': 'edited'}, {'tests/registered.rs': 'edited'}):
            changed = {**actual, **extra}
            self.assertEqual(gate.accounting_surface(crate, changed, expected), changed)
        # A path module or include hidden in the admitted file is refused even at the pin.
        with tempfile.TemporaryDirectory() as directory:
            fake = Path(directory)
            (fake / 'src').mkdir()
            (fake / 'src/lib.rs').write_text(gate.ACCOUNTING['library'])
            source = (crate / 'src/accounting.rs').read_text()
            for hidden in ('#[path = "x.rs"]\nmod x;\n', 'include!("x.rs");\n', 'mod extra {}\n',
                           '    pub mod extra;\n', 'pub(crate) mod extra {}\n',
                           '#[cfg(test)] mod hidden;\n', '/* c */ mod hidden;\n', 'fn f(){} mod hidden;\n'):
                (fake / 'src/accounting.rs').write_text(source + hidden)
                self.assertEqual(gate.accounting_surface(fake, actual, expected), actual)
            # Comments and prose that mention "mod" are not module items.
            for prose in ('/// accepted as `x mod N`\n', '// see mod tests\n', '//! x mod N, mod p\n'):
                (fake / 'src/accounting.rs').write_text(source + prose)
                self.assertEqual(gate.accounting_surface(fake, actual, expected), expected)

    def test_mod_items_skip_comments_only(self):
        items = 'mod a;\n  pub mod b {}\npub(crate) mod c;\n#[cfg(test)] mod d;\n/* c */ mod e;\nfn f(){} mod g;\n'
        self.assertEqual(gate.mod_items(items), ['a', 'b', 'c', 'd', 'e', 'g'])
        self.assertEqual(gate.mod_items('/// x mod N\n// mod d\n/* mod e\n mod f */\n//! y mod p\n'), [])
        # A comment opener inside a literal does not start a comment.
        self.assertEqual(gate.mod_items('let s = "//"; mod h;\nlet c = \'"\'; let t = "//"; mod i;\n'
                                        'let r = r#"/*"#; mod j; // */\n'), ['h', 'i', 'j'])
        # Strings that mention "mod" are a safe false positive; a nested or unclosed
        # block comment leaves the rest visible.
        self.assertEqual(gate.mod_items('let s = "mod x";\n'), ['x'])
        self.assertEqual(gate.mod_items('/* a /* b */ mod k; */\n/* open mod l;\n'), ['k', 'l'])

    def test_rejects_missing_actual_zerocheck_point_receipt(self):
        names=['matches_reference_zerocheck_bytes_and_accounting','matches_reference_retained_tail_and_failed_prefix',
               'matches_reference_naive_zerocheck_qm31','matches_reference_naive_zerocheck_om31','zerocheck::rejects_zerocheck_binding_tampers']
        output='\n'.join(f'test {name} ... ok' for name in names)
        with patch.object(gate.subprocess,'run',return_value=subprocess.CompletedProcess([],0,output,'')) as run:
            gate.zerocheck(ROOT);self.assertEqual(run.call_count,5)
        for code,text in [(1,output),(0,output.replace(f'test {names[1]} ... ok',''))]:
            with patch.object(gate.subprocess,'run',return_value=subprocess.CompletedProcess([],code,text,'')) as run:
                with self.assertRaisesRegex(ValueError,'zerocheck bytes'):gate.zerocheck(ROOT)
                self.assertEqual(run.call_count,1)

    def test_rejects_missing_a1_work_sources_exports_and_receipts(self):
        names = ('matches_reference_buffered_qm31', 'matches_reference_buffered_om31',
                 'accepts_empty_inputs_and_reuses_proof_and_byte_buffers',
                 'rejects_buffer_shapes_before_mutating_transcript',
                 'matches_reference_payloads_and_rejects_short_buffers_without_partial_writes',
                 'rejects_buffered_false_sum_and_invalid_descriptor', 'rejects_buffered_unused_final_value',
                 'matches_reference_qm31_allocation_observations', 'matches_reference_om31_allocation_observations')
        lines = [f'test {name} ... ok' for name in names]; output = '\n'.join(lines)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); crate = root/'crates/stele-sumcheck'
            for name in ('src/lib.rs', 'src/work.rs', 'tests/work.rs'):
                target = crate/name; target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy(ROOT/'crates/stele-sumcheck'/name, target)
            with patch.object(gate.subprocess, 'run', return_value=subprocess.CompletedProcess([], 0, output, '')) as run:
                gate.buffered_engine(root)
                run.assert_called_once_with(
                    ['cargo', 'test', '-p', 'stele-sumcheck', '--test', 'buffers', '--test', 'work', '--locked', '--offline'],
                    cwd=root, text=True, capture_output=True)
            for code, text in [(1, output)] + [(0, output.replace(line, '')) for line in lines]:
                with self.subTest(code=code, output=text), patch.object(gate.subprocess, 'run',
                        return_value=subprocess.CompletedProcess([], code, text, '')):
                    with self.assertRaisesRegex(ValueError, 'buffered A1 parity/consumer mismatch'):
                        gate.buffered_engine(root)
            path = crate/'src/lib.rs'; saved = path.read_text()
            for old, new in [('mod work;', 'pub mod work;'),
                             ('pub use work::{ProverWork, RoundWork, VerifierWork};', 'pub use work::*;')]:
                self.assertIn(old, saved); path.write_text(saved.replace(old, new, 1))
                with self.subTest(api=old), patch.object(gate.subprocess, 'run') as run:
                    with self.assertRaisesRegex(ValueError, 'not wired'):
                        gate.buffered_engine(root)
                    run.assert_not_called()
            path.write_text(saved)
            for name in ('src/work.rs', 'tests/work.rs'):
                path = crate/name; saved = path.read_bytes(); path.unlink()
                with self.subTest(missing=name), patch.object(gate.subprocess, 'run') as run:
                    with self.assertRaisesRegex(ValueError, 'not wired'):
                        gate.buffered_engine(root)
                    run.assert_not_called()
                path.write_bytes(saved)

    def test_accepts_development_digests_and_rejects_tamper_or_unaccepted_amendment(self):
        import hashlib
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            shutil.copytree(ROOT / 'docs/rfcs', root / 'docs/rfcs')
            fixture = root / 'crates/stele-prover/tests/fixtures/synthetic-e2e.json'
            fixture.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy(ROOT / 'crates/stele-prover/tests/fixtures/synthetic-e2e.json', fixture)
            digests_dir = root / 'tests/digests'
            digests_dir.mkdir(parents=True)

            payloads = {
                ('L0', 'one-layer', 16, 'CircleAll', 3): (b'l0-a12-proof-bytes', 'RFC-0026 A12'),
                ('L0', 'one-layer', 16, 'CircleAllGrind', 5): (b'l0-a14-proof-bytes', 'RFC-0026 A14'),
                ('L1', 'eight-layer', 64, 'CircleAll', 3): (b'l1-a12-proof-bytes', 'RFC-0026 A12'),
                ('L1', 'eight-layer', 64, 'CircleAllGrind', 5): (b'l1-a14-proof-bytes', 'RFC-0026 A14'),
            }
            manifest = {
                'schema_version': 1,
                'fixture_manifest': 'crates/stele-prover/tests/fixtures/synthetic-e2e.json',
                'entries': [
                    {
                        'rung': rung, 'case': case, 't': t, 'sources': sources,
                        'profile_byte': pbyte, 'proof_bytes': len(raw),
                        'fnv1a_64': gate._fnv1a_64(raw),
                        'sha256': hashlib.sha256(raw).hexdigest(),
                        'amendment': amendment,
                    }
                    for (rung, case, t, sources, pbyte), (raw, amendment) in payloads.items()
                ],
            }
            manifest_path = digests_dir / 'development.json'
            manifest_path.write_text(json.dumps(manifest, indent=2) + '\n')

            def producer(command, **kwargs):
                out_dir = Path(kwargs['env']['STELE_DIGEST_DIR'])
                err_lines = []
                for (rung, case, t, sources, _), (raw, _) in payloads.items():
                    (out_dir / f'{rung}-{sources}.proof').write_bytes(raw)
                    err_lines.append(
                        f'digest {rung} {case} T={t} {sources} bytes={len(raw)} fnv1a={gate._fnv1a_64(raw)}'
                    )
                return subprocess.CompletedProcess(
                    command, 0, 'test dumps_development_digests ... ok\n', '\n'.join(err_lines) + '\n'
                )

            with patch.object(gate.subprocess, 'run', side_effect=producer) as run:
                gate.development_digests(root)
                self.assertEqual(run.call_count, 1)

            # 1-byte proof tamper fails digest comparison.
            def tampered_producer(command, **kwargs):
                res = producer(command, **kwargs)
                p = Path(kwargs['env']['STELE_DIGEST_DIR']) / 'L1-CircleAll.proof'
                b = bytearray(p.read_bytes())
                b[0] ^= 1
                p.write_bytes(bytes(b))
                err = res.stderr.replace(
                    f'fnv1a={gate._fnv1a_64(payloads[("L1", "eight-layer", 64, "CircleAll", 3)][0])}',
                    f'fnv1a={gate._fnv1a_64(bytes(b))}',
                )
                return subprocess.CompletedProcess(command, 0, res.stdout, err)

            with patch.object(gate.subprocess, 'run', side_effect=tampered_producer):
                with self.assertRaisesRegex(ValueError, 'proof digest mismatch'):
                    gate.development_digests(root)

            # Missing producer ok receipt or non-zero exit fails.
            with patch.object(gate.subprocess, 'run', return_value=subprocess.CompletedProcess([], 1, '', 'boom')):
                with self.assertRaisesRegex(ValueError, 'digest producer failed'):
                    gate.development_digests(root)
            with patch.object(gate.subprocess, 'run', return_value=subprocess.CompletedProcess([], 0, '', '')):
                with self.assertRaisesRegex(ValueError, 'digest producer failed'):
                    gate.development_digests(root)

            # Unaccepted (Draft / missing / malformed) amendments fail before invoking cargo.
            for bad_amend in ('RFC-0026 A7', 'RFC-0026 A99', 'RFC-0028 A1', 'RFC-0026', 'none'):
                bad = json.loads(json.dumps(manifest))
                bad['entries'][0]['amendment'] = bad_amend
                manifest_path.write_text(json.dumps(bad))
                with self.subTest(bad_amend=bad_amend), patch.object(gate.subprocess, 'run') as run:
                    with self.assertRaises(ValueError):
                        gate.development_digests(root)
                    run.assert_not_called()

            # Missing L1 entry fails before invoking cargo.
            missing = json.loads(json.dumps(manifest))
            missing['entries'].pop()
            manifest_path.write_text(json.dumps(missing))
            with patch.object(gate.subprocess, 'run') as run:
                with self.assertRaisesRegex(ValueError, 'required L0/L1 fixtures'):
                    gate.development_digests(root)
                run.assert_not_called()

            # Extra unvalidated file in tests/digests/ fails with 'not wired'.
            manifest_path.write_text(json.dumps(manifest))
            extra = digests_dir / 'unvalidated.bin'
            extra.write_bytes(b'{}')
            with patch.object(gate.subprocess, 'run') as run:
                with self.assertRaisesRegex(ValueError, 'not wired'):
                    gate.development_digests(root)
                run.assert_not_called()
            extra.unlink()

            # Duplicate JSON key in manifest fails.
            manifest_path.write_text('{"schema_version": 1, "schema_version": 1}\n')
            with patch.object(gate.subprocess, 'run') as run:
                with self.assertRaisesRegex(ValueError, 'duplicate JSON key'):
                    gate.development_digests(root)
                run.assert_not_called()

            # Loose field types (float/bool/list) on tuple-key fields fail with ValueError before cargo.
            for field, bad_val in [('t', 16.0), ('profile_byte', 3.0), ('t', True), ('rung', ['L0'])]:
                bad = json.loads(json.dumps(manifest))
                bad['entries'][0][field] = bad_val
                manifest_path.write_text(json.dumps(bad))
                with self.subTest(field=field, bad_val=bad_val), patch.object(gate.subprocess, 'run') as run:
                    with self.assertRaisesRegex(ValueError, 'invalid entry field types'):
                        gate.development_digests(root)
                    run.assert_not_called()

            # Synthetic RFC edge cases for `_verify_accepted_amendment` (F1/F2/F3).
            gate._verify_accepted_amendment(root, 'RFC-0018 A2')
            synthetic_cases = [
                (
                    'no-preamble-status',
                    '# RFC-9001\n\n## 1. Amendment log\n\n### A1 — x\n\nStatus: Accepted.\n',
                    'RFC-9001 A1',
                ),
                (
                    'draft-rfc-with-accepted-amendment',
                    '# RFC-9002\n\nStatus: Draft\n\n## 1. Amendment log\n\n### A1 — x\n\nStatus: Accepted.\n',
                    'RFC-9002 A1',
                ),
                (
                    'preamble-accepted-prefix-spoof',
                    '# RFC-9003\n\nStatus: AcceptedNot\n\n## 1. Amendment log\n\n### A1 — x\n\nStatus: Accepted.\n',
                    'RFC-9003 A1',
                ),
                (
                    'section-accepted-prefix-spoof',
                    '# RFC-9004\n\nStatus: Accepted\n\n## 1. Amendment log\n\n### A1 — x\n\nStatus: AcceptedPending.\n',
                    'RFC-9004 A1',
                ),
                (
                    'negated-draft-bullet',
                    '# RFC-9005\n\nStatus: Accepted\n\n## 1. Amendment log\n\n- **A1 — x.** Draft; not yet Accepted.\n',
                    'RFC-9005 A1',
                ),
                (
                    'bullet-under-draft-subsection',
                    '# RFC-9006\n\nStatus: Accepted\n\n## 1. Amendment log\n\n### A7 — d\n\nStatus: Draft.\n\n- **A1 — x.** Accepted.\n',
                    'RFC-9006 A1',
                ),
                (
                    'heading-outside-amendment-log',
                    '# RFC-9007\n\nStatus: Accepted\n\n## 1. Body\n\n### A1 — x\n\nStatus: Accepted.\n\n## 2. Amendment log\n\nNone.\n',
                    'RFC-9007 A1',
                ),
                (
                    'heading-inside-fenced-code-block',
                    '# RFC-9008\n\nStatus: Accepted\n\n## 1. Amendment log\n\n```md\n### A1 — x\n\nStatus: Accepted.\n```\n',
                    'RFC-9008 A1',
                ),
                (
                    'duplicate-headings',
                    '# RFC-9009\n\nStatus: Accepted\n\n## 1. Amendment log\n\n### A1 — x\n\nStatus: Accepted.\n\n### A1 — y\n\nStatus: Accepted.\n',
                    'RFC-9009 A1',
                ),
                (
                    'colliding-heading-and-bullet',
                    '# RFC-9010\n\nStatus: Accepted\n\n## 1. Amendment log\n\n### A1 — x\n\nStatus: Accepted.\n\n- **A1 — y.** Accepted.\n',
                    'RFC-9010 A1',
                ),
                (
                    'duplicate-draft-and-accepted-bullets',
                    '# RFC-9011\n\nStatus: Accepted\n\n## 1. Amendment log\n\n- **A1 — x.** Draft.\n- **A1 — y.** Accepted.\n',
                    'RFC-9011 A1',
                ),
                (
                    'punctuation-suffixed-id',
                    '# RFC-9012\n\nStatus: Accepted\n\n## 1. Amendment log\n\n### A1-draft — x\n\nStatus: Accepted.\n\n### A12 — y\n\nStatus: Accepted.\n',
                    'RFC-9012 A1',
                ),
                (
                    'greedy-bold-draft-bullet',
                    '# RFC-9013\n\nStatus: Accepted\n\n## 1. Amendment log\n\n- **A1 — x.** Status: Draft. **Note:** Accepted A0 is unchanged.\n',
                    'RFC-9013 A1',
                ),
                (
                    'h3-before-h2-preamble-leak',
                    '# RFC-9014\n\n### A1 — x\n\nStatus: Accepted.\n\n## 1. Amendment log\n\n### A1 — x\n\nStatus: Accepted.\n',
                    'RFC-9014 A1',
                ),
            ]
            for label, body, ref in synthetic_cases:
                rfc_num = ref.split()[0]
                rfc_file = root / f'docs/rfcs/{rfc_num}-synthetic.md'
                rfc_file.write_text(body)
                with self.subTest(synthetic=label):
                    with self.assertRaises(ValueError):
                        gate._verify_accepted_amendment(root, ref)
                rfc_file.unlink()


if __name__ == '__main__':
    unittest.main()
