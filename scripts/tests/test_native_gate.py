"""RFC-0020 §5: combined execution retains gate coverage without duplicate work."""
from contextlib import ExitStack, redirect_stderr
import importlib.util
import io
import shutil
import subprocess
import tempfile
from pathlib import Path
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location('native_gate', ROOT / 'scripts/gates/check.py')
gate = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(gate)
VALIDATORS = ('controls_layout', 'field_source_codec', 'field_sources', 'bootstrap_guard', 'native_encoder',
              'public_coefficients', 'transcript_registry', 'sumcheck_corpus', 'fraction_reductions',
              'small_strategy', 'small_corpus', 'batch_instances', 'batch_claims', 'batch_corpus',
              'zerocheck', 'zero_corpus', 'buffered_engine', 'streaming_strategy', 'file_source',
              'streaming_corpus', 'merkle_vectors')


class NativeGateTests(unittest.TestCase):
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


if __name__ == '__main__':
    unittest.main()
