"""RFC-0020 §5: combined execution retains gate coverage without duplicate work."""
from contextlib import ExitStack, redirect_stderr
import importlib.util
import io
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


if __name__ == '__main__':
    unittest.main()
