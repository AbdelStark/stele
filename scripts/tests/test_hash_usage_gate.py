"""RFC-0012 A10: omission of actual work-usage controls fails the gates."""
import importlib.util
import json
from pathlib import Path
import subprocess
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location('gate_check', ROOT / 'scripts/gates/check.py')
gate = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(gate)


class HashUsageGateTests(unittest.TestCase):
    def test_accepts_actual_hash_usage_and_byte_vectors(self):
        gate.transcript_registry(ROOT)
        gate.merkle_vectors(ROOT)

    def test_rejects_missing_or_failed_transcript_usage_controls(self):
        registry = json.loads((ROOT / 'docs/security/transcript-labels.json').read_text())
        produced = subprocess.CompletedProcess([], 0, '\n'.join('\t'.join(row) for row in registry), '')
        names = ('transcript_tests::matches_reference_transcript_vectors',
                 'transcript_tests::rejects_empty_public_input',
                 'usage_tests::rejects_unrepresentable_frame_lengths',
                 'usage_tests::matches_reference_transcript_usage',
                 'usage_tests::rejects_usage_overflow_before_unrecorded_work',
                 'usage_tests::rejects_sampling_exhaustion_with_usage',
                 'usage_tests::rejects_merkle_overflow_with_usage',
                 'pcs::tests::rejects_column_thresholds_exhaustion_and_invalid_domains',
                 'pcs::tests::matches_reference_full_field_column_ratchets',
                 'pcs::tests::rejects_certificate_id_hash_overflow')
        for omitted in (*names, None):
            output = '\n'.join(f'test {name} ... ok' for name in names if name != omitted)
            result = subprocess.CompletedProcess([], int(omitted is None), output, '')
            with mock.patch.object(gate.subprocess, 'run', side_effect=[produced, result]):
                with self.assertRaisesRegex(ValueError, 'transcript primitive tests failed'):
                    gate.transcript_registry(ROOT)

    def test_rejects_missing_or_failed_merkle_usage_controls(self):
        names = ('matches_reference_roots_paths_and_rejections',
                 'rejects_descriptor_aliasing_and_invalid_shapes',
                 'accepts_authenticated_child_root_and_rejects_wrong_child',
                 'rejects_merkle_failures_with_usage')
        for omitted in (*names, None):
            output = '\n'.join(f'test {name} ... ok' for name in names if name != omitted)
            result = subprocess.CompletedProcess([], int(omitted is None), output, '')
            with mock.patch.object(gate.subprocess, 'run', return_value=result) as run:
                with self.assertRaisesRegex(ValueError, 'Merkle authentication/vector checks failed'):
                    gate.merkle_vectors(ROOT)
                self.assertEqual(run.call_count, 1)


if __name__ == '__main__':
    unittest.main()
