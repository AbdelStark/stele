"""RFC-0010 A9: certificate/opening authority is private; unwired APIs reject."""
import importlib.util
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location('gate_check', ROOT / 'scripts/gates/check.py')
gate = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(gate)


class FieldSourceGateTests(unittest.TestCase):
    def test_accepts_actual_source_codec(self):
        gate.field_source_codec(ROOT)

    def test_rejects_unwired_accepting_api_and_dependencies(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            crate = root / 'crates/stele-pcs'
            shutil.copytree(ROOT / 'crates/stele-pcs', crate)
            for name, added in [('src/lib.rs', '\npub fn verify() -> bool { true }\n'),
                                ('src/source.rs', '\nimpl<K: ChallengeField> Source<K> { '
                                 'pub fn verify_certificate(&self) -> bool { true } }\n'),
                                ('src/source.rs', '\nimpl<K: ChallengeField> From<Source<K>> for bool { '
                                 'fn from(_: Source<K>) -> bool { true } }\n'),
                                ('src/preparation.rs', '\nimpl<K: ChallengeField> PreparedSource<\'_, K> { '
                                 'pub fn verify_certificate(&self) -> bool { true } }\n'),
                                ('src/preparation.rs', '\nimpl<K: ChallengeField> From<PreparedSource<\'_, K>> for bool { '
                                 'fn from(_: PreparedSource<\'_, K>) -> bool { true } }\n'),
                                ('src/producer.rs', '\npub fn verify_certificate() -> bool { true }\n'),
                                ('src/producer.rs', '\nimpl From<CertificateFailure> for bool { '
                                 'fn from(_: CertificateFailure) -> bool { true } }\n'),
                                ('src/certificate.rs', '\nimpl<K: ChallengeField> VerifiedCertificate<K> { '
                                 'pub fn from_digest(_: [u8; 32]) -> Self { todo!() } }\n'),
                                ('src/certificate.rs', '\nimpl<K: ChallengeField> From<VerifiedCertificate<K>> for bool { '
                                 'fn from(_: VerifiedCertificate<K>) -> bool { true } }\n'),
                                ('src/opening.rs', '\nimpl<K: ChallengeField> OpeningRecord<\'_, K> { '
                                 'pub fn from_digest(_: [u8; 32]) -> Self { todo!() } }\n'),
                                ('src/opening.rs', '\nimpl<K: ChallengeField> From<OpeningRecord<\'_, K>> for bool { '
                                 'fn from(_: OpeningRecord<\'_, K>) -> bool { true } }\n'),
                                ('Cargo.toml', '\n[features]\nunwired = []\n')]:
                path = crate / name
                original = path.read_text()
                path.write_text(original + added)
                with mock.patch.object(gate.subprocess, 'run') as run:
                    with self.assertRaisesRegex(ValueError, 'not wired'):
                        gate.field_source_codec(root)
                    run.assert_not_called()
                path.write_text(original)
            (crate / 'src/opening.rs').write_text('pub fn verify() -> bool { true }')
            with self.assertRaisesRegex(ValueError, 'not wired'):
                gate.field_source_codec(root)

    def test_rejects_failed_or_missing_validation(self):
        for code, output in [(1, 'failed'), (0, '')]:
            result = subprocess.CompletedProcess([], code, output, '')
            with mock.patch.object(gate.subprocess, 'run', return_value=result):
                with self.assertRaisesRegex(ValueError, 'checks failed'):
                    gate.field_source_codec(ROOT)

    def test_rejects_missing_preparation_and_compile_fail_producers(self):
        actual = subprocess.run(['cargo', 'test', '-p', 'stele-pcs', '--locked', '--offline'],
                                cwd=ROOT, text=True, capture_output=True)
        self.assertEqual(actual.returncode, 0, actual.stderr)
        for name in ('preparation::tests::rejects_preparation_allocation_sizes',
                     'matches_reference_qm31_prepared_columns',
                     'matches_reference_om31_prepared_columns',
                     'rejects_preparation_shape_and_hash_overflow',
                     'producer::tests::matches_reference_qm31_certificate_production',
                     'producer::tests::matches_reference_om31_certificate_production',
                     'certificate::tests::matches_reference_qm31_certificates',
                     'certificate::tests::matches_reference_om31_certificates',
                     'matches_reference_qm31_openings', 'matches_reference_om31_openings',
                     'crates/stele-pcs/src/certificate.rs', 'crates/stele-pcs/src/source.rs',
                     'crates/stele-pcs/src/preparation.rs'):
            self.assertIn(name, actual.stdout)
            output = '\n'.join(line for line in actual.stdout.splitlines() if name not in line)
            result = subprocess.CompletedProcess([], 0, output, '')
            with mock.patch.object(gate.subprocess, 'run', return_value=result) as run:
                with self.assertRaisesRegex(ValueError, 'checks failed'):
                    gate.field_source_codec(ROOT)
                self.assertEqual(run.call_count, 1)
        opening_docs = [line for line in actual.stdout.splitlines()
                        if line.startswith('test crates/stele-pcs/src/opening.rs') and 'compile fail' in line]
        self.assertEqual(len(opening_docs), 2)
        for line in opening_docs:
            result = subprocess.CompletedProcess([], 0, actual.stdout.replace(line, '', 1), '')
            with mock.patch.object(gate.subprocess, 'run', return_value=result):
                with self.assertRaisesRegex(ValueError, 'missing compile-fail boundary'):
                    gate.field_source_codec(ROOT)
        # The scoped oracle still runs in native and fails closed on failure/missing output.
        policy = subprocess.CompletedProcess([], 0, '59 native query pairs match exact independently checked minima', '')
        for code, output in [(1, 'failure'), (0, ''), (2, 'missing checker')]:
            result = subprocess.CompletedProcess([], code, output, '')
            with mock.patch.object(gate.subprocess, 'run', side_effect=[actual, policy, result]) as run:
                with self.assertRaisesRegex(ValueError, 'checks failed'):
                    gate.field_source_codec(ROOT)
                self.assertEqual(run.call_args.args[0],
                                 ['uv', 'run', '--locked', '--script', 'research/merkle-oracle/check_field_wire.py'])


if __name__ == '__main__':
    unittest.main()
