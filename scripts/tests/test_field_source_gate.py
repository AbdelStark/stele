"""RFC-0010 A9/A10: certificate and retained-row boundaries; unwired APIs reject."""
import importlib.util
from contextlib import redirect_stdout
import io
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
                                ('src/opening.rs', '\nimpl<K: ChallengeField> RetainedRow<\'_, \'_, K> { '
                                 'pub fn from_values(_: Vec<K>) -> Self { todo!() } }\n'),
                                ('src/opening.rs', '\nimpl<K: ChallengeField> RetainedRow<\'_, \'_, K> { '
                                 'pub fn values_mut(&mut self) -> &mut [K] { &mut self.values } }\n'),
                                ('src/work.rs', '\npub fn verify() -> bool { true }\n'),
                                ('src/work.rs', '\nimpl From<ProverWork> for bool {}\n'),
                                ('src/work.rs', '\ninclude!("unchecked.rs");\n'),
                                ('Cargo.toml', '\n[features]\nunwired = []\n')]:
                path = crate / name
                original = path.read_text()
                path.write_text(original + added)
                with mock.patch.object(gate.subprocess, 'run') as run:
                    with self.assertRaisesRegex(ValueError, 'not wired'):
                        gate.field_source_codec(root)
                    run.assert_not_called()
                path.write_text(original)
            path = crate/'src/work.rs'; saved = path.read_text()
            for old, new in [('pub proof_bytes: usize', 'pub proof_bytes: u64'),
                             ('pub encoded_values_read: usize', 'pub encoded_values_read: bool'),
                             ('pub encoder: stele_code::EncoderWork', 'pub encoder: usize'),
                             ('pub(crate) fn bytes', 'pub fn bytes'),
                             ('pub(crate) fn add', 'pub(super) fn add')]:
                self.assertIn(old, saved); path.write_text(saved.replace(old, new, 1))
                with self.subTest(work_api=old), mock.patch.object(gate.subprocess, 'run') as run:
                    with self.assertRaisesRegex(ValueError, 'not wired'):
                        gate.field_source_codec(root)
                    run.assert_not_called()
            path.write_text(saved)
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
                     'opening::rejects_retained_row_allocation_sizes',
                     'work::tests::matches_reference_capacity_observations',
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
        self.assertEqual(len(opening_docs), 6)
        for line in opening_docs:
            result = subprocess.CompletedProcess([], 0, actual.stdout.replace(line, '', 1), '')
            with mock.patch.object(gate.subprocess, 'run', return_value=result):
                with self.assertRaisesRegex(ValueError, 'missing compile-fail boundary'):
                    gate.field_source_codec(ROOT)
        retained_docs = [line for line in opening_docs if ' - opening::RetainedRow (' in line]
        self.assertEqual(len(retained_docs), 4)
        for output in (
                actual.stdout.replace(retained_docs[0], retained_docs[1], 1),
                actual.stdout.replace(' - opening::RetainedRow (', ' - opening::Unrelated (')):
            result = subprocess.CompletedProcess([], 0, output, '')
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


class RequantFixtureTests(unittest.TestCase):
    def test_accepts_pinned_payloads_and_reconstructed_mutations(self):
        gate.requant_fixtures(ROOT)

    def test_rejects_missing_altered_extra_and_escaping_fixtures(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            suite = root/'tests/negative-controls'
            fixtures = suite/'fixtures/requant'
            shutil.copytree(ROOT/'tests/negative-controls/fixtures/requant', fixtures)
            for name in ('witness_fixtures.py', 'input_padding_fixture.py'):
                (suite/'requant').mkdir(exist_ok=True)
                shutil.copy(ROOT/'tests/negative-controls/requant'/name, suite/'requant'/name)
            gate.requant_fixtures(root)
            for name in ('manifest.json', 'scalar-K4.bin', 'input-padding-K8.json'):
                path = fixtures/name; saved = path.read_bytes(); path.unlink()
                with self.subTest(missing=name), self.assertRaisesRegex(ValueError, 'not wired'):
                    gate.requant_fixtures(root)
                path.write_bytes(saved+b'0')
                with self.subTest(altered=name), self.assertRaisesRegex(ValueError, 'not wired'):
                    gate.requant_fixtures(root)
                path.write_bytes(saved)
            extra = fixtures/'unlisted.bin'; extra.write_bytes(b'0')
            with self.assertRaisesRegex(ValueError, 'inventory'):
                gate.requant_fixtures(root)
            extra.unlink()
            path = fixtures/'scalar-K4.bin'; saved = path.read_bytes(); path.unlink()
            outside = root/'outside.bin'; outside.write_bytes(saved); path.symlink_to(outside)
            with self.assertRaisesRegex(ValueError, 'inventory'):
                gate.requant_fixtures(root)
            path.unlink(); path.write_bytes(saved)
            path = suite/'requant/input_padding_fixture.py'; path.write_bytes(path.read_bytes()+b'\n')
            with self.assertRaisesRegex(ValueError, 'generator'):
                gate.requant_fixtures(root)


class ClosedStackedGateTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        shutil.copytree(ROOT/'crates/stele-reductions', self.root/'crates/stele-reductions')
        oracle = self.root/'tests/negative-controls'
        oracle.mkdir(parents=True)
        for name in ('lookup_corpus.py', 'lookup_corpus.py.lock', 'lookup_closed.py', 'examples/support/lookup_verifier.rs',
                     'matmul_corpus.py', 'matmul_corpus.py.lock', 'examples/matmul_corpus.rs', 'src/matmul.rs', 'src/matmul_composer.rs',
                     'requant_schema.py', 'requant/verifier.rs', 'src/requant.rs', 'src/requant_composer.rs'):
            (oracle/name).parent.mkdir(parents=True, exist_ok=True)
            shutil.copy(ROOT/'tests/negative-controls'/name, oracle/name)
        self.outputs = [
            '\n'.join(f'test pcs_a1::{name} ... ok' for name in (
                'accepts_qm31_closed_originals', 'accepts_om31_closed_originals',
                'rejects_qm31_later_source_and_roster', 'rejects_om31_later_source_and_roster',
                'matches_reference_closed_a1_bytes')),
            'test rejects_unused_original_final ... ok',
            '\n'.join(f'test crates/stele-reductions/src/{module}.rs - {module}::{record} (line {line}) - compile fail ... ok'
                      for module,record,line in [('field_sources','FieldSourceRecord',30),
                          ('stacked_sources','StackedSourceRecord',43),('stacked_sources','StackedSourceRecord',48),
                          ('lookup','Statement',60),('lookup','Descriptor',100)])+'\n'+'\n'.join(
                      f'test crates/stele-reductions/src/lookup_records.rs - lookup::verifier::records::LookupRecord (line {line}) - compile fail ... ok' for line in (61,66,82))+'\n'+'\n'.join(
                      f'test crates/stele-reductions/src/matmul.rs - matmul::Record (line {line}) - compile fail ... ok'
                      for line in (64,69,82))+'\n'+'\n'.join(
                      f'test crates/stele-reductions/src/requant_codec.rs - requant::codec::Descriptor (line {line}) - compile fail ... ok'
                      for line in (35,43))+'\n'+'\n'.join(
                      f'test crates/stele-reductions/src/requant_verifier.rs - requant::codec::verifier::Record (line {line}) - compile fail ... ok'
                      for line in (85,90,103,115,127))+'\n'
                      'test crates/stele-reductions/src/matmul.rs - matmul::Record (line 95) ... ok',
            '\n'.join(f'test {name} ... ok' for name in ('accepts_qm31_certified_stacked_sources',
                'accepts_om31_certified_stacked_sources', 'rejects_qm31_malformed_certified_stacked_sources',
                'rejects_om31_malformed_certified_stacked_sources')),
            '\n'.join(f'test {name} ... ok' for name in ('rejects_wrong_restored_point_at_actual_opening',
                'rejects_substituted_verified_certificate_at_actual_opening')),
            '\n'.join([f'test lookup::sizes_tests::matches_reference_{field}_lookup_sizes ... ok' for field in ('qm31','om31')]
                      + [f'test lookup::functionals::tests::matches_reference_{field}_lookup_prefix_functionals ... ok'
                         for field in ('qm31','om31')]
                      + ['test matmul::producer::rejects_retained_allocation_sizes ... ok',
                         'test matmul::matches_reference_owned_capacities ... ok']
                      + [f'test requant::tests::{n} ... ok' for n in ('matches_reference_complete_schema',
                         'accepts_shared_tail_and_zero_caps','rejects_parameters_reader_and_capacity')]
                      + [f'test requant::constraints::tests::{n} ... ok' for n in ('matches_reference_qm31_constraints',
                         'matches_reference_om31_constraints','rejects_constraint_caps_and_resources')]
                      + [f'test requant::codec::tests::{n} ... ok' for n in ('matches_reference_qm31_codec',
                         'matches_reference_om31_codec','rejects_codec_statement_and_sources')]),
            '\n'.join(f'test {prefix}_{field}_lookup_{suffix} ... ok' for field in ('qm31','om31')
                      for prefix,suffix in (('matches_reference','statement'),('rejects','shape_and_limits'))),
            '\n'.join(f'test {prefix}_{field}_lookup_producer_{suffix} ... ok' for field in ('qm31','om31')
                      for prefix,suffix in (('accepts','registrations'),('rejects','before_mutation'),('rejects','after_registration'))),
            '\n'.join(f'test {prefix}_{field}_closed_lookup{suffix} ... ok' for field in ('qm31','om31')
                      for prefix,suffix in (('accepts',''),('rejects','_tampers')))+'\n'+'\n'.join(
                      f'test rejects_{field}_matmul_preflight ... ok' for field in ('qm31','om31'))+'\n'+'\n'.join(
                      f'test matches_reference_{field}_matmul_producer ... ok' for field in ('qm31','om31')),
            '\n'.join(f'test lookup::accepts_{field}_nonzero_lookup_tail ... ok' for field in ('qm31','om31')),
            '\n'.join(f'test rejects_nc_{i:04} ... ok' for i in (400,401,402,403,415,416,417,418,419,610,802,306,307,606,611,308,309,310,311,312,313,314))+'\n'
                      'test rejects_wrong_coefficient_at_actual_a7 ... ok\n'
                      'test matches_reference_requant_full_wire_qm31 ... ok\n'
                      'test matches_reference_requant_full_wire_om31 ... ok\n'
                      'test rejects_requant_scoped_cqis_bindings ... ok',
            'lookup producer corpus: 8 complete cases; QM31/OM31; bytes, registration, usage, public payloads and continuation; '
            'SHA256 cb8e5b658bbd7f5ed6c917f36605daf33331a7fa46e12eb31d7584c0d76887c9; no lookup verification credit\n'
            'lookup closed corpus: 40 complete cases; QM31/OM31; 8 accepts and 32 rejects; actual records, imports, failure usage and continuation; '
            'SHA256 ce40cdb3b09cf153b6f81a4962abe2e8959c38e05f6d71b149a2f486a1574a41',
            'matmul closed corpus: 2000 seeded cases (1000 per field), 34 honest controls and 34 rejects; '
            'complete wires, actual records, imports, usage and continuation; '
            'SHA256 808a85fc4d0eb81ad193aa2361ec55e0d4c14845d8b15d1b1694884c13603456\n'
            'matmul producer corpus: 2000 native proofs (1000 per field); identical complete wires, '
            'actual closed records, usage, retained visits and continuation',
        ]

    def run_gate(self, outputs=None, failed=None):
        outputs = self.outputs if outputs is None else outputs
        results = [subprocess.CompletedProcess([], int(i == failed), text, '')
                   for i,text in enumerate(outputs)]
        # Payload integrity is exercised separately; receipt permutations do not reread 28 MB.
        with mock.patch.object(gate, 'requant_fixtures'), mock.patch.object(gate.subprocess, 'run', side_effect=results) as run, redirect_stdout(io.StringIO()):
            gate.field_sources(self.root)
        return [call.args[0] for call in run.call_args_list]

    def test_accepts_complete_closed_consumers(self):
        commands = self.run_gate()
        self.assertEqual(len(commands), 13)
        self.assertTrue(all('--locked' in c and '--offline' in c for c in commands[:-2]))
        self.assertEqual(commands[-2], ['uv', 'run', '--python', '3.12', '--locked', '--script',
                                        'tests/negative-controls/lookup_corpus.py'])
        self.assertEqual(commands[-1], ['uv', 'run', '--python', '3.12', '--locked', '--script',
                                       'tests/negative-controls/matmul_corpus.py'])
        self.assertEqual(sum('--doc' in c for c in commands), 1)
        self.assertEqual([c for c in commands if 'stele-reductions' in c and '--lib' in c],
                         [['cargo', 'test', '-p', 'stele-reductions', '--lib', '--locked', '--offline']])
        self.assertEqual([c[i+1] for c in commands for i,arg in enumerate(c) if arg == '--test'],
                         ['nc-0609','stacked','stacked-certified','lookup_codec','lookup_producer','lookup_verifier','matmul','matmul_producer']+
                         [f'nc-{i:04}' for i in (400,401,402,403,415,416,417,418,419,610,802,306,307,606,611,308,309,310,311,312,313,314)]+['requant-verifier'])

    def test_rejects_missing_fixture_manifest_before_execution(self):
        with mock.patch.object(gate.subprocess, 'run') as run:
            with self.assertRaisesRegex(ValueError, 'missing manifest'):
                gate.field_sources(self.root)
            run.assert_not_called()

    def test_rejects_every_failure_and_omitted_receipt(self):
        for i, output in enumerate(self.outputs):
            with self.subTest(failed=i), self.assertRaisesRegex(ValueError, 'checks failed'):
                self.run_gate(failed=i)
            for line in output.splitlines():
                altered=self.outputs.copy(); altered[i]=output.replace(line,'')
                with self.subTest(missing=line), self.assertRaisesRegex(ValueError, 'checks failed'):
                    self.run_gate(altered)
        altered=self.outputs.copy(); altered[2]=altered[2].replace('stacked_sources::StackedSourceRecord','unrelated::Record')
        with self.assertRaisesRegex(ValueError, 'missing StackedSourceRecord boundary'):
            self.run_gate(altered)
        matmul_docs = [line for line in self.outputs[2].splitlines()
                       if ' - matmul::Record (' in line and 'compile fail' in line]
        self.assertEqual(len(matmul_docs), 3)
        for output in (self.outputs[2].replace(matmul_docs[0], matmul_docs[1], 1),
                       self.outputs[2].replace(' - matmul::Record (', ' - unrelated::Record (')):
            altered = self.outputs.copy(); altered[2] = output
            with self.assertRaisesRegex(ValueError, 'missing Record boundary'):
                self.run_gate(altered)
        requant_docs = [line for line in self.outputs[2].splitlines() if ' - requant::codec::Descriptor (' in line]
        self.assertEqual(len(requant_docs), 2)
        for output in (self.outputs[2].replace(requant_docs[0], requant_docs[1], 1),
                       self.outputs[2].replace(' - requant::codec::Descriptor (', ' - unrelated::Descriptor (')):
            altered = self.outputs.copy(); altered[2] = output
            with self.assertRaisesRegex(ValueError, 'missing Descriptor boundary'):
                self.run_gate(altered)
        record_docs = [line for line in self.outputs[2].splitlines() if ' - requant::codec::verifier::Record (' in line]
        self.assertEqual(len(record_docs), 5)
        for output in (self.outputs[2].replace(record_docs[0], record_docs[1], 1),
                       self.outputs[2].replace(' - requant::codec::verifier::Record (', ' - unrelated::Record (')):
            altered = self.outputs.copy(); altered[2] = output
            with self.assertRaisesRegex(ValueError, 'missing Record boundary'):
                self.run_gate(altered)
        for old, new in (('8 complete', '6 complete'), ('QM31/OM31', 'QM31'),
                         ('cb8e5b658', '000000000'), ('ce40cdb3', '00000000'), ('40 complete', '38 complete'),
                         ('8 accepts and 32 rejects', '40 accepts'), ('records,', ''), ('failure usage', 'usage'),
                         ('usage,', ''), ('continuation;', ';')):
            altered = self.outputs.copy(); altered[-2] = altered[-2].replace(old, new)
            with self.subTest(receipt=old), self.assertRaisesRegex(ValueError, 'corpus checks failed'):
                self.run_gate(altered)

        for old, new in (('2000 seeded', '1999 seeded'), ('1000 per field', '999 per field'),
                         ('2000 seeded', '2000 repeated'), ('34 honest controls and ', ''),
                         ('34 honest controls', '33 honest controls'), ('34 rejects', '34 accepts'),
                         ('808a85fc', '00000000'), ('complete wires, ', ''), ('actual records, ', ''),
                         ('imports, ', ''), ('usage and ', ''), ('continuation;', ';')):
            altered = self.outputs.copy()
            self.assertIn(old, altered[-1])
            altered[-1] = altered[-1].replace(old, new)
            with self.subTest(matmul_receipt=old), self.assertRaisesRegex(ValueError, 'matmul corpus checks failed'):
                self.run_gate(altered)
        for old, new in (('2000 native proofs', '1999 native proofs'), ('1000 per field', '999 per field'),
                         ('native proofs', 'reference proofs'), ('identical complete wires, ', ''),
                         ('actual closed records, ', ''), ('usage, ', ''), ('retained visits and ', ''),
                         ('continuation', '')):
            lines = self.outputs[-1].splitlines()
            self.assertEqual(len(lines), 2)
            self.assertIn(old, lines[1])
            lines[1] = lines[1].replace(old, new)
            altered = self.outputs.copy(); altered[-1] = '\n'.join(lines)
            with self.subTest(producer_receipt=old), self.assertRaisesRegex(ValueError, 'matmul corpus checks failed'):
                self.run_gate(altered)
        altered = self.outputs.copy(); altered[-1] = '\n'.join(reversed(altered[-1].splitlines()))
        with self.assertRaisesRegex(ValueError, 'matmul corpus checks failed'):
            self.run_gate(altered)
        altered = self.outputs.copy(); altered[-1] += '\nextra receipt'
        with self.assertRaisesRegex(ValueError, 'matmul corpus checks failed'):
            self.run_gate(altered)

    def test_rejects_missing_lookup_oracle_before_execution(self):
        for name in ('lookup_corpus.py', 'lookup_corpus.py.lock', 'lookup_closed.py', 'examples/support/lookup_verifier.rs',
                     'matmul_corpus.py', 'matmul_corpus.py.lock', 'examples/matmul_corpus.rs', 'src/matmul.rs', 'src/matmul_composer.rs',
                     'requant_schema.py'):
            path = self.root/'tests/negative-controls'/name
            saved = path.read_bytes(); path.unlink()
            with mock.patch.object(gate.subprocess, 'run') as run:
                with self.assertRaisesRegex(ValueError, 'not wired'):
                    gate.field_sources(self.root)
                run.assert_not_called()
            path.write_bytes(saved)

    def test_rejects_unreviewed_api_conversions_and_dependencies(self):
        for name in ('src/requant.rs', 'src/requant_tests.rs', 'tests/fixtures/requant-schema.txt',
                     'src/requant_constraints.rs', 'src/requant_constraint_tests.rs', 'tests/fixtures/requant-constraints.txt',
                     'src/requant_codec.rs', 'src/requant_codec_tests.rs', 'tests/fixtures/requant-codec.txt', 'src/requant_verifier.rs'):
            path = self.root/'crates/stele-reductions'/name
            saved = path.read_bytes(); path.unlink()
            with mock.patch.object(gate.subprocess, 'run') as run:
                with self.assertRaisesRegex(ValueError, 'not wired'):
                    gate.field_sources(self.root)
                run.assert_not_called()
            path.write_bytes(saved)
        for name, addition in (
            ('src/requant_verifier.rs',"\nimpl<K: ChallengeField> Record<'_, K> { pub fn from_digest(_: [u8; 32]) -> Self { todo!() } }\n"),
            ('src/requant_verifier.rs',"\nimpl<K: ChallengeField> From<bool> for Record<'_, K> {}\n"),
            ('src/requant_verifier.rs','\ninclude!("unchecked.rs");\n'),
            ('src/requant.rs','\npub fn verify() {}\n'),
            ('src/requant.rs','\nimpl From<bool> for Schema {}\n'),
            ('src/requant.rs','\ninclude!("unchecked.rs");\n'),
            ('src/requant_constraints.rs','\npub fn from_terms() {}\n'),
            ('src/requant_constraints.rs','\nimpl<K> From<Vec<Term<K>>> for Constraints<K> {}\n'),
            ('src/requant_constraints.rs','\ninclude!("unchecked.rs");\n'),
            ('src/requant_codec.rs','\npub fn from_terms() {}\n'),
            ('src/requant_codec.rs','\nimpl From<bool> for Descriptor {}\n'),
            ('src/requant_codec.rs','\ninclude!("unchecked.rs");\n'),
            ('src/matmul.rs','\npub fn prove() {}\n'),
            ('src/matmul.rs',"\nimpl<K: ChallengeField> Record<'_, K> { pub fn from_digest(_: [u8; 32]) -> Self { todo!() } }\n"),
            ('src/matmul.rs',"\nimpl<K: ChallengeField> From<bool> for Record<'_, K> { fn from(_: bool) -> Self { todo!() } }\n"),
            ('src/matmul.rs','\ninclude!("unchecked.rs");\n'),
            ('src/matmul.rs','\nimpl From<VerifierWork> for bool { fn from(_: VerifierWork) -> bool { true } }\n'),
            ('src/matmul_producer.rs','\npub fn from_digest() {}\n'),
            ('src/matmul_producer.rs','\nimpl From<Work> for bool { fn from(_: Work) -> bool { true } }\n'),
            ('src/matmul_producer.rs','\ninclude!("unchecked.rs");\n'),
            ('src/stacked_sources.rs','\npub fn accept_unchecked() {}\n'),
            ('src/stacked_sources.rs','\nimpl<K> From<Proof<K>> for StackedSourceRecord<\'_,K> {}\n'),
            ('src/stacked_sources.rs','\ninclude!("unchecked.rs");\n'),
            ('src/lookup.rs','\npub fn verify_lookup_unchecked() {}\n'),
            ('src/lookup.rs','\nimpl From<bool> for Descriptor { fn from(_: bool) -> Self { todo!() } }\n'),
            ('src/lookup.rs','\ninclude!("unchecked.rs");\n'),
            ('src/lookup_producer.rs','\npub fn verify_unchecked() {}\n'),
            ('src/lookup_producer.rs','\nimpl From<bool> for ProverUsage {}\n'),
            ('src/lookup_producer.rs','\ninclude!("unchecked.rs");\n'),
            ('src/lookup_verifier.rs','\npub fn verify_unchecked() {}\n'),
            ('src/lookup_records.rs','\nimpl From<bool> for LookupRecord {}\n'),
            ('src/lookup_records.rs','\npub fn from_digest() {}\n'),
            ('src/lookup_records.rs','\ninclude!("unchecked.rs");\n'),
            ('src/lookup_resources.rs','\npub(super) fn accept_unchecked() {}\n'),
            ('src/lookup_work.rs','\npub fn verify_unchecked() {}\n'),
            ('src/lookup_work.rs','\nimpl From<ProverWork> for bool { fn from(_: ProverWork) -> bool { true } }\n'),
            ('src/lookup_functionals.rs','\npub fn verify_unchecked() {}\n'),
            ('src/lookup_functionals.rs','\nimpl From<bool> for Piece<bool> {}\n'),
            ('src/lookup_functionals.rs','\nmacro_rules! unchecked { () => {} }\n'),
            ('Cargo.toml','\n[features]\nunwired = []\n'),
        ):
            path=self.root/'crates/stele-reductions'/name; saved=path.read_text()
            path.write_text(saved+addition)
            with self.subTest(addition=addition), mock.patch.object(gate.subprocess,'run') as run:
                with self.assertRaisesRegex(ValueError,'not wired'):
                    gate.field_sources(self.root)
                run.assert_not_called()
            path.write_text(saved)
        path = self.root/'crates/stele-reductions/src/matmul.rs'; saved = path.read_text()
        for old, new in (('    sc: ScRecord,', '    pub sc: ScRecord,'),
                         ('pub fn values(&self) -> &[K; 2]', 'pub fn values(&mut self) -> &mut [K; 2]')):
            self.assertIn(old, saved)
            path.write_text(saved.replace(old, new, 1))
            with mock.patch.object(gate.subprocess, 'run') as run:
                with self.assertRaisesRegex(ValueError, 'not wired'):
                    gate.field_sources(self.root)
                run.assert_not_called()
            path.write_text(saved)
        for name, old, new in (
            ('requant_verifier.rs', '    phase: u8,', '    pub phase: u8,'),
            ('requant_verifier.rs', '    point: Vec<K>,', '    pub point: Vec<K>,'),
            ('requant_verifier.rs', "    lookups: [LookupRecord<'cert, K>; 2],", "    pub lookups: [LookupRecord<'cert, K>; 2],"),
            ('requant_verifier.rs', 'pub fn weights(&self) -> &[K]', 'pub fn weights(&mut self) -> &mut [K]'),
            ('requant_verifier.rs', "Result<(Record<'cert, K>, Usage), Failure>", "Result<(Record<'static, K>, Usage), Failure>"),
            ('requant_verifier.rs', "multiplicities: [&[&'cert VerifiedCertificate<K>]; 2]", "multiplicities: [&[&'static VerifiedCertificate<K>]; 2]"),
            ('requant_verifier.rs', "'original: 'cert,", "'cert: 'original,"),
            ('requant.rs', 'pub use stele_cqis::Format;', 'pub use stele_cqis::*;'),
            ('lookup.rs', 'pub(crate) fn registration_bytes', 'pub fn registration_bytes'),
            ('requant.rs', '    cap: u64,', '    pub cap: u64,'),
            ('requant.rs', 'pub fn values(&self) -> &[Block]', 'pub fn values(&mut self) -> &mut [Block]'),
            ('requant.rs', 'mantissa: u32, shift: u32, format: Format', 'record: bounds::Record'),
            ('requant.rs', 'cap: u64,', 'cap: u32,'),
            ('requant.rs', 'pub use constraints::Constraints;', 'pub use constraints::*;'),
            ('requant_constraints.rs', '    equations: Vec<Vec<Term<K>>>,', '    pub equations: Vec<Vec<Term<K>>>,'),
            ('requant_constraints.rs', 'pub fn equations(&self) -> &[Vec<Term<K>>]', 'pub fn equations(&mut self) -> &mut [Vec<Term<K>>]'),
            ('requant_constraints.rs', 'constraints<K: ChallengeField>', 'constraints<K: stele_field::Field>'),
            ('requant_codec.rs', '    output: Instance<K>,', '    pub output: Instance<K>,'),
            ('requant_codec.rs', "pub schema: &'a Schema,", 'pub schema: bounds::Record,'),
            ('requant_codec.rs', "pub input: &'cert VerifiedCertificate<K>,", 'pub input: Source<K>,'),
            ('requant_codec.rs', "advice: &'cert VerifiedCertificate<K>,", 'advice: Source<K>,'),
            ('requant_codec.rs', "pub point: &'a [K],", "pub point: &'a mut [K],"),
            ('requant_codec.rs', "K: ChallengeField> Descriptor", "K: stele_field::Field> Descriptor"),
            ('requant_codec.rs', 'pub fn preflight(&self, bytes: &[u8])', 'pub fn preflight(&mut self, bytes: &[u8])'),
            ('matmul.rs', 'mod producer;', 'pub mod producer;'),
            ('matmul.rs', 'pub use producer::{prove, prove_measured, Work};', 'pub use producer::*;'),
            ('matmul.rs', 'pub context_bytes: usize,', 'pub context_bytes: ScRecord,'),
            ('matmul.rs', 'pub a1: stele_sumcheck::VerifierWork,', 'pub a1: ScRecord,'),
            ('matmul.rs', 'pub openings: [stele_pcs::VerifierWork; 2],', 'pub openings: [stele_pcs::VerifierWork; 1],'),
            ('matmul.rs', 'pub restored_points_bytes: [usize; 2],', 'pub restored_points_bytes: usize,'),
            ('matmul.rs', 'pub fn verify_measured', 'pub fn from_work'),
            ('matmul.rs', "Result<(Record<'cert, K>, Usage, VerifierWork), Failure>", "Result<(Record<'static, K>, Usage, VerifierWork), Failure>"),
            ('matmul.rs', 'fn proof_bytes<K>', 'pub fn proof_bytes<K>'),
            ('matmul_producer.rs', 'pub proof_bytes: usize,', 'pub proof_bytes: ScRecord,'),
            ('matmul_producer.rs', 'pub a1: stele_sumcheck::ProverWork,', 'pub a1: ScRecord,'),
            ('matmul_producer.rs', 'pub openings: [stele_pcs::ProverWork; 2],', 'pub openings: [stele_pcs::ProverWork; 1],'),
            ('matmul_producer.rs', 'pub dense: stacked::Work,', 'pub dense: stele_sumcheck::ScRecord,'),
            ('matmul_producer.rs', 'pub retained_rows: [RetainedRowWork; 2],', 'pub retained_rows: [RetainedRowWork; 1],'),
            ('matmul_producer.rs', "sources: [&PreparedSource<'_, K>; 2]", "sources: [PreparedSource<'_, K>; 2]"),
            ('matmul_producer.rs', 'certificates: [&VerifiedCertificate<K>; 2]', 'certificates: [VerifiedCertificate<K>; 2]'),
            ('matmul_producer.rs', 'retained_row_entries: usize', 'retained_row_entries: &mut usize'),
        ):
            path = self.root/'crates/stele-reductions/src'/name; saved = path.read_text()
            self.assertIn(old, saved)
            path.write_text(saved.replace(old, new, 1))
            with self.subTest(producer_api=old), mock.patch.object(gate.subprocess, 'run') as run:
                with self.assertRaisesRegex(ValueError, 'not wired'):
                    gate.field_sources(self.root)
                run.assert_not_called()
            path.write_text(saved)
        for name in ('lookup_resources.rs', 'lookup_functionals.rs', 'lookup_records.rs'):
            path = self.root/'crates/stele-reductions/src'/name; saved = path.read_text()
            for visibility in ('pub', 'pub(crate)'):
                path.write_text(saved.replace('pub(super)', visibility))
                with mock.patch.object(gate.subprocess, 'run') as run:
                    with self.assertRaisesRegex(ValueError, 'not wired'):
                        gate.field_sources(self.root)
                    run.assert_not_called()
            path.write_text(saved)
        for name in ('src/stacked_sources.rs', 'src/matmul_producer.rs', 'tests/matmul_producer.rs'):
            path = self.root/'crates/stele-reductions'/name; saved = path.read_bytes(); path.unlink()
            with self.subTest(missing=name), mock.patch.object(gate.subprocess,'run') as run:
                with self.assertRaises((ValueError,FileNotFoundError)):
                    gate.field_sources(self.root)
                run.assert_not_called()
            path.write_bytes(saved)


if __name__ == '__main__':
    unittest.main()
