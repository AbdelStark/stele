"""RFC-0020 §5: real gate entry points must reject synthetic violations."""
import json
import pathlib
import shutil
import subprocess
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[2]


class GateTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = pathlib.Path(self.directory.name)
        for name in ('.github', 'scripts', 'crates', 'docs', 'tests', 'bench',
                     'agents', 'research', 'formal'):
            shutil.copytree(ROOT / name, self.root / name)
        for name in ('README.md', 'Cargo.toml', 'Cargo.lock'):
            shutil.copy(ROOT / name, self.root / name)

    def run_gate(self, gate):
        return subprocess.run(['bash', str(self.root / 'scripts/gates' / f'{gate}.sh')],
                              cwd='/', text=True, capture_output=True)

    def test_rejects_unvalidated_implementation(self):
        for gate, crate in [('digest', 'prover'), ('negative-controls', 'gkr'),
                            ('soundness-accounting', 'gkr'), ('parity', 'gpu')]:
            with self.subTest(gate=gate):
                source = self.root / f'crates/stele-{crate}/src/lib.rs'
                original = source.read_text()
                source.write_text(original + '\npub fn unvalidated() {}\n')
                result = self.run_gate(gate)
                source.write_text(original)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn('not wired', result.stderr)

    def test_rejects_unvalidated_a1_adapter_and_missing_parity(self):
        source = self.root / 'crates/stele-reductions/src/lib.rs'
        original = source.read_text()
        source.write_text(original + '\npub fn unvalidated() {}\n')
        result = self.run_gate('soundness-accounting')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('reductions API not wired', result.stderr)
        source.write_text(original)
        tests = self.root / 'tests/negative-controls/src/pcs_a1.rs'
        tests.write_text(tests.read_text().replace('fn matches_reference_closed_a1_bytes()', 'fn omitted_parity()'))
        result = self.run_gate('soundness-accounting')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('closed A1 consumer checks failed', result.stderr)

    def test_rejects_public_coefficient_drift_and_missing_field_check(self):
        extra = self.root / 'crates/stele-gkr/src/stage.rs'
        extra.write_text('pub fn unvalidated() {}')
        result = self.run_gate('soundness-accounting')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('not wired', result.stderr)
        extra.unlink()
        manifest = self.root / 'crates/stele-gkr/Cargo.toml'
        original_manifest = manifest.read_text()
        manifest.write_text(original_manifest + '\n[dev-dependencies]\nstele-hash = { path = "../stele-hash" }\n')
        result = self.run_gate('negative-controls')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('not wired', result.stderr)
        manifest.write_text(original_manifest)
        source = self.root / 'crates/stele-gkr/src/public_mle.rs'
        original = source.read_text()
        source.write_text(original.replace('state[0]', 'state[1]'))
        result = self.run_gate('soundness-accounting')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('public coefficient arithmetic checks failed', result.stderr)
        source.write_text(original)
        tests = self.root / 'crates/stele-gkr/tests/public_mle.rs'
        tests.write_text(tests.read_text().replace('fn matches_reference_om31_all_kinds()', 'fn omitted_field_check()'))
        result = self.run_gate('soundness-accounting')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('public coefficient arithmetic checks failed', result.stderr)

    def test_rejects_native_digest_drift_and_missing_test(self):
        vectors = self.root / 'crates/stele-code/tests/encoder-vectors.txt'
        original = vectors.read_bytes()
        vectors.write_bytes(original[:-2]+b'!\n')
        result = self.run_gate('digest')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('reference digests drift', result.stderr)
        vectors.write_bytes(original)
        source = self.root / 'crates/stele-code/tests/encoder.rs'
        original = source.read_text()
        name = 'matches_reference_materialized_codeword_digests'
        self.assertIn(name, original)
        source.write_text(original.replace(name, 'omitted_reference_test'))
        result = self.run_gate('digest')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('native encoder gate failed', result.stderr)
        source.write_text(original)
        source = self.root / 'research/code-provenance/check_native.py'
        original = source.read_text()
        self.assertIn('        check()', original)
        source.write_text(original.replace('        check()', '        pass'))
        result = self.run_gate('digest')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('native encoder gate failed', result.stderr)

    def test_rejects_unwired_fraction_engine_codec_drift_and_missing_field(self):
        extra = self.root / 'crates/stele-lookup/src/engine.rs'
        extra.write_text('pub fn unvalidated() {}')
        result = self.run_gate('soundness-accounting')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('not wired', result.stderr)
        extra.unlink()
        fixture = self.root / 'crates/stele-lookup/tests/fixtures/fraction-codec.jsonl'
        original = fixture.read_text()
        records = [json.loads(line) for line in original.splitlines()]
        record = records[0]
        record['payload_hex'] = ('00' if record['payload_hex'][:2] != '00' else '01') + record['payload_hex'][2:]
        fixture.write_text(''.join(json.dumps(row)+'\n' for row in records))
        result = self.run_gate('negative-controls')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('fraction codec checks failed', result.stderr)
        fixture.write_text(original)
        records = [json.loads(line) for line in original.splitlines()]
        record = records[0]
        record['unexpected_reference_metadata'] = 1
        fixture.write_text(''.join(json.dumps(row)+'\n' for row in records))
        result = self.run_gate('soundness-accounting')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('fraction codec reference drift', result.stderr)
        fixture.write_text(original)
        tests = self.root / 'crates/stele-lookup/tests/codec.rs'
        tests.write_text(tests.read_text().replace('fn matches_reference_om31_fraction_codec()', 'fn omitted_field_check()'))
        result = self.run_gate('soundness-accounting')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('fraction codec checks failed', result.stderr)

    def test_rejects_selected_product_codec_reference_drift(self):
        fixture = self.root / 'crates/stele-lookup/tests/fixtures/leaf-codec.jsonl'
        rows = [json.loads(line) for line in fixture.read_text().splitlines()]
        rows[0]['unexpected_reference_metadata'] = 1
        fixture.write_text(''.join(json.dumps(row)+'\n' for row in rows))
        result = self.run_gate('soundness-accounting')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('selected-product codec reference drift', result.stderr)

    def test_rejects_selected_product_original_consumer_bypass(self):
        source = self.root / 'crates/stele-lookup/src/selected.rs'
        original = source.read_text()
        self.assertIn('if actual != *expected {', original)
        source.write_text(original.replace('if actual != *expected {', 'if false {'))
        result = self.run_gate('negative-controls')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('fraction corpus decisions/claims/accounting/continuation mismatch',
                      result.stdout + result.stderr)
        # The corpus now detects this mutation before the gate reaches catalog
        # controls. Still exercise the real controls and require their reason.
        result = subprocess.run(['cargo','run','-q','-p','stele-negative-controls',
                                 '--bin','stele-controls','--locked','--offline','--','--coverage'],
                                cwd=self.root,text=True,capture_output=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('NC-0410', result.stdout + result.stderr)
        self.assertIn('TamperAccepted', result.stdout + result.stderr)

    def test_rejects_fraction_transcript_control_omission(self):
        source = self.root / 'tests/negative-controls/src/fraction_transcript.rs'
        original = source.read_text()
        self.assertIn('fn rejects_fraction_missing_final_continuations()', original)
        source.write_text(original.replace('fn rejects_fraction_missing_final_continuations()',
                                          'fn omitted_fraction_continuation_check()'))
        result = self.run_gate('soundness-accounting')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('fraction transcript controls failed', result.stderr)

    def test_rejects_fraction_corpus_drift_and_accounting_omission(self):
        corpus = self.root / 'research/logup-characteristic/corpus.jsonl'
        original = corpus.read_text()
        corpus.write_text('\n'.join(original.splitlines()[:-1])+'\n')
        result = self.run_gate('soundness-accounting')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('fraction corpus regeneration mismatch', result.stderr)
        corpus.write_text(original)
        adapter = self.root / 'crates/stele-lookup/examples/fraction_corpus.rs'
        source = adapter.read_text()
        self.assertIn('"fold":a.fold', source)
        adapter.write_text(source.replace('"fold":a.fold', '"fold":0'))
        result = self.run_gate('soundness-accounting')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('fraction corpus decisions/claims/accounting/continuation mismatch', result.stderr)

    def test_rejects_fraction_benchmark_consumer_test_omission(self):
        source = self.root / 'crates/stele-lookup/examples/fraction_bench.rs'
        original = source.read_text()
        self.assertIn('fn accepts_fraction_benchmark_original_consumers()', original)
        source.write_text(original.replace('fn accepts_fraction_benchmark_original_consumers()',
                                          'fn omitted_benchmark_consumer_check()'))
        result = self.run_gate('soundness-accounting')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('fraction benchmark pipeline failed', result.stderr)

    def test_rejects_external_field_seal_removal(self):
        source = self.root / 'crates/stele-code/src/encoder.rs'
        original = source.read_text()
        before = 'CodeField: Field + private::SealedField'
        self.assertIn(before, original)
        source.write_text(original.replace(before, 'CodeField: Field'))
        result = self.run_gate('digest')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('Test compiled successfully, but it\'s marked `compile_fail`', result.stderr)

    def test_rejects_native_query_order_drift(self):
        source = self.root / 'crates/stele-code/examples/encoder_corpus.rs'
        original = source.read_text()
        before = 'word.into_iter().chain(selected)'
        self.assertIn(before, original)
        source.write_text(original.replace(before, 'word.into_iter().chain(selected.into_iter().rev())'))
        result = self.run_gate('digest')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('native corpus byte mismatch', result.stderr)

    def test_rejects_native_measurement_overlap_omission(self):
        source = self.root / 'crates/stele-code/src/measurement.rs'
        original = source.read_text()
        before = 'self.work.peak_owned_bytes.max(self.live)'
        self.assertIn(before, original)
        source.write_text(original.replace(before, 'self.work.peak_owned_bytes.max(bytes(&values))'))
        result = self.run_gate('digest')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('native encoder gate failed', result.stderr)
        self.assertIn('matches_reference_complete_work_and_capacity_all_fields', result.stderr)

    def test_rejects_registry_mapping_drift_and_invalid_production_registry(self):
        inventory = self.root / 'docs/security/transcript-labels.json'
        original = inventory.read_text()
        rows = json.loads(original)
        rows[-1][-1] = 'LU'
        inventory.write_text(json.dumps(rows))
        result = self.run_gate('soundness-accounting')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('registry mapping mismatch', result.stderr)
        inventory.write_text(original)
        source = self.root / 'crates/stele-hash/src/lib.rs'
        source.write_text(source.read_text().replace('loss: Some(LossLine::Sc)', 'loss: None'))
        result = self.run_gate('negative-controls')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('registry producer failed', result.stderr)

    def test_rejects_sumcheck_accounting_drift(self):
        source = self.root / 'crates/stele-sumcheck/src/lib.rs'
        original = source.read_text()
        for before, after in [
            ('numerator: u64::from(i.num_vars) * degree as u64',
             'numerator: u64::from(i.num_vars) * degree as u64 + 1'),
            ('AbsorbLabel::Final', 'AbsorbLabel::Round'),
        ]:
            changed = original.replace(before, after, 1)
            self.assertNotEqual(original, changed)
            source.write_text(changed)
            result = self.run_gate('soundness-accounting')
            self.assertNotEqual(result.returncode, 0)
            self.assertIn('sumcheck corpus decisions/accounting mismatch', result.stderr)

    def test_rejects_zerocheck_accounting_final_absorb_and_consumer_drift(self):
        source = self.root / 'crates/stele-sumcheck/src/zerocheck.rs'
        original = source.read_text()
        for before, after in [
            ('numerator: u64::from(m) * degree as u64', 'numerator: u64::from(m) * degree as u64 + 1'),
            ('AbsorbLabel::ZeroFinal', 'AbsorbLabel::Final'),
            ('if dot(table, &weights) != claim.value', 'if false'),
        ]:
            self.assertIn(before, original)
            source.write_text(original.replace(before, after, 1))
            result = self.run_gate('soundness-accounting')
            self.assertNotEqual(result.returncode, 0)
            self.assertIn('zerocheck bytes/claims/accounting/control mismatch', result.stderr)
        source.write_text(original)

    def test_rejects_missing_zerocheck_reference_check(self):
        source = self.root / 'crates/stele-sumcheck/tests/zerocheck_reference.rs'
        original = source.read_text()
        self.assertIn('fn matches_reference_naive_zerocheck_om31()', original)
        source.write_text(original.replace('fn matches_reference_naive_zerocheck_om31()', 'fn omitted_reference_check()'))
        result = self.run_gate('soundness-accounting')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('zerocheck bytes/claims/accounting/control mismatch', result.stderr)

    def test_rejects_missing_small_field_check(self):
        source = self.root / 'crates/stele-sumcheck/tests/small.rs'
        original = source.read_text()
        self.assertIn('fn matches_reference_small_om31()', original)
        source.write_text(original.replace('fn matches_reference_small_om31()', 'fn omitted_small_check()'))
        result = self.run_gate('soundness-accounting')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('small strategy parity/control mismatch', result.stderr)

    def test_rejects_missing_small_reference_check(self):
        source = self.root / 'crates/stele-sumcheck/tests/small_reference.rs'
        original = source.read_text()
        self.assertIn('fn matches_reference_naive_small_om31()', original)
        source.write_text(original.replace('fn matches_reference_naive_small_om31()', 'fn omitted_small_reference_check()'))
        result = self.run_gate('soundness-accounting')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('small strategy parity/control mismatch', result.stderr)

    def test_rejects_streaming_corpus_drift_and_source_bypass(self):
        corpus = self.root / 'research/streaming/corpus.jsonl'
        original = corpus.read_text()
        rows = [json.loads(line) for line in original.splitlines()]
        rows[0]['expected'] = 'ClaimMismatch'
        corpus.write_text('\n'.join(json.dumps(row) for row in rows)+'\n')
        result = self.run_gate('soundness-accounting')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('streaming corpus drift or adapter failure', result.stderr)
        corpus.write_text(original)
        source = self.root / 'crates/stele-sumcheck/examples/corpus.rs'
        original = source.read_text()
        self.assertIn('record.get("streaming")', original)
        source.write_text(original.replace('record.get("streaming")', 'record.get("omitted_streaming")'))
        result = self.run_gate('soundness-accounting')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('streaming corpus drift or adapter failure', result.stderr)

    def test_rejects_file_overwrite_and_missing_control(self):
        source = self.root / 'crates/stele-sumcheck/src/file.rs'
        original = source.read_text()
        self.assertIn('.create_new(true)', original)
        source.write_text(original.replace('.create_new(true)', '.create(true)'))
        result = self.run_gate('soundness-accounting')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('streaming file/control mismatch', result.stderr)
        source.write_text(original)
        source = self.root / 'tests/negative-controls/sumcheck/nc_0210.rs'
        source.write_text(source.read_text().replace('fn rejects_nc_0210()', 'fn omitted_nc_0210()'))
        result = self.run_gate('soundness-accounting')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('streaming file/control mismatch', result.stderr)

    def test_rejects_streaming_wrong_tail_order(self):
        source = self.root / 'crates/stele-sumcheck/src/streaming.rs'
        original = source.read_text()
        self.assertIn('reverse(block, suffix)', original)
        source.write_text(original.replace('reverse(block, suffix)', 'block'))
        result = self.run_gate('soundness-accounting')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('streaming A1 source/arena mismatch', result.stderr)

    def test_rejects_buffered_padding_and_missing_field_check(self):
        source = self.root / 'crates/stele-sumcheck/src/buffers.rs'
        original = source.read_text()
        self.assertIn('AbsorbLabel::Instance, &bytes[..size]', original)
        source.write_text(original.replace('AbsorbLabel::Instance, &bytes[..size]',
                                           'AbsorbLabel::Instance, bytes', 1))
        result = self.run_gate('soundness-accounting')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('buffered A1 parity/consumer mismatch', result.stderr)
        source.write_text(original)
        source = self.root / 'crates/stele-sumcheck/tests/buffers.rs'
        original = source.read_text()
        self.assertIn('fn matches_reference_buffered_om31()', original)
        source.write_text(original.replace('fn matches_reference_buffered_om31()', 'fn omitted_buffered_check()'))
        result = self.run_gate('soundness-accounting')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('buffered A1 parity/consumer mismatch', result.stderr)

    def test_rejects_small_corpus_drift_and_prover_mismatch(self):
        corpus = self.root / 'research/small-value/corpus.jsonl'
        original = corpus.read_text()
        rows = [json.loads(line) for line in original.splitlines()]
        rows[0]['expected'] = 'ClaimMismatch'
        corpus.write_text(''.join(json.dumps(row)+'\n' for row in rows))
        result = self.run_gate('soundness-accounting')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('small corpus drift', result.stderr)
        corpus.write_text(original)
        source = self.root / 'crates/stele-sumcheck/examples/corpus.rs'
        original = source.read_text()
        self.assertIn('Small::new(&i, source, k)', original)
        source.write_text(original.replace('Small::new(&i, source, k)', 'Small::new(&i, source, k + 4)'))
        result = self.run_gate('soundness-accounting')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('sumcheck corpus decisions/accounting mismatch', result.stderr)
        source.write_text(original.replace('receipt.claims.into_iter()', 'receipt.claims.into_iter().take(0)'))
        result = self.run_gate('soundness-accounting')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('sumcheck corpus decisions/accounting mismatch', result.stderr)

    def test_rejects_zerocheck_corpus_drift_and_receipts(self):
        corpus = self.root / 'research/zerocheck/corpus.jsonl'
        original = corpus.read_text()
        rows = [json.loads(line) for line in original.splitlines()]
        rows[0]['expected'] = 'ClaimMismatch'
        corpus.write_text(''.join(json.dumps(row)+'\n' for row in rows))
        result = self.run_gate('soundness-accounting')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('zerocheck corpus drift', result.stderr)
        corpus.write_text(original)
        source = self.root / 'crates/stele-sumcheck/examples/zero_corpus.rs'
        original = source.read_text()
        for before, after in [('"numerator":r.numerator', '"numerator":r.numerator + 1'),
                              ('result.claims.into_iter()', 'result.claims.into_iter().take(0)')]:
            self.assertIn(before, original)
            source.write_text(original.replace(before, after, 1))
            result = self.run_gate('soundness-accounting')
            self.assertNotEqual(result.returncode, 0)
            self.assertIn('zerocheck corpus decisions/claims/accounting mismatch', result.stderr)
        source.write_text(original)

    def test_rejects_batch_rlc_accounting_drift(self):
        source = self.root / 'crates/stele-sumcheck/src/batch.rs'
        old = source.read_text()
        self.assertIn('numerator: self.instances.len() as u64', old)
        source.write_text(old.replace('numerator: self.instances.len() as u64', 'numerator: 0'))
        result = self.run_gate('soundness-accounting')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('batch instance checks failed', result.stderr)

    def test_rejects_batch_corpus_drift_and_accounting(self):
        corpus = self.root / 'research/batching/corpus.jsonl'
        original = corpus.read_text()
        rows = [json.loads(line) for line in original.splitlines()]
        rows[0]['expected'] = 'ClaimMismatch'
        corpus.write_text(''.join(json.dumps(row)+'\n' for row in rows))
        result = self.run_gate('soundness-accounting')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('batch corpus drift', result.stderr)
        corpus.write_text(original)
        source = self.root / 'crates/stele-sumcheck/examples/batch_corpus.rs'
        old = source.read_text()
        self.assertIn('"numerator":result.rlc.numerator', old)
        source.write_text(old.replace('"numerator":result.rlc.numerator', '"numerator":result.rlc.numerator + 1'))
        result = self.run_gate('soundness-accounting')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('batch corpus decisions/obligations/accounting mismatch', result.stderr)

    def test_rejects_claim_coefficient_and_consumer_bypasses(self):
        source = self.root / 'crates/stele-sumcheck/src/claim_batch.rs'
        original = source.read_text()
        for before, after, error in [
            ('*target = *target + weight * value;', '*target = weight * value;', 'RoundSumMismatch'),
            ('if actual != result.claims[0].value', 'if false && actual != result.claims[0].value', 'TamperAccepted'),
        ]:
            self.assertIn(before, original)
            source.write_text(original.replace(before, after))
            result = self.run_gate('soundness-accounting')
            self.assertNotEqual(result.returncode, 0)
            self.assertIn('batch instance checks failed', result.stderr)
            self.assertIn(error, result.stderr)
        source.write_text(original)

    def test_rejects_merkle_binding_and_batch_bypasses(self):
        source = self.root / 'crates/stele-hash/src/merkle.rs'
        original = source.read_text()
        for before, after in [
            ('if current == *root {', 'if true || current == *root {'),
            ('spec.authenticate(root, index, opening)?;', 'let _ = (root, index, opening);'),
        ]:
            changed = original.replace(before, after, 1)
            self.assertNotEqual(original, changed)
            source.write_text(changed)
            result = self.run_gate('negative-controls')
            self.assertNotEqual(result.returncode, 0)
            self.assertIn('Merkle authentication/vector checks failed', result.stderr)

    def test_rejects_poseidon2_constant_drift(self):
        source = self.root / 'crates/stele-hash/src/poseidon2/constants.rs'
        original = source.read_text()
        changed = original.replace('0x768bab52', '0x768bab53', 1)
        self.assertNotEqual(original, changed)
        source.write_text(changed)
        result = self.run_gate('soundness-accounting')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('transcript primitive tests failed', result.stderr)

    def test_rejects_deleted_or_additional_source(self):
        source = self.root / 'crates/stele-prover/src/lib.rs'
        source.unlink()
        self.assertNotEqual(self.run_gate('digest').returncode, 0)
        source.write_bytes((ROOT / 'crates/stele-prover/src/lib.rs').read_bytes())
        (source.parent / 'unchecked.rs').write_text('pub fn unvalidated() {}')
        self.assertNotEqual(self.run_gate('digest').returncode, 0)

    def test_rejects_unvalidated_artifacts(self):
        for gate, path in [('ledger-validate', 'bench/ledger/invalid.json'),
                           ('digest', 'tests/digests/unvalidated.bin'),
                           ('negative-controls', 'tests/negative-controls/unchecked.rs')]:
            with self.subTest(gate=gate):
                file = self.root / path
                file.parent.mkdir(parents=True, exist_ok=True)
                file.write_text('{}')
                result = self.run_gate(gate)
                file.unlink()
                self.assertNotEqual(result.returncode, 0)
                expected = 'missing or unknown fields' if gate == 'ledger-validate' else 'not wired'
                self.assertIn(expected, result.stderr)

    def test_accepts_ledger_and_rejects_disabled_bindings_through_gate(self):
        fixture = (self.root / 'crates/stele-bench/tests/fixtures/valid.json').read_text()
        ledger = self.root / 'bench/ledger/fixture.json'
        ledger.parent.mkdir(parents=True, exist_ok=True)
        ledger.write_text(fixture)
        result = self.run_gate('ledger-validate')
        self.assertEqual(result.returncode, 0, result.stderr)
        ledger.write_text(fixture.replace('"bindings_all_on": true', '"bindings_all_on": false'))
        result = self.run_gate('ledger-validate')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('bindings_all_on must be true', result.stderr)

    def test_rejects_draft_research_missing_and_duplicate_rfc(self):
        file = self.root / 'crates/stele-field/src/lib.rs'
        original = file.read_text()
        for reference in ('9999', '0019', '9998'):
            with self.subTest(reference=reference):
                if reference == '9998':
                    (self.root / 'docs/rfcs/RFC-9998-draft.md').write_text('Status: Draft\n')
                file.write_text(original + f'\n// RFC-{reference}\n')
                self.assertNotEqual(self.run_gate('rfc-status').returncode, 0)
        file.write_text(original)
        harness = self.root / 'tests/negative-controls/src/lib.rs'
        harness_source = harness.read_text()
        harness.write_text(harness_source + '\n// RFC-9998\n')
        self.assertNotEqual(self.run_gate('rfc-status').returncode, 0)
        harness.write_text(harness_source)
        (self.root / 'docs/rfcs/RFC-0003-duplicate.md').write_text('Status: Accepted\n')
        self.assertNotEqual(self.run_gate('rfc-status').returncode, 0)

    def test_rejects_catalog_claiming_unexecuted_coverage(self):
        catalog = self.root / 'tests/negative-controls/catalog.md'
        catalog.write_text(catalog.read_text().replace('| todo |', '| done |', 1))
        result = self.run_gate('negative-controls')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('done without an executable control', result.stdout + result.stderr)

    def test_rejects_broken_local_doc_link(self):
        file = self.root / 'README.md'
        file.write_text('[broken](docs/missing.md)\n')
        self.assertNotEqual(self.run_gate('docs-links').returncode, 0)
        file.write_text('[valid](docs/prd.md#goals)\n[remote](https://example.org)\n')
        self.assertEqual(self.run_gate('docs-links').returncode, 0)

    def test_rejects_missing_workflow_link_target(self):
        (self.root / 'README.md').write_text('[workflow](.github/workflows/ci.yml)\n')
        result = self.run_gate('docs-links')
        self.assertEqual(result.returncode, 0, result.stderr)
        (self.root / '.github/workflows/ci.yml').unlink()
        result = self.run_gate('docs-links')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('broken local link .github/workflows/ci.yml', result.stderr)


if __name__ == '__main__':
    unittest.main()
