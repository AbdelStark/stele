"""RFC-0010 A9 §6: incomplete measured consumer receipts cannot become ledgers."""
import copy
import importlib.util
import json
from pathlib import Path
import subprocess
import shutil
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location('field_pcs', ROOT/'bench/field_pcs.py')
BENCH = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(BENCH)


class FieldPcsBenchTests(unittest.TestCase):
    def test_rejects_production_benchmark_dependency_and_undeclared_example(self):
        spec = importlib.util.spec_from_file_location('gates', ROOT/'scripts/gates/check.py')
        gates = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(gates)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            suite = root/'tests/negative-controls'
            shutil.copytree(ROOT/'tests/negative-controls', suite)
            gates.controls_layout(root)
            for name in ('lookup_corpus.py', 'lookup_corpus.py.lock', 'lookup_closed.py',
                         'src/lookup.rs', 'src/lookup_composer.rs', 'examples/support/lookup_verifier.rs',
                         'examples/lookup_bench.rs', 'src/matmul.rs', 'src/matmul_composer.rs',
                         'examples/matmul_corpus.rs', 'matmul_corpus.py', 'matmul_corpus.py.lock',
                         'examples/matmul_bench.rs', 'requant_schema.py', 'src/requant.rs',
                         'requant/verifier.rs', 'fixtures/requant/scalar-K4.bin',
                         'requant/producer.rs','requant/records.rs','requant/production_fixtures.py',
                         'requant/reference.py','requant/lookup_reference.py','requant/protocol_reference.py',
                         'requant/reference-provenance.json','requant_corpus.py','requant_corpus.py.lock',
                         'examples/requant_bench.rs','fixtures/requant-production/usage.json'):
                path = suite/name; saved = path.read_bytes(); path.unlink()
                with self.assertRaisesRegex(ValueError, 'not wired'):
                    gates.controls_layout(root)
                path.write_bytes(saved)
            manifest = suite/'Cargo.toml'
            original = manifest.read_text()
            target = '[[test]]\nname = "requant-verifier"\npath = "requant/verifier.rs"\n'
            self.assertIn(target, original)
            manifest.write_text(original.replace(target, ''))
            with self.assertRaisesRegex(ValueError, 'targets not wired'):
                gates.controls_layout(root)
            manifest.write_text(original)
            extra = suite/'fixtures/requant/unlisted.bin'; extra.write_bytes(b'0')
            with self.assertRaisesRegex(ValueError, 'inventory'):
                gates.controls_layout(root)
            extra.unlink()
            for name in ('lookup_bench', 'matmul_bench', 'requant_bench'):
                benchmark = f'[[example]]\nname = "{name}"\npath = "examples/{name}.rs"\n'
                self.assertIn(benchmark, original)
                manifest.write_text(original.replace(benchmark, ''))
                with self.subTest(missing_example=name), self.assertRaisesRegex(ValueError, 'example exact'):
                    gates.controls_layout(root)
                manifest.write_text(original)
            entry = 'serde_json = "=1.0.154"'
            manifest.write_text(original.replace(entry, '').replace('[dependencies]', '[dependencies]\n'+entry))
            with self.assertRaisesRegex(ValueError, 'dev-only'):
                gates.controls_layout(root)
            manifest.write_text(original)
            (suite/'examples/extra.rs').write_text('fn main() {}')
            with self.assertRaisesRegex(ValueError, 'not wired'):
                gates.controls_layout(root)

    def test_accepts_actual_consumers_and_rejects_incomplete_receipts(self):
        subprocess.run(['cargo', 'build', '-p', 'stele-negative-controls', '--example',
                        'field_pcs_bench', '--locked', '--offline'], cwd=ROOT,
                       check=True, capture_output=True)
        binary = ROOT/'target/debug/examples/field_pcs_bench'
        records = []
        for mode, ell, m, b, d in [('primitive', 0, 0, 1, 4), ('primitive', 2, 1, 2, 8),
                                  ('a1', 2, 1, 1, 4), ('a1', 2, 1, 2, 8)]:
            args = mode, ell, m, b, d
            result = subprocess.run([str(binary), *map(str, args)], cwd=ROOT,
                                    check=True, text=True, capture_output=True)
            value = BENCH.decode(result.stdout)
            BENCH.receipt(value, *args)
            records.append(value)
            mutations = [lambda x: x['stages_ns'].pop('certificate_verify'),
                         lambda x: x.update(total_ns=1),
                         lambda x: x['sources'][0].update(certificate_bytes=1),
                         lambda x: x['sources'][0]['preparation'].update(peak_owned_bytes=0),
                         lambda x: x['sources'][0]['certificate_verify']['local'].update(hash_evaluations=0),
                         lambda x: x['openings'].pop(),
                         lambda x: x['openings'][0].update(bytes=0),
                         lambda x: x['openings'][0].update(certificate_id='00'*32),
                         lambda x: x['consumer_usage']['local'].update(hash_evaluations=0),
                         lambda x: x.update(consumer_continuation='00'*(4*d)),
                         lambda x: x.update(source_count=True),
                         lambda x: x.update(extra=1),
                         lambda x: x.update(remainder_ns=1+x['remainder_ns'])]
            if mode == 'a1':
                mutations += [lambda x: x['stages_ns'].pop('a1_replay'),
                              lambda x: x['a1']['sc'].update(numerator=0),
                              lambda x: x['a1'].update(message_bytes=0)]
            for mutate in mutations:
                altered = copy.deepcopy(value)
                mutate(altered)
                with self.subTest(args=args, mutation=mutate), self.assertRaises(AssertionError):
                    BENCH.receipt(altered, *args)
        # Exercise the production formatter and native schema validator, not only inner receipts.
        metadata = dict(commit='0'*40,toolchain='schema fixture',device='schema fixture',plan={'test':1})
        data = BENCH.assemble(metadata, records)
        self.assertEqual(data['kernel_counters']['opening_merkle_hashes'],
                         sum(r['consumer_usage']['local']['hash_evaluations'] for r in records))
        with tempfile.TemporaryDirectory() as directory:
            ledger = Path(directory)/'schema-fixture.json'
            ledger.write_text(json.dumps(data))
            subprocess.run(['cargo','run','-q','-p','stele-bench','--locked','--offline',
                            '--','ledger','validate',str(ledger)],cwd=ROOT,check=True,capture_output=True)

    def test_rejects_missing_or_reordered_campaign_samples(self):
        with self.assertRaisesRegex(AssertionError, 'duplicate JSON keys'):
            BENCH.decode('{"mode":"a1","mode":"primitive"}')
        cases = BENCH.CASES
        BENCH.check_cases([dict(mode=a, ell=b, m=c, blowup=d, degree=e, sample=f)
                           for a,b,c,d,e,f in cases])
        for subset in (cases[:-1], cases[::-1], cases + cases[:1]):
            with self.assertRaises(AssertionError):
                BENCH.check_cases([dict(mode=a, ell=b, m=c, blowup=d, degree=e, sample=f)
                                   for a,b,c,d,e,f in subset])
