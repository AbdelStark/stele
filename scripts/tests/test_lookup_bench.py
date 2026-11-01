"""RFC-0008 A5 §6: complete actual lookup consumers precede ledger import."""
import copy
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location('lookup_bench', ROOT/'bench/lookup.py')
BENCH = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(BENCH)


class LookupBenchTests(unittest.TestCase):
    def test_accepts_complete_workers_and_rejects_missing_obligations(self):
        subprocess.run(['cargo', 'build', '-p', 'stele-negative-controls', '--example',
                        'lookup_bench', '--locked', '--offline'], cwd=ROOT, check=True, capture_output=True)
        records = []
        for scenario, degree in [('scalar', 4), ('grouped', 8), ('signed', 4), ('zero', 8)]:
            result = subprocess.run([str(ROOT/'target/debug/examples/lookup_bench'), scenario,
                                     str(degree), 'smoke'], cwd=ROOT, text=True, check=True, capture_output=True)
            value = BENCH.decode(result.stdout)
            BENCH.receipt(value, scenario, degree, 'smoke')
            records.append(value)
            mutations = [
                lambda v: v['stages_ns'].pop('verify'),
                lambda v: v['stages_ns'].pop('import_multiplicities'),
                lambda v: v['stages_ns'].pop('produce_including_mu_preparation_and_registration'),
                lambda v: v['stages_ns'].pop('certificate_verify/0'),
                lambda v: v.update(total_ns=1),
                lambda v: v.update(remainder_ns=v['remainder_ns']+1),
                lambda v: v.update(field_degree=True),
                lambda v: v.update(extra=1),
                lambda v: v['originals'].pop(),
                lambda v: v['multiplicities'].pop(),
                lambda v: v['record']['repetitions'][0]['originals'].pop(),
                lambda v: v['record']['repetitions'][0]['multiplicities'].pop(),
                lambda v: v['record']['parameters'].update(identity_numerator=0),
                lambda v: v['record']['repetitions'][0]['table']['accounting']['layers'].pop(),
                lambda v: v['record']['repetitions'][0]['originals'][0].update(certificate_id='00'*32),
                lambda v: v['originals'][0]['certificate'].update(kind='Opening'),
                lambda v: v['originals'][0]['certificate'].update(opening_queries=0),
                lambda v: v['originals'][0]['certificate'].update(context='00'*105),
                lambda v: v['originals'][0]['preparation'].update(peak_owned_bytes=0),
                lambda v: v['multiplicities'][0]['import_usage']['local'].update(hash_evaluations=0),
                lambda v: v['multiplicities'][0]['wire'].update(digest='00'*32),
                lambda v: v['work']['preparations'].__setitem__(0, None),
                lambda v: v['work']['repetitions'].__setitem__(0, None),
                lambda v: v['work'].update(peak_observed_bytes=0),
                lambda v: v['work']['repetitions'][0]['lookup'].update(peak_observed_bytes=v['work']['peak_observed_bytes']),
                lambda v: v.update(memory_scope='exact allocation peak'),
                lambda v: v['proof']['sections'].pop(),
                lambda v: v['proof'].update(capacity_bytes=0),
                lambda v: v['continuation'].update(consumer='00'*(4*degree)),
                lambda v: v['producer_usage']['transcript'].update(xof_requests=0),
                lambda v: v['consumer_usage']['local'].update(hash_evaluations=0),
                lambda v: v['diagnostics']['statement_hashes'].update(hash_evaluations=0),
                lambda v: v['diagnostics']['continuations']['producer'].update(hash_evaluations=0),
            ]
            for mutate in mutations:
                altered = copy.deepcopy(value)
                mutate(altered)
                with self.subTest(scenario=scenario, mutation=mutate), self.assertRaises(AssertionError):
                    BENCH.receipt(altered, scenario, degree, 'smoke')
        metadata = dict(commit='0'*40, toolchain='schema fixture', device='schema fixture', plan={'test': 1})
        ledger = BENCH.assemble(metadata, records)
        self.assertTrue(ledger['kernel_counters'])
        self.assertEqual(sum(ledger['stage_times_ns'].values()), ledger['prover_time_ns'])
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/'ledger.json'
            path.write_text(json.dumps(ledger))
            subprocess.run(['cargo', 'run', '-q', '-p', 'stele-bench', '--locked', '--offline',
                            '--', 'ledger', 'validate', str(path)], cwd=ROOT, check=True, capture_output=True)

    def test_rejects_duplicate_keys_and_incomplete_campaign(self):
        with self.assertRaisesRegex(AssertionError, 'duplicate JSON keys'):
            BENCH.decode('{"scenario":1,"scenario":2}')
        rows = [dict(scenario=c, field_degree=d, sample=s) for c, d, s in BENCH.CASES]
        BENCH.check_cases(rows)
        for wrong in [rows[:-1], rows[::-1], rows+rows[:1]]:
            with self.assertRaises(AssertionError):
                BENCH.check_cases(wrong)
        self.assertEqual(BENCH.identity({'sample': 1, 'total_ns': 2, 'proof': 'a'}), {'proof': 'a'})
        self.assertNotEqual(BENCH.identity({'proof': 'a'}), BENCH.identity({'proof': 'b'}))
