"""RFC-0006 A4 §6: complete real consumers are required before resource import."""
import copy
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[2]
SPEC=importlib.util.spec_from_file_location('stacked_bench',ROOT/'bench/stacked.py')
BENCH=importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(BENCH)


class StackedBenchTests(unittest.TestCase):
    def test_accepts_real_complete_calls_and_rejects_incomplete_receipts(self):
        subprocess.run(['cargo','build','-p','stele-negative-controls','--example','stacked_bench','--locked','--offline'],cwd=ROOT,check=True,capture_output=True)
        binary=ROOT/'target/debug/examples/stacked_bench'
        records=[]
        for mode,order,d in [('public','first',4),('public','last',8),('certified','first',4),('certified','last',8)]:
            result=subprocess.run([str(binary),mode,order,str(d),'smoke'],cwd=ROOT,text=True,check=True,capture_output=True)
            v=BENCH.decode(result.stdout);BENCH.receipt(v,mode,order,d,'smoke');records.append(v)
            mutations=[lambda x:x['stages_ns'].pop('verify'),lambda x:x.update(total_ns=1),
                lambda x:x.update(remainder_ns=x['remainder_ns']+1),lambda x:x.update(field_degree=True),
                lambda x:x.update(extra=1),lambda x:x['inputs'].pop(),lambda x:x['dense'].update(dense_entries=0),
                lambda x:x['dense'].update(round_scratch_entries=0),lambda x:x['dense'].update(rounds=0),
                lambda x:x['a1']['messages'].update(bytes=0),lambda x:x['record']['sc'].update(numerator=0),
                lambda x:x['framing']['sources'].update(bytes=0),lambda x:x['continuation'].update(consumer='00'*(4*d)),
                lambda x:x['producer_usage']['transcript'].update(xof_requests=0),
                lambda x:x['consumer_usage']['local'].update(hash_evaluations=x['consumer_usage']['local']['hash_evaluations']+1)]
            if mode=='certified':
                mutations += [lambda x:x['stages_ns'].pop('certificate_verify/0'),lambda x:x['sources'].pop(),
                    lambda x:x['record']['openings'].pop(),lambda x:x['record']['openings'][0].update(certificate_id='00'*32),
                    lambda x:x['sources'][0]['parameters'].update(opening_queries=0),
                    lambda x:x['sources'][0]['preparation'].update(peak_owned_bytes=0),
                    lambda x:x['sources'][0]['verifier']['local'].update(hash_evaluations=0)]
            for mutate in mutations:
                altered=copy.deepcopy(v);mutate(altered)
                with self.subTest(mode=mode,order=order,d=d,mutation=mutate),self.assertRaises(AssertionError):
                    BENCH.receipt(altered,mode,order,d,'smoke')
        metadata=dict(commit='0'*40,toolchain='schema fixture',device='schema fixture',plan={'test':1})
        data=BENCH.assemble(metadata,records)
        self.assertEqual(sum(data['stage_times_ns'].values()),data['prover_time_ns'])
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'ledger.json';path.write_text(json.dumps(data))
            subprocess.run(['cargo','run','-q','-p','stele-bench','--locked','--offline','--','ledger','validate',str(path)],cwd=ROOT,check=True,capture_output=True)

    def test_rejects_duplicate_keys_and_incomplete_campaign(self):
        with self.assertRaisesRegex(AssertionError,'duplicate JSON keys'):BENCH.decode('{"mode":1,"mode":2}')
        rows=[dict(mode=m,order=o,field_degree=d,sample=s) for m,o,d,s in BENCH.CASES]
        BENCH.check_cases(rows)
        for wrong in [rows[:-1],rows[::-1],rows+rows[:1]]:
            with self.assertRaises(AssertionError):BENCH.check_cases(wrong)
        self.assertEqual(BENCH.identity({'sample':1,'total_ns':2,'proof':'a'}),{'proof':'a'})
        self.assertNotEqual(BENCH.identity({'proof':'a'}),BENCH.identity({'proof':'b'}))
