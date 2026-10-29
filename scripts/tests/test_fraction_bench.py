"""RFC-0018 §1: ledger admission must retain all consumers, accounting and costs."""
import copy
import importlib.util
import json
from pathlib import Path
import subprocess
import unittest

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('fraction_bench',ROOT/'bench/fraction.py')
bench = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bench)


class FractionBenchTests(unittest.TestCase):
    def test_rejects_missing_obligations_and_underreported_costs(self):
        for field, degree in [('QM31',4),('OM31',8)]:
            case = dict(m=3,mode='selected3zero')
            output = subprocess.check_output(['cargo','run','-q','-p','stele-lookup','--example','fraction_bench',
                '--locked','--offline','--',field,'3',case['mode']],cwd=ROOT,text=True)
            row = json.loads(output)
            bench.validate(row,case,degree)
            for key, changed in [('leaf_claim_ids',[91,92]),('tree_claim_ids',[11]),('complete_ns',0),
                                 ('original_capacity_bytes',0),('encoded_capacity_bytes',0),('canonical','')]:
                with self.subTest(field=field,key=key):
                    bad = copy.deepcopy(row)
                    bad[key] = changed
                    with self.assertRaises(AssertionError):
                        bench.validate(bad,case,degree)
            for key in ('gamma','fold'):
                bad = copy.deepcopy(row)
                bad['accounting'][key] = 0
                with self.assertRaises(AssertionError):
                    bench.validate(bad,case,degree)


if __name__ == '__main__':
    unittest.main()
