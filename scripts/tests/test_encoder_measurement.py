"""RFC-0010 A5: reject incomplete worker receipts and ambiguous compiler stack evidence."""
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'bench'))
SPEC = importlib.util.spec_from_file_location('encoder_bench',ROOT/'bench/encoder.py')
BENCH = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(BENCH)
sys.path.pop(0)


class EncoderMeasurementTests(unittest.TestCase):
    def test_accepts_actual_receipts_and_rejects_omitted_costs(self):
        subprocess.run(['cargo','build','-p','stele-code','--example','encoder_bench','--locked','--offline'],
                       cwd=ROOT,check=True,capture_output=True)
        for j,d in ((3,1),(4,4),(4,8)):
            result = subprocess.run([str(ROOT/'target/debug/examples/encoder_bench'),str(j),str(d)],
                                    cwd=ROOT,check=True,text=True,capture_output=True)
            v = json.loads(result.stdout)
            BENCH.receipt(v,j,d)
            for key,value in dict(checked_symbols=0,validation_ns=0,total_ns=1,
                encode_hash_blocks=1 if j==3 else 0,encode_peak_owned_bytes=0,
                encode_sparse_limb_products=1,query_copied_symbols=0,
                native_live_peak_bytes=0,encode_max_recursive_frames=0,checksum=True).items():
                with self.subTest(j=j,d=d,key=key),self.assertRaises(AssertionError):
                    BENCH.receipt(dict(v,**{key:value}),j,d)
            del v['query_hash_blocks']
            with self.assertRaises(AssertionError):
                BENCH.receipt(v,j,d)



if __name__ == '__main__':
    unittest.main()
