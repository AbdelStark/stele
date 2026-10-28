"""RFC-0010 A4 / RFC-0018 §1: check actual receipts and reject incomplete costs."""
import importlib.util
import json
from pathlib import Path
import subprocess
import unittest

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location('expander_bench', ROOT/'bench/expander.py')
BENCH = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(BENCH)


class ExpanderBenchTests(unittest.TestCase):
    def test_accepts_native_receipts_and_rejects_missing_work(self):
        subprocess.run(['cargo', 'build', '-p', 'stele-code', '--example',
            'expander_bench', '--locked', '--offline'], cwd=ROOT, check=True,
            capture_output=True)
        for j, d in ((3, 1), (4, 4), (4, 8)):
            result = subprocess.run([str(ROOT/'target/debug/examples/expander_bench'),
                str(j), str(d)], cwd=ROOT, text=True, capture_output=True, check=True)
            receipt = json.loads(result.stdout)
            BENCH.receipt(receipt, j, d)
            mutations = dict(checked_symbols=0, validation_ns=0, total_ns=1,
                input_capacity_bytes=0, output_capacity_bytes=0,
                query_capacity_bytes=0, encode_owned_peak_bytes=0,
                native_live_peak_bytes=0, sparse_adds_per_encode=1,
                setup_blocks=1 if j == 3 else 0, checksum=True)
            for key, value in mutations.items():
                with self.subTest(j=j, d=d, key=key), self.assertRaises(AssertionError):
                    BENCH.receipt(dict(receipt, **{key: value}), j, d)
            missing = dict(receipt)
            del missing['checked_symbols']
            with self.assertRaises(AssertionError):
                BENCH.receipt(missing, j, d)


if __name__ == '__main__':
    unittest.main()
