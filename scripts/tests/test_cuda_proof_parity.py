"""RFC-0014 A2. A CPU-only response or a partial device schedule cannot pass as GPU parity."""
import importlib.util
from pathlib import Path
import unittest

path = Path(__file__).resolve().parents[2] / "tests/parity/check.py"
spec = importlib.util.spec_from_file_location("cuda_proof_parity", path)
parity = importlib.util.module_from_spec(spec)
spec.loader.exec_module(parity)


class DeviceCounts(unittest.TestCase):
    def test_requires_the_full_authenticated_batch_schedule(self):
        batches, originals = 4, 5
        good = [originals, batches, 7, 7, 7, batches, 464]

        def check(row):
            return parity.hardware_counts(" ".join(map(str, row)), batches, originals)

        self.assertEqual(check(good), (4, 7))
        for i, value in [(0, 4), (1, 3), (2, 6), (3, 6), (4, 6), (5, 3), (6, 463)]:
            changed = good.copy()
            changed[i] = value
            with self.subTest(index=i), self.assertRaises(ValueError):
                check(changed)
        # A self-consistent three-batch receipt omits the authenticated fourth batch.
        with self.assertRaises(ValueError):
            check([originals, 3, 6, 6, 6, 3, 384])

    def test_requires_gkr_folds_and_finals_against_pinned_proof(self):
        expected = (5, 14, 58)
        good = "5 14 14 14 5 256 1008 128 4096 5000"
        self.assertEqual(parity.gkr_counts(good, expected), (5, 14))
        for i, change in [(0, 4), (1, 13), (2, 13), (3, 13), (4, 4), (5, 0),
                          (6, 1007), (7, 257), (8, 0), (9, 0)]:
            with self.subTest(i=i), self.assertRaises(ValueError):
                words = good.split()
                words[i] = str(change)
                parity.gkr_counts(" ".join(words), expected)

    def test_requires_all_relation_rounds_and_original_final_fields(self):
        schedule = (5,14,58,20)
        row = [5,14,14,14,5,4096,16*(58+20),2048,512,8192,10000]
        def check(values):
            return parity.relation_counts(" ".join(map(str, values)), schedule)
        self.assertEqual(check(row), (5,14))
        for i,value in [(0,4),(1,13),(2,15),(3,13),(4,4),(5,2048),(6,1232),(7,0),(8,0),(9,0),(10,0)]:
            changed = row.copy()
            changed[i] = value
            with self.subTest(i=i), self.assertRaises(ValueError):
                check(changed)
