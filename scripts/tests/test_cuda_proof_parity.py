"""RFC-0014 A2. A CPU-only response or a partial device schedule cannot pass as GPU parity."""
import importlib.util
from pathlib import Path
import unittest

path = Path(__file__).resolve().parents[2] / "tests/parity/check.py"
spec = importlib.util.spec_from_file_location("cuda_proof_parity", path)
parity = importlib.util.module_from_spec(spec)
spec.loader.exec_module(parity)


class DeviceCounts(unittest.TestCase):
    def test_requires_all_authenticated_ordinary_batches_and_their_rounds(self):
        self.assertEqual(parity.hardware_counts("3 3 7 7 7 3 432", 4), (3, 7))
        for bad in ("0 0 0 0 0 0 0", "2 2 7 7 7 2 400", "3 3 7 6 6 3 384",
                    "3 3 7 7 6 3 432", "3 3 7 7 7 2 400", "3 3 7 7 7 3 431"):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                parity.hardware_counts(bad, 4)
