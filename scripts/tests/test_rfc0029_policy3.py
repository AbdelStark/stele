"""RFC-0029 Policy 3 exact-integer checker and recursive size model tests (task E19-01)."""
import importlib.util
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "research/rfc0029-pcs/check_policy3.py"
SPEC = importlib.util.spec_from_file_location("check_policy3", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
MOD = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MOD)


class Rfc0029Policy3Tests(unittest.TestCase):
    def test_matches_reference_policy3_counts_and_size_receipts(self):
        MOD.run_checks()

    def test_rejects_one_fewer_query_and_invalid_parameters(self):
        for b, expected_q in ((2, 241), (3, 202), (4, 185)):
            q, _, n, _, e = MOD.policy3_fresh_q(16, b, 100)
            self.assertEqual(q, expected_q)
            miss = n - e - 1
            self.assertLessEqual((1 << 100) * (miss**q), n**q)
            self.assertGreater((1 << 100) * (miss ** (q - 1)), n ** (q - 1))
        with self.assertRaises(ValueError):
            MOD.circle_params(-1, 2)
        with self.assertRaises(ValueError):
            MOD.circle_params(16, 0)
        with self.assertRaises(ValueError):
            MOD.policy3_certified_q(16, 2, 1 << 20, 100)

    def test_accepts_bet_b3_size_budget_under_rfc0030_caps(self):
        eight_mib = 8 * 1024 * 1024
        for deg, per_round in ((4, False), (4, True), (6, False), (8, False)):
            total, plan = MOD.minimise_recursive_proof(
                32, ext_degree=deg, target_bits=100, capped=True, per_round=per_round
            )
            self.assertLess(total, eight_mib)
            self.assertEqual(plan[-1][0], "final")


if __name__ == "__main__":
    unittest.main()
