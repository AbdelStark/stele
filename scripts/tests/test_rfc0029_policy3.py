"""RFC-0029 Policy 3 exact-integer checker and recursive size model tests (task E19-01)."""
import importlib.util
from pathlib import Path
import subprocess
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
        for b, expected_q in ((1, 381), (2, 241), (3, 202), (4, 185)):
            q, _, n, _, e = MOD.policy3_fresh_q(16, b, 100)
            self.assertEqual(q, expected_q)
            miss = n - e - 1
            self.assertLessEqual((1 << 100) * (miss**q), n**q)
            self.assertGreater((1 << 100) * (miss ** (q - 1)), n ** (q - 1))
        with self.assertRaises(ValueError):
            MOD.circle_params(-1, 2)
        with self.assertRaises(ValueError):
            MOD.circle_params(16, 0)
        # M31 coset domain and column-sampler ceiling: m + b <= 30 (RFC-0010 A2, RFC-0012 A10).
        with self.assertRaises(ValueError):
            MOD.circle_params(30, 1)
        with self.assertRaises(ValueError):
            MOD.circle_params(27, 4)
        # Certified radius must satisfy 1 <= e_c <= e_max (RFC-0010 A17).
        with self.assertRaises(ValueError):
            MOD.policy3_certified_q(16, 2, 0, 100)
        with self.assertRaises(ValueError):
            MOD.policy3_certified_q(16, 2, 1 << 20, 100)

    def test_accepts_bet_b3_size_budget_and_domain_and_certificate_caps(self):
        eight_mb = 8_000_000
        # Strict QM31 with b=1 (rate 1/2) and all Q50 configurations clear 8 MB with headroom.
        for deg, per_round, blowups in (
            (4, False, MOD.ALL_BLOWUPS),
            (4, True, MOD.DEFAULT_BLOWUPS),
            (6, False, MOD.DEFAULT_BLOWUPS),
            (8, False, MOD.DEFAULT_BLOWUPS),
        ):
            total, plan = MOD.minimise_recursive_proof(
                32, ext_degree=deg, target_bits=100, capped=True, per_round=per_round, blowups=blowups
            )
            self.assertLess(total, eight_mb)
            self.assertEqual(plan[-1][0], "final")
            MOD._assert_plan_domains_valid(plan)

        # Certified level 0 unconditionally obeys strict 2*ell*(e_c+1) <= QM31_CAP_100.
        for n in (31, 32, 33):
            total, info = MOD.minimise_certified_weight_opening(
                n, ext_degree=4, target_bits=100, capped=True, tail_per_round=True
            )
            self.assertLessEqual(2 * info["ell"] * (info["e_c"] + 1), MOD.QM31_CAP_100)
            self.assertLessEqual(info["m"] + info["b"], MOD.MAX_DOMAIN_BITS)
            self.assertLess(total, 1_500_000)

        # Faithful RFC-0029 §2 level-1 segment joining retains k blocks at level 1.
        seg_bytes, seg_plan = MOD.minimise_segmented_proof(30, 32, ext_degree=4, capped=True)
        self.assertEqual(seg_plan[0][0], "lvl0_segs")
        self.assertEqual(seg_plan[0][1], 32)
        self.assertEqual(seg_plan[1][0], 1)
        self.assertEqual(seg_plan[1][6], 32)  # blocks == 32 at level 1
        self.assertGreater(seg_bytes, 9 * 1024 * 1024)
        MOD._assert_plan_domains_valid(seg_plan)

    def test_matches_reference_python_recursive_verifier(self):
        proc = subprocess.run(
            ["uv", "run", "--locked", "--offline", "--script", "research/rfc0029-pcs/verify_recursive.py"],
            cwd=ROOT,
            capture_output=True,
            text=True,
        )
        self.assertEqual(proc.returncode, 0, f"{proc.stdout}\n{proc.stderr}")
        self.assertIn("rfc0029 verify_recursive: OK (10 vectors verified", proc.stdout)


if __name__ == "__main__":
    unittest.main()
