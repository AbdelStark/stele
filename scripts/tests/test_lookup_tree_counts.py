"""RFC-0014 A6. Tie each resident ID, final-child release and four views to the verified scope."""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "bench"))
from lookup_tree_counts import FIELDS, check_lookup_work


class LookupWork(unittest.TestCase):
    def test_checks_single_level_and_last_child_against_verified_scope(self):
        report = "\n".join(["LU\tcheck 0\t1/|K|", "LU\tcheck 1\t2/|K|",
                            "SC\tcheck 0 step 0\t3/|K|", "SC\tcheck 1 step 1\t4/|K|", "SC\tcheck 1 step 2\t5/|K|"])
        fields = dict(zip(FIELDS, [2, 1, 4, 1, 128, 512, 800, 780], strict=True))
        self.assertEqual(check_lookup_work(fields, report, 850), fields)
        for key in FIELDS:
            with self.subTest(key=key), self.assertRaises(ValueError):
                check_lookup_work({**fields, key: 0}, report, 850)
        for changed in [report.replace("check 1 step 1", "check 3 step 1"),
                        report.replace("check 1 step 2", "check 0 step 2"),
                        report.replace("step 2", "step 3")]:
            with self.assertRaises(ValueError):
                check_lookup_work(fields, changed, 850)
        with self.assertRaises(ValueError):
            check_lookup_work(fields, report, 779)
