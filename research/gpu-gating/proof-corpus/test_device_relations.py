import unittest
from device_relations import summarize


class Origin(unittest.TestCase):
    LOG = ("relation_gpu id=7 vars=2 factors=3 rounds=2 folds=2 finals=3 admitted=1 cpu_returned=0 d2h=144\n"
           "relation_gpu_complete relations=1 rounds=2 folds=2 finals=3")
    VERIFY = "dev-zk: 1 relation instances, 3 GKR steps, 2 batches, 473 proof bytes\nYES"

    def test_matches_verifier_and_rejects_cpu_or_missing_round(self):
        self.assertEqual(summarize(self.LOG, self.VERIFY)["rounds"], 2)
        for log in (self.LOG.replace("cpu_returned=0", "cpu_returned=1"),
                    self.LOG.replace("folds=2", "folds=1"), self.LOG.splitlines()[-1]):
            with self.assertRaises(ValueError):
                summarize(log, self.VERIFY)
        with self.assertRaises(ValueError):
            summarize(self.LOG, self.VERIFY.replace("1 relation", "2 relation"))
