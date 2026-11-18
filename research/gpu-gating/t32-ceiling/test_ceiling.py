import unittest
from ceiling import project, REPLACED


class Ceiling(unittest.TestCase):
    def test_retains_host_work_and_charges_cold_and_qualification_separately(self):
        laps = {"lap_zk_detail_" + k: 10 for k in REPLACED}
        laps.update(lap_zk_detail_batch_rounds=5, lap_zk_self_verify=4,
                    lap_zk_logup_gkr=30, lap_zk_relations_masked_sumcheck=2)
        r = project(100, laps, 3, 9, 4, 12)
        self.assertEqual((r["retained_cpu_ns"], r["warm_projected_ns"], r["cold_projected_ns"],
                          r["including_oracle_readbacks_ns"]), (20, 32, 36, 44))
        self.assertTrue(r["warm_reaches_three"])
        self.assertFalse(r["cold_reaches_three"])

    def test_rejects_impossible_replacement(self):
        with self.assertRaisesRegex(ValueError, "disjoint"):
            project(80, {"lap_zk_detail_" + k: 10 for k in REPLACED}, 1, 2, 3, 0)
