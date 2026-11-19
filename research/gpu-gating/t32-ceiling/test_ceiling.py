import unittest
from ceiling import project, REPLACED


class Ceiling(unittest.TestCase):
    def test_retains_host_work_and_charges_cold_and_qualification_separately(self):
        laps = {"lap_zk_detail_" + k: 10 for k in REPLACED}
        laps.update(lap_zk_detail_top_prepare=4, lap_zk_detail_batch_rounds=5, lap_zk_self_verify=4,
                    lap_zk_logup_gkr=30, lap_zk_relations_masked_sumcheck=2)
        r = project(90, laps, 2, 1, 6, 4, 12)
        self.assertEqual((r["retained_cpu_ns"], r["warm_projected_ns"], r["cold_projected_ns"],
                          r["including_oracle_readbacks_ns"]), (20, 29, 33, 41))
        self.assertTrue(r["warm_reaches_three"])
        self.assertFalse(r["cold_reaches_three"])

    def test_rejects_impossible_replacement(self):
        with self.assertRaisesRegex(ValueError, "disjoint"):
            project(70, {"lap_zk_detail_" + k: 10 for k in REPLACED}, 1, 1, 2, 3, 0)


class SourceAndBatchHost(unittest.TestCase):
    def test_charges_only_the_observed_host_remainder(self):
        from host import retained
        log = ("source_material id=0 ns=3\nsource_material id=1 ns=5\nearly_sources count=2 ns=13\n"
               "source_material id=3 ns=700\n" + "\n".join(
                   f"batch_setup id={i} total_ns=9 copy_ns=7" for i in (1265, 1266, 1267)))
        self.assertEqual(retained(log), dict(early_source_host_ns=5, ordinary_batch_setup_host_ns=6))
        with self.assertRaisesRegex(ValueError, "overlapping"):
            retained(log.replace("copy_ns=7", "copy_ns=10"))
