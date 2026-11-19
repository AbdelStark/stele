"""Controls for the T32 measurement that detects omitted or repeated stage visits."""
import unittest

from receipt import summarize


def example():
    lines = ["t32_cold ns=10"]
    for kind in ("top", "rebuild"):
        for i in range(21):
            lines.extend([
                f"t32_cpu_lookup kind={kind} id={i} ns=100",
                f"t32_lookup kind={kind} id={i} normalize_ns=7 wall_ns=10 h2d_bytes=4 d2h_bytes=8",
                f"t32_normalize_release kind={kind} id={i} ns=3",
            ])
    for i in (17, 41, 55):
        lines.extend([
            f"t32_batch id={i} rows=4 columns=4 claims=1 positions=2 wall_ns=20 h2d_bytes=40 term_bytes=8 round_h2d_bytes=40",
            f"t32_cpu_weights id={i} ns=50",
            f"t32_cpu_face id={i} ns=50",
        ])
        for j in range(3):
            lines.extend([
                f"t32_round id={i} index={j} cpu_ns=100 gpu_ns=20 d2h_bytes=48",
                f"t32_fold id={i} index={j} cpu_ns=100 gpu_ns=20",
            ])
        lines.append(f"t32_finals id={i} rounds=3 cpu_ns=100 gpu_ns=20 d2h_bytes=32")
    return lines


class Receipt(unittest.TestCase):
    def test_accepts_exact_visits_and_charges_normalization(self):
        result = summarize("\n".join(example()))
        self.assertEqual(result["top"]["gpu_ns"], 420)
        self.assertEqual(result["batch_prepare"]["h2d_bytes"], 144)
        self.assertEqual(result["batch_dense"]["d2h_bytes"], 528)

    def test_reconciles_tile_schedule_and_buffers(self):
        from packing import summarize as packing
        row = dict(rows=4, columns=4, tile=128, claims=1, positions=2, runs=1, run_checks=4,
                   h2d_bytes=160, host_pack_bytes=160, device_build_bytes=320,
                   index_ns=1, group_ns=1, upload_ns=2, build_ns=3, setup_ns=4)
        totals = packing([row]*3)
        self.assertEqual(totals["h2d_bytes"], 480)
        for key in ("run_checks", "h2d_bytes", "device_build_bytes"):
            with self.subTest(key=key), self.assertRaises(ValueError):
                packing([row, row, {**row, key: row[key]+1}])

    def test_rejects_missing_and_repeated_visits(self):
        lines = example()
        for prefix in ("t32_normalize_release", "t32_cpu_lookup", "t32_lookup", "t32_round", "t32_finals"):
            victim = next(line for line in lines if line.startswith(prefix))
            with self.subTest(prefix=prefix):
                for changed in ([line for line in lines if line != victim], [*lines, victim]):
                    with self.assertRaises(ValueError):
                        summarize("\n".join(changed))

    def test_rejects_swapped_fold_indices(self):
        lines = [line.replace("t32_fold id=17 index=0", "t32_fold id=17 index=1") for line in example()]
        with self.assertRaises(ValueError):
            summarize("\n".join(lines))


if __name__ == "__main__":
    unittest.main()
