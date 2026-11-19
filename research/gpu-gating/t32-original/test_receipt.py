"""RFC-0014 A1. Every original lifetime is identified and its DMA and release are counted."""
from pathlib import Path
import runpy
import unittest

check = runpy.run_path(str(Path(__file__).with_name("receipt.py")))["check_lifetimes"]


def schedule():
    owners = [(0, 1 << 31), (1, 1 << 31), (2, 1 << 16), (3, 1 << 22), (1268, 1 << 16)]
    live = 0
    rows = []
    for i, size in owners:
        if i == 1268:
            rows.append(f"t32_gkr_step original_live={live}")
            for batch, (source, payload) in enumerate(owners[:3], 1265):
                rows.append(f"t32_batch id={batch} original_id={source} original_bytes={payload}")
        live += size
        rows.append(f"t32_source id={i} opening=0 original_bytes={size} original_upload={size} originals_live={live}")
    for i, size in owners:
        live -= size
        rows.append(f"t32_source id={i} opening=1 original_bytes={size} original_upload=0 originals_live={live}")
    return "\n".join(rows)


class Lifetime(unittest.TestCase):
    def test_matches_exact_original_lifetimes(self):
        result = check(schedule())
        self.assertEqual(result, dict(original_uploads=5, original_payload_bytes=4_299_292_672,
                                      original_live_bytes_during_gkr=4_299_227_136))

    def test_rejects_cross_source_equal_size_batch(self):
        log = schedule().replace("id=1265 original_id=0", "id=1265 original_id=1")
        with self.assertRaisesRegex(ValueError, "incomplete original lifetime"):
            check(log)

    def test_rejects_opening_upload_and_missing_gkr_owner(self):
        with self.assertRaisesRegex(ValueError, "opening lacks its pinned source"):
            check(schedule().replace("original_upload=0", "original_upload=1", 1))
        with self.assertRaisesRegex(ValueError, "without all four"):
            check(schedule().replace("t32_gkr_step original_live=4299227136",
                                     "t32_gkr_step original_live=4295032832"))
