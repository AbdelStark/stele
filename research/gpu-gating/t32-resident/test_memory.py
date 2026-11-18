"""Validate every live-device budget in the E16-40z T32 qualification."""
from pathlib import Path
import sys
import unittest


def check_pool(row):
    total = row["total_bytes"]
    used, reserved = row["pool_used_high"], row["pool_reserved_high"]
    if not (0 <= row["pool_used_bytes"] <= used <= reserved <= total
            and row["pool_used_bytes"] <= row["pool_reserved_bytes"] <= reserved
            and 0 <= row["free_bytes"] <= total):
        raise ValueError("invalid pool counter ordering")
    if used <= 0 or used > total * 2 // 5:
        raise ValueError("measured live pool exceeds budget")
    outside = max(0, total - row["free_bytes"] - row["pool_reserved_bytes"])
    # CUDA's pool high-water counters are cumulative. Separately add the
    # sampled outside-pool occupancy to charge the observed context.
    if outside + reserved > total * 2 // 5:
        raise ValueError("measured reserved pool and context exceed budget")


def check_memory(log):
    rows = {}
    for line in log.splitlines():
        if line.startswith("t32_gkr_skip "):
            raise ValueError("GKR budget fallback")
        if not line.startswith("t32_gkr_step "):
            continue
        row = {k: int(v) for k, v in (field.split("=") for field in line.split()[1:])}
        step = row["step"]
        if step in rows:
            raise ValueError("duplicate GKR step")
        rows[step] = row
        construction, fold = row["construction_bytes"], row["first_fold_bytes"]
        if min(construction, fold) <= 0 or row["planned_bytes"] != max(construction, fold):
            raise ValueError("invalid GKR explicit peak")
        check_pool(row)
    if list(rows) != list(range(385)):
        raise ValueError("incomplete GKR memory qualification")
    interior, leaf = rows[96], rows[97]
    if (interior["variables"], leaf["variables"], interior["released_bytes"],
            leaf["released_bytes"]) != (27, 28, 32 * ((2 << 28) - 1), 0):
        raise ValueError("missing large-step final child handoff")
    if sum(bool(r["released_bytes"]) for r in rows.values()) != 21:
        raise ValueError("incomplete final child handoffs")
    return rows


class Memory(unittest.TestCase):
    def test_rejects_live_and_reserved_high_waters_separately(self):
        row = dict(total_bytes=100, pool_used_high=38, pool_reserved_high=39,
                   pool_used_bytes=10, pool_reserved_bytes=20, free_bytes=79)
        check_pool(row)
        with self.assertRaisesRegex(ValueError, "live pool"):
            check_pool(dict(row, pool_used_high=41, pool_reserved_high=42))
        with self.assertRaisesRegex(ValueError, "reserved pool and context"):
            check_pool(dict(row, free_bytes=78))

    def test_rejects_zero_fold_peak(self):
        with self.assertRaisesRegex(ValueError, "explicit peak"):
            check_memory("t32_gkr_step step=0 construction_bytes=5 first_fold_bytes=0 planned_bytes=5")

    def test_rejects_fallback(self):
        with self.assertRaisesRegex(ValueError, "fallback"):
            check_memory("t32_gkr_skip step=96")


if __name__ == "__main__":
    checked = check_memory(Path(sys.argv[1]).read_text())
    print(f"bounded_gkr_steps={len(checked)} last_child_handoffs=21 large_steps=96,97")
