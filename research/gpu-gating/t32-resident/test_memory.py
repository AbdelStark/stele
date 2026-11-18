"""Validate every live-device budget in the E16-40z T32 qualification."""
from pathlib import Path
import sys
import unittest


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
        if not 0 < construction <= row["planned_bytes"] == max(construction, fold):
            raise ValueError("invalid GKR explicit peak")
        total = row["total_bytes"]
        outside = max(0, total - row["free_bytes"] - row["pool_reserved_bytes"])
        # CUDA's pool high-water counters are cumulative. Adding current
        # outside-pool occupancy conservatively charges the observed context.
        if outside + row["pool_reserved_high"] > total * 2 // 5:
            raise ValueError("measured device high water exceeds budget")
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
    def test_rejects_fallback(self):
        with self.assertRaisesRegex(ValueError, "fallback"):
            check_memory("t32_gkr_skip step=96")


if __name__ == "__main__":
    checked = check_memory(Path(sys.argv[1]).read_text())
    print(f"bounded_gkr_steps={len(checked)} last_child_handoffs=21 large_steps=96,97")
