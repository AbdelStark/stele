"""RFC-0014 A1. Reconcile GKR original visits against the production schedule."""
from pathlib import Path
import runpy
import unittest

check = runpy.run_path(str(Path(__file__).with_name("receipt.py")))


def schedule():
    ordinary = []
    records = []
    lookups = []
    for step, lookup in enumerate((0, 0, 1)):
        leaf = step != 0
        ordinary.append(dict(lookup=lookup, step=step, input_bytes=4, descriptor_bytes=8))
        records.append(dict(lookup=lookup, step=step, leaf=int(leaf), inputs=4, descriptors=8,
                            equality=4, block_challenge=0, block_mask=0, column=0, mask=0, layer=0,
                            table_challenge=0, table=0, selector=0, coordinates=4, terms=4,
                            original_views=int(leaf), addressable_bytes=4 * int(leaf)))
        if leaf:
            lookups.append(dict(id=lookup, unique=1, legs=1, checked_bytes=4))
    return records, ordinary, lookups


class Transfers(unittest.TestCase):
    def test_matches_true_leaf_transfers(self):
        sums = check["account_inputs"](*schedule())
        self.assertEqual((sums["original_views"], sums["inputs"], sums["addressable_bytes"]), (2, 12, 8))

    def test_rejects_leaf_moved_to_early_round(self):
        records, ordinary, lookups = schedule()
        for key in ("leaf", "original_views", "addressable_bytes"):
            records[0][key], records[1][key] = records[1][key], records[0][key]
        with self.assertRaisesRegex(ValueError, "leaf schedule"):
            check["account_inputs"](records, ordinary, lookups)

    def test_rejects_offsets_that_cancel_in_input_partition(self):
        records, ordinary, lookups = schedule()
        records[0].update(equality=5, mask=-1)
        with self.assertRaisesRegex(ValueError, "negative"):
            check["account_inputs"](records, ordinary, lookups)
