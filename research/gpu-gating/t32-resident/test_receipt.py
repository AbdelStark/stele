"""Controls for the actual resident lookup and GKR lifetime receipts."""
import unittest

from receipt import check_resident_steps


class ResidentSteps(unittest.TestCase):
    def test_accepts_child_views_and_oversize_step_before_leaf(self):
        # The second nonleaf step in lookup zero is too large. It stays on CPU.
        steps = [(0, True, 0, 0), (1, False, 0, 0), (2, True, 0, None),
                 (3, True, 1, 1), (4, False, 1, None)]
        child = [{"step": 0, "id": 0, "views": 4, "view_bytes": 128, "retained_bytes": 192},
                 {"step": 3, "id": 1, "views": 2, "view_bytes": 64, "retained_bytes": 128}]
        self.assertEqual(check_resident_steps(steps, child, [192, 128]), (6, 192))

    def test_rejects_release_before_nonleaf_or_after_leaf(self):
        child = [{"step": 0, "id": 0, "views": 1, "view_bytes": 64, "retained_bytes": 96}]
        for held in ([0, None, None], [0, 0, 0], [1, 0, None]):
            steps = [(i, i != 1, 0, tree) for i, tree in enumerate(held)]
            with self.subTest(held=held), self.assertRaises(ValueError):
                check_resident_steps(steps, child, [96])

    def test_rejects_missing_and_misattributed_views(self):
        steps = [(0, True, 0, 0), (1, False, 0, None)]
        row = {"step": 0, "id": 0, "views": 1, "view_bytes": 64, "retained_bytes": 96}
        for children in ([], [row, row], [dict(row, retained_bytes=64)],
                         [dict(row, id=1)], [dict(row, view_bytes=0)]):
            with self.subTest(children=children), self.assertRaises(ValueError):
                check_resident_steps(steps, children, [96])
