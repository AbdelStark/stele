"""Controls for the actual resident lookup and GKR lifetime receipts."""
import unittest

from receipt import check_resident_steps


class ResidentSteps(unittest.TestCase):
    def test_accepts_child_views_and_oversize_step_before_leaf(self):
        # The second nonleaf step in lookup zero is too large. It stays on CPU.
        steps = [(0, True, 0, 0, 1), (1, False, 0, 0, 3), (2, True, 0, None, 4),
                 (3, True, 1, 1, 1), (4, False, 1, None, 3)]
        child = [{"step": 0, "id": 0, "views": 4, "view_bytes": 512, "retained_bytes": 992},
                 {"step": 3, "id": 1, "views": 4, "view_bytes": 512, "retained_bytes": 480}]
        self.assertEqual(check_resident_steps(steps, child, [992, 480]), (8, 1024))

    def test_rejects_release_before_nonleaf_or_after_leaf(self):
        child = [{"step": 0, "id": 0, "views": 4, "view_bytes": 512, "retained_bytes": 480}]
        for held in ([0, None, None], [0, 0, 0], [1, 0, None]):
            steps = [(i, i != 1, 0, tree, [1, 3, 4][i]) for i, tree in enumerate(held)]
            with self.subTest(held=held), self.assertRaises(ValueError):
                check_resident_steps(steps, child, [992])

    def test_rejects_missing_and_misattributed_views(self):
        steps = [(0, True, 0, 0, 1), (1, False, 0, None, 3)]
        row = {"step": 0, "id": 0, "views": 4, "view_bytes": 512, "retained_bytes": 480}
        for children in ([], [row, row], [dict(row, retained_bytes=64)],
                         [dict(row, id=1)], [dict(row, views=3)], [dict(row, view_bytes=480)]):
            with self.subTest(children=children), self.assertRaises(ValueError):
                check_resident_steps(steps, children, [480])
