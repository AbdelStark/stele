"""E16-40a: incomplete or overlapping stage measurements cannot justify GPU costs."""
import importlib.util
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location('stage_inventory', ROOT/'research/gpu-gating/stage_inventory.py')
INVENTORY = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(INVENTORY)
SMOKE = (ROOT/'research/gpu-gating/fixtures/zk-stage-smoke.log').read_text()


class StageInventoryTests(unittest.TestCase):
    def test_accepts_actual_producer_topology_without_double_counting(self):
        log = SMOKE.replace('stage zk/logup_gkr 0', 'stage zk/logup_gkr 19')
        log = log.replace('stage zk/detail/gkr_rounds 0', 'stage zk/detail/gkr_rounds 3')
        result = INVENTORY.parse(log)
        gkr = result['phases']['zk/logup_gkr']
        self.assertEqual(gkr['parent_ms'], 19)
        self.assertEqual(gkr['children_ms']['gkr_rounds'], 12)
        self.assertEqual(gkr['unattributed_ms'], 7)
        kinds = {item['kind'] for item in result['shapes']}
        self.assertEqual(kinds, {'relation', 'gkr_first', 'gkr_interior', 'gkr_leaf'})

    def test_rejects_missing_or_duplicated_measurements(self):
        for needle in ('stage zk/detail/batch_opening 0\n', 'stage zk/logup_gkr 0\n',
                       'stage zk/detail/gkr_rounds 0\n'):
            with self.subTest(needle=needle), self.assertRaises(ValueError):
                INVENTORY.parse(SMOKE.replace(needle, '', 1))
        with self.assertRaises(ValueError):
            INVENTORY.parse(SMOKE + SMOKE)
        with self.assertRaises(ValueError):
            INVENTORY.parse('')

    def test_rejects_overlapping_time_and_unknown_detail(self):
        for log in (SMOKE.replace('stage zk/detail/gkr_rounds 0', 'stage zk/detail/gkr_rounds 1'),
                    SMOKE + 'stage zk/detail/unknown 0\n',
                    SMOKE.replace('stage zk/logup_gkr 0', 'stage zk/logup_gkr -1')):
            with self.subTest(log=log[-80:]), self.assertRaises(ValueError):
                INVENTORY.parse(log)

    def test_rejects_changed_or_extra_shape_fields(self):
        shape = next(s for s in SMOKE.splitlines() if s.startswith('shape '))
        for replacement in (shape + ' seed=123', shape.replace('field=4', 'field=3'),
                            shape.replace('terms=', 'terms=999,'), shape.replace('compact=0', 'compact=2')):
            with self.subTest(replacement=replacement), self.assertRaises(ValueError):
                INVENTORY.parse(SMOKE.replace(shape, replacement, 1))


if __name__ == '__main__':
    unittest.main()
