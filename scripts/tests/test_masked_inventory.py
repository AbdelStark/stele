"""RFC-0014 §5: an incomplete public inventory cannot qualify masked kernels."""
import copy
import importlib.util
import json
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT/'research/gpu-gating'))
SPEC = importlib.util.spec_from_file_location('masked_inventory', ROOT/'research/gpu-gating/masked_inventory.py')
EXPORT = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(EXPORT)
LEDGER = json.loads((ROOT/'bench/ledger/e16-40a-dev-zk-stories42m-t32-h100-0.json').read_text())


class MaskedInventoryTests(unittest.TestCase):
    def test_accepts_complete_merged_inventory(self):
        lines = EXPORT.export(LEDGER).splitlines()
        self.assertEqual(lines[0], 'masked-shapes-v1 64')
        self.assertEqual(len(lines), 65)
        self.assertTrue(any('degree=7' in line for line in lines))
        self.assertTrue(any('compact=1' in line for line in lines))

    def test_rejects_missing_duplicate_or_unaccounted_shapes(self):
        for mutate in (lambda s: s.pop(), lambda s: s.append(s[0]),
                       lambda s: s[0].update(count=0), lambda s: s[0].update(count=True),
                       lambda s: s[0].update(field=8), lambda s: s[0].update(secret=7)):
            ledger = copy.deepcopy(LEDGER)
            mutate(ledger['model_config']['stage_inventory']['shapes'])
            with self.assertRaises(ValueError):
                EXPORT.export(ledger)

    def test_rejects_wrong_declared_count_or_disabled_binding(self):
        ledger = copy.deepcopy(LEDGER)
        ledger['model_config']['stage_inventory']['declared']['gkr'] += 1
        with self.assertRaises(ValueError):
            EXPORT.export(ledger)
        ledger = copy.deepcopy(LEDGER)
        ledger['bindings_all_on'] = False
        with self.assertRaises(ValueError):
            EXPORT.export(ledger)


if __name__ == '__main__':
    unittest.main()
