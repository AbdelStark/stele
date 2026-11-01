"""RFC-0023 §2.1: independently regenerate complete native layout fixtures."""
import importlib.util
from pathlib import Path
import sys
import unittest

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location('requant_schema', ROOT/'tests/negative-controls/requant_schema.py')
REF = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = REF
SPEC.loader.exec_module(REF)


class RequantSchemaTests(unittest.TestCase):
    def test_matches_reference_complete_fixtures(self):
        self.assertEqual((ROOT/'crates/stele-reductions/tests/fixtures/requant-schema.txt').read_text(), REF.fixtures())

    def test_rejects_invalid_parameters(self):
        for params in ((0,0,8), (65536,0,8), (1,63,8), (1,0,32)):
            with self.subTest(params=params), self.assertRaisesRegex(ValueError, 'Spec'):
                REF.Schema(*params)

    def test_accepts_full_width_tail_and_zero_columns(self):
        schema = REF.Schema(1,0,8)
        cap = schema.result_caps['division']
        self.assertEqual((cap.cap, len(cap.rows)), (256,4))
        self.assertIs(cap.rows, schema.blocks['t'].rows)
        self.assertGreater(65537, cap.cap)
        schema = REF.Schema(1,62,16)
        self.assertEqual((schema.blocks['q'].cap, len(schema.blocks['q'].rows)), (0,1))
        self.assertEqual(len(schema.static['columns']['quotient_product']['result_caps']), 8)
