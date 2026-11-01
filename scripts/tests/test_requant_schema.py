"""RFC-0023 §§2.1-2.2: independent complete layouts, ordered terms and equations."""
import importlib.util
from math import prod
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

    def test_matches_reference_constraint_fixtures(self):
        self.assertEqual((ROOT/'crates/stele-reductions/tests/fixtures/requant-constraints.txt').read_text(), REF.constraint_fixtures())

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

    def test_matches_reference_equations_and_single_value_tampers(self):
        cases = [((1,0,8), (0,1,-1,127,-128)), ((1,1,8), (-3,-1,0,1,3)),
                 ((1,2,8), (-1,1)), ((65535,32,16), (-(1 << 31),(1 << 31)-1)),
                 ((1,62,16), (-(1 << 31),0,(1 << 31)-1)), ((65535,0,16), (0,))]
        def evaluate(terms, row):
            return sum(c*prod(row[f] for f in factors) for c, factors in terms) % ((1 << 31)-1)
        zero_factor_seen = False
        for params, inputs in cases:
            schema = REF.Schema(*params)
            equations = schema.constraints()
            caps = list(schema.blocks.values())+list(schema.result_caps.values())
            roles = schema.static['columns'].values()
            expected_j = schema.R+13+sum(2*len(b.rows)-1 for b in caps)+sum(len(r['result_caps']) for r in roles)
            self.assertEqual(len(equations), expected_j)
            self.assertEqual(max(len(f) for _, terms in equations for _, f in terms), 3)
            self.assertEqual(equations[0], ('sign.Boolean', [(1,(0,5,5)), (-1,(0,5))]))
            zero_factor_seen |= any(c == 0 and len(f) == 2 for _, terms in equations for c, f in terms)
            for acc in inputs:
                row = schema.witness(acc)
                self.assertEqual(len(row), 5+schema.R)
                for name, terms in equations:
                    self.assertEqual(evaluate(terms,row), 0, (params,acc,name))
            padding = [0]*(5+schema.R)
            self.assertTrue(all(evaluate(t,padding) == 0 for _, t in equations))
            for ordinal, name in [(1,'input.padding[0]'), (5,'advice.padding[0]'),
                                  (5+schema.L,f'advice.zero[{schema.L}]')]:
                changed = padding.copy(); changed[ordinal] = 1
                self.assertNotEqual(evaluate(dict(equations)[name],changed), 0)
            changed = padding.copy(); changed[0] = changed[5+schema.L] = 1
            self.assertNotEqual(evaluate(dict(equations)[f'advice.zero[{schema.L}]'],changed), 0)
        self.assertTrue(zero_factor_seen)
        schema = REF.Schema(1,0,8)
        equations = dict(schema.constraints())
        row = schema.witness(1)
        changes = [(1,0,'input_lhs.column[0]'),
                   (5+schema.blocks['w0'].rows[0],2,'input_rhs.column[0]'),
                   (5+schema.blocks['v'].carry[0],2,'v.cap.Boolean[0]'),
                   (5+schema.role_carries['product'][0].rows[0],1,'product.column[0]'),
                   (5+schema.u_carries[0],2,'u-add.Boolean[0]'),
                   (5+schema.blocks['q'].rows[0],128,'target')]
        for ordinal, value, name in changes:
            changed = row.copy(); self.assertNotEqual(changed[ordinal],value); changed[ordinal] = value
            self.assertNotEqual(evaluate(equations[name],changed), 0, name)
        changed = schema.witness(0); changed[5] = 1
        self.assertNotEqual(evaluate(equations['u-add.column[0]'],changed), 0)
        changed = row.copy(); changed[5+schema.blocks['t'].rows[2]] = 1
        for k in range(2):
            self.assertEqual(evaluate(equations[f'division.column[{k}]'],changed), 0)
        self.assertNotEqual(evaluate(equations['division.result.cap.column[2]'],changed), 0)
