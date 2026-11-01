"""RFC-0018 §1: ledger admission must retain all consumers, accounting and costs."""
import copy
import importlib.util
import json
from pathlib import Path
import subprocess
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('fraction_bench',ROOT/'bench/fraction.py')
bench = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bench)
gate_spec = importlib.util.spec_from_file_location('fraction_gate', ROOT/'scripts/gates/check.py')
gate = importlib.util.module_from_spec(gate_spec)
gate_spec.loader.exec_module(gate)


class FractionBenchTests(unittest.TestCase):
    def test_rejects_missing_actual_work_observations(self):
        existing = ('matches_reference_qm31_fraction_codec','matches_reference_om31_fraction_codec',
            'rejects_fraction_codec_boundaries','accepts_maximum_verifier_shape_without_domain_allocation',
            'accepts_qm31_fraction_tree_original_consumers','accepts_om31_fraction_tree_original_consumers',
            'rejects_fraction_tree_source_shape_and_poles','rejects_qm31_leaf_codec_boundaries',
            'rejects_om31_leaf_codec_boundaries','matches_reference_qm31_selected_product_codec',
            'matches_reference_om31_selected_product_codec','accepts_qm31_selected_product_original_consumers',
            'accepts_om31_selected_product_original_consumers','rejects_selected_product_context_and_source_shapes')
        observed = ('matches_reference_qm31_fraction_work','matches_reference_om31_fraction_work',
                    'rejects_qm31_measured_fraction_failures','rejects_om31_measured_fraction_failures')
        for missing in (*observed, None):
            output = '\n'.join(f'test {name} ... ok' for name in existing+observed if name != missing)
            result = subprocess.CompletedProcess([], int(missing is None), output, '')
            with mock.patch.object(gate.subprocess, 'run', return_value=result) as run:
                with self.assertRaisesRegex(ValueError, 'fraction codec checks failed'):
                    gate.fraction_reductions(ROOT)
                run.assert_called_once_with(['cargo','test','-p','stele-lookup','--locked','--offline'],
                                            cwd=ROOT,text=True,capture_output=True)

    def test_rejects_missing_obligations_and_underreported_costs(self):
        for field, degree in [('QM31',4),('OM31',8)]:
            case = dict(m=3,mode='selected3zero')
            output = subprocess.check_output(['cargo','run','-q','-p','stele-lookup','--example','fraction_bench',
                '--locked','--offline','--',field,'3',case['mode']],cwd=ROOT,text=True)
            row = json.loads(output)
            bench.validate(row,case,degree)
            for key, changed in [('leaf_claim_ids',[91,92]),('tree_claim_ids',[11]),('complete_ns',0),
                                 ('original_capacity_bytes',0),('encoded_capacity_bytes',0),('canonical','')]:
                with self.subTest(field=field,key=key):
                    bad = copy.deepcopy(row)
                    bad[key] = changed
                    with self.assertRaises(AssertionError):
                        bench.validate(bad,case,degree)
            for key in ('gamma','fold'):
                bad = copy.deepcopy(row)
                bad['accounting'][key] = 0
                with self.assertRaises(AssertionError):
                    bench.validate(bad,case,degree)


if __name__ == '__main__':
    unittest.main()
