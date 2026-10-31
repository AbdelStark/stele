"""RFC-0020 §5: required checks cannot pass through missing/skipped results."""
import copy
import importlib.util
import itertools
from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location('ci_result', ROOT / 'scripts/ci_result.py')
result = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(result)


class ReadinessTests(unittest.TestCase):
    def test_rejects_each_incomplete_required_check(self):
        for flags in itertools.product(('true', 'false'), repeat=3):
            scope = dict(zip(('tables', 'research', 'gpu'), flags))
            needs = {'plan': {'result': 'success', 'outputs': scope},
                     'native': {'result': 'success'}}
            for job, name in (('table-parity', 'tables'), ('research', 'research'), ('gpu-parity', 'gpu')):
                needs[job] = {'result': 'success' if scope[name] == 'true' else 'skipped'}
            self.assertTrue(result.accepts(needs))
            for job in needs:
                for value in ('success', 'failure', 'cancelled', 'skipped', ''):
                    bad = copy.deepcopy(needs)
                    bad[job]['result'] = value
                    self.assertEqual(result.accepts(bad), value == needs[job]['result'], (flags, job, value))
                bad = copy.deepcopy(needs)
                del bad[job]
                self.assertFalse(result.accepts(bad))
            for name in scope:
                for value in ('', 'maybe', None):
                    bad = copy.deepcopy(needs)
                    bad['plan']['outputs'][name] = value
                    self.assertFalse(result.accepts(bad))
        self.assertFalse(result.accepts({}))

    def test_requires_readiness_and_complete_table_partition(self):
        text = (ROOT / '.github/workflows/ci.yml').read_text()
        self.assertIn('ready_for_review, converted_to_draft', text)
        self.assertIn("if: github.event_name != 'pull_request' || github.event.pull_request.draft == false", text)
        self.assertIn('needs: [plan, native, table-parity, research, gpu-parity]', text)
        self.assertIn('NEEDS: ${{ toJSON(needs) }}', text)
        self.assertIn('run: python3 scripts/ci_result.py', text)
        shards = re.search(r'^        shard: \[([^]]+)\]', text, re.M)
        self.assertIsNotNone(shards)
        oracle = (ROOT / 'crates/stele-cqis/tests/support/table_mle.rs').read_text()
        count = re.search(r'pub const CASES: [^\n]*;\s*(\d+)\]', oracle)
        self.assertIsNotNone(count)
        self.assertEqual([int(x) for x in shards[1].split(',')], list(range(2 * int(count[1]))))
        self.assertNotIn('continue-on-error', text)


if __name__ == '__main__':
    unittest.main()
