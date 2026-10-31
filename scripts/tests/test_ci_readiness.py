"""RFC-0020 §5: draft scheduling cannot produce a successful merge gate."""
import os
from pathlib import Path
import re
import subprocess
import textwrap
import unittest


WORKFLOW = Path(__file__).resolve().parents[2] / '.github/workflows/ci.yml'


class ReadinessTests(unittest.TestCase):
    def setUp(self):
        self.text = WORKFLOW.read_text()
        self.jobs = dict(re.findall(r'^  ([a-z][a-z0-9-]*):\n(.*?)(?=^  [a-z]|\Z)',
                                    self.text.split('jobs:\n', 1)[1], re.M | re.S))

    def test_requires_full_run_when_pr_becomes_ready(self):
        events = re.search(r'^  pull_request:\n    types: \[([^]]+)\]', self.text, re.M)
        self.assertIsNotNone(events)
        self.assertEqual(set(events[1].split(', ')),
                         {'opened', 'synchronize', 'reopened', 'ready_for_review', 'converted_to_draft'})
        self.assertIn("    if: github.event_name != 'pull_request' || github.event.pull_request.draft == false\n",
                      self.jobs['plan'])

    def test_requires_plan_before_expensive_checks(self):
        for name, job in self.jobs.items():
            with self.subTest(job=name):
                if name in {'plan', 'gates'}:
                    continue
                if name in {'simd-throughput', 'gpu-parity'}:
                    self.assertIn('    needs: gates\n', job)
                elif name == 'nightly-w1':
                    self.assertIn("    if: github.event_name == 'schedule'\n", job)
                else:
                    self.assertIn('    needs: plan\n', job)

    def test_rejects_draft_and_each_incomplete_prerequisite(self):
        gate = self.jobs['gates']
        self.assertIn('    if: always()\n', gate)
        names = re.findall(r'^          ([A-Z_]+_RESULT):', gate, re.M)
        self.assertTrue(names)
        script = textwrap.dedent(gate.split('        run: |\n', 1)[1])

        def accepts(values):
            result = subprocess.run(['bash', '-e', '-c', script], capture_output=True,
                                    env={**os.environ, **dict(zip(names, values))})
            return result.returncode == 0

        self.assertTrue(accepts(['success'] * len(names)))
        self.assertFalse(accepts(['skipped'] * len(names)))
        for index in range(len(names)):
            for failure in ('failure', 'cancelled', 'skipped', ''):
                values = ['success'] * len(names)
                values[index] = failure
                with self.subTest(prerequisite=names[index], result=failure):
                    self.assertFalse(accepts(values))


if __name__ == '__main__':
    unittest.main()
