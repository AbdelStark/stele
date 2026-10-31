"""RFC-0020 §5: preserve the research inventory and reject incomplete CI runs."""
import ast
from contextlib import redirect_stderr, redirect_stdout
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import re
import shlex
import subprocess
import sys
import tempfile
import textwrap
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / 'scripts/research_ci.py'
SPEC = importlib.util.spec_from_file_location('research_ci', SCRIPT)
ci = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(ci)


class ResearchCiTests(unittest.TestCase):
    def test_matches_reference_command_inventory(self):
        commands = [command for group in ci.load_groups().values() for command in group]
        # Independent snapshot: inventory through full-capacity attention base.
        self.assertEqual(len(commands), 153)
        digest = hashlib.sha256(json.dumps(sorted(commands), separators=(',', ':')).encode()).hexdigest()
        self.assertEqual(digest, 'fc63de891885474fe787e6eab3791eeecafca5cbd5dc28ac14afce16eb0fef1a')
        for command in commands:
            argv = shlex.split(command)
            if argv[0] == 'curl':
                continue
            script = ROOT / argv[4 if argv[0] == 'uv' else 1]
            self.assertTrue(script.is_file(), command)
            if argv[0] == 'uv':
                self.assertTrue(Path(str(script) + '.lock').is_file(), command)

    def test_accepts_complete_matrix(self):
        output = io.StringIO()
        with redirect_stdout(output):
            self.assertEqual(ci.main(['--matrix']), 0)
        self.assertEqual(json.loads(output.getvalue().removeprefix('matrix=')),
                         {'group': list(ci.load_groups())})

    def test_rejects_invalid_manifest(self):
        cases = ('{}', '[]', '{"group":[]}', '{"bad name":["true"]}',
                 '{"group":[""]}', '{"group":[1]}', '{"group":[{}]}',
                 '{"a":["true"],"b":["true"]}',
                 '{"a":["true"],"a":["false"]}')
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'checks.json'
            for raw in cases:
                with self.subTest(raw=raw):
                    path.write_text(raw)
                    with self.assertRaises(ValueError):
                        ci.load_groups(path)

    def test_rejects_unknown_group(self):
        result = subprocess.run([sys.executable, str(SCRIPT), '--group', 'unknown; exit 0'],
                                capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn('RUN ', result.stdout)

    def test_rejects_command_failure_and_preserves_environment(self):
        with tempfile.TemporaryDirectory(prefix='research ci ') as directory:
            commands = ['pwd > "$RUNNER_TEMP/cwd"',
                        'printf \'%s\' "$RUNNER_TEMP" > "$RUNNER_TEMP/environment"',
                        'exit 23', 'touch "$RUNNER_TEMP/after"']
            with mock.patch.object(ci, 'load_groups', return_value={'probe': commands}), \
                    mock.patch.dict(os.environ, {'RUNNER_TEMP': directory}), \
                    redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                self.assertEqual(ci.main(['--group', 'probe']), 23)
            self.assertEqual(Path(directory, 'environment').read_text(), directory)
            self.assertEqual(Path(Path(directory, 'cwd').read_text().strip()).resolve(), ROOT)
            self.assertFalse(Path(directory, 'after').exists())

    def test_rejects_masked_pipeline_failure(self):
        with mock.patch.object(ci, 'load_groups', return_value={'probe': ['false | true']}), \
                redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            self.assertNotEqual(ci.main(['--group', 'probe']), 0)

    def test_rejects_missing_checkpoint_directory(self):
        for directory in ('', 'relative'):
            with self.subTest(directory=directory), \
                    mock.patch.dict(os.environ, {'RUNNER_TEMP': directory}), \
                    mock.patch.object(ci.subprocess, 'run') as run:
                with self.assertRaisesRegex(ValueError, 'RUNNER_TEMP'):
                    ci.run_group('probe', {'probe': ['touch "$RUNNER_TEMP/checkpoint"']})
                run.assert_not_called()

    def test_matches_reference_download_order(self):
        for prefix in ('causal', 'cqis-source'):
            matches = [group for group in ci.load_groups().values()
                       if any(f'$RUNNER_TEMP/{prefix}' in command for command in group)]
            self.assertEqual(len(matches), 1)
            sequence = [command for command in matches[0] if f'$RUNNER_TEMP/{prefix}' in command]
            self.assertEqual([command.split()[0] for command in sequence],
                             ['curl', 'curl', 'uv'] if prefix == 'causal' else ['curl', 'uv', 'uv'])

    def test_rejects_incomplete_required_gates(self):
        workflow = (ROOT / '.github/workflows/ci.yml').read_text()
        block = re.search(r'^  gates:\n(.*?)(?=^  [a-z]|\Z)', workflow, re.M | re.S).group(1)
        self.assertIn('needs: [plan, native, research, range-capacity, norm-product-full, norm-sign-full, norm-statistic-full, norm-quotient-product-full, norm-bias-full, norm-division-full, norm-left-full, norm-signed-output-full, norm-configured-output-full, norm-composition-full, residual-aligned-full, residual-sign-full, residual-rounding-full, residual-composition-full, rotary-consumer-full, attention-maximum-full, attention-index-full, attention-exp-full, attention-probability-sum-full, attention-values-full, attention-offset-sum-full, attention-base-full, attention-sign-full, attention-block-rounding-full, attention-block-sum-full, attention-block-total-sign-full, attention-global-probability-sum-full]', block)
        self.assertIn('if: always()', block)
        self.assertIn('gpu: ${{ needs.plan.outputs.gpu }}', block)
        self.assertIn('PLAN_RESULT: ${{ needs.plan.result }}', block)
        self.assertIn('NATIVE_RESULT: ${{ needs.native.result }}', block)
        self.assertIn('RESEARCH_RESULT: ${{ needs.research.result }}', block)
        self.assertIn('CAPACITY_RESULT: ${{ needs.range-capacity.result }}', block)
        self.assertIn('PRODUCT_RESULT: ${{ needs.norm-product-full.result }}', block)
        self.assertIn('SIGN_RESULT: ${{ needs.norm-sign-full.result }}', block)
        self.assertIn('GLOBAL_PROBABILITY_SUM_RESULT: ${{ needs.attention-global-probability-sum-full.result }}', block)
        self.assertIn('ATTN_BLOCK_TOTAL_SIGN_RESULT: ${{ needs.attention-block-total-sign-full.result }}', block)
        self.assertIn('ATTN_BLOCK_SUM_RESULT: ${{ needs.attention-block-sum-full.result }}', block)
        self.assertIn('ATTENTION_BLOCK_ROUNDING_RESULT: ${{ needs.attention-block-rounding-full.result }}', block)
        self.assertIn('ATTENTION_SIGN_RESULT: ${{ needs.attention-sign-full.result }}', block)
        self.assertIn('ATTENTION_BASE_RESULT: ${{ needs.attention-base-full.result }}', block)
        self.assertIn('ATTENTION_OFFSET_SUM_RESULT: ${{ needs.attention-offset-sum-full.result }}', block)
        self.assertIn('ATTENTION_VALUES_RESULT: ${{ needs.attention-values-full.result }}', block)
        self.assertIn('PROBABILITY_SUM_RESULT: ${{ needs.attention-probability-sum-full.result }}', block)
        self.assertIn('ATTENTION_EXP_RESULT: ${{ needs.attention-exp-full.result }}', block)
        self.assertIn('ATTENTION_INDEX_RESULT: ${{ needs.attention-index-full.result }}', block)
        self.assertIn('ATTENTION_MAXIMUM_RESULT: ${{ needs.attention-maximum-full.result }}', block)
        self.assertIn('ROTARY_CONSUMER_RESULT: ${{ needs.rotary-consumer-full.result }}', block)
        self.assertIn('RESIDUAL_COMPOSITION_RESULT: ${{ needs.residual-composition-full.result }}', block)
        self.assertIn('RESIDUAL_ROUNDING_RESULT: ${{ needs.residual-rounding-full.result }}', block)
        self.assertIn('RESIDUAL_SIGN_RESULT: ${{ needs.residual-sign-full.result }}', block)
        self.assertIn('RESIDUAL_ALIGNED_RESULT: ${{ needs.residual-aligned-full.result }}', block)
        self.assertIn('COMPOSITION_RESULT: ${{ needs.norm-composition-full.result }}', block)
        self.assertIn('CONFIGURED_OUTPUT_RESULT: ${{ needs.norm-configured-output-full.result }}', block)
        self.assertIn('SIGNED_OUTPUT_RESULT: ${{ needs.norm-signed-output-full.result }}', block)
        self.assertIn('LEFT_RESULT: ${{ needs.norm-left-full.result }}', block)
        self.assertIn('DIVISION_RESULT: ${{ needs.norm-division-full.result }}', block)
        self.assertIn('BIAS_RESULT: ${{ needs.norm-bias-full.result }}', block)
        self.assertIn('STATISTIC_RESULT: ${{ needs.norm-statistic-full.result }}', block)
        self.assertIn('QUOTIENT_RESULT: ${{ needs.norm-quotient-product-full.result }}', block)
        script = textwrap.dedent(block.split('        run: |\n')[1])
        names = ('PLAN_RESULT', 'NATIVE_RESULT', 'RESEARCH_RESULT', 'CAPACITY_RESULT', 'PRODUCT_RESULT', 'SIGN_RESULT', 'STATISTIC_RESULT', 'QUOTIENT_RESULT', 'BIAS_RESULT', 'DIVISION_RESULT', 'LEFT_RESULT', 'SIGNED_OUTPUT_RESULT', 'CONFIGURED_OUTPUT_RESULT', 'COMPOSITION_RESULT', 'RESIDUAL_ALIGNED_RESULT', 'RESIDUAL_SIGN_RESULT', 'RESIDUAL_ROUNDING_RESULT', 'RESIDUAL_COMPOSITION_RESULT', 'ROTARY_CONSUMER_RESULT', 'ATTENTION_MAXIMUM_RESULT', 'ATTENTION_INDEX_RESULT', 'ATTENTION_EXP_RESULT', 'PROBABILITY_SUM_RESULT', 'ATTENTION_VALUES_RESULT', 'ATTENTION_OFFSET_SUM_RESULT', 'ATTENTION_BASE_RESULT', 'ATTENTION_SIGN_RESULT', 'ATTENTION_BLOCK_ROUNDING_RESULT', 'ATTN_BLOCK_SUM_RESULT', 'ATTN_BLOCK_TOTAL_SIGN_RESULT', 'GLOBAL_PROBABILITY_SUM_RESULT')
        outcomes = ('success', 'failure', 'cancelled', 'skipped', '')
        baseline = dict.fromkeys(names, 'success')
        cases = [dict(baseline, **{name: outcome}) for name in names for outcome in outcomes]
        cases += [dict.fromkeys(names, outcome) for outcome in outcomes]
        for results in cases:
            result = subprocess.run(['bash', '-e', '-c', script], capture_output=True,
                                    env={**os.environ, **results})
            self.assertEqual(result.returncode == 0, all(value == 'success' for value in results.values()))
        self.assertIn('research: ${{ steps.research.outputs.matrix }}', workflow)
        self.assertIn('matrix: ${{ fromJSON(needs.plan.outputs.research) }}', workflow)
        self.assertIn('fail-fast: false', workflow)
        for name in ('native', 'research'):
            job = re.search(r'^  '+name+r':\n(.*?)(?=^  [a-z]|\Z)', workflow, re.M | re.S).group(1)
            self.assertIn('needs: plan', job)


    def test_matches_reference_full_capacity_jobs(self):
        workflow = (ROOT / '.github/workflows/ci.yml').read_text()
        block = re.search(r'^  range-capacity:\n(.*?)(?=^  [a-z]|\Z)', workflow, re.M | re.S).group(1)
        self.assertIn('name: range-capacity-${{ matrix.mode }}', block)
        self.assertIn('mode: [wide, signed, normxy]', block)
        self.assertIn('fail-fast: false', block)
        self.assertNotIn('if:', block)
        self.assertNotIn('continue-on-error', block)
        self.assertIn('uv run --locked --script research/cqis-bounds/check_range_capacity.py --${{ matrix.mode }}', block)
        commands = [command for group in ci.load_groups().values() for command in group]
        self.assertEqual([command for command in commands if 'check_range_capacity.py' in command],
                         ['uv run --locked --script research/cqis-bounds/check_range_capacity.py --shapes'])


    def test_matches_reference_full_consumer_modes(self):
        workflow = (ROOT / '.github/workflows/ci.yml').read_text()
        matrix_modes = {'attention-block-sum': ('maximum', 'full-blocks', 'full-wide'),
                        'attention-block-rounding': ('maximum', 'full-blocks', 'full-wide'),
                        'attention-offset-sum': ('maximum', 'full-keys', 'full-wide'),
                        'attention-values': ('maximum', 'full-static'),
                        'attention-exp': ('maximum', 'full-direct', 'full-corrected'),
                        'left': ('maximum', 'full-nonzero'),
                        'configured-output': ('maximum', 'full-left', 'full-right'),
                        'composition': ('maximum', 'full-left', 'full-right')}
        for name, suffix, flags in (('product', 'product', '--corpus --honest --controls --boundaries --composition --offset-bound'),
                                    ('sign', 'sign', '--corpus --honest --controls --boundaries --composition'),
                                    ('statistic', 'statistic_full', '--corpus --honest --controls --boundaries --composition --tails'),
                                    ('quotient-product', 'quotient_product', '--corpus --honest --controls --boundaries --composition --middle'),
                                    ('bias', 'bias', '--corpus --honest --controls --boundaries --composition'),
                                    ('division', 'division', '--corpus --honest --controls --boundaries --composition --aliases'),
                                    ('left', 'left', '--corpus --honest --controls --boundaries --composition'),
                                    ('signed-output', 'signed_output', '--corpus --honest --controls --zeros --boundaries --composition'),
                                    ('configured-output', 'configured_output', '--corpus --honest --controls --zeros'),
                                    ('composition', 'composition', '--corpus --controls --zero-exponent --honest4r1 --honest4r2 --honest8r1 --honest8r2'),
                                    ('residual-aligned', 'aligned', '--corpus --controls --boundaries --honest --no-carry'),
                                    ('residual-sign', 'sign', '--corpus --controls --boundaries --composition --honest'),
                                    ('residual-rounding', 'rounding', '--corpus --controls --boundaries --composition --honest'),
                                    ('residual-composition', 'composition', '--corpus --controls --zeros --boundaries --honest'),
                                    ('rotary-consumer', 'consumer', '--corpus --controls --originals --boundaries --honest'),
                                    ('attention-maximum', 'maximum', '--corpus --controls --originals --boundaries --honest'),
                                    ('attention-index', 'exp_index', '--corpus --controls --originals --boundaries --composition --honest'),
                                    ('attention-exp', 'exp', '--corpus --controls --originals --boundaries --tables --branches --arithmetic --composition --honest'),
                                    ('attention-probability-sum', 'probability_sum', '--corpus --controls --originals --boundaries --composition --honest'),
                                    ('attention-values', 'values', '--corpus --controls --originals --boundaries --edge-controls --composition --honest'),
                                    ('attention-offset-sum', 'offset_sum', '--corpus --controls --originals --boundaries --composition --honest'),
                                    ('attention-base', 'base', '--corpus --controls --boundaries --composition --honest'),
                                    ('attention-sign', 'sign', '--corpus --controls --boundaries --composition --honest'),
                                    ('attention-block-rounding', 'block_rounding', '--corpus --controls --boundaries --composition --honest'),
                                    ('attention-block-sum', 'block_sum', '--corpus --controls --boundaries --composition --honest'),
                                    ('attention-block-total-sign', 'block_total_sign', '--corpus --controls --boundaries --composition --honest'),
                                    ('attention-global-probability-sum', 'global_probability_sum', '--corpus --controls --boundaries --composition --honest')):
            prefix = name.split('-')[0] if name.startswith(('residual-', 'rotary-', 'attention-')) else 'norm'
            job = name if prefix != 'norm' else 'norm-' + name
            block = re.search(r'^  '+job+r'-full:\n(.*?)(?=^  [a-z]|\Z)', workflow, re.M | re.S).group(1)
            self.assertNotIn('if:', block)
            self.assertNotIn('continue-on-error', block)
            script = f'research/cqis-bounds/check_{prefix}_{suffix}.py'
            command = 'uv run --locked --script ' + script
            full = matrix_modes.get(name, ('maximum',))
            if name in matrix_modes:
                self.assertIn('name: '+job+'-${{ matrix.mode }}', block)
                self.assertIn('mode: ['+', '.join(full)+']', block)
                self.assertIn('fail-fast: false', block)
                self.assertIn(command + ' --${{ matrix.mode }}', block)
            else:
                self.assertIn(command + ' --maximum', block)
            normal = [line for lines in ci.load_groups().values() for line in lines if script in line]
            expected = [command + ' ' + flags]
            if name == 'composition':
                expected = [command + ' --corpus --controls --zero-exponent']
                expected += [command + ' --honest' + mode for mode in ('4r1', '4r2', '8r1', '8r2')]
            self.assertEqual(normal, expected)
            tree = ast.parse((ROOT / script).read_text())
            guard = ast.dump(ast.parse("__name__ == '__main__'", mode='eval').body)
            entrypoints = [node for node in tree.body if isinstance(node, ast.If)
                           and ast.dump(node.test) == guard]
            self.assertEqual(len(entrypoints), 1)
            modes = [node.value for node in entrypoints[0].body if isinstance(node, ast.Assign)
                     and any(isinstance(target, ast.Name) and target.id == 'modes' for target in node.targets)]
            self.assertEqual(len(modes), 1)
            self.assertIsInstance(modes[0], ast.Dict)
            self.assertEqual({key.value for key in modes[0].keys}, {mode for line in normal for mode in shlex.split(line)[5:]} | {'--'+mode for mode in full})


if __name__ == '__main__':
    unittest.main()
