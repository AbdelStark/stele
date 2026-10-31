"""RFC-0020 §5: preserve the research inventory and reject incomplete CI runs."""
from contextlib import redirect_stderr, redirect_stdout
import importlib.util
import io
import json
import os
from pathlib import Path
import shlex
import subprocess
import sys
import tempfile
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
        for command in commands:
            argv = shlex.split(command)
            if argv[0] == 'curl':
                continue
            script = ROOT / argv[4 if argv[0] == 'uv' else 1]
            self.assertTrue(script.is_file(), command)
            if argv[0] == 'uv':
                self.assertTrue(Path(str(script) + '.lock').is_file(), command)

    def test_requires_reference_field_vectors_and_complete_consumers(self):
        self.assertEqual(ci.load_groups().get('reference-field'),
                         ['uv run --locked --script research/sumcheck/check_field.py --vectors --proofs'])

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

    def test_accepts_full_inventory_and_existing_scripts(self):
        groups = ci.load_groups(ci.FULL_MANIFEST)
        for commands in groups.values():
            for command in commands:
                argv = shlex.split(command)
                self.assertEqual(argv[:4], ['uv', 'run', '--locked', '--script'])
                self.assertTrue((ROOT / argv[4]).is_file(), command)
                self.assertTrue((ROOT / (argv[4] + '.lock')).is_file(), command)


if __name__ == '__main__':
    unittest.main()
