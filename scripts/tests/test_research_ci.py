"""RFC-0020 §5: preserve the research inventory and reject incomplete CI runs."""
from contextlib import redirect_stderr, redirect_stdout
import hashlib
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

    def test_matches_reference_native_selection_and_command_union(self):
        groups = ci.load_groups()
        commands = [c for group in groups.values() for c in group]
        self.assertEqual((len(groups), len(commands), len(set(commands))), (76, 181, 181))
        legacy = [c for name, group in groups.items() if name != 'model-contract' for c in group]
        self.assertEqual(len(legacy), 180)
        self.assertEqual(hashlib.sha256(json.dumps(sorted(legacy), separators=(',', ':')).encode()).hexdigest(),
                         '8d60b4e68d8d7bf7dbb2872a02e7f8cec719ddfad59b6ee9c1c84810010ef790')
        selected = groups['native-comparisons']
        self.assertEqual(len(selected), 9)
        self.assertEqual([shlex.split(c)[4] for c in selected[:6]], [
            'harness/cqis/check_arithmetic.py', 'research/cqis-bounds/check_requant.py',
            'research/cqis-bounds/check_norm_bounds.py', 'research/cqis-bounds/check_encoding.py',
            'research/cqis-checkpoint/check_causal_model.py', 'research/cqis-checkpoint/check_causal_model.py'])
        self.assertTrue(selected[4].endswith('--model-norm'))
        self.assertTrue(selected[5].endswith('--model-functions'))
        self.assertEqual([c.split()[0] for c in selected[-3:]], ['curl', 'curl', 'uv'])
        for arguments, expected in [
            (['--matrix', '--selection', 'native'], ['native-comparisons']),
            (['--matrix', '--selection', 'stacked'], ['stacked-gkr']),
            (['--matrix', '--selection', 'native-stacked'], [g for g in groups if g in ('native-comparisons','stacked-gkr')]),
            *[(['--matrix', '--selection', name], [g for g in groups if g in subset])
              for name, subset in ci.SUBSETS.items() if 'model' in name],
            (['--matrix', '--selection', 'none'], []),
            (['--matrix', '--selection', 'all'], list(groups)),
            (['--full', '--matrix'], list(ci.load_groups(ci.FULL_MANIFEST))),
        ]:
            output = io.StringIO()
            with redirect_stdout(output):
                self.assertEqual(ci.main(arguments), 0)
            self.assertEqual(json.loads(output.getvalue().removeprefix('matrix=')), {'group': expected})

    def test_rejects_invalid_or_missing_selection(self):
        for args in (['--matrix', '--selection'], ['--matrix', '--selection', ''],
                     ['--matrix', '--selection', 'unknown'], ['--full', '--matrix', '--selection', 'native'],
                     ['--group', 'native-comparisons', '--selection', 'none']):
            with self.subTest(args=args), redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as error:
                ci.main(args)
            self.assertEqual(error.exception.code, 2)
        for groups in ({'other': ['true']}, {'native-comparisons': []}):
            with mock.patch.object(ci, 'load_groups', return_value=groups), redirect_stderr(io.StringIO()):
                self.assertNotEqual(ci.main(['--matrix', '--selection', 'native']), 0)
        for selection in ci.SUBSETS:
            for args in (['--full','--matrix','--selection',selection],['--group','stacked-gkr','--selection',selection]):
                with redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                    ci.main(args)
            for groups in ({'irrelevant':['true']},{'stacked-gkr':[]},{}):
                with mock.patch.object(ci,'load_groups',return_value=groups),redirect_stderr(io.StringIO()):
                    self.assertEqual(ci.main(['--matrix','--selection',selection]),1)
            for missing in ci.SUBSETS[selection]:
                groups = {name: ['true'] for name in ci.SUBSETS[selection] if name != missing}
                with mock.patch.object(ci,'load_groups',return_value=groups),redirect_stderr(io.StringIO()):
                    self.assertEqual(ci.main(['--matrix','--selection',selection]),1)
        with mock.patch.object(ci,'load_groups',return_value={'stacked-gkr':['true']}),redirect_stderr(io.StringIO()):
            self.assertEqual(ci.main(['--matrix','--selection','native-stacked']),1)

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

    def test_rejects_invalid_additional_inventory(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'model.json'
            for raw in ('{}', '[]', '{"typo":["true"]}', '{"native-comparisons":["true"]}',
                        '{"model-contract":[]}', '{"model-contract":["true"],"model-contract":["false"]}'):
                path.write_text(raw)
                with self.subTest(raw=raw), mock.patch.object(ci, 'MODEL_MANIFEST', path):
                    with self.assertRaises(ValueError):
                        ci.load_groups()

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

    def test_matches_reference_consolidated_inventories(self):
        # Migration snapshots include group names and ordered command sequences.
        for manifest, expected in (
            (ci.MANIFEST, '454f735df16fde56996a6118a4f6663933350220ea7963f753539d9ab26f349d'),
            (ci.FULL_MANIFEST, '0195261794103b7ebcc33aa5be6315d05d2a1a9fd43a209306aa3722cfb877ec'),
        ):
            groups = ci.load_groups(manifest)
            if manifest == ci.MANIFEST:
                self.assertEqual(groups.pop('model-contract'),
                                 ['uv run --locked --script research/cqis-model-contract/check_ci.py'])
            digest = hashlib.sha256(json.dumps(groups, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
            self.assertEqual(digest, expected, manifest.name)

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
