"""RFC-0020 §5: the native A4 gate rejects omitted evidence and accepting APIs."""
from contextlib import redirect_stdout
import importlib.util
import io
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location('stacked_gate', ROOT / 'scripts/gates/check.py')
gate = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(gate)
TESTS = (
    ('matches_reference_qm31_all_kinds', 'matches_reference_om31_all_kinds',
     'rejects_invalid_descriptors_and_resource_limits',
     'accepts_large_masks_and_scalar_axes_without_domain_allocation'),
    ('matches_reference_qm31_stacked_rounds_and_consumers',
     'matches_reference_om31_stacked_rounds_and_consumers',
     'rejects_preflight_without_transcript_mutation',
     'rejects_unaddressable_storage_before_any_transcript_work',
     'accepts_empty_constant_and_zero_coefficient_relations',
     'rejects_malformed_statements_sources_and_proofs'),
    ('rejects_wrong_layer_coefficient', 'rejects_changed_onehot_and_exact_table_source',
     'rejects_unused_original_at_draw_order_point',
     'rejects_missing_stack_or_sources_before_successor'),
)


class StackedGateTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        for name in ('crates/stele-gkr',):
            shutil.copytree(ROOT / name, self.root / name)
        for name in ('research/stacked-gkr/check_native_wire.py',
                     'research/stacked-gkr/check_native_wire.py.lock',
                     'tests/negative-controls/fixtures/stacked-public.sha256',
                     'tests/negative-controls/fixtures/stacked-certified.sha256'):
            target = self.root / name
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy(ROOT / name, target)
        self.outputs = ['\n'.join(f'test {name} ... ok' for name in names) for names in TESTS]
        self.outputs += [
            'test crates/stele-gkr/src/stacked/mod.rs - stacked::Record (line 40) - compile fail ... ok',
            'stacked native wire: 116 both-field decisions; complete frames/proofs/restored claims/SC/continuation agree; '
            + (self.root / 'tests/negative-controls/fixtures/stacked-public.sha256').read_text().strip()
            + '\nstacked certified wire: 48 both-field decisions; actual certificates/producer/openings/records/usage/continuation agree; '
            + (self.root / 'tests/negative-controls/fixtures/stacked-certified.sha256').read_text().strip(),
        ]

    def run_gate(self, outputs=None, failed=None):
        outputs = self.outputs if outputs is None else outputs
        results = [subprocess.CompletedProcess([], int(i == failed), text, '')
                   for i, text in enumerate(outputs)]
        with patch.object(gate.subprocess, 'run', side_effect=results) as run, redirect_stdout(io.StringIO()):
            gate.public_coefficients(self.root)
        return [call.args[0] for call in run.call_args_list]

    def test_accepts_only_complete_locked_native_evidence(self):
        commands = self.run_gate()
        self.assertEqual(len(commands), 5)
        self.assertEqual([c[c.index('--test') + 1] for c in commands[:3]],
                         ['public_mle', 'stacked', 'stacked-public'])
        self.assertIn('--doc', commands[3])
        self.assertEqual(commands[4], ['uv', 'run', '--locked', '--script',
                                       'research/stacked-gkr/check_native_wire.py'])
        self.assertTrue(all('--offline' in c and '--locked' in c for c in commands[:4]))

    def test_rejects_every_failure_and_missing_receipt(self):
        for i, output in enumerate(self.outputs):
            with self.subTest(failed_command=i), self.assertRaisesRegex(ValueError, 'checks failed'):
                self.run_gate(failed=i)
            for line in output.splitlines():
                altered = self.outputs.copy()
                altered[i] = output.replace(line, '')
                with self.subTest(missing=line), self.assertRaisesRegex(ValueError, 'checks failed'):
                    self.run_gate(altered)
        altered = self.outputs.copy()
        altered[3] = altered[3].replace('stacked::Record', 'unrelated::Boundary')
        with self.assertRaisesRegex(ValueError, 'missing opaque Record boundary'):
            self.run_gate(altered)
        altered = self.outputs.copy()
        digest = (self.root / 'tests/negative-controls/fixtures/stacked-certified.sha256').read_text().strip()
        altered[4] = altered[4].replace(digest, '0'*64)
        with self.assertRaisesRegex(ValueError, 'checks failed'):
            self.run_gate(altered)

    def test_rejects_missing_locked_checker_before_execution(self):
        for name in ('research/stacked-gkr/check_native_wire.py',
                     'research/stacked-gkr/check_native_wire.py.lock',
                     'tests/negative-controls/fixtures/stacked-public.sha256',
                     'tests/negative-controls/fixtures/stacked-certified.sha256'):
            path = self.root / name
            saved = path.read_bytes()
            path.unlink()
            with patch.object(gate.subprocess, 'run') as run:
                with self.assertRaisesRegex(ValueError, 'missing locked checker'):
                    gate.public_coefficients(self.root)
                run.assert_not_called()
            path.write_bytes(saved)

    def test_rejects_unreviewed_api_and_dependency_before_execution(self):
        for name, addition in (
            ('src/stacked/mod.rs', '\npub fn accept_unchecked() {}\n'),
            ('src/stacked/mod.rs', '\nimpl<K> From<Reduction<K>> for Record<K> {}\n'),
            ('src/stacked/mod.rs', '\ninclude!("unchecked.rs");\n'),
            ('src/stacked/statement.rs', '\npub struct Unchecked;\n'),
            ('src/stacked/strategy.rs', '\npub fn unchecked_point() {}\n'),
            ('Cargo.toml', '\nstele-pcs = { path = "../stele-pcs" }\n'),
        ):
            path = self.root / 'crates/stele-gkr' / name
            saved = path.read_text()
            path.write_text(saved.replace('[dependencies]', '[dependencies]' + addition)
                            if name == 'Cargo.toml' else saved + addition)
            with self.subTest(addition=addition), patch.object(gate.subprocess, 'run') as run:
                with self.assertRaisesRegex(ValueError, 'not wired'):
                    gate.public_coefficients(self.root)
                run.assert_not_called()
            path.write_text(saved)


if __name__ == '__main__':
    unittest.main()
