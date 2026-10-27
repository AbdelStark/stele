"""RFC-0020 §5: real gate entry points must reject synthetic violations."""
import pathlib
import shutil
import subprocess
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[2]
GATES = ('digest', 'negative-controls', 'soundness-accounting', 'parity',
         'ledger-validate', 'rfc-status', 'docs-links')


class GateTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = pathlib.Path(self.directory.name)
        for name in ('scripts', 'crates', 'docs', 'tests', 'bench'):
            shutil.copytree(ROOT / name, self.root / name)
        for name in ('README.md', 'Cargo.toml', 'Cargo.lock'):
            shutil.copy(ROOT / name, self.root / name)

    def run_gate(self, gate):
        return subprocess.run(['bash', str(self.root / 'scripts/gates' / f'{gate}.sh')],
                              cwd='/', text=True, capture_output=True)

    def test_accepts_empty_scaffold(self):
        for gate in GATES:
            with self.subTest(gate=gate):
                result = self.run_gate(gate)
                self.assertEqual(result.returncode, 0, result.stderr)

    def test_rejects_unvalidated_implementation(self):
        for gate, crate in [('digest', 'prover'), ('negative-controls', 'sumcheck'),
                            ('soundness-accounting', 'hash'), ('parity', 'gpu')]:
            with self.subTest(gate=gate):
                source = self.root / f'crates/stele-{crate}/src/lib.rs'
                original = source.read_text()
                source.write_text(original + '\npub fn unvalidated() {}\n')
                result = self.run_gate(gate)
                source.write_text(original)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn('not wired', result.stderr)

    def test_rejects_deleted_or_additional_source(self):
        source = self.root / 'crates/stele-prover/src/lib.rs'
        source.unlink()
        self.assertNotEqual(self.run_gate('digest').returncode, 0)
        source.write_bytes((ROOT / 'crates/stele-prover/src/lib.rs').read_bytes())
        (source.parent / 'unchecked.rs').write_text('pub fn unvalidated() {}')
        self.assertNotEqual(self.run_gate('digest').returncode, 0)

    def test_rejects_unvalidated_artifacts(self):
        for gate, path in [('ledger-validate', 'bench/ledger/invalid.json'),
                           ('digest', 'tests/digests/unvalidated.bin'),
                           ('negative-controls', 'tests/negative-controls/unchecked.rs')]:
            with self.subTest(gate=gate):
                file = self.root / path
                file.parent.mkdir(parents=True, exist_ok=True)
                file.write_text('{}')
                result = self.run_gate(gate)
                file.unlink()
                self.assertNotEqual(result.returncode, 0)
                expected = 'missing or unknown fields' if gate == 'ledger-validate' else 'not wired'
                self.assertIn(expected, result.stderr)

    def test_accepts_ledger_and_rejects_disabled_bindings_through_gate(self):
        fixture = (self.root / 'crates/stele-bench/tests/fixtures/valid.json').read_text()
        ledger = self.root / 'bench/ledger/fixture.json'
        ledger.parent.mkdir(parents=True, exist_ok=True)
        ledger.write_text(fixture)
        result = self.run_gate('ledger-validate')
        self.assertEqual(result.returncode, 0, result.stderr)
        ledger.write_text(fixture.replace('"bindings_all_on": true', '"bindings_all_on": false'))
        result = self.run_gate('ledger-validate')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('bindings_all_on must be true', result.stderr)

    def test_rejects_draft_research_missing_and_duplicate_rfc(self):
        file = self.root / 'crates/stele-field/src/lib.rs'
        original = file.read_text()
        for reference in ('9999', '0019', '9998'):
            with self.subTest(reference=reference):
                if reference == '9998':
                    (self.root / 'docs/rfcs/RFC-9998-draft.md').write_text('Status: Draft\n')
                file.write_text(original + f'\n// RFC-{reference}\n')
                self.assertNotEqual(self.run_gate('rfc-status').returncode, 0)
        file.write_text(original)
        harness = self.root / 'tests/negative-controls/src/lib.rs'
        harness_source = harness.read_text()
        harness.write_text(harness_source + '\n// RFC-9998\n')
        self.assertNotEqual(self.run_gate('rfc-status').returncode, 0)
        harness.write_text(harness_source)
        (self.root / 'docs/rfcs/RFC-0003-duplicate.md').write_text('Status: Accepted\n')
        self.assertNotEqual(self.run_gate('rfc-status').returncode, 0)

    def test_rejects_catalog_claiming_unexecuted_coverage(self):
        catalog = self.root / 'tests/negative-controls/catalog.md'
        catalog.write_text(catalog.read_text().replace('| todo |', '| done |', 1))
        result = self.run_gate('negative-controls')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('done without an executable control', result.stdout + result.stderr)

    def test_rejects_broken_local_doc_link(self):
        file = self.root / 'README.md'
        file.write_text('[broken](docs/missing.md)\n')
        self.assertNotEqual(self.run_gate('docs-links').returncode, 0)
        file.write_text('[valid](docs/prd.md#goals)\n[remote](https://example.org)\n')
        self.assertEqual(self.run_gate('docs-links').returncode, 0)


if __name__ == '__main__':
    unittest.main()
