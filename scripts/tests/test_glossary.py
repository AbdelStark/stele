"""RFC-0020 §4: exact legacy exceptions must not mask new terminology."""
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]


class GlossaryTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        for directory in ('scripts', 'agents', 'docs', 'tests', 'crates', 'bench', 'harness', 'formal'):
            shutil.copytree(ROOT / directory, self.root / directory)
        for path in ROOT.glob('*.md'):
            shutil.copy(path, self.root / path.name)

    def run_gate(self):
        return subprocess.run(['bash', str(self.root / 'scripts/gates/glossary-lint.sh')],
                              cwd='/', text=True, capture_output=True)

    def test_accepts_exact_legacy_wording(self):
        result = self.run_gate()
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_rejects_new_synonyms_in_docs(self):
        file = self.root / 'docs/new.md'
        for term in ('circuit', 'Circuits', 'trace', 'gadgets', 'constraint\nsystems', 'prover‑side randomness'):
            with self.subTest(term=term):
                file.write_text(f'New {term} description.\n')
                result = self.run_gate()
                self.assertNotEqual(result.returncode, 0)
                self.assertIn('docs/new.md: new forbidden wording', result.stderr)
        file.write_text('A reduction consumes a claim.\n')
        self.assertEqual(self.run_gate().returncode, 0)

    def test_rejects_duplicated_or_stale_exception(self):
        file = self.root / 'agents/context/glossary.md'
        source = file.read_text()
        line = next(line for line in source.splitlines() if line.startswith('- **reduction**'))
        file.write_text(source + '\n' + line + '\n')
        self.assertIn('new forbidden wording', self.run_gate().stderr)
        file.write_text(source.replace(line, ''))
        self.assertIn('stale glossary exception', self.run_gate().stderr)

    def test_rejects_new_term_in_existing_accepted_document(self):
        # Find by RFC id because the title is not part of the policy.
        file = next((self.root / 'docs/rfcs').glob('RFC-0003-*.md'))
        file.write_text(file.read_text() + '\nNew gadget.\n')
        self.assertNotEqual(self.run_gate().returncode, 0)


if __name__ == '__main__':
    unittest.main()
