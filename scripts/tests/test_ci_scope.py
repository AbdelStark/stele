"""RFC-0020 §5: parity must include deleted/renamed files and PR-only changes."""
import json
import importlib.util
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

SCRIPT = Path(__file__).resolve().parents[1] / 'ci_scope.py'
SPEC = importlib.util.spec_from_file_location('ci_scope', SCRIPT)
scope = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(scope)


class ScopeTests(unittest.TestCase):
    def test_matches_reference_native_owned_oracle_scope(self):
        oracle = b'research/merkle-oracle/check_field_wire.py'
        lock = oracle + b'.lock'
        for paths in ([oracle], [lock], [oracle, lock]):
            self.assertFalse(scope.scopes(paths)['research'])
        for neighbor in (b'research/merkle-oracle/field_wire.py',
                         b'research/merkle-oracle/vectors.json', oracle + b'.extra',
                         b'research/sumcheck/check.py', b'harness/check.py', b'formal/proof.md'):
            self.assertTrue(scope.scopes([oracle, lock, neighbor])['research'])
        for shared in (b'Cargo.lock', b'.github/workflows/ci.yml', b'scripts/ci_scope.py'):
            result = scope.scopes([oracle, shared])
            self.assertTrue(result['research'])
            self.assertTrue(result['tables'])

    def test_matches_reference_git_changes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)

            def git(*args):
                return subprocess.check_output(['git', *args], cwd=root, stderr=subprocess.DEVNULL).decode().strip()

            def run(event):
                file = root / 'event.json'
                file.write_text(json.dumps(event))
                return subprocess.run(['python3', str(SCRIPT)], cwd=root, capture_output=True,
                                      text=True, env={**os.environ, 'GITHUB_EVENT_PATH': str(file)})

            git('init', '-b', 'main')
            git('config', 'user.email', 'test@example.invalid')
            git('config', 'user.name', 'Gate test')
            source = root / 'crates/stele-gpu/src/lib.rs'
            source.parent.mkdir(parents=True)
            source.write_text('// skeleton\n')
            git('add', 'crates')
            git('commit', '-m', 'initial')
            base = git('rev-parse', 'HEAD')
            self.assertEqual(run({'before': '0' * 40, 'after': base}).stdout, 'gpu=true\ntables=false\nresearch=false\n')
            (root / 'README.md').write_text('docs\n')
            git('add', 'README.md')
            git('commit', '-m', 'docs')
            head = git('rev-parse', 'HEAD')
            self.assertEqual(run({'before': base, 'after': head}).stdout, 'gpu=false\ntables=false\nresearch=false\n')
            git('mv', 'crates/stele-gpu/src/lib.rs', 'moved.rs')
            git('commit', '-m', 'move GPU source out of crate')
            renamed = git('rev-parse', 'HEAD')
            event = {'pull_request': {'base': {'sha': head}, 'head': {'sha': renamed}}}
            self.assertEqual(run(event).stdout, 'gpu=true\ntables=false\nresearch=false\n')
            git('switch', '-c', 'base-ahead', head)
            source.write_text('// base-only change\n')
            git('add', 'crates')
            git('commit', '-m', 'base advances')
            advanced = git('rev-parse', 'HEAD')
            event = {'pull_request': {'base': {'sha': advanced}, 'head': {'sha': head}}}
            self.assertEqual(run(event).stdout, 'gpu=false\ntables=false\nresearch=false\n')
            self.assertNotEqual(run({'before': '--help', 'after': head}).returncode, 0)
            for path, expected in [
                ('crates/stele-field/src/lib.rs', ('true', 'false')),
                ('crates/stele-cqis/tests/support/oracle.rs', ('true', 'false')),
                ('research/sumcheck/check_sumcheck.py', ('false', 'true')),
                ('Cargo.lock', ('true', 'true')),
                ('.github/workflows/ci.yml', ('true', 'true')),
                ('scripts/gates/check.py', ('false', 'false')),
                ('scripts/research-checks.json', ('false', 'true')),
                ('research/merkle-oracle/check_field_wire.py', ('false', 'false')),
                ('research/merkle-oracle/check_field_wire.py.lock', ('false', 'false')),
            ]:
                before = git('rev-parse', 'HEAD')
                file = root / path
                file.parent.mkdir(parents=True, exist_ok=True)
                file.write_text('changed\n')
                git('add', path)
                git('commit', '-m', 'scope fixture')
                result = run({'before': before, 'after': git('rev-parse', 'HEAD')})
                self.assertEqual(result.returncode, 0, result.stderr)
                outputs = dict(line.split('=') for line in result.stdout.splitlines())
                self.assertEqual((outputs['tables'], outputs['research']), expected)

            before = git('rev-parse', 'HEAD')
            git('rm', 'research/merkle-oracle/check_field_wire.py')
            git('commit', '-m', 'delete native-owned checker')
            result = run({'before': before, 'after': git('rev-parse', 'HEAD')})
            self.assertIn('research=false', result.stdout)
            before = git('rev-parse', 'HEAD')
            git('mv', 'research/sumcheck/check_sumcheck.py', 'research/merkle-oracle/check_field_wire.py')
            git('commit', '-m', 'move shared research into native-owned path')
            result = run({'before': before, 'after': git('rev-parse', 'HEAD')})
            self.assertIn('research=true', result.stdout)



if __name__ == '__main__':
    unittest.main()
