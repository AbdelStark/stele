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
    def test_matches_reference_stacked_scope_and_union(self):
        files = [b'formal/stacked-runtime.md', b'formal/stacked-ownership.md', b'formal/stacked-statement.md']
        oracle = b'research/stacked-gkr/check_native_wire.py'
        for path in files:
            self.assertEqual(scope.scopes([path]), dict(gpu=False,tables=False,research=True,research_selection='stacked'))
        for paths in (files, list(reversed(files)), files+files+[oracle]):
            self.assertEqual(scope.scopes(paths)['research_selection'], 'stacked')
        for native in (b'Cargo.lock', b'crates/stele-field/src/lib.rs', b'crates/stele-cqis/src/lib.rs'):
            for paths in (files+[native], [native]+files):
                self.assertEqual(scope.scopes(paths)['research_selection'], 'native-stacked')
                self.assertTrue(scope.scopes(paths)['tables'])
        for path in (files[0]+b'.extra',b'formal/stacked.md',b'research/stacked-gkr/stage.py',
                     b'research/stacked-gkr/weighted_mle.py',b'harness/check.py',b'scripts/research_ci.py',
                     b'scripts/ci_scope.py',b'.github/workflows/ci.yml'):
            self.assertEqual(scope.scopes(files+[b'Cargo.lock',oracle,path])['research_selection'], 'all')
        self.assertEqual(scope.scopes([])['research_selection'],'none')

    def test_matches_reference_native_tier_and_broad_precedence(self):
        for native in (b'Cargo.lock', b'crates/stele-cqis/src/lib.rs', b'crates/stele-field/tests/field.rs'):
            selected = scope.scopes([native, b'crates/stele-reductions/src/field_sources.rs'])
            self.assertEqual((selected['research'], selected['tables'], selected['research_selection']),
                             (True, True, 'native'))
            for broad in (b'Cargo.toml', b'Cargo.lock.extra', b'.cargo/config.toml', b'rust-toolchain.toml',
                          b'uv.lock', b'pyproject.toml', b'.github/actions/setup/action.yml',
                          b'.github/workflows/ci.yml', b'.github/workflows/exhaustive.yml',
                          b'scripts/ci_scope.py', b'scripts/ci_result.py', b'scripts/research_ci.py',
                          b'scripts/research-checks.json', b'scripts/research-full-checks.json',
                          b'research/merkle-oracle/field_wire.py', b'harness/check.py', b'formal/proof.md'):
                with self.subTest(native=native, broad=broad):
                    self.assertEqual(scope.scopes([native, broad])['research_selection'], 'all')
        self.assertEqual(scope.scopes([b'crates/stele-reductions/src/field_sources.rs'])['research_selection'], 'none')

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
        oracle = b'research/stacked-gkr/check_native_wire.py'
        for paths in ([oracle], [oracle+b'.lock'], [oracle,oracle+b'.lock']):
            self.assertEqual(scope.scopes(paths)['research_selection'],'none')
        for neighbor in (oracle+b'.extra',b'research/stacked-gkr/stage.py',b'research/stacked-gkr/check_stage.py'):
            self.assertEqual(scope.scopes([oracle,neighbor])['research_selection'],'all')

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
            self.assertEqual(run({'before': '0' * 40, 'after': base}).stdout, 'gpu=true\ntables=false\nresearch=false\nresearch_selection=none\n')
            (root / 'README.md').write_text('docs\n')
            git('add', 'README.md')
            git('commit', '-m', 'docs')
            head = git('rev-parse', 'HEAD')
            self.assertEqual(run({'before': base, 'after': head}).stdout, 'gpu=false\ntables=false\nresearch=false\nresearch_selection=none\n')
            git('mv', 'crates/stele-gpu/src/lib.rs', 'moved.rs')
            git('commit', '-m', 'move GPU source out of crate')
            renamed = git('rev-parse', 'HEAD')
            event = {'pull_request': {'base': {'sha': head}, 'head': {'sha': renamed}}}
            self.assertEqual(run(event).stdout, 'gpu=true\ntables=false\nresearch=false\nresearch_selection=none\n')
            git('switch', '-c', 'base-ahead', head)
            source.write_text('// base-only change\n')
            git('add', 'crates')
            git('commit', '-m', 'base advances')
            advanced = git('rev-parse', 'HEAD')
            event = {'pull_request': {'base': {'sha': advanced}, 'head': {'sha': head}}}
            self.assertEqual(run(event).stdout, 'gpu=false\ntables=false\nresearch=false\nresearch_selection=none\n')
            self.assertNotEqual(run({'before': '--help', 'after': head}).returncode, 0)
            for path, expected in [
                ('crates/stele-field/src/lib.rs', ('true', 'true')),
                ('crates/stele-cqis/tests/support/oracle.rs', ('true', 'true')),
                ('research/sumcheck/check_sumcheck.py', ('false', 'true')),
                ('Cargo.lock', ('true', 'true')),
                ('.github/workflows/ci.yml', ('true', 'true')),
                ('scripts/gates/check.py', ('false', 'false')),
                ('scripts/research-checks.json', ('false', 'true')),
                ('research/merkle-oracle/check_field_wire.py', ('false', 'false')),
                ('research/merkle-oracle/check_field_wire.py.lock', ('false', 'false')),
                ('research/stacked-gkr/check_native_wire.py', ('false', 'false')),
                ('research/stacked-gkr/check_native_wire.py.lock', ('false', 'false')),
                ('formal/stacked-runtime.md', ('false', 'true')),
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
            git('mv','formal/stacked-runtime.md','moved-stacked')
            git('commit','-m','move stacked contract')
            self.assertIn('research_selection=stacked',run({'before':before,'after':git('rev-parse','HEAD')}).stdout)
            (root/'formal/shared.md').write_text('shared\n')
            git('add','formal/shared.md');git('commit','-m','shared formal fixture')
            before = git('rev-parse', 'HEAD')
            git('mv','formal/shared.md','formal/stacked-runtime.md');git('commit','-m','move shared into stacked path')
            self.assertIn('research_selection=all',run({'before':before,'after':git('rev-parse','HEAD')}).stdout)
            before = git('rev-parse', 'HEAD')
            git('rm','formal/stacked-runtime.md');git('commit','-m','delete stacked contract')
            self.assertIn('research_selection=stacked',run({'before':before,'after':git('rev-parse','HEAD')}).stdout)
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
            for path in ('Cargo.lock', 'crates/stele-cqis/tests/support/oracle.rs', 'crates/stele-field/src/lib.rs'):
                before = git('rev-parse', 'HEAD')
                git('mv', path, 'moved-native')
                git('commit', '-m', 'move native input out of scope')
                result = run({'before': before, 'after': git('rev-parse', 'HEAD')})
                self.assertIn('research_selection=native', result.stdout)
                self.assertIn('tables=true', result.stdout)
                git('mv', 'moved-native', path)
                git('commit', '-m', 'restore fixture')
                before = git('rev-parse', 'HEAD')
                git('rm', path)
                git('commit', '-m', 'delete native input')
                result = run({'before': before, 'after': git('rev-parse', 'HEAD')})
                self.assertIn('research_selection=native', result.stdout)



if __name__ == '__main__':
    unittest.main()
