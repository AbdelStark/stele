"""RFC-0020 §5: parity must include deleted/renamed files and PR-only changes."""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

SCRIPT = Path(__file__).resolve().parents[1] / 'ci_scope.py'


class ScopeTests(unittest.TestCase):
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
            self.assertEqual(run({'before': '0' * 40, 'after': base}).stdout, 'gpu=true\n')
            (root / 'README.md').write_text('docs\n')
            git('add', 'README.md')
            git('commit', '-m', 'docs')
            head = git('rev-parse', 'HEAD')
            self.assertEqual(run({'before': base, 'after': head}).stdout, 'gpu=false\n')
            git('mv', 'crates/stele-gpu/src/lib.rs', 'moved.rs')
            git('commit', '-m', 'move GPU source out of crate')
            renamed = git('rev-parse', 'HEAD')
            event = {'pull_request': {'base': {'sha': head}, 'head': {'sha': renamed}}}
            self.assertEqual(run(event).stdout, 'gpu=true\n')
            git('switch', '-c', 'base-ahead', head)
            source.write_text('// base-only change\n')
            git('add', 'crates')
            git('commit', '-m', 'base advances')
            advanced = git('rev-parse', 'HEAD')
            event = {'pull_request': {'base': {'sha': advanced}, 'head': {'sha': head}}}
            self.assertEqual(run(event).stdout, 'gpu=false\n')
            self.assertNotEqual(run({'before': '--help', 'after': head}).returncode, 0)


if __name__ == '__main__':
    unittest.main()
