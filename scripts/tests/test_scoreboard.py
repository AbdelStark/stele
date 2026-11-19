"""RFC-0018 A2 (task E17-02): stele-bench scoreboard matches bench/scoreboard.py and checks freshness."""
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]


class ScoreboardTests(unittest.TestCase):
    def test_matches_reference_generated_scoreboard(self):
        py = subprocess.run(
            [sys.executable, str(ROOT / 'bench/scoreboard.py')],
            cwd=ROOT, capture_output=True, text=True, check=True,
        )
        rust = subprocess.run(
            ['cargo', 'run', '-q', '-p', 'stele-bench', '--locked', '--offline', '--', 'scoreboard'],
            cwd=ROOT, capture_output=True, text=True, check=True,
        )
        self.assertEqual(rust.stdout, py.stdout, 'stele-bench scoreboard differs from bench/scoreboard.py')
        check = subprocess.run(
            ['cargo', 'run', '-q', '-p', 'stele-bench', '--locked', '--offline', '--', 'scoreboard', '--check'],
            cwd=ROOT, capture_output=True, text=True,
        )
        self.assertEqual(check.returncode, 0, check.stderr)

    def test_rejects_stale_scoreboard_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / 'scoreboard.md'
            out.write_text('# Stale\n')
            stale = subprocess.run(
                ['cargo', 'run', '-q', '-p', 'stele-bench', '--locked', '--offline', '--',
                 'scoreboard', '--check', '--out', str(out)],
                cwd=ROOT, capture_output=True, text=True,
            )
            self.assertNotEqual(stale.returncode, 0)
            write = subprocess.run(
                ['cargo', 'run', '-q', '-p', 'stele-bench', '--locked', '--offline', '--',
                 'scoreboard', '--write', '--out', str(out)],
                cwd=ROOT, capture_output=True, text=True,
            )
            self.assertEqual(write.returncode, 0, write.stderr)
            fresh = subprocess.run(
                ['cargo', 'run', '-q', '-p', 'stele-bench', '--locked', '--offline', '--',
                 'scoreboard', '--check', '--out', str(out)],
                cwd=ROOT, capture_output=True, text=True,
            )
            self.assertEqual(fresh.returncode, 0, fresh.stderr)

    def test_matches_python_exact_rounding_at_binary64_midpoints(self):
        sys.path.insert(0, str(ROOT / 'bench'))
        import scoreboard as py_sb  # noqa: E402
        self.assertEqual(py_sb.fmt_fixed(15_650_000, 1_000_000, 1), '15.6')
        self.assertEqual(py_sb.fmt_fixed(15_750_000, 1_000_000, 1), '15.8')
        self.assertEqual(py_sb.fmt_fixed(2_675_000_000, 1_000_000_000, 2), '2.68')
        self.assertEqual(py_sb.fmt_fixed(2_665_000_000, 1_000_000_000, 2), '2.66')
        self.assertEqual(py_sb.fmt_fixed(1_000_000_000, 80_000_000_000, 3), '0.012')


if __name__ == '__main__':
    unittest.main()
