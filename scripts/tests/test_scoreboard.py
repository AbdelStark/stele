"""RFC-0018 A2: the committed scoreboard equals the one generated from the ledgers."""
from pathlib import Path
import subprocess
import sys
import unittest

ROOT = Path(__file__).resolve().parents[2]


class ScoreboardTests(unittest.TestCase):
    def test_matches_reference_generated_scoreboard(self):
        result = subprocess.run([sys.executable, str(ROOT / 'bench/scoreboard.py'), '--check'],
                                capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == '__main__':
    unittest.main()
