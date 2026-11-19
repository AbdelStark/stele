"""RFC-0018 A2 (task E17-01): stage_ns and counter parsing in bench/dev_e2e.py."""
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'bench'))

from dev_e2e import (  # noqa: E402
    REQUIRED_COUNTERS,
    REQUIRED_STAGES,
    SECTION_BYTE_COUNTERS,
    external_wall_ns,
    parse_report,
)


def sample_report(lookup_total=128, check_values=(128,), section_bytes=10):
    lines = ['profile development', 'sources CircleAll']
    for i, stage in enumerate(sorted(REQUIRED_STAGES), start=1):
        lines.append(f'stage_ns {stage} {i * 1000}')
    for counter in sorted(REQUIRED_COUNTERS):
        if counter == 'lookup_positions':
            val = lookup_total
        elif counter in SECTION_BYTE_COUNTERS:
            val = section_bytes
        else:
            val = 4
        lines.append(f'counter {counter} {val}')
    for idx, val in enumerate(check_values):
        lines.append(f'counter lookup_positions_check_{idx}_range_8 {val}')
    lines.append('PROOF WRITTEN')
    return '\n'.join(lines) + '\n'


class DevE2EStageReportTests(unittest.TestCase):
    def test_accepts_complete_report_and_legacy_empty_report(self):
        text = sample_report(lookup_total=200, check_values=(128, 72), section_bytes=10)
        stages, counters = parse_report(text, proof_bytes=100, require_nonempty=True)
        self.assertTrue(REQUIRED_STAGES <= stages.keys())
        self.assertIn('plan', REQUIRED_STAGES)
        self.assertTrue(REQUIRED_COUNTERS <= counters.keys())
        self.assertEqual(counters['lookup_positions_check_0_range_8'], 128)
        self.assertEqual(counters['lookup_positions_check_1_range_8'], 72)
        self.assertEqual(parse_report('profile development\nPROOF WRITTEN\n'), ({}, {}))

    def test_rejects_missing_empty_reserved_duplicate_and_malformed_lines(self):
        text = sample_report()
        lines = text.splitlines()
        without_witness = '\n'.join(l for l in lines if not l.startswith('stage_ns witness ')) + '\n'
        without_plan = '\n'.join(l for l in lines if not l.startswith('stage_ns plan ')) + '\n'
        without_weight_reads = '\n'.join(l for l in lines if not l.startswith('counter weight_reads ')) + '\n'
        for bad in [
            without_witness,
            without_plan,
            without_weight_reads,
            text + 'stage_ns witness 1\n',
            text + 'stage_ns prove_dev_wall 1\n',
            text + 'stage_ns model_commitment_once 1\n',
            text + 'counter weight_reads 2\n',
            text + 'stage_ns bad-name 1\n',
            text + 'counter bad -5\n',
            text + 'stage_ns\n',
            text + 'counter\n',
            text + 'stage_ns\twitness 1\n',
            text + 'counter\tfoo 1\n',
        ]:
            with self.assertRaises(ValueError, msg=bad):
                parse_report(bad, proof_bytes=1000, require_nonempty=True)
        with self.assertRaises(ValueError):
            parse_report('profile development\nPROOF WRITTEN\n', require_nonempty=True)

    def test_rejects_inconsistent_lookup_sum_and_section_bytes(self):
        bad_lookups = sample_report(lookup_total=128, check_values=(64, 32))
        with self.assertRaises(ValueError):
            parse_report(bad_lookups, proof_bytes=1000, require_nonempty=True)
        text = sample_report(section_bytes=20)
        # 6 section byte counters * 20 = 120 > 100 proof bytes.
        with self.assertRaises(ValueError):
            parse_report(text, proof_bytes=100, require_nonempty=True)

    def test_external_wall_ns_validates_against_time_resolution(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.assertEqual(external_wall_ns(tmp, 120_000_000, 10_000_000), 120_000_000)
            wall = Path(tmp) / 'prove.wall_ns'
            wall.write_text('123456789\n')
            self.assertEqual(external_wall_ns(tmp, 120_000_000, 10_000_000), 123_456_789)
            wall.write_text('200000000\n')
            with self.assertRaises(ValueError):
                external_wall_ns(tmp, 120_000_000, 10_000_000)
            wall.write_text('not-a-number\n')
            with self.assertRaises(ValueError):
                external_wall_ns(tmp, 120_000_000, 10_000_000)

    def test_cli_requires_valid_rung_for_post_e17_02_records(self):
        base = [
            sys.executable, str(ROOT / 'bench/dev_e2e.py'),
            '/nonexistent/run', '/nonexistent/out.json',
            '--workload', 'dev/sample',
            '--commit', '0' * 40,
            '--device', 'cpu',
            '--model-config', '/nonexistent/config.json',
            '--toolchain', 'rustc 1.0',
            '--prompt-tokens', '1',
            '--threads', '1',
            '--host-context', 'test',
        ]
        missing = subprocess.run(base, capture_output=True, text=True)
        self.assertNotEqual(missing.returncode, 0)
        self.assertIn('--rung is required', missing.stderr)
        bad = subprocess.run(base + ['--rung', 'L9'], capture_output=True, text=True)
        self.assertNotEqual(bad.returncode, 0)
        self.assertIn('--rung must be one of', bad.stderr)


if __name__ == '__main__':
    unittest.main()
