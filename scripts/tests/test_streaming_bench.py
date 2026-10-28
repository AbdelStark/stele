"""RFC-0018 §1: the actual streaming exporter must satisfy the micro schema."""
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location('streaming_bench', ROOT/'bench/streaming.py')
BENCH = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(BENCH)


class StreamingLedgerTests(unittest.TestCase):
    def test_accepts_exported_micro_ledger_with_complete_stage_costs(self):
        plan = dict(cases=BENCH.cases(), samples=3)
        data = {}
        for case in plan['cases']:
            name = f"m{case['m']}-d{case['degree']}-{case['mode']}"
            data[name] = [dict(times_ns=dict(fixture_ns=1, preparation_ns=2,
                prover_ns=3, consumer_ns=1000), prover=dict(source_io=dict(reads=7)))
                for _ in range(3)]
        with tempfile.TemporaryDirectory() as directory, patch.object(BENCH, 'run', return_value='synthetic test metadata'):
            for field in ('QM31', 'OM31'):
                ledger = BENCH.make_ledger(plan, data, {}, '1'*40, field, 14, 72)
                path = Path(directory)/f'{field}.json'
                path.write_text(json.dumps(ledger))
                result = subprocess.run(['cargo', 'run', '-q', '-p', 'stele-bench',
                    '--locked', '--offline', '--', 'ledger', 'validate', str(path)],
                    cwd=ROOT, capture_output=True, text=True)
                self.assertEqual(result.returncode, 0, result.stdout+result.stderr)
                self.assertEqual(ledger['prover_time_ns'], 24*3*1006)
                self.assertEqual(ledger['model_config']['controls_executed'], 14)
                self.assertEqual(ledger['model_config']['samples'], data)
                self.assertEqual(sum(ledger['stage_times_ns'].values()), ledger['prover_time_ns'])


if __name__ == '__main__':
    unittest.main()
