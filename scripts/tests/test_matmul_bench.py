"""RFC-0007 A2 §6: measured workers execute both actual closed consumers."""
import copy
import json
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]


class MatmulBenchTests(unittest.TestCase):
    def test_accepts_real_workers_and_rejects_altered_public_artifacts(self):
        subprocess.run(['cargo', 'build', '-p', 'stele-negative-controls', '--example',
                        'matmul_bench', '--profile', 'test', '--locked', '--offline'], cwd=ROOT, check=True, capture_output=True)
        with tempfile.TemporaryDirectory() as directory:
            request = Path(directory)/'request.json'
            command = ['uv', 'run', '--python', '3.12', '--locked', '--script',
                       str(ROOT/'tests/negative-controls/matmul_corpus.py'), '--verify-native', str(request)]
            for scenario, degree in [('scalar', 4), ('single', 8), ('stacked', 4), ('zero', 8)]:
                result = subprocess.run([str(ROOT/'target/debug/examples/matmul_bench'), scenario,
                                         str(degree), 'smoke'], cwd=ROOT, check=True, text=True, capture_output=True)
                native = json.loads(result.stdout)
                request.write_text(json.dumps(native['request']))
                result = subprocess.run(command, cwd=ROOT, check=True, text=True, capture_output=True)
                oracle = json.loads(result.stdout)
                self.assertEqual(native['verification'], oracle['verification'])
                self.assertEqual(oracle['runtime']['implementation'], 'cpython')
                self.assertTrue(oracle['runtime']['version'].startswith('3.12.'))
                self.assertTrue(oracle['runtime']['executable'])
                self.assertEqual(native['diagnostic_probe_usage']['consumer'], oracle['diagnostic_probe_usage'])
                self.assertEqual(native['diagnostic_probe_usage']['producer'], oracle['diagnostic_probe_usage'])
                self.assertEqual(native['verification']['decision'], 'accept')
                self.assertEqual(len(native['verification']['record']['openings']), 2)
                self.assertEqual([r['source_visits'] for r in native['work']['prover']['retained_rows']], [1, 1])
                self.assertEqual([r['source_elements'] for r in native['work']['prover']['openings']], [0, 0])
                self.assertEqual(set(oracle['stages_ns']), {'decode', 'certificate_import_x', 'certificate_import_w', 'closed_relation', 'continuation'})
                for receipt in (native, oracle):
                    self.assertTrue(all(t > 0 for t in receipt['stages_ns'].values()))
                    self.assertEqual(receipt['total_ns'], sum(receipt['stages_ns'].values())+receipt['remainder_ns'])
                if scenario == 'stacked':
                    valid = native['request']
                    attacks = [(json.dumps(dict(valid, messages_hex=['', ''])), 'NativeRequestKeys'),
                               (json.dumps(valid).replace('"id": 101', '"id": 101, "id": 101', 1), 'NativeRequestDuplicateKey')]
                    for target in ('certificate_hex', 'proof_hex', 'following_hex'):
                        altered = copy.deepcopy(valid)
                        holder = altered['originals'][0] if target == 'certificate_hex' else altered
                        wire = bytearray.fromhex(holder[target])
                        if target == 'following_hex':
                            offset = 2*4*degree
                            limb = (int.from_bytes(wire[offset:offset+4], 'little')+1) % 2147483647
                            wire[offset:offset+4] = limb.to_bytes(4, 'little')
                        else:
                            wire[-1] ^= 1
                        holder[target] = wire.hex()
                        attacks.append((json.dumps(altered), 'FinalEvaluationMismatch' if target == 'following_hex' else 'RootMismatch'))
                    for raw, cause in attacks:
                        request.write_text(raw)
                        rejected = subprocess.run(command, cwd=ROOT, text=True, capture_output=True)
                        self.assertNotEqual(rejected.returncode, 0)
                        self.assertFalse(rejected.stdout)
                        self.assertIn(cause, rejected.stderr)
