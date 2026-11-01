"""RFC-0007 A2 §6: complete real consumers precede conditional ledger credit."""
import copy
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location('matmul_bench', ROOT/'bench/matmul.py')
BENCH = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(BENCH)


class MatmulBenchTests(unittest.TestCase):
    def test_accepts_real_consumers_and_rejects_missing_evidence(self):
        subprocess.run(['cargo', 'build', '-p', 'stele-negative-controls', '--example',
                        'matmul_bench', '--profile', 'test', '--locked', '--offline'], cwd=ROOT, check=True, capture_output=True)
        records = []
        with tempfile.TemporaryDirectory() as directory:
            for scenario, degree in [('scalar', 4), ('single', 8), ('stacked', 4), ('zero', 8)]:
                result = subprocess.run([str(ROOT/'target/debug/examples/matmul_bench'), scenario,
                                         str(degree), 'smoke'], cwd=ROOT, check=True, text=True, capture_output=True)
                native = BENCH.decode(result.stdout)
                request = Path(directory)/'request.json'
                request.write_text(json.dumps(native['request']))
                verified = subprocess.run(BENCH.python_command(request), cwd=ROOT, check=True, text=True, capture_output=True)
                oracle = BENCH.decode(verified.stdout)
                BENCH.receipt(native, oracle, request.read_bytes(), scenario, degree, 'smoke')
                records.append(BENCH.compact(native, oracle, request.read_bytes()))
                mutations = [
                    lambda n, p: n['stages_ns'].pop('verify'),
                    lambda n, p: n['stages_ns'].pop('certificate_verify/0'),
                    lambda n, p: n.update(total_ns=1),
                    lambda n, p: n.update(remainder_ns=n['remainder_ns']+1),
                    lambda n, p: n.update(field_degree=True),
                    lambda n, p: n.update(extra=1),
                    lambda n, p: n['originals'].pop(),
                    lambda n, p: n['verification']['record']['openings'].pop(),
                    lambda n, p: n['request']['originals'][0].update(source_hex='00'*105),
                    lambda n, p: n['request'].update(proof_hex=n['request']['proof_hex']+'00'),
                    lambda n, p: n['work']['prover']['retained_rows'][1].update(source_visits=2),
                    lambda n, p: n['work']['prover']['openings'][1].update(source_elements=1),
                    lambda n, p: n['work']['verifier']['openings'][1].update(encoded_values_read=0),
                    lambda n, p: n['work']['verifier']['openings'][1]['encoder'].update(circle_transform_products=0),
                    lambda n, p: n['memory']['logical_input_bytes'].__setitem__(0, 0),
                    lambda n, p: n['memory'].update(peak_owned_bytes=0),
                    lambda n, p: n['producer_usage']['transcript'].update(xof_requests=0),
                    lambda n, p: n['verification']['usage']['non_transcript'].update(hash_evaluations=0),
                    lambda n, p: p['stages_ns'].update(closed_relation=0),
                    lambda n, p: p.update(request_sha256='00'*32),
                    lambda n, p: p['sources'].pop('stacked-gkr/stage.py'),
                    lambda n, p: p.pop('runtime'),
                    lambda n, p: p['runtime'].update(version='3.11.0'),
                    lambda n, p: p['runtime'].update(implementation='pypy'),
                    lambda n, p: p['runtime'].update(executable=''),
                    lambda n, p: p['runtime'].update(extra='unexpected'),
                    lambda n, p: n['memory']['logical_input_bytes'].append(1),
                    lambda n, p: n['work']['verifier']['restored_points_bytes'].append(1),
                    lambda n, p: (n['verification']['restored_points'].append([]),
                                  p['verification']['restored_points'].append([])),
                    lambda n, p: (n['verification']['consumed_claims'].append({}),
                                  p['verification']['consumed_claims'].append({})),
                    lambda n, p: p['verification'].update(continuation=None),
                    lambda n, p: p['verification']['restored_points'][0].append([0]*degree),
                ]
                if scenario != 'scalar':
                    mutations.append(lambda n, p: n['work']['prover'].update(round_scratch_peak_bytes=0))
                    mutations.append(lambda n, p: n['work']['prover']['dense'].update(
                        partial_entries=n['work']['prover']['dense']['partial_entries']+1024,
                        round_scratch_entries=n['work']['prover']['dense']['round_scratch_entries']+1024))
                for mutate in mutations:
                    n, p = copy.deepcopy(native), copy.deepcopy(oracle)
                    mutate(n, p)
                    with self.subTest(scenario=scenario, mutation=mutate), self.assertRaises(AssertionError):
                        BENCH.receipt(n, p, request.read_bytes(), scenario, degree, 'smoke')
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
                        rejected = subprocess.run(BENCH.python_command(request), cwd=ROOT, text=True, capture_output=True)
                        self.assertNotEqual(rejected.returncode, 0)
                        self.assertFalse(rejected.stdout)
                        self.assertIn(cause, rejected.stderr)
            metadata = dict(commit='0'*40, toolchain='schema fixture', device='schema fixture', plan={'test': 1})
            ledger = BENCH.assemble(metadata, records)
            self.assertEqual(sum(ledger['stage_times_ns'].values()), ledger['prover_time_ns'])
            path = Path(directory)/'ledger.json'
            path.write_text(json.dumps(ledger))
            subprocess.run(['cargo', 'run', '-q', '-p', 'stele-bench', '--locked', '--offline',
                            '--', 'ledger', 'validate', str(path)], cwd=ROOT, check=True, capture_output=True)

    def test_rejects_duplicate_keys_and_incomplete_campaign(self):
        with self.assertRaisesRegex(AssertionError, 'duplicate JSON keys'):
            BENCH.decode('{"scenario":1,"scenario":2}')
        rows = [dict(scenario=c, field_degree=d, sample=s) for c, d, s in BENCH.CASES]
        BENCH.check_cases(rows)
        for wrong in [rows[:-1], rows[::-1], rows+rows[:1]]:
            with self.assertRaises(AssertionError):
                BENCH.check_cases(wrong)
        self.assertNotEqual(BENCH.identity({'proof': 'a'}), BENCH.identity({'proof': 'b'}))
