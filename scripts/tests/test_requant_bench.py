"""RFC-0023 §6: actual public-only parity before granting resource receipt credit."""
import copy
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location('requant_bench', ROOT/'bench/requant.py')
BENCH = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(BENCH)


class RequantBenchTests(unittest.TestCase):
    def test_accepts_actual_radix_consumers_and_rejects_incomplete_receipts(self):
        build=subprocess.run(['cargo','build','-p','stele-negative-controls','--example','requant_bench',
                        '--profile','test','--locked','--offline','--message-format=json-render-diagnostics'],cwd=ROOT,check=True,capture_output=True)
        artifacts=[BENCH.decode(line) for line in build.stdout.splitlines()]
        binaries={a['executable'] for a in artifacts if a.get('reason')=='compiler-artifact'
            and a['target']['name']=='requant_bench' and a['target']['kind']==['example'] and a['executable']}
        self.assertEqual(len(binaries),1);binary=binaries.pop()
        rows=[]
        with tempfile.TemporaryDirectory() as directory:
            request=Path(directory)/'request.json'
            for scenario,degree in [('radix255',4),('radix256',8)]:
                native=BENCH.decode(subprocess.run([binary,scenario,str(degree)],
                    cwd=ROOT,check=True,capture_output=True).stdout)
                request.write_text(json.dumps(native['request']))
                oracle=BENCH.decode(subprocess.run(BENCH.python_command(request),cwd=ROOT,check=True,capture_output=True).stdout)
                raw=request.read_bytes()
                BENCH.receipt(native,oracle,raw,scenario,degree)
                rows.append(BENCH.compact(native,oracle,raw))
                mutations=[
                    lambda n,p:n.update(field_degree=True),
                    lambda n,p:n.update(extra=1),
                    lambda n,p:n['stages_ns'].pop('multiplicity_imports'),
                    lambda n,p:n['stages_ns'].pop('witness'),
                    lambda n,p:n.update(total_ns=1),
                    lambda n,p:n['request'].update(proof_hex=n['request']['proof_hex']+'00'),
                    lambda n,p:n['verification']['record']['groups'].pop(),
                    lambda n,p:n['verification']['record']['rlc'][0]['weights'].pop(),
                    lambda n,p:n['producer_usage']['registrations'][0].pop(),
                    lambda n,p:n['producer_usage']['non_transcript'].update(hash_evaluations=0),
                    lambda n,p:n['originals'][0]['preparation_hashes'].update(hash_evaluations=0),
                    lambda n,p:n['work']['prover'].update(aggregate_tables_bytes=0),
                    lambda n,p:n['work']['prover'].update(output_tables_bytes=0),
                    lambda n,p:n['work']['prover']['group_coefficients_bytes'][1].__setitem__(2,0),
                    lambda n,p:n['work']['verifier']['group_coefficients_bytes'][2].__setitem__(1,0),
                    lambda n,p:n['memory'].update(witness_bytes=0),
                    lambda n,p:n['memory'].update(peak_owned_bytes=1),
                    lambda n,p:p.update(request_sha256='00'*32),
                    lambda n,p:p['sources'].pop('tests/negative-controls/requant/reference.py'),
                    lambda n,p:p['runtime'].update(version='3.11.0'),
                    lambda n,p:p['runtime'].update(optimization=1),
                    lambda n,p:p['stages_ns'].update(advice_import=0),
                    lambda n,p:p['verification'].update(continuation=None),
                    lambda n,p:n['diagnostic_probe_usage']['producer'].update(hash_evaluations=0),
                    lambda n,p:[(v['verification']['record']['rlc'][0]['weights'].pop(),v['verification']['record']['rlc'][0].update(count=v['verification']['record']['rlc'][0]['count']-1)) for v in (n,p)],
                ]
                for side,fields in [('certificate_producer',('weights_bytes','path_peak_bytes','peak_owned_bytes')),
                                    ('certificate_verifier',('weights_bytes','row_bytes','encoded_bytes','peak_owned_bytes'))]:
                    for field in fields:
                        mutations.append(lambda n,p,s=side,f=field:n['originals'][0][s].update({f:0}))
                for field in ('prepared_bytes','mu_values_bytes','mu_limbs_bytes','originals_bytes','selector_bytes','index_bytes','group_weights_bytes','coefficients_bytes','temporary_wire_bytes'):
                    mutations.append(lambda n,p,f=field:n['work']['lookups'][0].update({f:0}))
                for mutate in mutations:
                    n,p=copy.deepcopy(native),copy.deepcopy(oracle);mutate(n,p)
                    with self.subTest(scenario=scenario,mutation=mutate),self.assertRaises(AssertionError):
                        BENCH.receipt(n,p,raw,scenario,degree)
                # Actual final A9 and following A1 consumers, not receipt mutation.
                if scenario=='radix255':
                    attacks=[(json.dumps(native['request']|{'witness':[]}), 'NativeRequestKeys'),
                        (raw.decode().replace('"stage": 41','"stage": 41, "stage": 41',1),'NativeRequestDuplicateKey')]
                    for target in ('certificate_hex','proof_hex','following_hex'):
                        q=copy.deepcopy(native['request']);holder=q['input'] if target=='certificate_hex' else q
                        wire=bytearray.fromhex(holder[target])
                        if target!='following_hex': wire[-1]^=1
                        else:
                            at=2*4*degree
                            wire[at:at+4]=((int.from_bytes(wire[at:at+4],'little')+1)%2147483647).to_bytes(4,'little')
                        holder[target]=wire.hex()
                        attacks.append((json.dumps(q),'FinalEvaluationMismatch' if target=='following_hex' else 'RootMismatch'))
                    for text,cause in attacks:
                        request.write_text(text)
                        rejected=subprocess.run(BENCH.python_command(request),cwd=ROOT,capture_output=True,text=True)
                        self.assertNotEqual(rejected.returncode,0);self.assertFalse(rejected.stdout);self.assertIn(cause,rejected.stderr)
            metadata=dict(commit='0'*40,toolchain='schema fixture',device='schema fixture',plan={'test':1})
            ledger=BENCH.assemble(metadata,rows)
            self.assertEqual(sum(ledger['stage_times_ns'].values()),ledger['prover_time_ns'])
            path=Path(directory)/'ledger.json';path.write_text(json.dumps(ledger))
            validated=subprocess.run(['cargo','run','-q','-p','stele-bench','--locked','--offline','--','ledger','validate',str(path)],cwd=ROOT,capture_output=True,text=True)
            self.assertEqual(validated.returncode,0,validated.stderr)

    def test_rejects_duplicate_keys_and_incomplete_campaign(self):
        with self.assertRaisesRegex(AssertionError,'duplicate JSON keys'):BENCH.decode('{"a":1,"a":1}')
        rows=[dict(scenario=c,field_degree=d,sample=s) for c,d,s in BENCH.CASES]
        BENCH.check_cases(rows)
        for bad in [rows[:-1],rows[::-1],rows+rows[:1]]:
            with self.assertRaises(AssertionError):BENCH.check_cases(bad)
        self.assertNotEqual(BENCH.identity({'proof':'a'}),BENCH.identity({'proof':'b'}))
