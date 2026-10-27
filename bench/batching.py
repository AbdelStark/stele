"""Verified RFC-0006 A2 CPU batching baseline, RFC-0018 §1 / E3-02."""
import hashlib
import json
import pathlib
import platform
import subprocess
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[1]
CASES = ['instances-equal-d0', 'instances-unequal-d0', 'instances-equal-d2',
         'instances-unequal-d2', 'instances-equal-d4', 'instances-unequal-d4',
         'claims-disjoint', 'claims-overlap', 'claims-arbitrary']


def run(*args):
    return subprocess.check_output(args, cwd=ROOT, text=True).strip()


def main():
    if len(sys.argv) != 3 or sys.argv[1] not in ('QM31', 'OM31') or platform.system() != 'Darwin':
        raise SystemExit('usage (macOS): python3 bench/batching.py QM31|OM31 <new-ledger.json>')
    field, output = sys.argv[1], pathlib.Path(sys.argv[2]).absolute()
    if output.exists() or run('git', 'status', '--porcelain'):
        raise SystemExit('requires a clean committed checkout and new ledger path')
    commit = run('git', 'rev-parse', 'HEAD')
    for command in [['scripts/gates/negative-controls.sh'], ['scripts/gates/soundness-accounting.sh'],
                    ['cargo', 'test', '-p', 'stele-sumcheck', '--example', 'batching', '--release', '--locked', '--offline'],
                    ['cargo', 'build', '-p', 'stele-sumcheck', '--example', 'batching', '--release', '--locked', '--offline']]:
        subprocess.run(command, cwd=ROOT, check=True)
    plan = dict(operation='batch prove', field=field, small=False, variables=12, cases=CASES,
        instance_dimensions=dict(equal=[12,12,12], unequal=[12,10,8]), inputs_per_instance=2,
        instance_polynomial='f0^degree + 2*f1^(max(degree-1,0))',
        instance_values=['((j*73+19+member)%31)-15', '((j*29+7+member)%17)-8'],
        claim_count=4, claim_table='((j*73+19)%31)-15',
        claim_points='first two coordinates are block bits for disjoint/overlap; others are 2+coordinate+claim',
        claim_blocks=dict(disjoint=[0,1,2,3], overlap=[0,1,0,1]),
        samples=3, iterations=3, warmup_calls=1, build='release', order='reverse cases on odd samples',
        timed='clone/allocation, transcript initialization, coefficient construction, rounds and BatchFinal',
        verification='every warmup/measured proof fully checked outside timing')
    times, rss, payloads, points, outputs = {}, {}, {}, {}, {}
    field_bytes = 16 if field == 'QM31' else 32
    with tempfile.TemporaryDirectory() as directory:
        stats = pathlib.Path(directory) / 'time.txt'
        for sample in range(plan['samples']):
            for case in list(range(len(CASES)))[::(-1 if sample % 2 else 1)]:
                name = CASES[case]
                result = json.loads(run('/usr/bin/time', '-l', '-o', str(stats),
                    str(ROOT / 'target/release/examples/batching'), field, str(case)))
                assert set(result) == {'time_ns','output','m','degree','count','claims','points','working_table_payload_bytes'}
                expected_points = (3*4096 if case%2 == 0 else 4096+1024+256) if case<6 else 4096
                degree, count, claims = (max(2*(case//2),case%2),3,6) if case<6 else (2,4,1)
                assert (result['m'],result['degree'],result['count'],result['claims']) == (12,degree,count,claims)
                assert result['points'] == expected_points
                assert result['working_table_payload_bytes'] == 2*expected_points*field_bytes
                assert len(bytes.fromhex(result['output'])) == (12*(degree+1)+claims)*field_bytes
                assert outputs.setdefault(name,result['output']) == result['output'], 'proof changed between samples'
                peaks = [int(line.split()[0]) for line in stats.read_text().splitlines() if 'maximum resident set size' in line]
                assert type(result['time_ns']) is int and result['time_ns']>0 and len(peaks)==1 and peaks[0]>0
                times.setdefault(name,[]).append(result['time_ns'])
                rss.setdefault(name,[]).append(peaks[0])
                payloads[name], points[name] = result['working_table_payload_bytes'], expected_points
    assert len(times)==9 and all(len(v)==3 for v in times.values())
    if commit != run('git','rev-parse','HEAD') or run('git','status','--porcelain'):
        raise SystemExit('source state changed during measurement')
    totals = {key:sum(values) for key,values in times.items()}
    proofs = plan['samples']*plan['iterations']
    ledger = dict(schema_version=1, kind='micro', workload='micro/batching', commit=commit,
        toolchain=run('rustc','-Vv'), device=platform.machine()+' '+run('sysctl','-n','machdep.cpu.brand_string'),
        driver='not-applicable', model_config=dict(plan=plan, os=platform.platform(), sample_times_ns=times,
            peak_process_rss_bytes=rss, working_table_payload_bytes=payloads,
            c_sc_ns_per_point={key:dict(numerator=value,denominator=proofs*points[key]) for key,value in totals.items()},
            subproof_values_sha256={key:hashlib.sha256(bytes.fromhex(value)).hexdigest() for key,value in outputs.items()}),
        plan_digest=hashlib.sha256(json.dumps(plan,sort_keys=True,separators=(',',':')).encode()).hexdigest(),
        profile='standard' if field=='QM31' else 'treaty', bindings_all_on=True, batch_size=1,
        prompt_tokens=0, generated_tokens=0, prover_time_ns=sum(totals.values()), witness_recompute_ns=0,
        stage_times_ns=totals, kernel_counters={key+'/summand_points':proofs*points[key] for key in totals},
        proof_size_bytes=0, verifier_time_ns=dict(rust=0,python=0), controls=dict(total=0,passed=0,failed=0),
        note='Native CPU batch baseline with all public obligations verified outside timing. c_sc denominator is the sum of original member hypercube sizes in mode 0, and tensor size in mode 1; mode 1 includes coefficient construction. Shapes/statements differ: ratios across cases are not speedups. Working table payload counts prover-owned input tables and the mode-1 coefficient table before folding, excluding caller originals, descriptors, temporary eq tables, proof and allocator metadata. Process peak RSS includes setup, warmup, prover, verifier, code and allocator; not isolated scratch or DRAM traffic. Exact time/point ratios are measurements, not a cost-model fit. Profile selects only the field for this microbenchmark; no inference, GPU, ZK or profile-security certification. No samples discarded.')
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open('x') as stream:
        json.dump(ledger,stream,indent=2); stream.write('\n')
    subprocess.run(['cargo','run','-p','stele-bench','--locked','--offline','--','ledger','validate',str(output)],cwd=ROOT,check=True)
    print(f'Validated {field} batching ledger: {output}')


if __name__ == '__main__':
    main()
