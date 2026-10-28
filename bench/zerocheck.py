"""RFC-0006 A3 / RFC-0018 §1: complete zerocheck CPU cost and memory ledger."""
import hashlib
import json
import pathlib
import platform
import subprocess
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[1]
CASES = [(d, k, strategy) for d in range(5) for k in ([0] if d == 0 else [0, 1, 2, 4])
         for strategy in ('reference', 'dense')]


def run(*args):
    return subprocess.check_output(args, cwd=ROOT, text=True).strip()


def main():
    if len(sys.argv) != 3 or sys.argv[1] not in ('QM31', 'OM31') or platform.system() != 'Darwin':
        raise SystemExit('usage (macOS): python3 bench/zerocheck.py QM31|OM31 <new-ledger.json>')
    field, output = sys.argv[1], pathlib.Path(sys.argv[2]).absolute()
    if output.exists() or run('git', 'status', '--porcelain'):
        raise SystemExit('requires a clean committed checkout and new ledger path')
    commit = run('git', 'rev-parse', 'HEAD')
    for command in [['scripts/gates/negative-controls.sh'], ['scripts/gates/soundness-accounting.sh'],
                    ['cargo', 'test', '-p', 'stele-sumcheck', '--example', 'zerocheck', '--release', '--locked', '--offline'],
                    ['cargo', 'build', '-p', 'stele-sumcheck', '--example', 'zerocheck', '--release', '--locked', '--offline']]:
        subprocess.run(command, cwd=ROOT, check=True)
    plan = dict(operation='zerocheck prove and public consume', field=field, small=False,
        variables=8, inputs=4, cases=CASES, polynomial='f0^degree-f1; empty zero relation at degree 0',
        values=['((j*73+19)%31)-15', 'f0^degree', 'f0 (unused)', 'f0 (unused)'],
        samples=3, iterations=3, warmup_calls=1, build='release', order='reverse cases on odd samples',
        timed='prover and complete public consumer separately, including allocation and transcript initialization',
        excluded='synthetic input construction, proof encoding, receipt assertions and continuation comparison',
        memory='separate-process peak RSS; actual input/proof payload; conservative requested scratch payload bounds',
        scratch_fields=dict(reference='W+2*a*s+2*a+4*j+2*s', dense='2*a*W+3*W+3*a+3*s+2*(D+degree+2)+3*j',
                            consumer='N+a*s*(m+1)+3*j+3*s+2*(D+degree+2)+3*a'),
        scratch_framing_bytes='descriptor_length+wire_bytes+40+(L+degree+1+a*s)*wire_bytes',
        definitions='N=2^m,s=2^k,j=m-k,W=N/s,D=degree*(s-1),L=(degree-1)*(s-1) or 0 at degree 0')
    samples, rss, metadata, outputs = {}, {}, {}, {}
    wire = 16 if field == 'QM31' else 32
    with tempfile.TemporaryDirectory() as directory:
        stats = pathlib.Path(directory) / 'time.txt'
        for sample in range(plan['samples']):
            for degree, skip, strategy in CASES[::(-1 if sample % 2 else 1)]:
                name = f'd{degree}-k{skip}-{strategy}'
                result = json.loads(run('/usr/bin/time', '-l', '-o', str(stats),
                    str(ROOT / 'target/release/examples/zerocheck'), field, str(degree), str(skip), strategy))
                assert set(result) == {'prover_ns','consumer_ns','output','sc','points','m','degree','skip','claims',
                    'caller_input_payload_bytes','proof_payload_bytes','prover_scratch_payload_bound_bytes',
                    'consumer_scratch_payload_bound_bytes'}
                assert (result['points'],result['m'],result['degree'],result['skip'],result['claims']) == (256,8,degree,skip,4*2**skip)
                j, s = 8-skip, 2**skip
                records = [dict(id=100,phase=p,m=m,degree=delta,field_degree=wire//4,numerator=m*delta)
                           for p,(m,delta) in enumerate([(j,1),(int(skip>0),degree*(s-1)),(j,degree)])]
                assert result['sc'] == records
                fields = max(degree-1,0)*(2**skip-1)+(8-skip)*(degree+1)+4*2**skip
                assert len(bytes.fromhex(result['output'])) == fields*wire == result['proof_payload_bytes']
                assert result['caller_input_payload_bytes'] == 4*256*wire
                assert all(type(result[k]) is int and result[k] > 0 for k in ('prover_ns','consumer_ns',
                    'prover_scratch_payload_bound_bytes','consumer_scratch_payload_bound_bytes'))
                # Equal descriptor/k: exact reference/dense subproof values, including every original final.
                key = f'd{degree}-k{skip}'
                assert outputs.setdefault(key,result['output']) == result['output'], 'proof parity/determinism failed'
                peaks = [int(line.split()[0]) for line in stats.read_text().splitlines() if 'maximum resident set size' in line]
                assert len(peaks)==1 and peaks[0]>0
                samples.setdefault(name,[]).append({k:result[k] for k in ('prover_ns','consumer_ns')})
                rss.setdefault(name,[]).append(peaks[0])
                data = {k:v for k,v in result.items() if k not in ('output','prover_ns','consumer_ns')}
                assert metadata.setdefault(name,data) == data
    assert len(samples)==34 and all(len(v)==3 for v in samples.values())
    if commit != run('git','rev-parse','HEAD') or run('git','status','--porcelain'):
        raise SystemExit('source state changed during measurement')
    totals = {key:{stage:sum(row[stage] for row in values) for stage in ('prover_ns','consumer_ns')}
              for key,values in samples.items()}
    complete = {key:sum(value.values()) for key,value in totals.items()}
    proofs = plan['samples']*plan['iterations']
    ratios = {key:dict(numerator=complete[key+'-dense'],denominator=complete[key+'-reference']) for key in outputs}
    skips = {key:dict(numerator=complete[key+'-dense'],denominator=complete[key.split('-')[0]+'-k0-dense']) for key in outputs}
    stages = {key+'/'+stage:value for key,values in totals.items() for stage,value in values.items()}
    ledger = dict(schema_version=1,kind='micro',workload='micro/zerocheck',commit=commit,
        toolchain=run('rustc','-Vv'),device=platform.machine()+' '+run('sysctl','-n','machdep.cpu.brand_string'),
        driver='not-applicable',model_config=dict(plan=plan,os=platform.platform(),sample_times_ns=samples,
            peak_process_rss_bytes=rss,case_metadata=metadata,complete_dense_over_reference=ratios,complete_skip_over_eq_only=skips,
            c_sc_ns_per_point={key:dict(numerator=value['prover_ns'],denominator=proofs*256) for key,value in totals.items()},
            complete_ns_per_point={key:dict(numerator=value,denominator=proofs*256) for key,value in complete.items()},
            subproof_values_sha256={key:hashlib.sha256(bytes.fromhex(value)).hexdigest() for key,value in outputs.items()}),
        plan_digest=hashlib.sha256(json.dumps(plan,sort_keys=True,separators=(',',':')).encode()).hexdigest(),
        profile='standard' if field=='QM31' else 'treaty',bindings_all_on=True,batch_size=1,prompt_tokens=0,generated_tokens=0,
        prover_time_ns=sum(complete.values()),witness_recompute_ns=0,stage_times_ns=stages,
        kernel_counters={key+'/summand_points':proofs*256 for key in totals},proof_size_bytes=0,
        verifier_time_ns=dict(rust=0,python=0),controls=dict(total=0,passed=0,failed=0),
        note='Complete native CPU zerocheck operation: prover plus actual public consumption, each timed separately. Every warmup/measured proof is fully consumed; no binding disabled. Dense/reference comparisons fix descriptor and k. Different k selects a different A3 protocol for the same row assertion; SC loss and final-claim count change. The direct reference uses exhaustive original-slice evaluations, not a tuned linear-time baseline. All samples, including skip losses, are retained. Process peak RSS includes setup, warmup, prover, consumer, encoding/assertions, code, descriptors and allocator retention. Caller/proof payloads are separate; scratch bounds sum all relevant field-buffer maxima plus framing and exclude Vec/allocator headers and stack. They are conservative requested-payload bounds, not isolated measured scratch peaks. Time/point is an observation, not a fitted constant. Profile selects field only; no inference, GPU, ZK or profile certification.')
    output.parent.mkdir(parents=True,exist_ok=True)
    with output.open('x') as stream:
        json.dump(ledger,stream,indent=2);stream.write('\n')
    subprocess.run(['cargo','run','-p','stele-bench','--locked','--offline','--','ledger','validate',str(output)],cwd=ROOT,check=True)
    print(f'Validated {field} zerocheck ledger: {output}')


if __name__ == '__main__':
    main()
