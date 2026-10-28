"""RFC-0006 A5 / RFC-0018 §1: actual prover/consumer time and separate peak RSS."""
import hashlib
import json
import pathlib
import platform
import subprocess
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[1]
CASES = [(8,d,k) for d in range(5) for k in (0,2,3,4)]+[(18,1,k) for k in (0,2,3,4)]


def run(*args):
    return subprocess.check_output(args,cwd=ROOT,text=True).strip()


def stage(args, stats, data=None):
    result = subprocess.run(['/usr/bin/time','-l','-o',str(stats),*args],cwd=ROOT,
                            input=None if data is None else json.dumps(data),text=True,capture_output=True,check=True)
    peaks = [int(line.split()[0]) for line in stats.read_text().splitlines() if 'maximum resident set size' in line]
    assert len(peaks)==1 and peaks[0]>0
    return json.loads(result.stdout),peaks[0]


def main():
    if len(sys.argv)!=3 or sys.argv[1] not in ('QM31','OM31') or platform.system()!='Darwin':
        raise SystemExit('usage (macOS): python3 bench/small_value.py QM31|OM31 <new-ledger.json>')
    field, output = sys.argv[1],pathlib.Path(sys.argv[2]).absolute()
    if output.exists() or run('git','status','--porcelain'):
        raise SystemExit('requires a clean committed checkout and new ledger path')
    commit = run('git','rev-parse','HEAD')
    plan = dict(operation='Small/Dense prepare, prove and public consume',field=field,small=True,
        cases=CASES,inputs=4,samples=3,iterations=3,warmup_calls=1,build='release',
        strategy='k=0 Dense; k=2/3/4 Small, chosen before proving',
        polynomial='f0^degree-f1 for degree>0; constant 5 for degree=0',
        values=['x=((j*73+19)%15)-7 signed i16','x^degree signed i16','(j*8191)%65536 unsigned u16 unused','x signed i16 unused'],
        order='reverse cases on odd samples',
        timed='prover: typed clone or K expansion, constructor, prefix/transition/tail, transcript, proof; consumer: K expansion, transcript, every original claim, table deallocation',
        excluded='synthetic fixture construction, proof serialization/transport/parsing, receipt assertions, continuation comparison and process launch',
        memory='sequential separate-process prover and consumer peak RSS including setup, warmup, retained capacities, transition overlap, transport buffers and process overhead; native-worker pipeline peak is their maximum; Python controller excluded',
        scope='24 synthetic CPU cases per field; m18 degree1 is the memory probe; no inference or profile certificate')
    for command in [['scripts/gates/negative-controls.sh'],['scripts/gates/soundness-accounting.sh'],
                    ['cargo','test','-p','stele-sumcheck','--example','small_bench','--release','--locked','--offline'],
                    ['cargo','build','-p','stele-sumcheck','--example','small_bench','--release','--locked','--offline']]:
        subprocess.run(command,cwd=ROOT,check=True)
    samples, rss, metadata, outputs = {},{},{},{}
    wire = 16 if field=='QM31' else 32
    with tempfile.TemporaryDirectory() as directory:
        stats = pathlib.Path(directory)/'time.txt'
        for sample in range(plan['samples']):
            for m,degree,k in CASES[::(-1 if sample%2 else 1)]:
                name = f'm{m}-d{degree}-k{k}'
                args = [str(ROOT/'target/release/examples/small_bench'),field,str(degree),str(m),str(k)]
                produced,prss = stage([*args,'prove'],stats)
                consumed,crss = stage([*args,'consume'],stats,produced)
                assert set(produced)=={'prover_ns','proofs','continuations','descriptor','m','degree','k','caller_input_payload_bytes'}
                assert set(consumed)=={'consumer_ns','sc','verified_proofs','claims','proof_payload_bytes'}
                assert (produced['m'],produced['degree'],produced['k'])==(m,degree,k)
                assert produced['caller_input_payload_bytes']==4*(1<<m)*2
                assert len(produced['proofs'])==len(produced['continuations'])==consumed['verified_proofs']==4
                assert consumed['claims']==4 and consumed['sc']==dict(id=204,m=m,degree=degree,field_degree=wire//4,numerator=m*degree)
                assert consumed['proof_payload_bytes']==(m*(degree+1)+4)*wire
                assert all(proof==produced['proofs'][0] for proof in produced['proofs'])
                assert all(nxt==produced['continuations'][0] for nxt in produced['continuations'])
                evidence = [produced['descriptor'],produced['proofs'][0],produced['continuations'][0]]
                assert outputs.setdefault(f'm{m}-d{degree}',evidence)==evidence,'strategy proof/continuation parity failed'
                times = dict(prover_ns=produced['prover_ns'],consumer_ns=consumed['consumer_ns'])
                assert all(len(v)==3 and all(type(t) is int and t>0 for t in v) for v in times.values())
                samples.setdefault(name,[]).append(times)
                rss.setdefault(name,[]).append(dict(prover=prss,consumer=crss,pipeline=max(prss,crss)))
                data = dict(m=m,degree=degree,k=k,claims=4,sc=consumed['sc'],
                    caller_input_payload_bytes=produced['caller_input_payload_bytes'],proof_payload_bytes=consumed['proof_payload_bytes'])
                assert metadata.setdefault(name,data)==data
                print(f'{field} sample {sample+1}: {name} fully consumed',flush=True)
    assert len(samples)==24 and all(len(v)==3 for v in samples.values())
    if commit!=run('git','rev-parse','HEAD') or run('git','status','--porcelain'):
        raise SystemExit('source state changed during measurement')
    totals = {key:{stage:sum(sum(row[stage]) for row in values) for stage in ('prover_ns','consumer_ns')} for key,values in samples.items()}
    complete = {key:sum(value.values()) for key,value in totals.items()}
    ratios = {key:dict(numerator=value,denominator=complete[key.rsplit('-k',1)[0]+'-k0']) for key,value in complete.items()}
    peaks = {key:{stage:max(row[stage] for row in values) for stage in ('prover','consumer','pipeline')} for key,values in rss.items()}
    memory_ratios = {key:{stage:dict(numerator=value,denominator=peaks[key.rsplit('-k',1)[0]+'-k0'][stage]) for stage,value in values.items()} for key,values in peaks.items()}
    proofs = plan['samples']*plan['iterations']
    ledger = dict(schema_version=1,kind='micro',workload='micro/small-value',commit=commit,
        toolchain=run('rustc','-Vv'),device=platform.machine()+' '+run('sysctl','-n','machdep.cpu.brand_string'),driver='not-applicable',
        model_config=dict(plan=plan,os=platform.platform(),sample_times_ns=samples,peak_process_rss_bytes=rss,
            case_metadata=metadata,complete_over_dense=ratios,peak_memory_over_dense=memory_ratios,
            c_sc_ns_per_point={key:dict(numerator=value['prover_ns'],denominator=proofs*(1<<metadata[key]['m'])) for key,value in totals.items()},
            complete_ns_per_point={key:dict(numerator=value,denominator=proofs*(1<<metadata[key]['m'])) for key,value in complete.items()},
            verified_proofs=24*3*4,
            proof_and_continuation_sha256={key:hashlib.sha256(json.dumps(value,separators=(',',':')).encode()).hexdigest() for key,value in outputs.items()}),
        plan_digest=hashlib.sha256(json.dumps(plan,sort_keys=True,separators=(',',':')).encode()).hexdigest(),
        profile='standard' if field=='QM31' else 'treaty',bindings_all_on=True,batch_size=1,prompt_tokens=0,generated_tokens=0,
        prover_time_ns=sum(complete.values()),witness_recompute_ns=0,
        stage_times_ns={key+'/'+stage:value for key,values in totals.items() for stage,value in values.items()},
        kernel_counters={key+'/summand_points':proofs*(1<<metadata[key]['m']) for key in totals},
        proof_size_bytes=0,verifier_time_ns=dict(rust=0,python=0),controls=dict(total=0,passed=0,failed=0),
        note='Native CPU Small/Dense pipeline: each of four produced proofs (one warmup plus three measured) is fully consumed in a separate process against reconstructed original public tables; ledger emission requires all acceptance and continuation checks. All strategy/k proofs are identical per descriptor. Operation time includes preparation, allocation, transition, proving and consumer K materialization; excludes synthetic fixtures, transport/parsing, assertions and launch. Process RSS includes all these and allocator retention; each native stage is isolated and pipeline peak is max, not sum, because workers do not overlap; Python controller memory is excluded. RSS is not live allocation or isolated scratch size. All samples/losses retained; no automatic k choice or statistical/fitted constant claim. Profile selects field only; no inference, GPU, ZK or profile certification.')
    output.parent.mkdir(parents=True,exist_ok=True)
    with output.open('x') as stream:
        json.dump(ledger,stream,indent=2);stream.write('\n')
    subprocess.run(['cargo','run','-p','stele-bench','--locked','--offline','--','ledger','validate',str(output)],cwd=ROOT,check=True)
    print(f'Validated {field} small-value ledger: {output}')


if __name__=='__main__':
    main()
