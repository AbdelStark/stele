"""RFC-0006 A6 / RFC-0018 §1: complete file/streaming/Dense CPU measurements."""
import hashlib
import json
import pathlib
import platform
import re
import shutil
import subprocess
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[1]


def cases():
    result = []
    for m, degree in [(8, d) for d in range(5)]+[(18, 1)]:
        for mode in ('dense', 'tail', 'one', 'multi'):
            windows = {'dense': [], 'tail': [], 'one': [m//2], 'multi': [m//3, m//3]}[mode]
            work = max([max(2, degree+1)**w+3*2**w+6 for w in windows]+[3*2**(m-sum(windows))+3])
            result.append(dict(m=m, degree=degree, mode=mode, windows=windows, budget=0 if mode=='dense' else work))
    return result


def run(*args):
    return subprocess.check_output(args, cwd=ROOT, text=True).strip()


def stage(args, stats):
    result = subprocess.run(['/usr/bin/time', '-l', '-o', str(stats), *args], cwd=ROOT,
                            text=True, capture_output=True, check=True)
    peaks = [int(line.split()[0]) for line in stats.read_text().splitlines() if 'maximum resident set size' in line]
    assert len(peaks)==1 and peaks[0]>0
    return json.loads(result.stdout), peaks[0]


def main():
    if len(sys.argv)!=3 or sys.argv[1] not in ('QM31', 'OM31') or platform.system()!='Darwin':
        raise SystemExit('usage (macOS): python3 bench/streaming.py QM31|OM31 <new-ledger.json>')
    field, output = sys.argv[1], pathlib.Path(sys.argv[2]).absolute()
    if output.exists() or run('git', 'status', '--porcelain'):
        raise SystemExit('requires a clean committed checkout and new ledger path')
    commit = run('git', 'rev-parse', 'HEAD')
    plan = dict(operation='canonical fixture, file preparation, bounded A1 prove, original public consume',
        cases=cases(), field=field, inputs=3, samples=3, proofs_per_sample=1, warmup=0, build='release',
        fixture='fixed full-extension c; x=c*(((j*73+19)%15)-7); y=x^degree; unused=c*((j%31)-15)',
        polynomial='x^degree-y for degree>0; constant 5 for degree=0',
        order='reverse cases on odd samples; fresh native processes and files for every sample',
        timed='fixture generation/writes; separate layout conversion; source reads, allocation, constructor, windows/tail, transcript/proof, continuation, binary transport writes; original-file reads, transport parsing, all original claims, continuation and table deallocation',
        excluded='argument parsing, process launch/exit, result JSON formatting, controller cleanup and small output/descriptor buffer destruction after measurement',
        memory='sequential native preparation/prover/consumer peak RSS; pipeline peak is maximum; includes setup, transition overlap, transport and allocator retention; Python controller and OS filesystem cache excluded',
        capacities='actual retained Vec/PathBuf capacities during bounded proving; named Rust type sizes separately, not compiler stack/allocator/OS bounds; consumer transient equality weights covered by measured RSS',
        caches='no cache flush or warmup; no physical disk traffic claim',
        scope='synthetic CPU A1 instances only; all original consumers enabled; no inference/GPU/ZK/profile certification')
    for command in [['scripts/gates/negative-controls.sh'], ['scripts/gates/soundness-accounting.sh'],
                    ['cargo', 'test', '-p', 'stele-sumcheck', '--features', 'std', '--example', 'streaming_bench', '--release', '--locked', '--offline'],
                    ['cargo', 'build', '-p', 'stele-sumcheck', '--features', 'std', '--example', 'streaming_bench', '--release', '--locked', '--offline']]:
        subprocess.run(command, cwd=ROOT, check=True)
    coverage = run('cargo', 'run', '-q', '-p', 'stele-negative-controls', '--bin', 'stele-controls', '--locked', '--offline', '--', '--coverage')
    passed, catalog = map(int, re.search(r'(\d+)/(\d+) controls', coverage).groups())
    data, evidence = {}, {}
    wire = 16 if field=='QM31' else 32
    with tempfile.TemporaryDirectory() as directory:
        base = pathlib.Path(directory)
        for sample in range(plan['samples']):
            for case in plan['cases'][::(-1 if sample%2 else 1)]:
                m, degree, mode = case['m'], case['degree'], case['mode']
                name = f'm{m}-d{degree}-{mode}'
                path = base/f'{sample}-{name}'; path.mkdir()
                args = [str(ROOT/'target/release/examples/streaming_bench'), field, str(degree), str(m), mode, str(case['budget']), str(path)]
                prepared, arss = stage([*args, 'prepare'], base/'time.txt')
                produced, prss = stage([*args, 'prove'], base/'time.txt')
                consumed, crss = stage([*args, 'consume'], base/'time.txt')
                assert set(prepared)=={'fixture_ns','preparation_ns','fixture_io','preparation_io','preparation_buffer_capacity_bytes','record_bytes','external_input_bytes'}
                assert set(produced)=={'prover_ns','source_io','work_capacity_cells','work_budget_cells','prover_buffer_capacity_bytes','strategy_storage_bytes','proof_capacity_bytes','absorb_capacity_bytes','descriptor_heap_bytes','caller_heap_bytes','named_inline_bytes','transport_capacity_bytes','transport_bytes'}
                assert set(consumed)=={'consumer_ns','claims','sc','source_io','consumer_retained_buffer_bytes','transport_bytes'}
                assert produced['prover_buffer_capacity_bytes']==sum(produced[key] for key in ('strategy_storage_bytes','proof_capacity_bytes','absorb_capacity_bytes','descriptor_heap_bytes','caller_heap_bytes'))
                assert prepared['record_bytes']==wire and produced['named_inline_bytes']>0
                records = 3*(1<<m); visits = 1 if mode=='dense' else len(case['windows'])+1
                assert prepared['fixture_io']['writes']==records and prepared['fixture_io']['written_bytes']==records*wire
                expected_preparation = dict(reads=0, writes=0, seeks=0, read_bytes=0, written_bytes=0, eof_checks=0) if mode=='dense' else dict(reads=records, writes=records, seeks=records, read_bytes=records*wire, written_bytes=records*wire, eof_checks=3)
                assert prepared['preparation_io']==expected_preparation
                assert produced['source_io']==dict(reads=records*visits, writes=0, seeks=0 if mode=='dense' else 3*visits, read_bytes=records*visits*wire, written_bytes=0, eof_checks=3*visits)
                assert consumed['source_io']==dict(reads=records, writes=0, seeks=0, read_bytes=records*wire, written_bytes=0, eof_checks=3)
                assert produced['work_capacity_cells']==produced['work_budget_cells']==case['budget']
                if mode in ('one', 'multi'): assert case['budget']<records
                assert consumed['claims']==3 and consumed['sc']==dict(id=305, m=m, degree=degree, field_degree=wire//4, numerator=m*degree)
                proof = (path/'proof.bin').read_bytes()
                assert len(proof)==produced['transport_bytes']==consumed['transport_bytes']
                assert produced['transport_capacity_bytes']>=len(proof) and consumed['consumer_retained_buffer_bytes']>=records*wire
                digest = hashlib.sha256(proof).hexdigest()
                assert evidence.setdefault(f'm{m}-d{degree}', digest)==digest, 'strategy proof/continuation mismatch'
                external = sum(p.stat().st_size for p in path.iterdir())
                assert external==prepared['external_input_bytes']+len(proof)
                times = {key: row[key] for row,keys in [(prepared, ('fixture_ns','preparation_ns')), (produced, ('prover_ns',)), (consumed, ('consumer_ns',))] for key in keys}
                assert all(type(value) is int and value>=0 for value in times.values()) and times['prover_ns']>0 and times['consumer_ns']>0
                data.setdefault(name, []).append(dict(times_ns=times, preparation=prepared, prover=produced, consumer=consumed,
                    peak_rss_bytes=dict(preparation=arss, prover=prss, consumer=crss, pipeline=max(arss,prss,crss)), external_storage_bytes=external))
                shutil.rmtree(path)  # Controller cleanup is outside the native operation.
                print(f'{field} sample {sample+1}: {name} original claims consumed', flush=True)
    assert len(data)==24 and all(len(rows)==3 for rows in data.values())
    if commit!=run('git','rev-parse','HEAD') or run('git','status','--porcelain'):
        raise SystemExit('source state changed during measurement')
    ledger = make_ledger(plan, data, evidence, commit, field, passed, catalog)
    output.parent.mkdir(parents=True,exist_ok=True)
    with output.open('x') as stream: json.dump(ledger,stream,indent=2);stream.write('\n')
    subprocess.run(['cargo','run','-p','stele-bench','--locked','--offline','--','ledger','validate',str(output)],cwd=ROOT,check=True)
    print(f'Validated {field} streaming ledger: {output}')


def make_ledger(plan, data, evidence, commit, field, passed, catalog):
    totals = {name:{key:sum(row['times_ns'][key] for row in rows) for key in rows[0]['times_ns']} for name,rows in data.items()}
    complete = {name:sum(times.values()) for name,times in totals.items()}
    ratios = {name:dict(numerator=value, denominator=complete[name.rsplit('-',1)[0]+'-dense']) for name,value in complete.items()}
    return dict(schema_version=1, kind='micro', workload='micro/streaming', commit=commit,
        toolchain=run('rustc','-Vv'), device=platform.machine()+' '+run('sysctl','-n','machdep.cpu.brand_string'), driver='not-applicable',
        model_config=dict(plan=plan, os=platform.platform(), samples=data, complete_over_dense=ratios,
            complete_time_ns=sum(complete.values()), proof_and_continuation_sha256=evidence, verified_proofs=72,
            controls_executed=passed, controls_catalog=catalog,
            observed_prover_ns_per_point={name:dict(numerator=totals[name]['prover_ns'],denominator=3*(1<<case['m'])) for case in plan['cases'] for name in [f"m{case['m']}-d{case['degree']}-{case['mode']}"]}),
        plan_digest=hashlib.sha256(json.dumps(plan,sort_keys=True,separators=(',',':')).encode()).hexdigest(),
        profile='standard' if field=='QM31' else 'treaty', bindings_all_on=True, batch_size=1, prompt_tokens=0, generated_tokens=0,
        prover_time_ns=sum(complete.values()), witness_recompute_ns=0, stage_times_ns={name+'/'+key:value for name,times in totals.items() for key,value in times.items()},
        kernel_counters={name+'/source_records':sum(row['prover']['source_io']['reads'] for row in rows) for name,rows in data.items()},
        proof_size_bytes=0, verifier_time_ns=dict(rust=0,python=0),
        controls=dict(total=0,passed=0,failed=0),
        note='Complete native CPU synthetic A1 pipeline: 24 cases, three fresh samples each, every proof and original public claim verified; all schedules and losses retained. Inclusive micro-operation time includes fixture generation, preparation, proving and original consumption, with separate stage times. Inference proof/verifier/control fields remain zero; actual subproof consumption and control coverage are retained in model_config. Operation times include transport and source IO but exclude argument parsing, launch/exit, output JSON formatting, controller cleanup and small final buffer destruction. Native RSS includes these, allocator retention and transition overlap; sequential pipeline peak is max of native phases. Python/controller and OS file cache are excluded, so no total-host-memory bound. Reported capacities use actual retained Vec/PathBuf allocations; named Rust type sizes are not native stack bounds. File IO counters are successful logical operations, not physical disk traffic. No warmup/cache flush or fitted/statistical constant claim. Profile selects field only; no inference, GPU, ZK or profile certification. Controls include configuration coverage and do not establish complete claim-graph coverage.')


if __name__=='__main__': main()
