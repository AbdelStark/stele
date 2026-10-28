"""RFC-0008 A3 / RFC-0018 §1: complete conditional primitive CPU ledger."""
import hashlib
import json
from pathlib import Path
import platform
import re
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
STAGES = ('preparation_ns','tree_prover_ns','leaf_prover_ns','encode_ns','tree_consumer_ns','leaf_consumer_ns')


def run(*args):
    return subprocess.check_output(args,cwd=ROOT,text=True).strip()


def cases():
    return [dict(m=m,mode=mode) for m in (0,1,8,12,16)
            for mode in ('ordinary','weighted','selected1','selected3zero')]


def validate(row, case, degree):
    m, mode = case['m'], case['mode']
    n, wire = 1 << m, 4*degree
    c = {'ordinary':0,'weighted':0,'selected1':1,'selected3zero':3}[mode]
    b = m//2 if mode == 'weighted' else m
    assert set(row) == {*STAGES,'complete_ns','m','b','columns','points','field_degree','original_capacity_bytes',
        'tree_proof_bytes','leaf_proof_bytes','encoded_capacity_bytes','canonical','tree_claim_ids','accounting','leaf_claim_ids','leaf_sc'}
    assert (row['m'],row['b'],row['columns'],row['points'],row['field_degree']) == (m,b,c,n,degree)
    assert all(type(row[key]) is int and row[key] >= 0 for key in STAGES)
    assert all(row[key] > 0 for key in ('preparation_ns','tree_prover_ns','encode_ns','tree_consumer_ns'))
    assert (row['leaf_prover_ns'] > 0) == (c > 0) == (row['leaf_consumer_ns'] > 0)
    assert row['complete_ns'] >= sum(row[key] for key in STAGES)
    record = lambda i,k: dict(id=i,m=k,degree=3,field_degree=degree,numerator=3*k)
    assert row['accounting'] == dict(tree_id=307,field_degree=degree,gamma=m,fold=m,layers=[record(k,k) for k in range(m)])
    assert row['tree_claim_ids'] == [11,12]
    assert row['leaf_claim_ids'] == (list(range(91,91+c)) if c else None)
    assert row['leaf_sc'] == (record(307,m) if c else None)
    assert row['tree_proof_bytes'] == wire*(2+2*m*m+3*m)
    assert row['leaf_proof_bytes'] == (wire*(4*m+c+2) if c else 0)
    size = row['tree_proof_bytes']+row['leaf_proof_bytes']
    assert row['encoded_capacity_bytes'] >= size
    assert len(bytes.fromhex(row['canonical'])) == size+wire
    assert row['original_capacity_bytes'] >= wire*n*(2+(c+1 if c else 0))


def main():
    if len(sys.argv) != 3 or sys.argv[1] not in ('QM31','OM31') or platform.system() != 'Darwin':
        raise SystemExit('usage (macOS): python3 bench/fraction.py QM31|OM31 <new-ledger.json>')
    field, output = sys.argv[1], Path(sys.argv[2]).absolute()
    if output.exists() or run('git','status','--porcelain'):
        raise SystemExit('requires a clean committed checkout and new ledger path')
    commit = run('git','rev-parse','HEAD')
    plan = dict(operation='prepare, fraction-tree prove, optional selected-product prove, encode, decode and consume originals',
        cases=cases(),field=field,samples=3,proofs_per_sample=1,warmup=0,build='release',batch_size=1,
        fixture='full-extension coefficient from production Transcript with public fraction synthetic fixture/v1; deterministic arrays defined in fraction_bench.rs',
        context='fixed public recipe, descriptor and mode; synthetic public original arrays, no commitment',
        order='reverse cases on odd samples; fresh native process for every sample',
        timed='fixture/descriptor construction, all internal levels/copies, tree and selected-product proving, transcript initialization, encoding, decoding, all original public consumers, receipt/continuation validation, result construction and original/source/proof/descriptor cleanup',
        excluded='argument parsing, process launch/exit, JSON serialization/printing and result-value destruction after complete_ns',
        memory='native whole-operation peak RSS includes preparation, all retained tree levels, dense/equality copies, original inputs, proof objects and encodings, consumers, allocator retention and output; Python/controller and OS memory excluded',
        capacities='actual original leaves/sigma/columns and encoded Vec capacities only; other internal storage is included in RSS, not attributed or asserted as an allocator/stack bound',
        scope='conditional public CPU primitives; separate scoped records; no lookup membership, private source, PCS, ZK, GPU, FS, inference or profile certification')
    for command in [['scripts/gates/negative-controls.sh'],['scripts/gates/soundness-accounting.sh'],
                    ['cargo','test','-p','stele-lookup','--example','fraction_bench','--release','--locked','--offline'],
                    ['cargo','build','-p','stele-lookup','--example','fraction_bench','--release','--locked','--offline']]:
        subprocess.run(command,cwd=ROOT,check=True)
    coverage = run('cargo','run','-q','-p','stele-negative-controls','--bin','stele-controls','--locked','--offline','--','--coverage')
    passed, catalog = map(int,re.search(r'(\d+)/(\d+) controls',coverage).groups())
    data, evidence = {}, {}
    degree = 4 if field == 'QM31' else 8
    with tempfile.TemporaryDirectory() as directory:
        stats = Path(directory)/'time.txt'
        for sample in range(plan['samples']):
            for case in plan['cases'][::(-1 if sample%2 else 1)]:
                name = f"m{case['m']}-{case['mode']}"
                row = json.loads(run('/usr/bin/time','-l','-o',str(stats),str(ROOT/'target/release/examples/fraction_bench'),field,str(case['m']),case['mode']))
                validate(row,case,degree)
                peaks = [int(line.split()[0]) for line in stats.read_text().splitlines() if 'maximum resident set size' in line]
                assert len(peaks) == 1 and peaks[0] > 0
                canonical = row.pop('canonical')
                digest = hashlib.sha256(bytes.fromhex(canonical)).hexdigest()
                assert evidence.setdefault(name,digest) == digest, 'proof/continuation nondeterminism'
                row['peak_native_rss_bytes'] = peaks[0]
                row['validation_cleanup_ns'] = row['complete_ns']-sum(row[key] for key in STAGES)
                data.setdefault(name,[]).append(row)
                print(f'{field} sample {sample+1}: {name} original claims consumed',flush=True)
    assert len(data) == 20 and all(len(rows) == 3 for rows in data.values())
    if commit != run('git','rev-parse','HEAD') or run('git','status','--porcelain'):
        raise SystemExit('source state changed during measurement')
    totals = {name:{key:sum(row[key] for row in rows) for key in (*STAGES,'validation_cleanup_ns','complete_ns')}
              for name,rows in data.items()}
    stages = {name+'/'+key:value for name,times in totals.items() for key,value in times.items() if key != 'complete_ns'}
    complete = sum(times['complete_ns'] for times in totals.values())
    assert sum(stages.values()) == complete
    ledger = dict(schema_version=1,kind='micro',workload='micro/fraction',commit=commit,
        toolchain=run('rustc','-Vv'),device=platform.machine()+' '+run('sysctl','-n','machdep.cpu.brand_string'),driver='not-applicable',
        model_config=dict(plan=plan,os=platform.platform(),samples=data,complete_time_ns=complete,
            proof_and_continuation_sha256=evidence,verified_proofs=60,controls_executed=passed,controls_catalog=catalog,
            complete_ns_per_original_pair={name:dict(numerator=times['complete_ns'],denominator=3*rows[0]['points']) for name,rows in data.items() for times in [totals[name]]}),
        plan_digest=hashlib.sha256(json.dumps(plan,sort_keys=True,separators=(',',':')).encode()).hexdigest(),
        profile='standard' if field=='QM31' else 'treaty',bindings_all_on=True,batch_size=1,prompt_tokens=0,generated_tokens=0,
        prover_time_ns=complete,witness_recompute_ns=0,stage_times_ns=stages,
        kernel_counters={name+'/original_pairs':3*rows[0]['points'] for name,rows in data.items()},proof_size_bytes=0,
        verifier_time_ns=dict(rust=0,python=0),controls=dict(total=0,passed=0,failed=0),
        note='Complete conditional fraction CPU operation, every original public consumer enabled. Both tree and selected-product claims are discharged against original arrays, including unused columns under beta=0. Complete time includes preparation, all copies/levels, serialization/parsing, actual consumption, continuation/receipt checks, result construction and original-buffer cleanup. Stage times separate these; remaining validation/cleanup overhead is charged. Process RSS covers the entire native operation, allocator retention and output; it is neither an isolated prover peak nor a total-host bound. Capacities describe only named original/encoded buffers, not all allocations. All samples retained; fresh processes, no warmup/cache flush, no fitted constant or statistical comparison. No inference is performed, so witness and top-level inference proof/verifier/control fields are zero. Native primitive consumption and exact scoped records are retained per sample; Python parity is checked by the shared corpus outside measurement. Profile selects field only. No c_lu, full lookup, private source, PCS, ZK, GPU, FS or inference/profile claim follows.')
    output.parent.mkdir(parents=True,exist_ok=True)
    with output.open('x') as stream:
        json.dump(ledger,stream,indent=2);stream.write('\n')
    subprocess.run(['cargo','run','-p','stele-bench','--locked','--offline','--','ledger','validate',str(output)],cwd=ROOT,check=True)
    print(f'Validated {field} fraction ledger: {output}')


if __name__ == '__main__':
    main()
