"""RFC-0010 A4/A5 and RFC-0018 §1: complete bounded native encoder measurements."""
import hashlib
import json
from pathlib import Path
import platform
import subprocess
import sys
import tempfile
from encoder_stack import inspect

ROOT = Path(__file__).resolve().parents[1]
CASES = [(j, d, sample) for j in range(3,11) for d in (1,4,8) for sample in range(3)]
STAGES = ('factory', 'input', 'encode', 'query', 'validation')
WORK = ('peak_owned_bytes', 'hash_blocks', 'generated_rows', 'sparse_limb_additions',
        'sparse_limb_products', 'initialized_symbols', 'copied_symbols', 'circle_calls',
        'circle_transform_additions', 'circle_transform_products', 'twiddle_elements',
        'inverse_prefix_elements', 'max_recursive_frames')
KEYS = {'j','d','input_symbols','checked_symbols','total_ns','input_capacity_bytes',
        'output_capacity_bytes','query_capacity_bytes','native_live_peak_bytes',
        'encoder_inline_bytes','observation_inline_bytes','query_input_bytes','checksum'}
KEYS |= {s+'_ns' for s in STAGES} | {p+'_'+s for p in ('encode','query') for s in WORK}


def run(*args):
    return subprocess.check_output(args, cwd=ROOT, text=True).strip()


def receipt(v,j,d):
    assert set(v) == KEYS and all(type(x) is int and 0 <= x < 1 << 64 for x in v.values())
    n, w = 4**j, 4*d
    assert (v['j'],v['d'],v['input_symbols'],v['checked_symbols']) == (j,d,n,2*n)
    # Tiny factory/input stages can quantize to zero; retain the actual clock value.
    assert all(v[s+'_ns'] > 0 for s in ('encode','query','validation'))
    assert v['total_ns'] >= sum(v[s+'_ns'] for s in STAGES)
    assert v['input_capacity_bytes'] >= n*w and v['output_capacity_bytes'] >= 2*n*w
    assert v['query_capacity_bytes'] >= 4*w and v['query_input_bytes'] == 32
    assert v['native_live_peak_bytes'] == (v['input_capacity_bytes'] + v['output_capacity_bytes']
                                         + v['query_peak_owned_bytes'])
    assert v['encoder_inline_bytes'] > 0 and v['observation_inline_bytes'] > 0
    a = (25,21,19,19,18,18,17,17,17,18,18,18)
    b = (26,21)+(18,)*10
    edges = sum(4**l*a[l-4] + 4**l//2*b[l-4] for l in range(4,j+1))
    assert v['encode_sparse_limb_additions'] == v['encode_sparse_limb_products'] == d*edges
    assert v['encode_generated_rows'] == 2*n-128
    if j == 3:
        assert v['encode_hash_blocks'] == 0
    else:
        assert 0 < v['encode_hash_blocks'] <= 64*(2*n-128)
    assert v['encode_peak_owned_bytes'] >= (2*n+(n-64)//3+128)*w + 127*4 + 7*24
    assert v['encode_initialized_symbols'] == 2*n+(n-64)//3+64
    assert v['encode_copied_symbols'] == sum(4**l for l in range(4,j+1))+192
    assert v['encode_circle_calls'] == 1
    assert v['encode_circle_transform_additions'] == 1280
    assert v['encode_circle_transform_products'] == 704
    assert v['encode_twiddle_elements'] == 190 and v['encode_inverse_prefix_elements'] == 63
    assert v['encode_max_recursive_frames'] == j-2
    for s in WORK:
        extra = v['query_capacity_bytes'] if s == 'peak_owned_bytes' else 4 if s == 'copied_symbols' else 0
        assert v['query_'+s] == v['encode_'+s] + extra


def main():
    if len(sys.argv) != 2 or (platform.system(), platform.machine()) != ('Darwin','arm64'):
        raise SystemExit('usage on arm64 macOS: python3 bench/encoder.py <new-ledger.json>')
    output = Path(sys.argv[1]).absolute()
    if output.exists() or run('git','status','--porcelain'):
        raise SystemExit('requires clean committed sources and a new ledger path')
    commit = run('git','rev-parse','HEAD')
    plan = dict(cases=CASES, samples_per_case=3, workers=1, build='release',
        fixture='full limbs (37*i+17*k+9) mod p; exact zero-seed v2 identity',
        scope='CPU bounded encoder only; standard is a schema tag, no PCS/profile admission or fit',
        timing='factory, input preparation, complete measured encode, complete query re-encoding '
               'and every-output integer validation; includes observation overhead and all per-call '
               'setup hashing, sampling, sorting, allocation, initialization, copies and base work; '
               'excludes build, launch, argument parsing, JSON serialization and final native drops',
        generation='performed inside both encode and query timers, never amortized; actual hash '
                   'blocks and rows are observed, not a separately isolated timing',
        validation='independent integer sparse evaluator and independently derived dense Circle base; '
                   'independently assembled BLAKE3 records; every output and query value checked',
        capacities='actual owned Vec liveness includes output/scratch/base/twiddle/prefix/query '
                   'overlap; native live adds retained caller input and original encoded output; '
                   'excludes validator, stack, runtime and allocator bookkeeping',
        process_memory='per-worker time -l peak RSS includes native and validation buffers, all '
                       'stack, runtime and allocator retention; controller excluded',
        stack='exact compiled native/hash frame inventory and explicit recursion counts, separate '
              'from inline object sizes and process RSS; not a whole-process stack bound',
        counters='logical operations: sparse base-limb adds/products, K initialization/copies and '
                 'Circle transform K operations; twiddle/prefix values recorded separately; '
                 'no instruction/traffic or complete base-field-operation equivalence is claimed',
        warmup='release code tests, dense-base fixture check and small receipt smoke in separate processes')
    for command in [
        ['cargo','test','-p','stele-code','--release','--locked','--offline'],
        ['cargo','build','-p','stele-code','--example','encoder_bench','--release','--locked','--offline'],
        ['uv','run','--locked','--script','research/code-provenance/check_measurement.py'],
    ]:
        subprocess.run(command,cwd=ROOT,check=True)
    binary = ROOT/'target/release/examples/encoder_bench'
    stack = inspect(binary)
    receipt(json.loads(run(str(binary),'3','1')),3,1)
    records = []
    with tempfile.TemporaryDirectory() as directory:
        stats = Path(directory)/'time.txt'
        for j,d,sample in CASES:
            result = subprocess.run(['/usr/bin/time','-l','-o',str(stats),str(binary),str(j),str(d)],
                                    cwd=ROOT,text=True,capture_output=True,check=True)
            v = json.loads(result.stdout)
            receipt(v,j,d)
            raw = stats.read_text()
            peaks = [int(line.split()[0]) for line in raw.splitlines() if 'maximum resident set size' in line]
            assert len(peaks) == 1 and peaks[0] > 0
            records.append(dict(**v,sample=sample,peak_rss_bytes=peaks[0],native_time_resource_report=raw))
            print(f'Validated J={j}, degree={d}, sample={sample}',flush=True)
    assert [(r['j'],r['d'],r['sample']) for r in records] == CASES
    if commit != run('git','rev-parse','HEAD') or run('git','status','--porcelain'):
        raise SystemExit('source state changed during measurement')
    data = dict(schema_version=1,kind='micro',workload='micro/native-bounded-encoder',commit=commit,
        toolchain=run('rustc','-Vv'),device=platform.machine()+' '+run('sysctl','-n','machdep.cpu.brand_string'),
        driver='not-applicable',model_config=dict(plan=plan,os=platform.platform(),samples=records,compiled_frames=stack),
        plan_digest=hashlib.sha256(json.dumps(plan,sort_keys=True,separators=(',',':')).encode()).hexdigest(),
        profile='standard',bindings_all_on=True,batch_size=1,prompt_tokens=0,generated_tokens=0,
        prover_time_ns=sum(r['total_ns'] for r in records),witness_recompute_ns=0,
        stage_times_ns={f'j{r["j"]}/d{r["d"]}/sample{r["sample"]}/{s}':r[s+'_ns'] for r in records for s in STAGES},
        kernel_counters={s:sum(r[p+'_'+s] for r in records for p in ('encode','query'))
                         for s in WORK if s not in ('peak_owned_bytes','max_recursive_frames')},
        proof_size_bytes=0,verifier_time_ns=dict(rust=0,python=0),controls=dict(total=0,passed=0,failed=0),
        note='All sizes J=3..10 and all three fields measured without amortization or discarded samples. '
             'Every codeword checked independently. Full query cost includes regenerated encoding. '
             'Owned capacities, inline layouts, compiled stack frames and whole-worker process RSS '
             'have distinct explicit scopes. No inference, GPU, ZK, PCS/profile, fit or speed comparison.')
    output.parent.mkdir(parents=True,exist_ok=True)
    with output.open('x') as stream:
        json.dump(data,stream,indent=2)
        stream.write('\n')
    subprocess.run(['cargo','run','-p','stele-bench','--locked','--offline','--','ledger','validate',str(output)],cwd=ROOT,check=True)


if __name__ == '__main__':
    main()
