"""RFC-0010 A4 / RFC-0018 §1: complete native expander costs, no PCS admission."""
import hashlib
import json
import pathlib
import platform
import subprocess
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[1]
CASES = [(j, d, r) for j in (3, 6, 9) for d in (1, 4, 8) for r in range(3)]
STAGES = ('input', 'setup', 'encode', 'query', 'validation')


def run(*args):
    return subprocess.check_output(args, cwd=ROOT, text=True).strip()


def receipt(v, j, d):
    assert set(v) == {
        'j', 'd', 'input_symbols', 'checked_symbols', 'input_ns', 'setup_ns',
        'encode_ns', 'query_ns', 'validation_ns', 'total_ns', 'graph_capacity_bytes',
        'input_capacity_bytes', 'output_capacity_bytes', 'query_capacity_bytes',
        'encode_owned_peak_bytes', 'query_owned_peak_bytes', 'native_live_peak_bytes',
        'id_capacity_bytes', 'setup_blocks', 'sparse_adds_per_encode',
        'sparse_base_products_per_encode', 'checksum',
    }
    assert all(type(x) is int and 0 <= x < 1 << 64 for x in v.values())
    n = 4**j
    assert (v['j'], v['d'], v['input_symbols'], v['checked_symbols']) == (j, d, n, 2*n)
    assert all(v[s+'_ns'] > 0 for s in STAGES)
    assert v['total_ns'] >= sum(v[s+'_ns'] for s in STAGES)
    assert v['input_capacity_bytes'] >= n*d*4 and v['output_capacity_bytes'] >= 2*n*d*4
    assert v['query_capacity_bytes'] >= 4*d*4
    assert v['encode_owned_peak_bytes'] >= v['graph_capacity_bytes'] + v['output_capacity_bytes']
    assert v['query_owned_peak_bytes'] == v['encode_owned_peak_bytes'] + v['query_capacity_bytes']
    assert v['native_live_peak_bytes'] == (
        v['id_capacity_bytes'] + v['input_capacity_bytes']
        + v['output_capacity_bytes'] + v['query_owned_peak_bytes'])
    degrees_a = (25, 21, 19, 19, 18, 18, 17, 17, 17, 18, 18, 18)
    degrees_b = (26, 21) + (18,)*10
    edges = sum(4**l*degrees_a[l-4] + 4**l//2*degrees_b[l-4] for l in range(4, j+1))
    assert v['sparse_adds_per_encode'] == v['sparse_base_products_per_encode'] == edges
    assert v['graph_capacity_bytes'] >= 8*edges
    if j == 3:
        assert v['setup_blocks'] == 0
    else:
        assert 0 < v['setup_blocks'] <= 64*sum(4**l + 4**l//2 for l in range(4, j+1))


def main():
    if len(sys.argv) != 2 or platform.system() != 'Darwin':
        raise SystemExit('usage (macOS): python3 bench/expander.py <new-ledger.json>')
    output = pathlib.Path(sys.argv[1]).absolute()
    if output.exists() or run('git', 'status', '--porcelain'):
        raise SystemExit('requires clean committed sources and a new ledger path')
    commit = run('git', 'rev-parse', 'HEAD')
    plan = dict(
        operation='native expander setup, full encode, ordered query and full integer validation',
        cases=CASES, build='release', parallel_workers=1, samples_per_case=3,
        fixture='limb k of input i = (37*i+17*k+9) mod p; fixed zero setup seed',
        fixture_scope='nonzero structured full-field inputs; value-independent encoding loops',
        amortized_setup=False,
        query_columns='[2*n-1,0,n,0]; nonempty eval_row re-encodes the whole row',
        validation='separate integer sparse evaluator, independently derived dense Circle base; '
                   'shares fixed hash block primitive already checked against Python',
        timing='includes input allocation, setup regeneration, encoding, query allocation/full '
               're-encoding and every-symbol validation; excludes build, process launch, '
               'argument parsing, final drops and stdout',
        heap='actual native live heap capacities, including graph, recursive overlap, base '
             'transforms, retained caller input/output/id and query result; excludes validator, '
             'stack, runtime and allocator metadata',
        process_memory='separate worker peak RSS includes all native and integer validation '
                       'buffers/runtime; controller excluded',
        counters='sparse K additions and K-by-base products counted from exact loop geometry; '
                 'base transforms add 1280 K additions and 704 K multiplications per encode; '
                 'base twiddle construction/inversion work is timed but not included in those '
                 'arithmetic counters',
        warmup='release tests, independent oracle checks and j=3 field=1 receipt smoke in '
               'separate processes',
        scope='CPU encoder microbenchmark only, no proof/profile/GPU claim or cost-model fit',
    )
    for command in [
        ['cargo', 'test', '-p', 'stele-code', '--all-targets', '--release', '--locked', '--offline'],
        ['cargo', 'build', '-p', 'stele-code', '--example', 'expander_bench',
         '--release', '--locked', '--offline'],
        ['uv', 'run', '--locked', '--script', 'research/code-provenance/check_native.py'],
    ]:
        subprocess.run(command, cwd=ROOT, check=True)
    distance = json.loads(run('uv', 'run', '--locked', '--script',
        'research/code-provenance/estimate_native_distance.py'))
    binary = str(ROOT/'target/release/examples/expander_bench')
    receipt(json.loads(run(binary, '3', '1')), 3, 1)
    records = []
    with tempfile.TemporaryDirectory() as directory:
        stats = pathlib.Path(directory)/'time.txt'
        for j, d, sample in CASES:
            result = subprocess.run(['/usr/bin/time', '-l', '-o', str(stats), binary, str(j), str(d)],
                cwd=ROOT, text=True, capture_output=True, check=True)
            data = json.loads(result.stdout)
            receipt(data, j, d)
            report = stats.read_text()
            peaks = [int(line.split()[0]) for line in report.splitlines()
                     if 'maximum resident set size' in line]
            assert len(peaks) == 1 and peaks[0] > 0
            records.append(dict(**data, sample=sample, peak_rss_bytes=peaks[0],
                native_time_resource_report=report))
            print(f'Validated j={j}, field={d}, sample={sample}', flush=True)
    if commit != run('git', 'rev-parse', 'HEAD') or run('git', 'status', '--porcelain'):
        raise SystemExit('source state changed')
    assert [(v['j'], v['d'], v['sample']) for v in records] == CASES
    times = {f'j{v["j"]}/d{v["d"]}/sample{v["sample"]}/{s}': v[s+'_ns']
             for v in records for s in STAGES}
    per_input = [dict(j=v['j'], denominator=v['input_symbols'],
        k_additions_numerator=v['sparse_adds_per_encode']+1280,
        sparse_k_base_products_numerator=v['sparse_base_products_per_encode'],
        circle_transform_k_multiplications_numerator=704)
        for v in records if v['d'] == 1 and v['sample'] == 0]
    data = dict(
        schema_version=1, kind='micro', workload='micro/expander-code', commit=commit,
        toolchain=run('rustc', '-Vv'),
        device=platform.machine()+' '+run('sysctl', '-n', 'machdep.cpu.brand_string'),
        driver='not-applicable',
        model_config=dict(plan=plan, os=platform.platform(), samples=records,
            distance_estimates=distance, operations_per_input=per_input),
        plan_digest=hashlib.sha256(json.dumps(plan, sort_keys=True, separators=(',', ':')).encode()).hexdigest(),
        profile='standard', bindings_all_on=True, batch_size=1, prompt_tokens=0, generated_tokens=0,
        prover_time_ns=sum(v['total_ns'] for v in records), witness_recompute_ns=0, stage_times_ns=times,
        kernel_counters=dict(
            input_symbols=sum(v['input_symbols'] for v in records),
            checked_symbols=sum(v['checked_symbols'] for v in records),
            setup_hash_blocks=sum(v['setup_blocks'] for v in records),
            sparse_k_additions=2*sum(v['sparse_adds_per_encode'] for v in records),
            sparse_k_base_products=2*sum(v['sparse_base_products_per_encode'] for v in records),
            circle_transform_k_additions=2*1280*len(records),
            circle_transform_k_multiplications=2*704*len(records)),
        proof_size_bytes=0, verifier_time_ns=dict(rust=0, python=0),
        controls=dict(total=0, passed=0, failed=0),
        note='Full native encoding and query with actual setup regeneration for every sample, '
             'all outputs checked by a separate integer evaluator. All three fields and all '
             'repetitions retained. Native heap capacities and whole-process peaks have '
             'different stated scopes. Setup hashing, full query re-encoding and complete '
             'validation are included, not amortized. Arithmetic counters distinguish '
             'sparse/transform K work and exclude timed twiddle preparation. Distance witnesses '
             'are sampled upper observations only. Standard is a schema tag, no profile or '
             'inference evidence, performance comparison or fitted constant.',
    )
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open('x') as stream:
        json.dump(data, stream, indent=2)
        stream.write('\n')
    subprocess.run(['cargo', 'run', '-p', 'stele-bench', '--locked', '--offline', '--',
        'ledger', 'validate', str(output)], cwd=ROOT, check=True)


if __name__ == '__main__':
    main()
