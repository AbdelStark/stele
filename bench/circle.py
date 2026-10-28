"""RFC-0010 A2 / RFC-0018 §1: actual 2^30-input-symbol runs at both rates."""
import hashlib
import json
import pathlib
import platform
import subprocess
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[1]
CASES = [(29, 1, row) for row in range(2)] + [(28, 2, row) for row in range(4)]


def run(*args):
    return subprocess.check_output(args, cwd=ROOT, text=True).strip()


def receipt(data, m, b, row):
    assert set(data) == {'m', 'b', 'row', 'input_symbols', 'output_symbols',
        'input_capacity_bytes', 'output_capacity_bytes', 'preparation_ns',
        'encode_ns', 'validation_ns', 'checked_symbols', 'checksum'}
    assert all(type(value) is int and 0 <= value < 1 << 64 for value in data.values())
    assert (data['m'], data['b'], data['row']) == (m, b, row)
    assert data['input_symbols'] == 1 << m
    assert data['output_symbols'] == data['checked_symbols'] == 1 << (m + b)
    assert data['input_capacity_bytes'] >= 4 << m
    assert data['output_capacity_bytes'] >= 4 << (m + b)
    assert all(data[name] > 0 for name in ('preparation_ns', 'encode_ns', 'validation_ns'))


def main():
    if len(sys.argv) != 2 or platform.system() != 'Darwin':
        raise SystemExit('usage (macOS): python3 bench/circle.py <new-ledger.json>')
    output = pathlib.Path(sys.argv[1]).absolute()
    if output.exists() or run('git', 'status', '--porcelain'):
        raise SystemExit('requires a clean committed checkout and new ledger path')
    commit = run('git', 'rev-parse', 'HEAD')
    plan = dict(operation='M31 circle encode and exhaustive output validation', cases=CASES,
        input_symbols_per_rate=1 << 30, rows_per_rate={'1/2': 2, '1/4': 4},
        samples_per_row=1, build='release', parallel_workers=1,
        fixture='(17+r)+(29+2*r)*y+((43+3*r)+(71+5*r)*y)*v_(m-1)(x), r=row',
        fixture_scope='four nonzero coefficients; value-independent full encoder loops; not random dense coefficients',
        stages={'preparation': 'allocate and populate original row with independent integer arithmetic',
            'encode': 'complete public encode call: allocation/copy/zero expansion, inverse normalization, domain/twiddle construction and batch inversions, full forward transform',
            'validation': 'compare EVERY output with independent integer circle recurrence and polynomial; checksum all outputs'},
        amortized_setup=False, warmup='small release tests and m=8 smoke only, separate process',
        excluded='process launch, stdout serialization and final buffer deallocation',
        memory='separate native worker peak RSS per row, including retained input, all internal allocation capacities/overlap, returned output, validation and runtime; Python controller excluded',
        scope='CPU weight-registration encoding only; no proof, inference, GPU, PCS/profile admission or cost-model fit')
    for command in [
        ['cargo', 'test', '-p', 'stele-code', '--all-targets', '--release', '--locked', '--offline'],
        ['cargo', 'build', '-p', 'stele-code', '--example', 'circle_bench', '--release', '--locked', '--offline'],
    ]:
        subprocess.run(command, cwd=ROOT, check=True)
    binary = str(ROOT / 'target/release/examples/circle_bench')
    # Exercise the exact subprocess/receipt contract before allocating large rows.
    smoke = json.loads(run(binary, '8', '2', '3'))
    receipt(smoke, 8, 2, 3)
    bad = dict(smoke, checked_symbols=smoke['checked_symbols'] - 1)
    try:
        receipt(bad, 8, 2, 3)
    except AssertionError:
        pass
    else:
        raise AssertionError('receipt accepted missing output checks')
    records = []
    with tempfile.TemporaryDirectory() as directory:
        stats = pathlib.Path(directory) / 'time.txt'
        for m, b, row in CASES:
            print(f'Encoding actual row m={m}, b={b}, row={row}', flush=True)
            result = subprocess.run(['/usr/bin/time', '-l', '-o', str(stats), binary,
                str(m), str(b), str(row)], cwd=ROOT, text=True, capture_output=True, check=True)
            data = json.loads(result.stdout)
            receipt(data, m, b, row)
            raw_stats = stats.read_text()
            peaks = [int(line.split()[0]) for line in raw_stats.splitlines() if 'maximum resident set size' in line]
            assert len(peaks) == 1 and peaks[0] > 0
            records.append(dict(**data, peak_rss_bytes=peaks[0], native_time_resource_report=raw_stats))
            print(f'Checked all {data["checked_symbols"]} outputs for b={b}, row={row}', flush=True)
    assert [(d['m'], d['b'], d['row']) for d in records] == CASES
    rates = {}
    for b in (1, 2):
        selected = [d for d in records if d['b'] == b]
        rates[str(b)] = dict(rows=len(selected), input_symbols=sum(d['input_symbols'] for d in selected),
            output_symbols=sum(d['output_symbols'] for d in selected),
            checked_symbols=sum(d['checked_symbols'] for d in selected),
            peak_rss_bytes=max(d['peak_rss_bytes'] for d in selected))
        assert rates[str(b)]['input_symbols'] == 1 << 30
        assert rates[str(b)]['output_symbols'] == rates[str(b)]['checked_symbols'] == 1 << (30 + b)
    if commit != run('git', 'rev-parse', 'HEAD') or run('git', 'status', '--porcelain'):
        raise SystemExit('source state changed during measurement')
    times = {f'b{d["b"]}/row{d["row"]}/{stage}': d[stage + '_ns']
        for d in records for stage in ('preparation', 'encode', 'validation')}
    ledger = dict(schema_version=1, kind='micro', workload='micro/circle-code', commit=commit,
        toolchain=run('rustc', '-Vv'), device=platform.machine() + ' ' + run('sysctl', '-n', 'machdep.cpu.brand_string'),
        driver='not-applicable', model_config=dict(plan=plan, os=platform.platform(), field='M31',
            samples=records, rates=rates, measured_input_output_capacities=True),
        plan_digest=hashlib.sha256(json.dumps(plan, sort_keys=True, separators=(',', ':')).encode()).hexdigest(),
        profile='standard', bindings_all_on=True, batch_size=1, prompt_tokens=0, generated_tokens=0,
        prover_time_ns=sum(times.values()), witness_recompute_ns=0, stage_times_ns=times,
        kernel_counters=dict(input_symbols=sum(d['input_symbols'] for d in records),
            output_symbols=sum(d['output_symbols'] for d in records),
            checked_symbols=sum(d['checked_symbols'] for d in records)),
        proof_size_bytes=0, verifier_time_ns=dict(rust=0, python=0), controls=dict(total=0, passed=0, failed=0),
        note='Six actual CPU encodings: two k=2^29 rows at rate 1/2 and four k=2^28 rows at rate 1/4, all N=2^30. Every output checked with independent integer arithmetic. Four-coefficient high-basis fixtures, no input-dependent transform shortcuts. One sample per distinct row, no rescaling/extrapolation/discarding. Encode stage includes all internal preparation, inverse, expansion, twiddles and forward transform without amortization; fixture construction and exhaustive validation separately timed and included in total. RSS includes all native process capacities/overlap, not isolated scratch or live allocation; no Python controller memory. Standard is a schema tag, not profile certification. No performance comparison, fitted constant, proof or PCS admission.')
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open('x') as stream:
        json.dump(ledger, stream, indent=2)
        stream.write('\n')
    subprocess.run(['cargo', 'run', '-p', 'stele-bench', '--locked', '--offline', '--',
        'ledger', 'validate', str(output)], cwd=ROOT, check=True)
    print(f'Validated full circle benchmark ledger: {output}', flush=True)


if __name__ == '__main__':
    main()
