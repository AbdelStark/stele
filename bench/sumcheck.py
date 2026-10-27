"""Verified dense sumcheck baseline on macOS; RFC-0018 §1, E3-01."""
import hashlib
import json
import pathlib
import platform
import subprocess
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[1]


def run(*args):
    return subprocess.check_output(args, cwd=ROOT, text=True).strip()


def main():
    if len(sys.argv) != 2 or platform.system() != 'Darwin':
        raise SystemExit('usage (macOS): python3 bench/sumcheck.py <new-ledger.json>')
    output = pathlib.Path(sys.argv[1]).absolute()
    if output.exists() or run('git', 'status', '--porcelain'):
        raise SystemExit('requires a clean committed checkout and a new ledger path')
    commit = run('git', 'rev-parse', 'HEAD')
    for command in [['scripts/gates/negative-controls.sh'], ['scripts/gates/soundness-accounting.sh'],
                    ['cargo', 'build', '-p', 'stele-sumcheck', '--example', 'baseline', '--release', '--locked', '--offline']]:
        subprocess.run(command, cwd=ROOT, check=True)
    plan = dict(operation='dense sumcheck prove', field='QM31', small=False, variables=14,
        inputs=2, degrees=list(range(5)), iterations=3, samples=3, warmup_calls=1, build='release',
        order='reverse degrees on odd samples', polynomial='f0^degree + 2*f1^(max(degree-1,0))',
        values=['((j*73+19)%31)-15', '((j*29+7)%17)-8'],
        timed='table clone/allocation, transcript initialization, dense prover and final absorb',
        verification='every warmup/measured proof checked by public adapter outside timing')
    times, rss, outputs = {}, {}, {}
    with tempfile.TemporaryDirectory() as directory:
        stats = pathlib.Path(directory) / 'time.txt'
        for sample in range(plan['samples']):
            for degree in plan['degrees'][::(-1 if sample % 2 else 1)]:
                result = dict(line.split() for line in run('/usr/bin/time', '-l', '-o', str(stats),
                    str(ROOT / 'target/release/examples/baseline'), str(degree)).splitlines())
                assert set(result) == {'time_ns', 'dense_table_payload_bytes', 'output'}
                elapsed = int(result['time_ns'])
                peaks = [int(line.split()[0]) for line in stats.read_text().splitlines() if 'maximum resident set size' in line]
                assert elapsed > 0 and len(peaks) == 1 and peaks[0] > 0
                assert int(result['dense_table_payload_bytes']) == 2*16384*16
                assert len(bytes.fromhex(result['output'])) == (14*(degree+1)+2)*16
                assert outputs.setdefault(degree, result['output']) == result['output'], 'proof values changed across samples'
                key = f'degree{degree}'
                times.setdefault(key, []).append(elapsed)
                rss.setdefault(key, []).append(peaks[0])
    assert all(len(v) == 3 for v in times.values()) and len(times) == 5
    if commit != run('git', 'rev-parse', 'HEAD') or run('git', 'status', '--porcelain'):
        raise SystemExit('source state changed during measurement')
    totals = {key: sum(values) for key, values in times.items()}
    proofs = plan['iterations']*plan['samples']
    ledger = dict(schema_version=1, kind='micro', workload='micro/dense-sumcheck', commit=commit,
        toolchain=run('rustc', '-Vv'), device=platform.machine()+' '+run('sysctl', '-n', 'machdep.cpu.brand_string'),
        driver='not-applicable', model_config=dict(plan=plan, os=platform.platform(), sample_times_ns=times,
            peak_process_rss_bytes=rss, dense_table_payload_bytes=2*16384*16,
            c_sc_ns_per_point={key: dict(numerator=value, denominator=proofs*16384) for key, value in totals.items()},
            subproof_values_sha256={str(d): hashlib.sha256(bytes.fromhex(v)).hexdigest() for d,v in outputs.items()}),
        plan_digest=hashlib.sha256(json.dumps(plan, sort_keys=True, separators=(',', ':')).encode()).hexdigest(),
        profile='standard', bindings_all_on=True, batch_size=1, prompt_tokens=0, generated_tokens=0,
        prover_time_ns=sum(totals.values()), witness_recompute_ns=0, stage_times_ns=totals,
        kernel_counters={key+'/input_field_elements': proofs*2*16384 for key in totals},
        proof_size_bytes=0, verifier_time_ns=dict(rust=0, python=0), controls=dict(total=0, passed=0, failed=0),
        note='Native dense QM31 baseline for c_sc(degree, small=false), including clone/allocation and transcript overhead. Every timed proof is subsequently verified with all public obligations consumed; correctness gates run first. Process RSS includes input setup, warmup, prover, verifier, code and allocator; it is not isolated scratch or DRAM traffic. Dense table payload counts logical working field elements only, excluding allocator/Vec metadata and proof storage. Exact integer time/point ratios are baseline measurements, not a cost-model fit. Micro schema proof/verifier/control fields are zero because no inference evidence is claimed. No GPU, ZK or profile-security certification.')
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open('x') as stream:
        json.dump(ledger, stream, indent=2); stream.write('\n')
    subprocess.run(['cargo', 'run', '-p', 'stele-bench', '--locked', '--offline', '--', 'ledger', 'validate', str(output)], cwd=ROOT, check=True)
    print(f'Validated dense sumcheck ledger: {output}')


if __name__ == '__main__':
    main()
