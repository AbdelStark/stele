"""Measure c_lu for plan-admitted lookups (RFC-0008 A2/§3, RFC-0018 §1, task E3-07)."""
import hashlib
import json
import pathlib
import platform
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
BINARY = ROOT/'target/release/examples/lookup_bench'


def run(*args):
    return subprocess.check_output(args, cwd=ROOT, text=True).strip()


def main():
    if len(sys.argv) != 3 or sys.argv[1] not in ('standard', 'treaty'):
        raise SystemExit('usage: python3 bench/clu.py standard|treaty bench/ledger/<run>.json')
    profile, output = sys.argv[1], pathlib.Path(sys.argv[2]).absolute()
    if output.exists():
        raise SystemExit('refusing to overwrite a benchmark ledger')
    if run('git', 'status', '--porcelain'):
        raise SystemExit('commit benchmark sources before measuring; worktree must be clean')
    commit = run('git', 'rev-parse', 'HEAD')
    plan = dict(profile=profile, field_degree=4 if profile == 'standard' else 8,
                repetitions=1 if profile == 'standard' else 2, m=[12, 14, 16, 18], samples=3, build='release',
                table='range_8', columns=1, selector='all positions real', original='id41 ell=m//2 blowup1, outside timer',
                multiplicities='ids 81,82 ell=4 blowup1', m31_unit='chained M31 multiplication, 2^24 per sample, black_box per result (as e1-02)',
                order='m ascending, samples consecutive, fresh process per sample; no warmup or discarded samples',
                c_lu='prove_ns*m31_multiplications/(positions*m31_chain_ns); prove includes mu preparation/registration, trees, SelectedProduct and every A9 opening')
    subprocess.run(['cargo', 'build', '-p', 'stele-negative-controls', '--example', 'lookup_bench',
                    '--release', '--locked', '--offline'], cwd=ROOT, check=True)
    binary_sha256 = hashlib.sha256(BINARY.read_bytes()).hexdigest()
    samples, stages = [], {}
    for m in plan['m']:
        for i in range(plan['samples']):
            v = json.loads(run(str(BINARY), 'clu', profile, str(m)))
            assert (v['profile'].lower(), v['field_degree'], v['m'], v['positions'], v['repetitions']) == (
                profile, plan['field_degree'], m, 1 << m, plan['repetitions'])
            t = v['stages_ns']
            assert set(t) == {'prove', 'import_multiplicities', 'verify', 'm31_chain'} and all(x > 0 for x in t.values())
            v['c_lu_numerator'] = t['prove']*v['m31_multiplications']
            v['c_lu_denominator'] = v['positions']*t['m31_chain']
            samples.append(v)
            for name, ns in t.items():
                stages[f'm{m}/{i}/{name}'] = ns
    if commit != run('git', 'rev-parse', 'HEAD') or run('git', 'status', '--porcelain') \
            or hashlib.sha256(BINARY.read_bytes()).hexdigest() != binary_sha256:
        raise SystemExit('source state changed during measurement')
    largest = [v for v in samples if v['m'] == plan['m'][-1]]
    c_lu = [v['c_lu_numerator']//v['c_lu_denominator'] for v in largest]
    ledger = {
        'schema_version': 1, 'kind': 'micro', 'workload': 'micro/lookup-clu', 'commit': commit,
        'toolchain': run('rustc', '-Vv'), 'device': platform.machine()+' '+run('sysctl', '-n', 'machdep.cpu.brand_string'),
        'driver': 'not-applicable',
        'model_config': dict(plan=plan, os=platform.platform(), binary_sha256=binary_sha256, samples=samples,
                             c_lu_floor_largest_m=c_lu),
        'plan_digest': hashlib.sha256(json.dumps(plan, sort_keys=True, separators=(',', ':')).encode()).hexdigest(),
        'profile': profile, 'bindings_all_on': True, 'batch_size': 1, 'prompt_tokens': 0, 'generated_tokens': 0,
        'prover_time_ns': sum(v['stages_ns']['prove'] for v in samples), 'witness_recompute_ns': 0,
        'stage_times_ns': stages,
        'kernel_counters': {'lookup_positions': sum(v['positions'] for v in samples),
                            'm31_chain_multiplications': sum(v['m31_multiplications'] for v in samples)},
        'proof_size_bytes': 0, 'verifier_time_ns': {'rust': 0, 'python': 0},
        'controls': {'total': 0, 'passed': 0, 'failed': 0},
        'note': 'Plan-admitted A5 lookup (RFC-0008 A2) on CPU, every binding on; c_lu in chained-M31-multiplication '
                'units from the same process. Original commitment excluded (c_c); timings inclusive of mu commitment '
                'and all openings. Per-sample proof bytes and verifier times are in model_config.samples. '
                'No planning-constant fit, GPU, inference or Fiat-Shamir claim.'}
    with output.open('x') as stream:
        json.dump(ledger, stream, indent=2)
        stream.write('\n')
    subprocess.run(['cargo', 'run', '-p', 'stele-bench', '--locked', '--offline', '--',
                    'ledger', 'validate', str(output)], cwd=ROOT, check=True)
    print(f'{profile}: c_lu (floor, m={plan["m"][-1]}) = {c_lu}; ledger: {output}')


if __name__ == '__main__':
    main()
