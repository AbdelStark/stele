# /// script
# requires-python = ">=3.12"
# dependencies = ["blake3==1.0.11", "python-flint==0.9.0"]
# ///
"""RFC-0018 §1: complete Python wide-range operation with every consumer on."""
import cProfile
import hashlib
import json
from pathlib import Path
import platform
import pstats
import resource
import subprocess
import sys
from time import perf_counter_ns, process_time_ns

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'research/sumcheck'))
import check_field as check


def run(*args):
    return subprocess.check_output(args, cwd=ROOT, text=True).strip()


def operation(d):
    times = {}
    start = perf_counter_ns()
    p, words, bs, cs, root = check.prepare()
    mark = perf_counter_ns(); times['witness'] = mark-start
    proof, state = check.r.assemble(p, words, bs, cs, d)
    after_prove = perf_counter_ns(); times['prove'] = after_prove-mark
    out = check.consume(p, root, proof, state, d)
    after_verify = perf_counter_ns(); times['verify'] = after_verify-after_prove
    payload = check.encoded(proof)
    digest = check.artifact(root, proof, out)
    end = perf_counter_ns(); times['encode_and_check'] = end-after_verify
    return times, digest, len(payload), (p, root, proof)


def main():
    if len(sys.argv) != 3 or sys.argv[1] not in ('QM31', 'OM31'):
        raise SystemExit('usage: uv run --locked --script bench/reference_field.py QM31|OM31 NEW_LEDGER')
    field, output = sys.argv[1], Path(sys.argv[2]).absolute()
    if platform.system() != 'Darwin' or output.exists() or run('git', 'status', '--porcelain'):
        raise SystemExit('requires macOS, clean committed checkout and new ledger path')
    commit = run('git', 'rev-parse', 'HEAD')
    d = 4 if field == 'QM31' else 8
    plan = dict(operation='complete public wide-range research proof', field=field, samples=3,
        caps=[0,257,(1<<31)+1], values=[0,256,(1<<31)+1], repetitions=1, identity=2757, source=29,
        warmup=1, profile_calls=1, profile_top_functions=20, table_rows=256, lookup_rows=32,
        timed='witness/root, prove, actual public verify, encoding and state/account checks',
        controls='two rejection controls separately timed on the warmup proof',
        encoding='lossless tagged JSON research artifact; not the production proof wire format',
        memory='process high-water RSS includes imports, warmup, samples, controls and profiler',
        contention='other original validation processes remain running; CPU time also recorded')
    expected = json.loads(check.FIXTURE.read_text())[f'{d}/1']
    _, digest, size, fixture = operation(d)
    assert digest == expected
    start = perf_counter_ns(); control_count = check.controls(*fixture, d)
    control_ns = perf_counter_ns()-start
    samples = []
    for sample in range(plan['samples']):
        cpu_start = process_time_ns()
        times, digest, encoded_size, _ = operation(d)
        cpu_ns = process_time_ns()-cpu_start
        assert digest == expected and encoded_size == size
        samples.append(dict(stages_ns=times, process_cpu_ns=cpu_ns))
        print('complete measured proof passed', field, sample+1, flush=True)
    profiler = cProfile.Profile()
    profiler.enable()
    _, digest, encoded_size, _ = operation(d)
    profiler.disable()
    assert digest == expected and encoded_size == size
    calls = []
    for (filename, line, function), (primitive, total, _, _, _) in pstats.Stats(profiler).stats.items():
        if filename.startswith(str(ROOT)):
            calls.append(dict(file=str(Path(filename).relative_to(ROOT)), line=line,
                function=function, primitive_calls=primitive, total_calls=total))
    calls.sort(key=lambda item: (-item['total_calls'], item['file'], item['line']))
    if run('git', 'rev-parse', 'HEAD') != commit or run('git', 'status', '--porcelain'):
        raise SystemExit('source state changed during measurement')
    stages = {key: sum(row['stages_ns'][key] for row in samples) for key in samples[0]['stages_ns']}
    total = sum(stages.values())
    ledger = dict(schema_version=1, kind='micro', workload='micro/reference-field-wide-range', commit=commit,
        toolchain=sys.version, device=platform.machine()+' '+run('sysctl','-n','machdep.cpu.brand_string'),
        driver='not-applicable', model_config=dict(plan=plan, os=platform.platform(), samples=samples,
            peak_process_rss_bytes=resource.getrusage(resource.RUSAGE_SELF).ru_maxrss,
            profiled_complete_operation_calls=calls[:plan['profile_top_functions']],
            control_time_ns=control_ns, artifact_sha256=expected),
        plan_digest=hashlib.sha256(json.dumps(plan,sort_keys=True,separators=(',',':')).encode()).hexdigest(),
        profile='standard' if d==4 else 'treaty', bindings_all_on=True, batch_size=1,
        prompt_tokens=0, generated_tokens=0, prover_time_ns=total,
        witness_recompute_ns=stages['witness'], stage_times_ns=stages,
        kernel_counters=dict(measured_complete_proofs=3, range_words=12, range_byte_cells=48, lookup_table_rows=768),
        proof_size_bytes=size, verifier_time_ns=dict(rust=0,python=stages['verify']),
        controls=dict(total=control_count,passed=control_count,failed=0),
        note='Complete public research range operation with original-source and lookup consumers enabled. Total includes witness/root preparation, prove, actual verify and encoding/state/account checks; warmup, separate controls and instrumented profile are excluded. CPU time includes operation call overhead. RSS includes the entire process and allocator retention. Three samples are observations under concurrent validation load, not a fitted constant. JSON proof size is not production wire size. Profile selects field only; no native inference, GPU, ZK, PCS, FS or profile certification claim.')
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open('x') as stream:
        json.dump(ledger, stream, indent=2); stream.write('\n')
    subprocess.run(['cargo','run','-p','stele-bench','--locked','--offline','--',
                    'ledger','validate',str(output)], cwd=ROOT, check=True)
    print('validated complete operation ledger', output, flush=True)


if __name__ == '__main__':
    main()
