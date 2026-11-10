"""RFC-0018 A1 development-profile ledger from one `stele prove-dev`/`verify-dev` run (task E16-11).

The run directory holds what `docs/development-e2e.md` ("Benchmark ledger") produces:
`prove.out`, `prove.time` and `verify.out`, `verify.time` (GNU `/usr/bin/time -v`),
`proof.bin`, `public.bin`, and `controls.log`, the `--nocapture` output of
`rejects_tampers_on_a_supplied_proof` against that proof.

  python3 bench/dev_e2e.py RUN_DIR OUT.json --workload dev/<name> --commit <sha> \
      --device "<cpu>" --toolchain "$(rustc -V)" --prompt-tokens P --threads N \
      --model-config config.json --host-context "<host>"
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess


def gnu_time(path):
    """Wall seconds and maximum RSS bytes from GNU time -v."""
    text = Path(path).read_text()
    clock = re.search(r'Elapsed \(wall clock\) time \(h:mm:ss or m:ss\): (\S+)', text).group(1)
    seconds = 0.0
    for part in clock.split(':'):
        seconds = seconds * 60 + float(part)
    rss = int(re.search(r'Maximum resident set size \(kbytes\): (\d+)', text).group(1)) * 1024
    assert 'Exit status: 0' in text, 'NonzeroExit'
    return round(seconds * 1e9), rss


def statement(path):
    lines = dict(line.split(' ', 1) for line in Path(path).read_text().splitlines() if ' ' in line)
    return {k: lines[k] for k in ('cqis_id', 'model', 'T', 'tokens', 'checked', 'next')}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('run', type=Path)
    p.add_argument('out', type=Path)
    for name in ('workload', 'commit', 'device', 'model-config', 'toolchain'):
        p.add_argument('--' + name, required=True)
    p.add_argument('--prompt-tokens', type=int, required=True)
    p.add_argument('--threads', type=int, required=True, help='hardware threads available to the run')
    p.add_argument('--host-context', required=True)
    a = p.parse_args()
    run = a.run
    assert (run / 'verify.out').read_text().splitlines()[-1] == 'YES', 'NotAccepted'
    assert (run / 'prove.out').read_text().splitlines()[-1] == 'PROOF WRITTEN', 'NotProved'
    prove_ns, prove_rss = gnu_time(run / 'prove.time')
    verify_ns, verify_rss = gnu_time(run / 'verify.time')
    s = statement(run / 'prove.out')
    assert s == statement(run / 'verify.out'), 'StatementDiffers'
    controls = re.findall(r'^(\w+): rejected with (\S+) in \d+ ms$', (run / 'controls.log').read_text(), re.M)
    assert [c for c, _ in controls] == ['next', 'token', 'weight', 'gain'], controls
    assert 'test result: ok. 1 passed' in (run / 'controls.log').read_text()
    proof, public = (run / 'proof.bin').read_bytes(), (run / 'public.bin').read_bytes()
    start, end = map(int, s['checked'].split('..'))
    t = int(s['T'])
    plan = dict(command='stele prove-dev / verify-dev', statement=s, threads=a.threads,
                model=json.loads(Path(a.model_config).read_text()))
    ledger = {
        'schema_version': 1, 'kind': 'inference', 'workload': a.workload, 'commit': a.commit,
        'toolchain': a.toolchain, 'device': a.device, 'driver': 'not-applicable',
        'model_config': dict(plan, proof_sha256=hashlib.sha256(proof).hexdigest(),
                             public_sha256=hashlib.sha256(public).hexdigest(),
                             controls={c: reason for c, reason in controls}, host_context=a.host_context),
        'plan_digest': hashlib.sha256(json.dumps(plan, sort_keys=True, separators=(',', ':')).encode()).hexdigest(),
        'profile': 'development', 'bindings_all_on': True, 'batch_size': 1,
        'prompt_tokens': a.prompt_tokens, 'generated_tokens': t - a.prompt_tokens,
        'prover_time_ns': prove_ns, 'witness_recompute_ns': 0,
        'stage_times_ns': {'prove_dev_wall': prove_ns},
        'kernel_counters': {'prove_peak_rss_bytes': prove_rss, 'verify_peak_rss_bytes': verify_rss,
                            'public_bytes': len(public), 'checked_positions': end - start},
        'proof_size_bytes': len(proof), 'verifier_time_ns': {'rust': verify_ns, 'python': 0},
        'controls': {'total': len(controls), 'passed': len(controls), 'failed': 0},
        'note': ('RFC-0026 development profile (RFC-0018 A1): no security level, FS unproven, PCS conjectural, '
                 'no zero-knowledge. Prover time is the prove-dev process wall time: Artifact decode, weight '
                 'commitment, executor capture (witness), plain check and proof; the witness is not timed '
                 'separately (witness_recompute_ns 0). Verifier time is the verify-dev process wall time. '
                 'CPU only, no GPU; threads is the hardware thread count available to the process. Peak RSS is GNU time maximum resident set size. Controls '
                 'are the four statement tampers of rejects_tampers_on_a_supplied_proof against this proof, each '
                 'rejected by the verifier with the header restamped. Not comparable to W1-W8 records; not a '
                 'cost-model fit input.'),
    }
    a.out.write_text(json.dumps(ledger, indent=1, sort_keys=True) + '\n')
    subprocess.run(['cargo', 'run', '-q', '-p', 'stele-bench', '--locked', '--offline', '--', 'ledger', 'validate',
                    str(a.out)], check=True)


if __name__ == '__main__':
    main()
