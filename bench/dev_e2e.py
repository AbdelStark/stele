"""RFC-0018 A1 development-profile ledger from one `stele prove-dev`/`verify-dev` run (task E16-11).

The run directory holds what `docs/development-e2e.md` ("Benchmark ledger") produces:
`prove.out`, `prove.time` and `verify.out`, `verify.time` (GNU `/usr/bin/time -v`),
`proof.bin`, `public.bin`, and `controls.log`, the `--nocapture` output of
`rejects_tampers_on_a_supplied_proof` against that proof. An optional `commit.log`, the
output of `matches_reference_model_commitment_of_a_supplied_proof`, adds the model
commitment time (measured in its own process) as stage `model_commitment`.

  python3 bench/dev_e2e.py RUN_DIR OUT.json --workload dev/<name> --commit <sha> \
      --device "<cpu>" --toolchain "$(rustc -V)" --prompt-tokens P --threads N \
      --model-config config.json --host-context "<host>" [--rung L1] [--counters extra.json]

`--zk` reads a dev-zk run against one published model commitment (RFC-0013 A6, A7):
`commit.out` and `commit.time` from `stele commit-model --zk`, `model.commit`, one
proof's files under the names above (its index, from `verify.out`, is recorded),
`verify1.out` (another proof against the same commitment, `--expect-model`) and
`pin.out` (a proof pinned to another model digest, the one control). It records the commitment as stage `model_commitment_once`, not part
of the prove time. `controls.log` is not read.

`--rung` names the ladder rung of RFC-0027 §3 and is written to `model_config.rung`
(RFC-0018 A2).

`--counters` names a JSON object of extra unsigned integer counters (for example the
proof section bytes that `accepts_eight_layer_window` prints). They are merged into
`kernel_counters`; a name that collides with a built-in counter is an error.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess


def gnu_time(path):
    """Wall seconds and maximum RSS bytes from GNU time -v, or from BSD (macOS) time -l."""
    text = Path(path).read_text()
    bsd = re.search(r'^\s*([\d.]+) real\b', text, re.M)
    if bsd:  # BSD time reports RSS in bytes and no exit status; the caller checks the outputs.
        rss = int(re.search(r'^\s*(\d+)\s+maximum resident set size$', text, re.M).group(1))
        return round(float(bsd.group(1)) * 1e9), rss
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


ZK_NOTE = ('RFC-0026 development tier (RFC-0018 A1): no security level, FS unproven, PCS conjectural. '
           'dev-zk profile byte {byte} ({sources}; RFC-0026 A9), development tier; zero knowledge is '
           'conditional and computational (seed-derived masks). The weights and the 1-D records (RFC-0013 A7) '
           'are committed once by commit-model as one published commitment for P = {proofs} proofs (A6), '
           'recorded as stage model_commitment_once and not part of the prove time. Prover time is the '
           'prove-dev --zk process wall time of proof index {index}: Artifact decode, executor capture, plain '
           'check and proof (witness_recompute_ns 0). Verifier time is verify-dev with --expect-model; another '
           'proof against the same commitment also verifies. The control is verify-dev of a proof pinned to '
           'another model digest. Repeats, if any, are in model_config.host_context.{ledger} CPU only, no GPU. '
           'Peak RSS is the {timer} maximum resident set size. Not a cost-model fit input.')
# RFC-0013 A8: byte 4 is balanced policy-2 hiding sources; byte 1 is A5's.
ZK_SOURCES = {1: 'RFC-0013 A5 sources', 4: 'balanced policy-2 hiding sources, RFC-0013 A8'}


def zk_ledger(verify):
    """The soundness-ledger sentence from verify-dev's last lines (E12-26), or nothing."""
    eps = re.search(r'^eps_interactive <= (\d+)/p\^4', verify, re.M)
    worst = re.search(r'^worst round\t(.+?)\t(\S+)\tgrinding (\d+) bits$', verify, re.M)
    if not (eps and worst):
        return ''
    return (f' Soundness ledger (verify-dev, E12-26): eps_interactive <= {eps.group(1)}/p^4; worst round '
            f'{worst.group(1)}, {worst.group(2)}, grinding {worst.group(3)} bits.')


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('run', type=Path)
    p.add_argument('out', type=Path)
    for name in ('workload', 'commit', 'device', 'model-config', 'toolchain'):
        p.add_argument('--' + name, required=True)
    p.add_argument('--prompt-tokens', type=int, required=True)
    p.add_argument('--threads', type=int, required=True, help='hardware threads available to the run')
    p.add_argument('--host-context', required=True)
    p.add_argument('--counters', type=Path, help='JSON object of extra unsigned integer counters')
    p.add_argument('--rung', help='ladder rung, for example L1 or L2a (RFC-0018 A2)')
    p.add_argument('--zk', action='store_true', help='a dev-zk run against a published model commitment')
    a = p.parse_args()
    run = a.run
    assert (run / 'verify.out').read_text().splitlines()[-1] == 'YES', 'NotAccepted'
    assert (run / 'prove.out').read_text().splitlines()[-1] == 'PROOF WRITTEN', 'NotProved'
    prove_ns, prove_rss = gnu_time(run / 'prove.time')
    timer = 'BSD /usr/bin/time -l' if re.search(r'^\s*[\d.]+ real\b', (run / 'prove.time').read_text(), re.M) else 'GNU time -v'
    verify_ns, verify_rss = gnu_time(run / 'verify.time')
    s = statement(run / 'prove.out')
    assert s == statement(run / 'verify.out'), 'StatementDiffers'
    if a.zk:
        assert (run / 'verify1.out').read_text().splitlines()[-1] == 'YES', 'NotAccepted'
        pin = (run / 'pin.out').read_text().splitlines()[-1]
        assert pin == 'NO: model differs from --expect-model', pin
        controls = [('pin', 'model differs from --expect-model')]
    else:
        controls = re.findall(r'^(\w+): rejected with (\S+) in \d+ ms$', (run / 'controls.log').read_text(), re.M)
        assert [c for c, _ in controls] == ['next', 'token', 'weight', 'gain'], controls
        assert 'test result: ok. 1 passed' in (run / 'controls.log').read_text()
    proof, public = (run / 'proof.bin').read_bytes(), (run / 'public.bin').read_bytes()
    stages = {'prove_dev_wall': prove_ns}
    if (run / 'commit.log').exists():  # separate process: Artifact decode and model commitment only
        stages['model_commitment'] = int(re.search(r'^model commitment: (\d+) ns$',
                                                   (run / 'commit.log').read_text(), re.M).group(1))
    start, end = map(int, s['checked'].split('..'))
    t = int(s['T'])
    plan = dict(command='stele prove-dev / verify-dev', statement=s, threads=a.threads,
                model=json.loads(Path(a.model_config).read_text()))
    extra_counters = {}
    if a.zk:
        commit_ns, commit_rss = gnu_time(run / 'commit.time')
        stages['model_commitment_once'] = commit_ns
        proofs = int(re.search(r'^proofs (\d+)$', (run / 'commit.out').read_text(), re.M).group(1))
        # RFC-0013 A8: the public file names the profile byte (v2 is byte 4).
        byte = 4 if public.startswith(b'stele-dev-zk-public-v2') else 1
        plan.update(command='stele commit-model --zk / prove-dev --zk / verify-dev --expect-model',
                    profile_byte=byte, proofs=proofs,
                    proof_index=int(re.search(r'^proof index (\d+) of', (run / 'verify.out').read_text(), re.M).group(1)))
        extra_counters = {'commit_peak_rss_bytes': commit_rss,
                          'model_commitment_bytes': (run / 'model.commit').stat().st_size}
    if a.rung:
        plan['rung'] = a.rung
    counters = {'prove_peak_rss_bytes': prove_rss, 'verify_peak_rss_bytes': verify_rss,
                'public_bytes': len(public), 'checked_positions': end - start, **extra_counters}
    if a.counters:
        extra = json.loads(a.counters.read_text())
        assert isinstance(extra, dict) and not set(extra) & set(counters), 'CounterNames'
        assert all(type(v) is int and v >= 0 for v in extra.values()), 'CounterValues'
        counters.update(extra)
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
        'stage_times_ns': stages,
        'kernel_counters': counters,
        'proof_size_bytes': len(proof), 'verifier_time_ns': {'rust': verify_ns, 'python': 0},
        'controls': {'total': len(controls), 'passed': len(controls), 'failed': 0},
        'note': ZK_NOTE.format(timer=timer, byte=plan['profile_byte'], sources=ZK_SOURCES[plan['profile_byte']],
                               proofs=plan['proofs'], index=plan['proof_index'],
                               ledger=zk_ledger((run / 'verify.out').read_text())) if a.zk else ('RFC-0026 development profile (RFC-0018 A1): no security level, FS unproven, PCS conjectural, '
                 'no zero-knowledge. Prover time is the prove-dev process wall time: Artifact decode, weight '
                 'commitment, executor capture (witness), plain check and proof; the witness is not timed '
                 'separately (witness_recompute_ns 0). Stage model_commitment, when present, is Artifact '
                 'decode plus model commitment timed in a separate test process; it is part of prove_dev_wall. Verifier time is the verify-dev process wall time. '
                 'CPU only, no GPU; threads is the hardware thread count available to the process. Peak RSS is the ' + timer + ' maximum resident set size. Controls '
                 'are the four statement tampers of rejects_tampers_on_a_supplied_proof against this proof, each '
                 'rejected by the verifier with the header restamped. Not comparable to W1-W8 records; not a '
                 'cost-model fit input.'),
    }
    a.out.write_text(json.dumps(ledger, indent=1, sort_keys=True) + '\n')
    subprocess.run(['cargo', 'run', '-q', '-p', 'stele-bench', '--locked', '--offline', '--', 'ledger', 'validate',
                    str(a.out)], check=True)


if __name__ == '__main__':
    main()
