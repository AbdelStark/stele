"""Stage profile of one stories42M prove from a macOS `sample` call tree (task E16-22).

Two views, one classifier:
- `wall`: the main thread's self samples (ADR-103's measure; the main thread waits inside
  every parallel region, so its samples are wall time), each charged to the first stage
  below that matches any frame on its stack;
- `cpu`: every thread's self samples, charged the same way (CPU time, all threads).

Stages are ordered so leaf work is named before its caller: grinding (BLAKE3 under
`grind`) before Merkle, Merkle before the source preparation that builds the tree, the
dev-zk claim batch and openings before the generic dense rounds. A sample that matches no
stage is `other`. A release build with line tables keeps the frames:

  CARGO_PROFILE_RELEASE_DEBUG=line-tables-only cargo build --release -p stele-cli
  target/release/stele prove-dev ... &  sample <pid> 900 1 -mayDie -file sample.txt
  python3 research/gpu-gating/stage_profile.py sample.txt [--json out.json]
"""
import json
import re
import sys

STAGES = [
    ('grinding', r'::grind|grind_'),
    ('encoding', r'stele_code(::|\.\.)|encode_rows|Circle.*encode|::transform'),
    ('merkle', r'merkle|blake3::'),
    ('logup_gkr', r'stele_lookup(::|\.\.)fraction|claims::lookup::|zk_lookup|relation_lookup|relation::lookup'),
    ('zerocheck', r'stele_sumcheck(::|\.\.)zerocheck'),
    ('claim_batching', r'claims::prove_batch|claims::weight_table|claims::face|claims::batch_instance|zk::prove_at|stele_sumcheck(::|\.\.)batch'),
    ('openings', r'stele_pcs(::|\.\.)opening|opening_point|stele_pcs(::|\.\.)certificate|hiding::'),
    ('masked_sumcheck', r'stele_sumcheck(::|\.\.)masked|claims::masked_instance|TermPlan|Occurrences|claims::block_table|claims::domain_table|claims::occurrence_claim'),
    ('matmul', r'relation::matmul|relation_matmul|Matmul'),
    ('dense_rounds', r'stele_sumcheck(::|\.\.)(dense|parallel)|eq_table'),
    ('witness', r'stele_cqis|stele_ir|executor|Executor|development::window|development::layout|zk::window_values|zk_relation_of|relation::columns'),
    ('relation_other', r'stele_reductions|stele_prover'),
]


def parse(lines):
    """(thread name, [(depth, count, frame)]) per thread of the call graph."""
    start = next(i for i, l in enumerate(lines) if l.startswith('Call graph:'))
    end = next(i for i in range(start, len(lines)) if lines[i].startswith('Total number in stack'))
    threads, current = [], None
    for l in lines[start + 1:end]:
        m = re.search(r'\d', l)
        if not m:
            continue
        parts = l[m.start():].split(' ', 1)
        if len(parts) < 2 or not parts[0].isdigit():
            continue
        depth, count, frame = m.start(), int(parts[0]), parts[1]
        if re.match(r'Thread_\d+', frame):
            current = (frame, [])
            threads.append(current)
            continue
        if current is not None:
            current[1].append((depth, count, frame))
    return threads


def charge(nodes, totals):
    stack = []
    for i, (depth, count, frame) in enumerate(nodes):
        while stack and stack[-1][0] >= depth:
            stack.pop()
        stack.append((depth, frame))
        children, j, first = 0, i + 1, None
        while j < len(nodes) and nodes[j][0] > depth:
            if first is None:
                first = nodes[j][0]
            if nodes[j][0] == first:
                children += nodes[j][1]
            j += 1
        own = count - children
        if own <= 0:
            continue
        path = ' '.join(f for _, f in stack)
        if re.search(r'__psynch_cvwait|__workq_kernreturn|semaphore_wait|_pthread_cond_wait|park', frame) and \
                not re.search(r'stele_', path):
            stage = 'idle'
        else:
            stage = next((s for s, p in STAGES if re.search(p, path)), 'other')
        totals[stage] = totals.get(stage, 0) + own


def main():
    lines = open(sys.argv[1], errors='ignore').read().splitlines()
    threads = parse(lines)
    wall, cpu = {}, {}
    for name, nodes in threads:
        if 'com.apple.main-thread' in name:
            charge(nodes, wall)
        charge(nodes, cpu)
    cpu.pop('idle', None)
    out = {}
    for label, totals in (('wall', wall), ('cpu', cpu)):
        total = sum(totals.values())
        out[label] = {s: dict(samples=n, share=round(n / total, 4)) for s, n in
                      sorted(totals.items(), key=lambda kv: -kv[1])}
        print(f'== {label} ({total} samples)')
        for s, n in sorted(totals.items(), key=lambda kv: -kv[1]):
            print(f'{s:18s} {n:8d} {100 * n / total:5.1f}%')
    if '--json' in sys.argv:
        open(sys.argv[sys.argv.index('--json') + 1], 'w').write(json.dumps(out, indent=1) + '\n')


if __name__ == '__main__':
    main()
