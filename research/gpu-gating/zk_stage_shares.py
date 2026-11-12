"""Main-thread wall-time shares of a macOS `sample` call tree of `prove-dev --zk`, by
dev-zk component (task E16-24).

A leaf's self samples go to `self_verify` when the dev-zk verifier is on its stack,
else to the innermost frame matching a component, so pool waits count toward the stage
that started them. A release build with line tables (`CARGO_PROFILE_RELEASE_DEBUG=
line-tables-only`) keeps the frames:

  target/release/stele prove-dev --zk ... &   # docs/development-e2e.md, eight-layer, --length 64
  sample <pid> 900 1 -mayDie -file sample.txt
  python3 research/gpu-gating/zk_stage_shares.py sample.txt [prove seconds]
"""
import re
import sys
from collections import Counter

ORDER = [
    ('self_verify', r'stele_prover::development::zk::verify\b'),
    ('rank_aborts', r'claims::block_rank|claims::full_rank|lookup::aborts'),
    ('claim_blocks', r'claims::block_table|claims::occurrence_claim|claims::domain_table|claims::eq_input|Plan.*::block\b|lookup::finals'),
    ('masked_rounds', r'Occurrences.*Summand|claims::masked_instance|masked::prove|claims::TermPlan'),
    ('mask_polynomials', r'Mask.*::plain|claims::shared_message|claims::mask_claim|claims::prove_batch|claims::weight_table|claims::batch_instance|zk::prove_at|Dense.*Summand'),
    ('zk_gkr', r'claims::lookup::|zk_lookup'),
    ('source_encoding', r'PreparedSource|hiding_message|claims::source_message|claims::certify|stele_code::|merkle::|MaskStream|compress_xof|hiding::draws'),
    ('planning', r'claims::plan_with|claims::assign|claims::vanish|relation::layout'),
    ('window_build', r'zk::window_values|relation::columns|relation::check|layout_for|development::decode|stele_cqis'),
]
lines = open(sys.argv[1]).read().splitlines()
seconds = float(sys.argv[2]) if len(sys.argv) > 2 else None
start = next(i for i, l in enumerate(lines) if 'com.apple.main-thread' in l)
end = next(i for i in range(start + 1, len(lines)) if re.match(r'\s+\d+ Thread_', lines[i]))
nodes = []
for l in lines[start:end]:
    m = re.match(r'(\s*[+!:| ]*)(\d+) (.*)$', l)
    if m:
        nodes.append((len(m.group(1)), int(m.group(2)), re.sub(r'::h[0-9a-f]{16}.*$', '', m.group(3).split('  (in')[0]).strip()))
agg = Counter()
total = 0
stack = []
for i, (d, c, fn) in enumerate(nodes):
    while stack and stack[-1][0] >= d:
        stack.pop()
    stack.append((d, fn))
    child, j, first = 0, i + 1, None
    while j < len(nodes) and nodes[j][0] > d:
        if first is None:
            first = nodes[j][0]
        if nodes[j][0] == first:
            child += nodes[j][1]
        j += 1
    own = c - child
    if own <= 0:
        continue
    total += own
    names = [f for _, f in stack]
    if any(re.search(ORDER[0][1], f) for f in names):
        agg['self_verify'] += own
        continue
    label = 'other'
    # A pool wait directly under prove_with is its source map/join (messages,
    # preparations, certificates): no named frame in between.
    stele = [f for f in names if 'stele' in f]
    if stele and stele[-1].endswith('claims::prove_with') and any(
            re.search(r'rayon|parallel::(map|join)', f) for f in names):
        agg['source_encoding'] += own
        continue
    for f in reversed(names):
        hit = next((k for k, p in ORDER[1:] if re.search(p, f)), None)
        if hit:
            label = hit
            break
    agg[label] += own
print(f'main-thread samples {total}')
for k, c in agg.most_common():
    s = f'  ~{seconds * c / total:6.1f} s' if seconds else ''
    print(f'{k:18s} {c:8d} {100 * c / total:5.1f}%{s}')
