"""Main-thread wall-time shares of a macOS `sample` call tree, by prover stage.

Each node's self samples (count minus children) are charged to the first category
whose pattern matches any frame on its stack, in the order below (task E16-21).

  target/release/stele prove-dev ... &   # docs/development-e2e.md, eight-layer, --length 64
  sample <pid> 600 1 -mayDie -file sample.txt
  python3 research/gpu-gating/stage_shares.py sample.txt
"""
import re, sys
CATEGORIES = [
    ('encoding', r'stele_code(::|\.\.)encoder'),
    ('merkle', r'stele_hash(::|\.\.)merkle|blake3::'),
    ('logup_levels', r'stele_lookup(::|\.\.)fraction'),
    ('zerocheck_rounds', r'stele_sumcheck(::|\.\.)zerocheck'),
    ('dense_rounds', r'stele_sumcheck(::|\.\.)(dense|parallel)|stele_poly::eq_table'),
    ('pcs_opening_combination', r'stele_pcs(::|\.\.)opening'),
    ('lookup_counts', r'relation::lookup::counts'),
    ('relation_other', r'stele_reductions::relation'),
    ('witness_layout_check', r'stele_prover::development|stele_cqis|stele_ir'),
]
lines = open(sys.argv[1]).read().splitlines()
start = next(i for i, l in enumerate(lines) if 'com.apple.main-thread' in l)
end = next(i for i in range(start + 1, len(lines)) if re.match(r'\s+\d+ Thread_', lines[i]))
nodes = []  # (depth, count, name)
for l in lines[start:end]:
    m = re.search(r'\d', l)
    count, name = l[m.start():].split(' ', 1)
    nodes.append((m.start(), int(count), name))
totals = {}
stack = []
for i, (depth, count, name) in enumerate(nodes):
    while stack and stack[-1][0] >= depth:
        stack.pop()
    stack.append((depth, name))
    children = 0
    # direct children: next nodes deeper than depth whose depth equals the first child's depth
    j, first = i + 1, None
    while j < len(nodes) and nodes[j][0] > depth:
        if first is None:
            first = nodes[j][0]
        if nodes[j][0] == first:
            children += nodes[j][1]
        j += 1
    own = count - children
    if own <= 0:
        continue
    path = ' '.join(n for _, n in stack)
    cat = next((c for c, p in CATEGORIES if re.search(p, path)), 'other')
    totals[cat] = totals.get(cat, 0) + own
total = sum(totals.values())
for cat, n in sorted(totals.items(), key=lambda kv: -kv[1]):
    print(f'{cat:28s} {n:6d} {100 * n / total:5.1f}%')
print('total', total)
