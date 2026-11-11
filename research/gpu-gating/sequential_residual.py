"""Sequential residual of one prove-dev run from a macOS `sample` call tree (task E16-23).

Counts self samples, on any thread, of prover code with no rayon frame inside its
innermost prover root (prove_window_profile, prove_inner, relation::prove, check::check).
That work runs on one thread. Unlike stage_shares.py it still applies when prove-dev
joins the plain checker and the engine, so the main thread only waits.

  python3 research/gpu-gating/sequential_residual.py sample.txt [depth] [rows]
"""
import re, sys
ROOT = r'stele_prover::development::prove_window_profile|stele_prover::development::prove_inner|stele_reductions::relation::prove\b|stele_reductions::relation::prove_plan|stele_ir::relation::check::check'
RAYON = r'rayon|thread::scope'
depth = int(sys.argv[2]) if len(sys.argv) > 2 else 1
lines = open(sys.argv[1]).read().splitlines()
start = next(i for i, l in enumerate(lines) if 'Call graph:' in l)
end = next(i for i in range(start, len(lines)) if lines[i].startswith('Total number in stack'))
nodes = []
for l in lines[start + 1:end]:
    m = re.search(r'\d', l)
    if not m:
        continue
    parts = l[m.start():].split(' ', 1)
    if len(parts) < 2 or not parts[0].isdigit():
        continue
    name = re.sub(r'\s+\(in .*$', '', parts[1])
    name = re.sub(r'::h[0-9a-f]{16}', '', name)
    name = name.replace('$LT$', '<').replace('$GT$', '>').replace('$u20$', ' ').replace('..', '::').replace('$u7b$$u7b$closure$u7d$$u7d$', '{c}')
    nodes.append((m.start(), int(parts[0]), name))
seq, par = {}, 0
stack = []
for i, (d, count, name) in enumerate(nodes):
    while stack and stack[-1][0] >= d:
        stack.pop()
    stack.append((d, name))
    children, j, first = 0, i + 1, None
    while j < len(nodes) and nodes[j][0] > d:
        if first is None:
            first = nodes[j][0]
        if nodes[j][0] == first:
            children += nodes[j][1]
        j += 1
    own = count - children
    if own <= 0:
        continue
    names = [n for _, n in stack]
    roots = [k for k, n in enumerate(names) if re.search(ROOT, n)]
    if not roots:
        continue
    inner = names[roots[-1]:]
    if any(re.search(RAYON, n) for n in inner):
        par += own
        continue
    st = [n for n in inner if 'stele' in n and '{c}' not in n.split('::')[-1]]
    key = ' > '.join(st[:depth + 1])[:220]
    seq[key] = seq.get(key, 0) + own
total = sum(seq.values())
print('sequential', total, 'parallel-or-waiting', par)
check = sum(v for k, v in seq.items() if k.startswith('stele_ir::relation::check::check'))
print('of which plain check (beside the engine after E16-23):', check)
for k, v in sorted(seq.items(), key=lambda kv: -kv[1])[:int(sys.argv[3]) if len(sys.argv) > 3 else 25]:
    print(f'{v:6d} {k}')
