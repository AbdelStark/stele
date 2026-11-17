"""E16-40a: one complete instrumented dev-zk prove, with nested costs kept separate.

Usage: python3 research/gpu-gating/stage_inventory.py prove.err > stages.json
The caller must independently verify the proof; log parsing is not verification.
"""
from collections import Counter, defaultdict
import json
from pathlib import Path
import re
import sys

PHASES = {
    'zk/sources_prepare_certify': ['sources_prepare', 'sources_certify'],
    'zk/logup_trees_and_tops': ['top_prefix', 'top_tree', 'top_values'],
    'zk/top_and_shared_sources': ['top_messages', 'top_prepare', 'top_certify'],
    'zk/relations_masked_sumcheck': ['relation_prefix', 'relation_factors', 'relation_setup', 'relation_rounds', 'relation_claims'],
    'zk/logup_gkr': ['gkr_tree', 'gkr_prefix', 'gkr_factors', 'gkr_setup', 'gkr_rounds', 'gkr_claims'],
    'zk/claim_batches_and_openings': ['batch_prefix', 'batch_weights', 'batch_face', 'batch_rounds', 'batch_opening'],
    'zk/shared_batch_and_opening': ['shared_weights_face', 'shared_prove', 'shared_opening'],
}
SHAPE = re.compile(r'shape (relation|gkr_first|gkr_interior|gkr_leaf) field=(4|8) vars=([0-9]+) degree=([0-9]+) masks=([0-9,-]+) terms=([0-9,.-]+) compact=([01])')
INVENTORY = re.compile(r'inventory field=(4|8) relations=([0-9]+) gkr=([0-9]+) lookups=([0-9]+) batches=([0-9]+)')


def shape_record(line):
    match = SHAPE.fullmatch(line)
    if not match:
        raise ValueError('invalid shape record or undeclared field')
    kind, field, variables, degree, masks, terms, compact = match.groups()
    variables, degree = int(variables), int(degree)
    if not variables or not degree:
        raise ValueError('empty variable or degree bound')
    masks = [None if x == '-' else int(x) for x in masks.split(',')]
    terms = [[] if x == '-' else [int(i) for i in x.split('.')] for x in terms.split(',')]
    if any(v is not None and not 0 <= v < variables for v in masks):
        raise ValueError('mask coordinate outside shape')
    if any(not 0 <= i < len(masks) for term in terms for i in term):
        raise ValueError('term factor outside shape')
    return dict(kind=kind, field=int(field), variables=variables, degree=degree,
                masks=masks, terms=terms, compact=bool(int(compact)))


def parse(text):
    parents = list(PHASES)
    phases, inventory, shapes = {}, Counter(), {}
    counts, times, kinds = Counter(), defaultdict(int), Counter()
    at, child, trees = 0, 0, 0
    declared = None
    pending_shape = tree_open = False
    for line in text.splitlines():
        if line.startswith('inventory '):
            match = INVENTORY.fullmatch(line)
            if not match or declared is not None or at or counts:
                raise ValueError('missing or repeated inventory declaration')
            declared = dict(zip(('field', 'relations', 'gkr', 'lookups', 'batches'), map(int, match.groups())))
        elif line.startswith('shape '):
            shape = shape_record(line)
            parent = 'zk/relations_masked_sumcheck' if shape['kind'] == 'relation' else 'zk/logup_gkr'
            if (declared is None or shape['field'] != declared['field'] or at >= len(parents)
                    or parents[at] != parent or not PHASES[parent][child].endswith('_setup') or pending_shape):
                raise ValueError('shape outside its factors/setup boundary')
            pending_shape = True
            if shape['kind'] == 'gkr_first':
                if tree_open:
                    raise ValueError('new GKR tree before previous leaf')
                tree_open = True
            elif shape['kind'] == 'gkr_interior' and not tree_open:
                raise ValueError('interior GKR step before first step')
            elif shape['kind'] == 'gkr_leaf':
                # An accepted one-step tree is both first and leaf (A7).
                tree_open = False
                trees += 1
            key = json.dumps(shape, sort_keys=True)
            inventory[key] += 1
            shapes[key] = shape
            kinds[shape['kind']] += 1
        elif line.startswith('stage zk/detail/'):
            match = re.fullmatch(r'stage zk/detail/(\w+) (\d+)', line)
            if (not match or declared is None or at >= len(parents)
                    or match[1] != PHASES[parents[at]][child]):
                raise ValueError('unknown or misplaced detail stage')
            if match[1] in ('relation_setup', 'gkr_setup'):
                if not pending_shape:
                    raise ValueError('missing instance shape')
                pending_shape = False
            counts[match[1]] += 1
            times[match[1]] += int(match[2])
            child = (child + 1) % len(PHASES[parents[at]])
        elif line.startswith('stage '):
            fields = line.split()
            if len(fields) < 2 or fields[1] not in PHASES:
                continue
            if len(fields) != 3 or not fields[2].isascii() or not fields[2].isdigit():
                raise ValueError('invalid parent time')
            parent = fields[1]
            if declared is None or at >= len(parents) or parents[at] != parent or child or pending_shape:
                raise ValueError('missing, repeated or out-of-order parent')
            children = PHASES[parent]
            number = counts[children[0]]
            if not number or any(counts[c] != number for c in children):
                raise ValueError('incomplete child measurements')
            if parent in ('zk/sources_prepare_certify', 'zk/top_and_shared_sources', 'zk/shared_batch_and_opening') and number != 1:
                raise ValueError('repeated source/shared phase')
            if parent == 'zk/relations_masked_sumcheck' and number != kinds['relation']:
                raise ValueError('relation inventory does not cover its rounds')
            if parent == 'zk/logup_gkr' and number != sum(kinds[k] for k in ('gkr_first', 'gkr_interior', 'gkr_leaf')):
                raise ValueError('GKR inventory does not cover its rounds')
            expected = {
                'zk/logup_trees_and_tops': declared['lookups'],
                'zk/relations_masked_sumcheck': declared['relations'],
                'zk/logup_gkr': declared['gkr'],
                'zk/claim_batches_and_openings': declared['batches'],
            }.get(parent, 1)
            if number != expected:
                raise ValueError('child count differs from declared plan')
            if parent == 'zk/logup_gkr' and (tree_open or trees != declared['lookups']):
                raise ValueError('incomplete GKR tree inventory')
            elapsed = int(fields[2])
            measured = sum(times[c] for c in children)
            if measured > elapsed:
                raise ValueError('child times exceed parent wall time')
            phases[parent] = dict(parent_ms=elapsed, children_ms={c: times[c] for c in children},
                                  child_count=number, unattributed_ms=elapsed - measured)
            counts.clear()
            times.clear()
            at += 1
    if at != len(parents) or counts or declared is None:
        raise ValueError('incomplete instrumented prove')
    return dict(declared=declared, phases=phases, shapes=[dict(shapes[k], count=count) for k, count in sorted(inventory.items())])


if __name__ == '__main__':
    if len(sys.argv) != 2:
        raise SystemExit('usage: stage_inventory.py prove.err')
    print(json.dumps(parse(Path(sys.argv[1]).read_text()), indent=2, sort_keys=True))
