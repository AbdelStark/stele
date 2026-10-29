"""RFC-0006 A4 / Q20 stacked-final composition; unmasked conditional research."""
import struct
from blake3 import blake3
import private_selection as ps
import weighted_private_selection as selection
from stage import instance, permutation, public_tables
from statement import header, need
from ownership import reorder

sc = ps.sc
PRIVATE_STACK = b'stele/v0.1/research/gkr/private-selection'
MAX_STAGE_CELLS = 1 << 18  # Original tables plus A only; excludes copies/scratch.


class Transcript(ps.Transcript):
    def __init__(self, public, degree):
        super().__init__(public, degree)
        ps.tr.registry(ps.tr.LABELS+(ps.SELECT, ps.ORIGINALS, ps.WEIGHTED, PRIVATE_STACK))

    def absorb(self, label, payload):
        if label == PRIVATE_STACK:
            raw = self.state+b'\0'+struct.pack('<I', len(label))+label+struct.pack('<Q', len(payload))+payload
            self.state = blake3(raw).digest()
        else:
            super().absorb(label, payload)


def descriptor(t, s):
    need(type(s) is dict and len(s) == 9)
    need(type(s.get('inputs')) in (list, tuple) and len(s['inputs']) <= 64)
    need(type(s.get('terms')) in (list, tuple) and len(s['terms']) <= 64)
    raw = header(s)
    need(t.degree == s['field'])
    # One main A1 plus at most 64 selection nodes; the plan reserves the full block.
    need(s['id'] % 65 == 0 and s['id'] <= (1 << 64)-65)
    c = s['coefficient']
    try:
        source = selection.metadata(c, t.degree)
    except ValueError:
        raise ValueError('InvalidStacked') from None
    need(c['layout'] == tuple(s['layout']))
    # This candidate uses a distinct typed index view; no implicit integer/K alias.
    need(c['source_id'] not in [s['coefficient_id'], s['output']['id'], *s['inputs']])
    return raw+source


def source(s, indices):
    c = s['coefficient']
    m = sum(b for b, _ in s['layout'])
    ps.need((len(s['inputs'])+1)*(1 << m) <= MAX_STAGE_CELLS, 'StageCapacity')
    spec = ps.GridSpec(tuple(c['layout'][a] for a in c['source_axes']), *c['layout'][c['category_axis']])
    ps.need((1 << spec.row_bits)*(2*spec.leaves()+spec.category_bits) <= ps.MAX_PREPARED_CELLS, 'SelectionCapacity')
    ps.need(len(indices) == spec.rows and all(type(i) is int and 0 <= i < spec.categories for i in indices), 'SelectionSource')


def coefficient(s, indices):
    """Dense reference preparation; source validity is checked before entry."""
    c, d = s['coefficient'], s['field']
    m, axes = sum(b for b, _ in s['layout']), c['layout']
    result = []
    for padded in range(1 << m):
        shift, coords = m, []
        for bits, _ in axes:
            shift -= bits
            coords.append((padded >> shift) & ((1 << bits)-1))
        if any(i >= n for i, (_, n) in zip(coords, axes)):
            result.append(sc.scalar(0, d)); continue
        real = 0
        for axis in c['source_axes']:
            real = real*axes[axis][1]+coords[axis]
        value = sc.scalar(int(coords[c['category_axis']] == indices[real]), d)
        for coordinate, selector in zip(coords, c['selectors']):
            if selector is not None:
                for j, z in enumerate(selector):
                    factor = z if coordinate >> (len(selector)-j-1) & 1 else sc.add(sc.scalar(1, d), sc.neg(z))
                    value = sc.mul(value, factor)
        result.append(value)
    return result


def restore(s, point):
    canonical = [None]*len(point)
    for axis, value in zip(permutation(s), point):
        canonical[axis] = value
    return canonical


def prove(t, s, tables, indices):
    raw = descriptor(t, s)
    source(s, indices)
    public_tables(s, tables)
    prepared = [reorder(table, permutation(s)) for table in [*tables, coefficient(s, indices)]]
    t.absorb(PRIVATE_STACK, raw)
    main, point = sc.prove(t, instance(s), prepared)
    child = selection.prove(t, s['coefficient'], restore(s, point), main['final'][-1], indices, instance_base=s['id']+1)
    return dict(stage=main, selection=child)


def verify_reduction(t, s, proof):
    raw = descriptor(t, s)
    ps.need(type(proof) is dict and len(proof) == 2 and set(proof) == {'stage', 'selection'}, 'ProofShape')
    t.absorb(PRIVATE_STACK, raw)
    main = sc.verify_reduction(t, instance(s), proof['stage'])
    point = restore(s, main['point'])
    child = selection.verify_reduction(t, s['coefficient'], point, main['claims'][-1][1], proof['selection'], instance_base=s['id']+1)
    return dict(point=point, claims=main['claims'][:-1], selection=child, sc=main['sc'])
