"""RFC-0006 A4 / Q20 candidate bit-source admission; no commitment or ZK construction."""
from pathlib import Path
import struct
import sys
from blake3 import blake3
import private_selection as ps
import private_stage as stage

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'zerocheck'))
import check_zerocheck as zc

sc = ps.sc
SOURCE = b'stele/v0.1/research/onehot/source'
EXTRA = (SOURCE, stage.PRIVATE_STACK, ps.SELECT, ps.ORIGINALS, ps.WEIGHTED)
MAX_PREPARED = 1 << 18  # Conservative field payloads only; scratch/copies are extra.


def need(ok, error='SourceShape'):
    ps.need(ok, error)


class Transcript(zc.Transcript):
    def __init__(self, public, degree):
        super().__init__(public, degree)
        zc.tr.registry(zc.LABELS+EXTRA)

    def absorb(self, label, payload):
        if label in EXTRA:
            raw = self.state+b'\0'+struct.pack('<I', len(label))+label+struct.pack('<Q', len(payload))+payload
            self.state = blake3(raw).digest()
        else:
            super().absorb(label, payload)


def derive(v, d):
    need(type(v) is dict and len(v) == 6 and set(v) == {'source_id', 'axes', 'bits', 'categories', 'instance_base', 'tensor_base'})
    spec = ps.GridSpec(v['axes'], v['bits'], v['categories'])
    try:
        spec.validate()
    except ValueError:
        raise ValueError('SourceShape') from None
    plane_bits = (max(1, spec.category_bits)-1).bit_length()
    need(d in (4, 8) and len(spec.axes) <= 63 and spec.row_bits+plane_bits <= 63)
    need(type(v['source_id']) is int and 0 <= v['source_id'] < 1 << 64)
    for key, size in [('instance_base', 128), ('tensor_base', 256)]:
        need(type(v[key]) is int and 0 <= v[key] <= (1 << 64)-size and v[key] % size == 0)
    need(not v['tensor_base'] <= v['source_id'] < v['tensor_base']+256)
    raw = bytes([1, d])+struct.pack('<QB', v['source_id'], len(spec.axes))
    raw += b''.join(struct.pack('<BQ', *axis) for axis in spec.axes)
    raw += struct.pack('<BQQQ', spec.category_bits, spec.categories, v['instance_base'], v['tensor_base'])
    return raw, spec, plane_bits, spec.row_bits+plane_bits


def capacity(spec):
    need((2*spec.leaves()+2*spec.category_bits+2)*(1 << spec.row_bits) <= MAX_PREPARED, 'SourceCapacity')


def encode(v, indices, d):
    _, spec, _, _ = derive(v, d); capacity(spec)
    need(len(indices) == spec.rows and all(type(i) is int and 0 <= i < 1 << spec.category_bits for i in indices), 'SourceEncoding')
    n, k = 1 << spec.row_bits, spec.category_bits
    fields = [sc.scalar(0, d)]*(spec.leaves()*n)
    for padded, real in ps.positions(spec):
        for j in range(k):
            fields[j*n+padded] = sc.scalar((indices[real] >> (k-j-1)) & 1, d)
    return fields


def mask(v, point, d):
    _, spec, plane_bits, dimension = derive(v, d)
    need(len(point) == dimension)
    value = ps.bounded(ps.pairs(point[:plane_bits], d), spec.category_bits, d)
    at = plane_bits
    for bits, real in spec.axes:
        value = sc.mul(value, ps.bounded(ps.pairs(point[at:at+bits], d), real, d)); at += bits
    return value


def descriptors(v, d):
    _, spec, _, dimension = derive(v, d)
    base, tensor, source = v['instance_base'], v['tensor_base'], v['source_id']
    one, minus = sc.scalar(1, d), sc.scalar(-1, d)
    def zero(identity, m, ids, terms):
        return dict(id=identity, m=m, k=0, ids=ids, terms=terms)
    return [zero(base, dimension, [source, tensor], [(one, [0, 0, 1]), (minus, [0, 1])]),
            zero(base+1, dimension, [source, tensor], [(one, [0]), (minus, [0, 1])]),
            zero(base+2, spec.row_bits, [tensor+191, tensor+1], [(one, [0, 1]), (minus, [0])])]


def chain(v, j, value, d):
    one, minus = sc.scalar(1, d), sc.scalar(-1, d)
    bit = v['categories'] >> (v['bits']-j-1) & 1
    terms = [(one, [0]), (minus, [0, 1]), (one, [0, 1, 2])] if bit else [(one, [0, 2]), (minus, [0, 1, 2])]
    return dict(id=v['instance_base']+3+j, m=sum(b for b, _ in v['axes']),
                ids=[v['tensor_base']+128+j, v['tensor_base']+65+j, v['tensor_base']+2+j], terms=terms, sum=value)


def zero_prove(t, i, tables):
    """Linear folded A3 path for the candidate's two-input, no-skip relations."""
    need(i['k'] == 0 and len(i['ids']) == 2)
    zc.describe(i, t.degree); zc.shape(i, tables, t.degree)
    alpha, state, rounds, point = zc.start(t, i), [list(row) for row in tables], [], []
    for h in range(i['m']):
        weights, row = ps.weights(alpha[h+1:], t.degree), []
        for x in range(sc.degree(i)+1):
            folded = [sc.fold(table, sc.scalar(x, t.degree)) for table in state]
            row.append(zc.total((sc.mul(w, sc.compose(i['terms'], values, t.degree)) for w, values in zip(weights, zip(*folded))), t.degree))
        rounds.append(row); t.absorb(zc.tr.ROUND, sc.message(i, h, row))
        point.append(sc.challenge(t)); state = [sc.fold(table, point[-1]) for table in state]
    final = [[table[0]] for table in state]
    t.absorb(zc.FINAL, zc.final_bytes(i, final))
    return dict(skip=[], rounds=rounds, final=final), point


def prove(t, v, fields):
    raw, spec, _, dimension = derive(v, t.degree); capacity(spec)
    need(len(fields) == 1 << dimension, 'PublicShape')
    for value in fields:
        ps.element(value, t.degree)
    d, n, k = t.degree, 1 << spec.row_bits, spec.category_bits
    valid = [sc.scalar(0, d)]*len(fields)
    for padded, _ in ps.positions(spec):
        for j in range(k):
            valid[j*n+padded] = sc.scalar(1, d)
    instructions = descriptors(v, d)
    t.absorb(SOURCE, raw)
    bits, _ = zero_prove(t, instructions[0], [fields, valid])
    padding, _ = zero_prove(t, instructions[1], [fields, valid])
    bounded = None
    if spec.categories != 1 << k:
        planes = [fields[j*n:(j+1)*n] for j in range(k)]
        suffix = [None]*k+[[sc.scalar(0, d)]*n]
        one = sc.scalar(1, d)
        for j in reversed(range(k)):
            if spec.categories >> (k-j-1) & 1:
                suffix[j] = [sc.add(sc.add(one, sc.neg(b)), sc.mul(b, r)) for b, r in zip(planes[j], suffix[j+1])]
            else:
                suffix[j] = [sc.mul(sc.add(one, sc.neg(b)), r) for b, r in zip(planes[j], suffix[j+1])]
        root, point = zero_prove(t, instructions[2], [valid[:n], suffix[0]])
        value, nodes = root['final'][1][0], []
        for j in range(k):
            node, point = sc.prove(t, chain(v, j, value, d), [ps.weights(point, d), planes[j], suffix[j+1]])
            nodes.append(node); value = node['final'][2]
        bounded = dict(root=root, nodes=nodes)
    return dict(bits=bits, padding=padding, range=bounded)


def verify_reduction(t, v, proof):
    raw, spec, plane_bits, _ = derive(v, t.degree)
    need(type(proof) is dict and len(proof) == 3 and set(proof) == {'bits', 'padding', 'range'}, 'ProofShape')
    bounded = spec.categories != 1 << spec.category_bits
    need(proof['range'] is None if not bounded else type(proof['range']) is dict and len(proof['range']) == 2 and set(proof['range']) == {'root', 'nodes'}
         and len(proof['range']['nodes']) == spec.category_bits, 'ProofShape')
    t.absorb(SOURCE, raw)
    instructions, claims, records = descriptors(v, t.degree), [], []
    for i, part in zip(instructions[:2], [proof['bits'], proof['padding']]):
        receipt, _ = zc.verify_reduction(t, i, part)
        need(receipt['claims'][1][2] == mask(v, receipt['point'], t.degree), 'SourceMaskMismatch')
        claims.append(receipt['claims'][0]); records.extend(receipt['sc'])
    if bounded:
        receipt, _ = zc.verify_reduction(t, instructions[2], proof['range']['root'])
        point, value = receipt['point'], receipt['claims'][1][2]
        need(receipt['claims'][0][2] == mask(v, [sc.scalar(0, t.degree)]*plane_bits+point, t.degree), 'SourceMaskMismatch')
        records.extend(receipt['sc'])
        for j, part in enumerate(proof['range']['nodes']):
            node = sc.verify_reduction(t, chain(v, j, value, t.degree), part)
            need(node['claims'][0][1] == ps.coefficient(point, node['point'], 1 << spec.row_bits, t.degree), 'SourceMaskMismatch')
            point, value = node['point'], node['claims'][2][1]
            prefix = [sc.scalar(j >> (plane_bits-b-1) & 1, t.degree) for b in range(plane_bits)]
            claims.append((v['source_id'], prefix+point, node['claims'][1][1])); records.append(node['sc'])
        need(value == sc.scalar(0, t.degree), 'ConstantRangeLeaf')
    return dict(claims=claims, sc=records)


def selection_claims(v, receipt, d):
    _, spec, plane_bits, _ = derive(v, d)
    need(receipt['source'] == (v['source_id'], spec.axes, spec.category_bits, spec.categories), 'SourceClaimScope')
    need([j for j, _, _ in receipt['claims']] == list(range(spec.category_bits)), 'SourceClaimScope')
    result = []
    for j, point, value in receipt['claims']:
        need(len(point) == spec.row_bits, 'SourceClaimScope')
        prefix = [sc.scalar(j >> (plane_bits-b-1) & 1, d) for b in range(plane_bits)]
        result.append((v['source_id'], prefix+point, value))
    return result


def link(t, v, s):
    _, spec, _, _ = derive(v, t.degree); stage.descriptor(t, s)
    c = s['coefficient']
    need((c['source_id'], tuple(c['layout'][a] for a in c['source_axes']), c['layout'][c['category_axis']])
         == (v['source_id'], spec.axes, (spec.category_bits, spec.categories)), 'SourceClaimScope')
    need(s['id']+64 < v['instance_base'] or v['instance_base']+127 < s['id'], 'SourceClaimScope')
    need(all(not v['tensor_base'] <= identity < v['tensor_base']+256
             for identity in [*s['inputs'], s['output']['id'], s['coefficient_id']]), 'SourceClaimScope')
