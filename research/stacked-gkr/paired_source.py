"""RFC-0006 A4 / Q20 two-bit source with actual degree-four bit consumers.

Table work O((Mb+k+Mp)*N); point/shape work O(n*s+k*(Db+s+1)).
Symbols, preparation bounds and conditional losses are defined in PAIRED-SOURCE.md.
"""
import struct
from blake3 import blake3
import selection_source as source

sc, ps, need = source.sc, source.ps, source.need
PAIRS = b'stele/v0.1/research/onehot/pairs'


class Transcript(source.Transcript):
    def __init__(self, public, degree):
        super().__init__(public, degree)
        source.zc.tr.registry(source.zc.LABELS+source.EXTRA+(PAIRS,))
    def absorb(self, label, payload):
        if label == PAIRS:
            self.state = blake3(self.state+b'\0'+struct.pack('<I', len(label))+label+struct.pack('<Q', len(payload))+payload).digest()
        else:
            super().absorb(label, payload)


def derive(v, d):
    raw, spec, _, _ = source.derive(v, d)
    need(v['instance_base'] % 512 == 0 and v['instance_base'] <= (1 << 64)-512)
    need(v['tensor_base'] % 1024 == 0 and v['tensor_base'] <= (1 << 64)-1024)
    need(not v['tensor_base'] <= v['source_id'] < v['tensor_base']+1024)
    ell = (max(1, (spec.category_bits+1)//2)-1).bit_length()
    virtual = {**v, 'source_id': v['tensor_base']+256}
    return raw[:2]+bytes([2])+raw[2:], spec, virtual, ell, ell+spec.row_bits


def prepare(v, fields, d):
    _, spec, _, ell, dimension = derive(v, d)
    need((2*spec.leaves()+2*spec.category_bits+2+(1 << ell))*(1 << spec.row_bits) <= source.MAX_PREPARED, 'SourceCapacity')
    if fields is not None:
        need(len(fields) == 1 << dimension, 'PublicShape')
        for value in fields: ps.element(value, d)
    return spec


def encode(v, indices, d):
    spec = prepare(v, None, d)
    bits = source.encode(derive(v, d)[2], indices, d)
    n, k, two = 1 << spec.row_bits, spec.category_bits, sc.scalar(2, d)
    if k < 2: return [sc.mul(two, value) for value in bits]
    return [sc.add(sc.mul(two, bits[2*j*n+r]), bits[(2*j+1)*n+r])
            for j in range(spec.leaves()//2) for r in range(n)]


def coefficients(theta, d):
    # (1-theta)*high(P)+theta*low(P) = (1-3theta)*high(P)+theta*P.
    h = sc.mul(sc.add(sc.scalar(1, d), sc.neg(sc.mul(sc.scalar(3, d), theta))), sc.scalar(pow(6, -1, sc.P), d))
    return [sc.add(theta, sc.neg(sc.mul(sc.scalar(7, d), h))), sc.mul(sc.scalar(9, d), h), sc.neg(sc.mul(sc.scalar(2, d), h))]


def unpack(v, fields, d):
    spec = prepare(v, fields, d)
    n, k = 1 << spec.row_bits, spec.category_bits
    c1, c2, c3 = coefficients(sc.scalar(0, d), d)
    high = [sc.mul(sc.add(sc.mul(sc.add(sc.mul(c3, x), c2), x), c1), x) for x in fields]
    if k < 2: return high
    low = [sc.add(x, sc.neg(sc.mul(sc.scalar(2, d), h))) for x, h in zip(fields, high)]
    return [value for j in range(spec.leaves()//2) for row in [high[j*n:(j+1)*n], low[j*n:(j+1)*n]] for value in row]


def low_descriptor(v, d):
    _, spec, _, _, dimension = derive(v, d)
    need(spec.category_bits < 2)
    return dict(id=v['instance_base']+257, m=dimension, k=0, ids=[v['source_id']],
                terms=[(sc.scalar(1, d), [0, 0]), (sc.scalar(-2, d), [0])])


def descriptor(v, claim, ordinal, d):
    _, spec, virtual, ell, dimension = derive(v, d)
    identity, point, value = claim
    need(identity == virtual['source_id'] and len(point) == source.derive(virtual, d)[-1], 'SourceClaimScope')
    for x in [*point, value]: ps.element(x, d)
    zero, one = sc.scalar(0, d), sc.scalar(1, d)
    prefix = point[:ell]
    theta = zero if spec.category_bits < 2 else point[ell]
    tail = point[ell+int(spec.category_bits >= 2):]
    fixed = all(x in (zero, one) for x in prefix)
    plane = sum(int(x == one) << (ell-j-1) for j, x in enumerate(prefix)) if fixed else None
    base = tail if fixed else prefix+tail
    tensor = v['tensor_base']+385+ordinal if fixed else v['source_id']
    i = dict(id=v['instance_base']+128+ordinal, m=spec.row_bits if fixed else dimension,
             ids=[v['tensor_base']+257+ordinal, tensor], sum=value,
             terms=[(c, [0]+[1]*(j+1)) for j, c in enumerate(coefficients(theta, d))])
    return i, base, plane


def resolution_plan(v, claims, offset, d):
    _, spec, _, _, _ = derive(v, d)
    expected = 2+(spec.category_bits if spec.categories != 1 << spec.category_bits else 0) if offset == 0 else spec.category_bits
    need(offset in (0, 65) and len(claims) == expected, 'SourceClaimScope')
    return [descriptor(v, claim, offset+j, d) for j, claim in enumerate(claims)]


def resolve_prove(t, v, fields, claims, offset):
    spec = prepare(v, fields, t.degree)
    plan, result, n = resolution_plan(v, claims, offset, t.degree), [], 1 << spec.row_bits
    for i, point, plane in plan:
        values = fields if plane is None else fields[plane*n:(plane+1)*n]
        proof, _ = sc.prove(t, i, [ps.weights(point, t.degree), values])
        result.append(proof)
    return result


def resolve_verify(t, v, claims, offset, proof):
    plan = resolution_plan(v, claims, offset, t.degree)
    need(type(proof) is list and len(proof) == len(plan), 'ProofShape')
    originals, records, ell = [], [], derive(v, t.degree)[3]
    for (i, point, plane), part in zip(plan, proof):
        receipt = sc.verify_reduction(t, i, part)
        need(receipt['claims'][0][1] == ps.coefficient(point, receipt['point'], 1 << i['m'], t.degree), 'SourceMaskMismatch')
        prefix = [] if plane is None else [sc.scalar(plane >> (ell-j-1) & 1, t.degree) for j in range(ell)]
        originals.append((v['source_id'], prefix+receipt['point'], receipt['claims'][1][1]))
        records.append(receipt['sc'])
    return dict(claims=originals, sc=records)


def prove(t, v, fields):
    prepare(v, fields, t.degree)
    raw, spec, virtual, _, _ = derive(v, t.degree)
    bits = unpack(v, fields, t.degree)
    t.absorb(PAIRS, raw)
    low = source.zero_prove(t, low_descriptor(v, t.degree), [fields])[0] if spec.category_bits < 2 else None
    core, claims = source.prove_with_claims(t, virtual, bits)
    resolutions = resolve_prove(t, v, fields, claims, 0)
    return dict(low=low, source=core, resolutions=resolutions)


def verify_reduction(t, v, proof):
    raw, spec, virtual, _, _ = derive(v, t.degree)
    need(type(proof) is dict and set(proof) == {'low', 'source', 'resolutions'}, 'ProofShape')
    need(proof['low'] is not None if spec.category_bits < 2 else proof['low'] is None, 'ProofShape')
    t.absorb(PAIRS, raw)
    originals, records = [], []
    if spec.category_bits < 2:
        receipt, _ = source.zc.verify_reduction(t, low_descriptor(v, t.degree), proof['low'])
        originals.extend(receipt['claims']); records.extend(receipt['sc'])
    core = source.verify_reduction(t, virtual, proof['source'])
    receipt = resolve_verify(t, v, core['claims'], 0, proof['resolutions'])
    return dict(claims=originals+receipt['claims'], sc=records+core['sc']+receipt['sc'])


def selection_claims(v, receipt, d):
    virtual = derive(v, d)[2]
    return [(virtual['source_id'], point, value) for _, point, value in source.selection_claims(v, receipt, d)]


def link(t, v, s):
    derive(v, t.degree); source.link(t, v, s)
    need(s['id']+64 < v['instance_base'] or v['instance_base']+511 < s['id'], 'SourceClaimScope')
    need(all(not v['tensor_base'] <= identity < v['tensor_base']+1024
             for identity in [*s['inputs'], s['output']['id'], s['coefficient_id']]), 'SourceClaimScope')
