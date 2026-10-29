"""RFC-0006 A4 / Q20 candidate onehot evaluation; unmasked, no private PCS admission."""
from dataclasses import dataclass
from pathlib import Path
import struct
import sys
from blake3 import blake3

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'sumcheck'))
import check_sumcheck as sc
import check_transcript as tr

SELECT = b'stele/v0.1/research/onehot/evaluation'
ORIGINALS = b'stele/v0.1/research/onehot/originals'
MAX_PREPARED_CELLS = 1 << 18  # Tree, bits and mask only; excludes A1 scratch/proof.


def need(condition, reason='SelectionShape'):
    if not condition:
        raise ValueError(reason)


def element(value, d):
    need(type(value) is tuple and len(value) == d
         and all(type(v) is int and 0 <= v < sc.P for v in value), 'NoncanonicalField')


class Transcript(tr.Transcript):
    def __init__(self, public, degree):
        tr.registry(tr.LABELS+(SELECT, ORIGINALS))
        super().__init__(public, degree)

    def absorb(self, label, payload):
        if label in (SELECT, ORIGINALS):
            raw = self.state+b'\0'+struct.pack('<I', len(label))+label+struct.pack('<Q', len(payload))+payload
            self.state = blake3(raw).digest()
        else:
            super().absorb(label, payload)


@dataclass(frozen=True)
class Spec:
    row_bits: int
    rows: int
    category_bits: int
    categories: int

    def validate(self):
        a, n, k, c = self.row_bits, self.rows, self.category_bits, self.categories
        need(all(type(v) is int for v in (a, n, k, c)))
        need(0 <= a <= 63 and 0 <= k <= 63 and 1 <= n <= 1 << a and 1 <= c <= 1 << k)

    def leaves(self):
        return 1 << (max(1, self.category_bits)-1).bit_length()


def frame(spec, r, s, value, d):
    spec.validate()
    need(d in (4, 8) and len(r) == spec.row_bits and len(s) == spec.category_bits)
    for v in [*r, *s, value]:
        element(v, d)
    return (struct.pack('<BBBQBQ', 1, d, spec.row_bits, spec.rows, spec.category_bits, spec.categories)
            +b''.join(sc.encode(v) for v in [*r, *s, value]))


def weights(point, d):
    values, one = [sc.scalar(1, d)], sc.scalar(1, d)
    for x in point:
        values = [sc.mul(v, b) for v in values for b in (sc.add(one, sc.neg(x)), x)]
    return values


def bounded(pairs, limit, d):
    """MSB prefix DP for sum_{i<limit} product_j pairs[j][i_j]."""
    less, equal = sc.scalar(0, d), sc.scalar(1, d)
    if limit == 1 << len(pairs):
        for zero, one in pairs:
            equal = sc.mul(equal, sc.add(zero, one))
        return equal
    for j, (zero, one) in enumerate(pairs):
        less = sc.mul(less, sc.add(zero, one))
        if limit >> (len(pairs)-j-1) & 1:
            less = sc.add(less, sc.mul(equal, zero))
            equal = sc.mul(equal, one)
        else:
            equal = sc.mul(equal, zero)
    return less


def coefficient(r, point, rows, d):
    one = sc.scalar(1, d)
    pairs = [(sc.mul(sc.add(one, sc.neg(x)), sc.add(one, sc.neg(y))), sc.mul(x, y))
             for x, y in zip(r, point)]
    return bounded(pairs, rows, d)


def source(spec, indices, d):
    spec.validate()
    need(len(indices) == spec.rows and all(type(i) is int and 0 <= i < spec.categories for i in indices), 'SelectionSource')
    n, k, m = 1 << spec.row_bits, spec.category_bits, spec.leaves()
    need(n*(2*m+k) <= MAX_PREPARED_CELLS, 'SelectionCapacity')
    return [[sc.scalar((indices[i] >> (k-j-1)) & 1, d) if i < spec.rows else sc.scalar(0, d)
             for i in range(n)] for j in range(k)]


def affine(s, d):
    return sc.add(sc.scalar(1, d), sc.neg(s)), sc.add(sc.add(s, s), sc.scalar(-1, d))


def evaluate(table, point):
    for x in point:
        table = sc.fold(table, x)
    return table[0]


def forest(spec, s, bits, d):
    n, m = 1 << spec.row_bits, spec.leaves()
    tree = [None]*(2*m)
    for j in range(m):
        if j < len(s):
            a, b = affine(s[j], d)
            tree[m+j] = [sc.add(a, sc.mul(b, v)) for v in bits[j]]
        else:
            tree[m+j] = [sc.scalar(1, d)]*n
    for j in range(m-1, 0, -1):
        tree[j] = [sc.mul(a, b) for a, b in zip(tree[2*j], tree[2*j+1])]
    return tree


def instance(node, a, value, d):
    count = 2 if node == 0 else 3
    return dict(id=node, m=a, ids=list(range(count)),
                terms=[(sc.scalar(1, d), list(range(count)))], sum=value)


def prove(t, spec, r, s, value, indices):
    raw = frame(spec, r, s, value, t.degree)
    bits = source(spec, indices, t.degree)
    tree, m = forest(spec, s, bits, t.degree), spec.leaves()
    mask = [w if i < spec.rows else sc.scalar(0, t.degree) for i, w in enumerate(weights(r, t.degree))]
    t.absorb(SELECT, raw)
    root, point = sc.prove(t, instance(0, spec.row_bits, value, t.degree), [mask, tree[1]])
    pending, nodes = {1: (point, root['final'][1])}, []
    for node in range(1, m):
        point, claimed = pending[node]
        proof, next_point = sc.prove(t, instance(node, spec.row_bits, claimed, t.degree),
                                     [weights(point, t.degree), tree[2*node], tree[2*node+1]])
        nodes.append(proof)
        pending[2*node] = (next_point, proof['final'][1])
        pending[2*node+1] = (next_point, proof['final'][2])
    originals = [evaluate(table, pending[m+j][0]) for j, table in enumerate(bits)]
    t.absorb(ORIGINALS, struct.pack('<I', len(originals))+b''.join(map(sc.encode, originals)))
    return dict(root=root, nodes=nodes, originals=originals)


def verify_reduction(t, spec, r, s, value, proof):
    raw = frame(spec, r, s, value, t.degree)
    m, k, d = spec.leaves(), spec.category_bits, t.degree
    need(set(proof) == {'root', 'nodes', 'originals'} and len(proof['nodes']) == m-1
         and len(proof['originals']) == k, 'ProofShape')
    for v in proof['originals']:
        element(v, d)
    t.absorb(SELECT, raw)
    root = sc.verify_reduction(t, instance(0, spec.row_bits, value, d), proof['root'])
    need(root['claims'][0][1] == coefficient(r, root['point'], spec.rows, d), 'CoefficientMismatch')
    pending, records = {1: (root['point'], root['claims'][1][1])}, [root['sc']]
    for node, p in enumerate(proof['nodes'], 1):
        point, claimed = pending[node]
        receipt = sc.verify_reduction(t, instance(node, spec.row_bits, claimed, d), p)
        need(receipt['claims'][0][1] == coefficient(point, receipt['point'], 1 << spec.row_bits, d), 'CoefficientMismatch')
        pending[2*node] = (receipt['point'], receipt['claims'][1][1])
        pending[2*node+1] = (receipt['point'], receipt['claims'][2][1])
        records.append(receipt['sc'])
    claims = []
    for j in range(m):
        point, leaf = pending[m+j]
        if j < k:
            a, b = affine(s[j], d)
            original = proof['originals'][j]
            need(leaf == sc.add(a, sc.mul(b, original)), 'LeafMismatch')
            claims.append((j, point, original))  # Retain even a zero-coefficient original.
        else:
            need(leaf == sc.scalar(1, d), 'ConstantLeaf')
    t.absorb(ORIGINALS, struct.pack('<I', k)+b''.join(map(sc.encode, proof['originals'])))
    return dict(claims=claims, sc=records)
