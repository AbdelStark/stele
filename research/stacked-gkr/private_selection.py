"""RFC-0006 A4 / Q20 candidate onehot evaluation; unmasked, no private PCS admission."""
from dataclasses import dataclass
import itertools
import math
from pathlib import Path
import struct
import sys
from blake3 import blake3

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'sumcheck'))
import check_sumcheck as sc
import check_transcript as tr

SELECT = b'stele/v0.1/research/onehot/evaluation'
ORIGINALS = b'stele/v0.1/research/onehot/originals'
WEIGHTED = b'stele/v0.1/research/onehot/weighted'
MAX_PREPARED_CELLS = 1 << 18  # Tree, bits and mask only; excludes A1 scratch/proof.


def need(condition, reason='SelectionShape'):
    if not condition:
        raise ValueError(reason)


def element(value, d):
    need(type(value) is tuple and len(value) == d
         and all(type(v) is int and 0 <= v < sc.P for v in value), 'NoncanonicalField')


class Transcript(tr.Transcript):
    def __init__(self, public, degree):
        tr.registry(tr.LABELS+(SELECT, ORIGINALS, WEIGHTED))
        super().__init__(public, degree)

    def absorb(self, label, payload):
        if label in (SELECT, ORIGINALS, WEIGHTED):
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


@dataclass(frozen=True)
class GridSpec:
    axes: tuple
    category_bits: int
    categories: int

    @property
    def row_bits(self):
        return sum(b for b, _ in self.axes)

    @property
    def rows(self):
        return math.prod(n for _, n in self.axes)

    def validate(self):
        need(type(self.axes) is tuple and 1 <= len(self.axes) <= 64)
        for axis in self.axes:
            need(type(axis) is tuple and len(axis) == 2)
            b, n = axis
            need(type(b) is int and type(n) is int and 0 <= b <= 63 and 1 <= n <= 1 << b)
        Spec(self.row_bits, self.rows, self.category_bits, self.categories).validate()

    def leaves(self):
        return 1 << (max(1, self.category_bits)-1).bit_length()


def axes_of(spec):
    need(type(spec) in (Spec, GridSpec))
    spec.validate()
    return spec.axes if type(spec) is GridSpec else ((spec.row_bits, spec.rows),)


def positions(spec):
    axes = axes_of(spec)
    for real, coordinates in enumerate(itertools.product(*(range(n) for _, n in axes))):
        padded = 0
        for coordinate, (bits, _) in zip(coordinates, axes):
            padded = (padded << bits)+coordinate
        yield padded, real


def frame(spec, r, s, value, d):
    need(type(spec) is Spec)  # The legacy frame cannot describe a different grid.
    spec.validate()
    need(d in (4, 8) and len(r) == spec.row_bits and len(s) == spec.category_bits)
    for v in [*r, *s, value]:
        element(v, d)
    return (struct.pack('<BBBQBQ', 1, d, spec.row_bits, spec.rows, spec.category_bits, spec.categories)
            +b''.join(sc.encode(v) for v in [*r, *s, value]))


def weights(point, d):
    return pair_weights(pairs(point, d), d)


def pairs(point, d):
    return [(sc.add(sc.scalar(1, d), sc.neg(x)), x) for x in point]


def pair_weights(choices, d):
    values = [sc.scalar(1, d)]
    for pair in choices:
        values = [sc.mul(v, b) for v in values for b in pair]
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
    axes_of(spec)
    n, k, m = 1 << spec.row_bits, spec.category_bits, spec.leaves()
    need(n*(2*m+k) <= MAX_PREPARED_CELLS, 'SelectionCapacity')
    need(len(indices) == spec.rows and all(type(i) is int and 0 <= i < spec.categories for i in indices), 'SelectionSource')
    bits = [[sc.scalar(0, d)]*n for _ in range(k)]
    for padded, real in positions(spec):
        for j in range(k):
            bits[j][padded] = sc.scalar((indices[real] >> (k-j-1)) & 1, d)
    return bits


def affine(pair):
    return pair[0], sc.add(pair[1], sc.neg(pair[0]))


def evaluate(table, point):
    for x in point:
        table = sc.fold(table, x)
    return table[0]


def forest(spec, s, bits, d):
    n, m = 1 << spec.row_bits, spec.leaves()
    tree = [None]*(2*m)
    for j in range(m):
        if j < len(s):
            a, b = affine(s[j])
            tree[m+j] = [sc.add(a, sc.mul(b, v)) for v in bits[j]]
        else:
            tree[m+j] = [sc.scalar(1, d)]*n
    for j in range(m-1, 0, -1):
        tree[j] = [sc.mul(a, b) for a, b in zip(tree[2*j], tree[2*j+1])]
    return tree


def instance(node, a, value, d, base=0):
    # Logical heap position fixes the degree; the plan base fixes its wire id.
    count = 2 if node == 0 else 3
    return dict(id=base+node, m=a, ids=list(range(count)),
                terms=[(sc.scalar(1, d), list(range(count)))], sum=value)


def instance_range(base, count):
    need(type(base) is int and 0 <= base <= (1 << 64)-count)


def prove(t, spec, r, s, value, indices):
    raw = frame(spec, r, s, value, t.degree)
    return _prove(t, spec, pairs(r, t.degree), pairs(s, t.degree), sc.scalar(1, t.degree), value, indices, SELECT, raw)


def _prepare(spec, rows, columns, scale, indices, d):
    bits = source(spec, indices, d)
    tree = forest(spec, columns, bits, d)
    vector = pair_weights(rows, d)
    mask = [sc.scalar(0, d)]*(1 << spec.row_bits)
    for padded, _ in positions(spec):
        mask[padded] = sc.mul(scale, vector[padded])
    return bits, tree, mask


def _prove(t, spec, rows, columns, scale, value, indices, label, raw, instance_base=0):
    instance_range(instance_base, spec.leaves())
    bits, tree, mask = _prepare(spec, rows, columns, scale, indices, t.degree)
    m = spec.leaves()
    t.absorb(label, raw)
    root, point = sc.prove(t, instance(0, spec.row_bits, value, t.degree, instance_base), [mask, tree[1]])
    pending, nodes = {1: (point, root['final'][1])}, []
    for node in range(1, m):
        point, claimed = pending[node]
        proof, next_point = sc.prove(t, instance(node, spec.row_bits, claimed, t.degree, instance_base),
                                     [weights(point, t.degree), tree[2*node], tree[2*node+1]])
        nodes.append(proof)
        pending[2*node] = (next_point, proof['final'][1])
        pending[2*node+1] = (next_point, proof['final'][2])
    originals = [evaluate(table, pending[m+j][0]) for j, table in enumerate(bits)]
    t.absorb(ORIGINALS, struct.pack('<I', len(originals))+b''.join(map(sc.encode, originals)))
    return dict(root=root, nodes=nodes, originals=originals)


def verify_reduction(t, spec, r, s, value, proof):
    raw = frame(spec, r, s, value, t.degree)
    return _verify(t, spec, pairs(r, t.degree), pairs(s, t.degree), sc.scalar(1, t.degree), value, proof, SELECT, raw)


def grid_coefficient(spec, rows, point, scale, d):
    choices = [(sc.mul(w[0], q[0]), sc.mul(w[1], q[1])) for w, q in zip(rows, pairs(point, d))]
    value, at = scale, 0
    for bits, real in axes_of(spec):
        value = sc.mul(value, bounded(choices[at:at+bits], real, d))
        at += bits
    return value


def _verify(t, spec, rows, columns, scale, value, proof, label, raw, instance_base=0):
    m, k, d = spec.leaves(), spec.category_bits, t.degree
    instance_range(instance_base, m)
    need(type(proof) is dict and len(proof) == 3 and set(proof) == {'root', 'nodes', 'originals'} and len(proof['nodes']) == m-1
         and len(proof['originals']) == k, 'ProofShape')
    for v in proof['originals']:
        element(v, d)
    t.absorb(label, raw)
    root = sc.verify_reduction(t, instance(0, spec.row_bits, value, d, instance_base), proof['root'])
    need(root['claims'][0][1] == grid_coefficient(spec, rows, root['point'], scale, d), 'CoefficientMismatch')
    pending, records = {1: (root['point'], root['claims'][1][1])}, [root['sc']]
    for node, p in enumerate(proof['nodes'], 1):
        point, claimed = pending[node]
        receipt = sc.verify_reduction(t, instance(node, spec.row_bits, claimed, d, instance_base), p)
        need(receipt['claims'][0][1] == coefficient(point, receipt['point'], 1 << spec.row_bits, d), 'CoefficientMismatch')
        pending[2*node] = (receipt['point'], receipt['claims'][1][1])
        pending[2*node+1] = (receipt['point'], receipt['claims'][2][1])
        records.append(receipt['sc'])
    claims = []
    for j in range(m):
        point, leaf = pending[m+j]
        if j < k:
            a, b = affine(columns[j])
            original = proof['originals'][j]
            need(leaf == sc.add(a, sc.mul(b, original)), 'LeafMismatch')
            claims.append((j, point, original))  # Retain even a zero-coefficient original.
        else:
            need(leaf == sc.scalar(1, d), 'ConstantLeaf')
    t.absorb(ORIGINALS, struct.pack('<I', k)+b''.join(map(sc.encode, proof['originals'])))
    return dict(claims=claims, sc=records)
