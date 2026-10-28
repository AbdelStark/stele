"""Q20 candidate closed public-stage wrapper; no production or private-source admission."""
import struct
from blake3 import blake3
from statement import encode, field, need
from weighted_mle import evaluate
from check_weighted_mle import boolean_table
from ownership import reorder
import check_sumcheck as sc
import check_transcript as tr

STACK = b'stele/v0.1/gkr/stacked'


class Transcript(tr.Transcript):
    def __init__(self, public, degree):
        tr.registry(tr.LABELS+(STACK,))
        super().__init__(public, degree)

    def absorb(self, label, payload):
        if label == STACK:
            raw = self.state+b'\x00'+struct.pack('<I', len(label))+label+struct.pack('<Q', len(payload))+payload
            self.state = blake3(raw).digest()
        else:
            super().absorb(label, payload)


def permutation(s):
    m, layer = sum(b for b, _ in s['layout']), s['layout'][0][0]
    return list(range(m)) if s['order'] == 0 else list(range(layer, m))+list(range(layer))


def instance(s):
    a = len(s['inputs'])
    return dict(id=s['id'], m=sum(b for b, _ in s['layout']), ids=s['inputs']+[s['coefficient_id']],
                terms=[(c, factors+[a]) for c, factors in s['terms']], sum=s['output']['value'])


def descriptor(t, s):
    raw = encode(s)
    need(t.degree == s['field'])
    return raw


def public_tables(s, tables):
    d, axes = s['field'], s['layout']
    m = sum(b for b, _ in axes)
    if len(tables) != len(s['inputs']) or any(len(table) != 1 << m for table in tables):
        raise ValueError('PublicShape')
    for table in tables:
        for index, value in enumerate(table):
            try:
                field(value, d)
            except ValueError:
                raise ValueError('PublicShape') from None
            shift = m
            for bits, real in axes:
                shift -= bits
                if ((index >> shift) & ((1 << bits)-1)) >= real and value != sc.scalar(0, d):
                    raise ValueError('PublicShape')


def evaluation(table, point, d):
    total = sc.scalar(0, d)
    for index, value in enumerate(table):
        weight = sc.scalar(1, d)
        for bit, coordinate in enumerate(reversed(point)):
            weight = sc.mul(weight, coordinate if index >> bit & 1 else sc.add(sc.scalar(1, d), sc.neg(coordinate)))
        total = sc.add(total, sc.mul(value, weight))
    return total


def prove(t, s, tables):
    raw = descriptor(t, s)
    public_tables(s, tables)
    # Explicit Boolean construction is independent of the verifier's weighted DP.
    inputs = [reorder(table, permutation(s)) for table in [*tables, boolean_table(s)]]
    t.absorb(STACK, raw)
    proof, _ = sc.prove(t, instance(s), inputs)
    return proof


def verify_reduction(t, s, proof):
    raw = descriptor(t, s)
    t.absorb(STACK, raw)
    nested = sc.verify_reduction(t, instance(s), proof)
    canonical = [None]*len(nested['point'])
    for axis, coordinate in zip(permutation(s), nested['point']):
        canonical[axis] = coordinate
    if evaluate(s, canonical) != nested['claims'][-1][1]:
        raise ValueError('CoefficientMismatch')
    # The framed A1 receipt cannot escape as an original tensor claim.
    return dict(point=canonical, claims=nested['claims'][:-1], sc=nested['sc'])


def verify_public(t, s, proof, tables):
    descriptor(t, s)
    public_tables(s, tables)
    receipt = verify_reduction(t, s, proof)
    for table, (_, expected) in zip(tables, receipt['claims']):
        if evaluation(table, receipt['point'], s['field']) != expected:
            raise ValueError('ClaimMismatch')
    return receipt
