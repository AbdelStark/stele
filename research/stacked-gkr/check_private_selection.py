# /// script
# requires-python = ">=3.12"
# dependencies = ["blake3==1.0.11"]
# ///
"""RFC-0006 A4 / Q20 exact reduction study; no ZK or production NC claim."""
import copy
import hashlib
import json
import random
import struct
from blake3 import blake3
from private_selection import (Spec, Transcript, SELECT, ORIGINALS, frame, prove,
                               verify_reduction, coefficient, bounded, sc)


def weight(point, index, d):
    value = sc.scalar(1, d)
    for j, x in enumerate(point):
        value = sc.mul(value, x if index >> (len(point)-j-1) & 1 else sc.add(sc.scalar(1, d), sc.neg(x)))
    return value


def total(values, d):
    out = sc.scalar(0, d)
    for value in values:
        out = sc.add(out, value)
    return out


def explicit(spec, indices, r, s, d):
    # Independent Boolean matrix predicate; never used by the candidate prover.
    return total([sc.mul(weight(r, i, d), weight(s, j, d))
                  for i in range(1 << spec.row_bits) for j in range(1 << spec.category_bits)
                  if i < spec.rows and j < spec.categories and j == indices[i]], d)


def original_consumer(spec, indices, receipt, d):
    if len(indices) != spec.rows or any(type(i) is not int or not 0 <= i < spec.categories for i in indices):
        raise ValueError('SelectionSource')
    assert [j for j, _, _ in receipt['claims']] == list(range(spec.category_bits))
    for j, point, value in receipt['claims']:
        expected = total([weight(point, i, d) for i, index in enumerate(indices)
                          if index >> (spec.category_bits-j-1) & 1], d)
        if value != expected:
            raise ValueError('OriginalSourceMismatch')


def public(indices):
    # Reference fixture only: these actual public bytes close the oracle statement.
    return b'Q20/onehot/public-reference/v1'+struct.pack('<I', len(indices))+b''.join(struct.pack('<Q', i) for i in indices)


def run(spec, indices, r, s, value, d):
    p, v = Transcript(public(indices), d), Transcript(public(indices), d)
    proof = prove(p, spec, r, s, value, indices)
    receipt = verify_reduction(v, spec, r, s, value, proof)
    original_consumer(spec, indices, receipt, d)
    assert p.state == v.state and sc.challenge(p) == sc.challenge(v)
    m = spec.leaves()
    assert receipt['sc'] == [dict(id=j, m=spec.row_bits, degree=2 if j == 0 else 3,
                                field_degree=d, numerator=spec.row_bits*(2 if j == 0 else 3)) for j in range(m)]
    assert sum(x['numerator'] for x in receipt['sc']) == spec.row_bits*(3*m-1)
    size = sum(sum(map(len, p['rounds']))+len(p['final']) for p in [proof['root'], *proof['nodes']])+len(proof['originals'])
    assert size == spec.row_bits*(4*m-1)+3*m-1+spec.category_bits
    return proof, receipt


def check():
    rng, digest = random.Random(30623), hashlib.sha256()
    for d in (4, 8):
        zero, one, half = sc.scalar(0, d), sc.scalar(1, d), sc.scalar(pow(2, -1, sc.P), d)
        element = lambda: tuple(rng.randrange(sc.P) for _ in range(d))
        for case in range(1000):
            a, k = case % 3, case % 5
            spec = Spec(a, rng.randrange(1, (1 << a)+1), k, rng.randrange(1, (1 << k)+1))
            indices = [rng.randrange(spec.categories) for _ in range(spec.rows)]
            r, s, point = [element() for _ in range(a)], [element() for _ in range(k)], [element() for _ in range(a)]
            sparse = total([sc.mul(weight(r, i, d), weight(s, index, d)) for i, index in enumerate(indices)], d)
            assert sparse == explicit(spec, indices, r, s, d)
            expected = total([sc.mul(weight(r, i, d), weight(point, i, d)) for i in range(spec.rows)], d)
            assert coefficient(r, point, spec.rows, d) == expected
        for case in range(128):
            a, k = case % 3, case // 3 % 6
            spec = Spec(a, rng.randrange(1, (1 << a)+1), k, rng.randrange(1, (1 << k)+1))
            indices = [rng.randrange(spec.categories) for _ in range(spec.rows)]
            r, s = [element() for _ in range(a)], [element() for _ in range(k)]
            if s and case % 7 == 0:
                s[0] = (zero, half, one)[case % 3]
            value = explicit(spec, indices, r, s, d)
            proof, receipt = run(spec, indices, r, s, value, d)
            digest.update(json.dumps([spec.__dict__, indices, r, s, value, proof, receipt], sort_keys=True, separators=(',', ':')).encode())
        # Wide categories never allocate a category-domain table.
        for k in (0, 1, 7, 31, 32, 63):
            spec = Spec(0, 1, k, 1 << k)
            index = (1 << k)-1
            s = [element() for _ in range(k)]
            run(spec, [index], [], s, weight(s, index, d), d)
        # Bounded verifier work at 63 row bits; complementary prefixes partition.
        pairs = [(element(), element()) for _ in range(63)]
        limit = (1 << 62)+123
        whole = one
        for x, y in pairs:
            whole = sc.mul(whole, sc.add(x, y))
        assert sc.add(bounded(pairs, limit, d), bounded([(y, x) for x, y in pairs], (1 << 63)-limit, d)) == whole
        # A single residue is not the original index: 0 and p select different columns.
        assert sc.scalar(sc.P, d) == zero
        assert weight([zero]*31, 0, d) != weight([zero]*31, sc.P, d)
        # Bit width alone permits a forbidden padded category.
        ragged = Spec(0, 1, 2, 3)
        assert explicit(ragged, [3], [], [one, one], d) == zero
        assert weight([one, one], 3, d) == one
        sc.rejects(lambda: prove(Transcript(b'range test', d), ragged, [], [one, one], one, [3]), 'SelectionSource')
        # A zero affine coefficient retains its original source obligation.
        spec, indices, r, s = Spec(0, 1, 1, 2), [0], [], [half]
        proof, _ = run(spec, indices, r, s, half, d)
        bad = copy.deepcopy(proof); bad['originals'][0] = one
        receipt = verify_reduction(Transcript(public(indices), d), spec, r, s, half, bad)
        sc.rejects(lambda: original_consumer(spec, indices, receipt, d), 'OriginalSourceMismatch')
        for key in ('nodes', 'originals'):
            bad = copy.deepcopy(proof); bad[key].append(one)
            t = Transcript(public(indices), d); before = t.state
            sc.rejects(lambda: verify_reduction(t, spec, r, s, half, bad), 'ProofShape')
            assert t.state == before
        bad = copy.deepcopy(proof); bad['originals'][0] = (sc.P,)+(0,)*(d-1)
        sc.rejects(lambda: verify_reduction(Transcript(public(indices), d), spec, r, s, half, bad), 'NoncanonicalField')
        proof, _ = run(spec, indices, r, [zero], one, d)
        bad = copy.deepcopy(proof); bad['originals'][0] = one
        sc.rejects(lambda: verify_reduction(Transcript(public(indices), d), spec, r, [zero], one, bad), 'LeafMismatch')
        proof, _ = run(spec, [1], r, [zero], zero, d)
        bad = copy.deepcopy(proof); bad['root']['final'][0] = sc.scalar(2, d)
        sc.rejects(lambda: verify_reduction(Transcript(public([1]), d), spec, r, [zero], zero, bad), 'CoefficientMismatch')
        spec = Spec(0, 1, 3, 8)
        proof, _ = run(spec, [1], [], [zero]*3, zero, d)
        bad = copy.deepcopy(proof); bad['nodes'][2]['final'][2] = sc.scalar(2, d)
        sc.rejects(lambda: verify_reduction(Transcript(public([1]), d), spec, [], [zero]*3, zero, bad), 'ConstantLeaf')
        spec, r = Spec(1, 2, 1, 2), [element()]
        value = explicit(spec, [0, 1], r, [zero], d)
        proof, _ = run(spec, [0, 1], r, [zero], value, d)
        sc.rejects(lambda: verify_reduction(Transcript(public([0, 1]), d), spec, r, [zero], sc.add(value, one), proof), 'RoundSumMismatch')
        bad = copy.deepcopy(proof); bad['root']['rounds'][0][0] = sc.add(bad['root']['rounds'][0][0], one)
        sc.rejects(lambda: verify_reduction(Transcript(public([0, 1]), d), spec, r, [zero], value, bad), 'RoundSumMismatch')
        for spec, indices, r, s, reason in [
                (Spec(0, 1, 1, 3), [0], [], [zero], 'SelectionShape'),
                (Spec(0, 1, 1, 2), [2], [], [zero], 'SelectionSource'),
                (Spec(0, 1, 1, 2), [True], [], [zero], 'SelectionSource'),
                (Spec(20, 1, 1, 2), [0], [zero]*20, [zero], 'SelectionCapacity')]:
            t = Transcript(b'shape test', d); before = t.state
            sc.rejects(lambda: prove(t, spec, r, s, zero, indices), reason)
            assert t.state == before
        # Record the honest pre-Originals state; only the adversarial prover reuses it.
        framed_spec, rq, sq, claimed = Spec(2, 3, 3, 7), [element(), element()], [element() for _ in range(3)], element()
        payload = bytes([1, d, 2])+(3).to_bytes(8, 'little')+bytes([3])+(7).to_bytes(8, 'little')
        payload += b''.join(limb.to_bytes(4, 'little') for v in [*rq, *sq, claimed] for limb in v)
        assert frame(framed_spec, rq, sq, claimed, d) == payload
        class Recorder(Transcript):
            def absorb(self, label, payload):
                if label == ORIGINALS:
                    self.before_originals = self.state
                super().absorb(label, payload)
        spec = Spec(0, 1, 1, 2)
        p = Recorder(public([0]), d)
        raw = frame(spec, [], [half], half, d)
        expected = blake3(p.state+b'\0'+len(SELECT).to_bytes(4, 'little')+SELECT+len(raw).to_bytes(8, 'little')+raw).digest()
        framed = Transcript(public([0]), d); framed.absorb(SELECT, raw)
        assert framed.state == expected
        first = prove(p, spec, [], [half], half, [0])
        stale = Transcript(public([0]), d); stale.state = p.before_originals
        second_spec, r = Spec(1, 2, 0, 1), [element()]
        honest = prove(p, second_spec, r, [], one, [0, 0])
        wrong = prove(stale, second_spec, r, [], one, [0, 0])
        assert honest['root']['rounds'] == wrong['root']['rounds']
        assert sum(x != y for x, y in zip(honest['root']['final'], wrong['root']['final'])) == 1
        v = Transcript(public([0]), d)
        original_consumer(spec, [0], verify_reduction(v, spec, [], [half], half, first), d)
        original_consumer(second_spec, [0, 0], verify_reduction(v, second_spec, r, [], one, honest), d)
        assert p.state == v.state and sc.challenge(p) == sc.challenge(v)
        v = Transcript(public([0]), d)
        verify_reduction(v, spec, [], [half], half, first)
        sc.rejects(lambda: verify_reduction(v, second_spec, r, [], one, wrong), 'FinalEvaluationMismatch')
    print(json.dumps(dict(algebra_per_field=1000, reductions_per_field=134, seed=30623, sha256=digest.hexdigest()), sort_keys=True))
    print('Conditional unmasked research: original index-bit/range/PCS and joint ZK consumers remain required.')


if __name__ == '__main__':
    check()
