# /// script
# requires-python = ">=3.12"
# dependencies = ["blake3==1.0.11"]
# ///
"""Q27 conditional tensor-opening checks; no production PCS or FS claim."""
from collections import Counter
from fractions import Fraction
from itertools import product
from math import prod
import random
from proximity import queries, tensor_parameters
from identity import parameters
from sampler import manifest
from recursive import sc


def tensor(point, prime):
    return [prod(r if (i >> bit) & 1 else 1-r for bit, r in enumerate(point)) % prime
            for i in range(1 << len(point))]


def folded(rows, point, prime):
    a = tensor(point, prime)
    return [sum(x*y for x, y in zip(a, column)) % prime for column in zip(*rows)]


def accepts(rows, point, u, b, v, columns, prime):
    # Ideal immutable matrix and repetition encoder, with u fixed before columns.
    return u*b % prime == v and all(folded(rows, point, prime)[c] == u for c in columns)


def check():
    # Independent repeated multiplication checks the exact minimal 130-bit count.
    for n in range(1, 25):
        for hit in range(1, n+1):
            count, left, right = 1, n-hit, n
            while (left << 130) > right:
                count, left, right = count+1, left*(n-hit), right*n
            assert queries(n, hit) == count
    for args in ((0, 1), (4, 0), (4, 5), (True, 1), (4, True), (1 << 32, 1)):
        sc.rejects(lambda: queries(*args), 'InvalidParameters')
    sc.rejects(lambda: queries(1 << 31, 1), 'UnsupportedParameters')
    for field, ell in ((1, 1), (4, -1), (4, True), (True, 1)):
        sc.rejects(lambda: tensor_parameters(manifest(bytes(32),4), field, ell), 'UnsupportedParameters')
    ids = [b'stele/circle-m31/v1'+bytes([m,b]) for b in (1,2) for m in range(31-b)]
    ids += [manifest(bytes(32),j) for j in range(3,16)]
    for raw_id in ids:
        info = parameters(raw_id, 4)
        n, distance = info['codeword_len'], info['distance']
        for field in (4, 8):
            p = tensor_parameters(raw_id, field, 20)
            e, q = p['radius'], p['queries']
            assert 3*e < distance and 3*(e+1) >= distance
            assert p['hit'] == e+1 and distance-e >= e+1
            assert p['gap'] == Fraction(40*(e+1), sc.P**field)
            assert ((n-e-1)**q << 130) <= n**q
            assert q == 1 or ((n-e-1)**(q-1) << 130) > n**(q-1)
            assert tensor_parameters(raw_id, field, 0)['gap'] == 0
    largest = manifest(bytes(32),15)
    assert tensor_parameters(largest,4,20)['gap'] > Fraction(1,1 << 100)
    p = tensor_parameters(largest,8,20)
    assert p['setup']+p['gap']+p['miss']**p['queries'] < Fraction(1,1 << 128)
    # Repetition [4,1,4], e=1. Interleaved distance counts union-of-error columns.
    cases = []
    for count in (1, 2):
        for values in product((0,1), repeat=count*4):
            cases.append((7, [list(values[4*i:4*i+4]) for i in range(count)]))
    rng = random.Random(4027)
    cases += [(17, [[rng.randrange(17) for _ in range(4)] for _ in range(4)]) for _ in range(24)]
    cases += [(17, [[i]*4 for i in range(4)]), (17, [[i,i,i,(i+1)%17] for i in range(4)])]
    near_cases = far_cases = 0
    for prime, rows in cases:
        ell = (len(rows)-1).bit_length()
        frequencies = Counter(zip(*rows))
        message, matching = frequencies.most_common(1)[0]
        near = 4-matching <= 1
        near_cases += near; far_cases += not near
        bad, exceptional = 0, 0
        for point in product(range(prime), repeat=ell):
            word = folded(rows, point, prime)
            counts = Counter(word)
            exceptional += max(counts.values()) >= 3
            if near:
                truth = sum(a*b for a,b in zip(tensor(point,prime),message)) % prime
                best = max((counts[u] for u in range(prime) if u != truth), default=0)
                assert best <= 1  # D-e=3 disagreements for every wrong message.
            else:
                best = max(counts.values())
            bad += best**3  # Exact worst u selected after r, before three iid columns.
        gap, miss = Fraction(2*ell*2,prime), Fraction(1,2)**3
        if not near:
            assert Fraction(exceptional,prime**ell) <= gap
        assert Fraction(bad,prime**ell*4**3) <= gap+miss
    assert near_cases and far_cases
    rows = [[1,0,0,0],[0,1,0,0]]
    assert all(4-max(Counter(row).values()) == 1 for row in rows)
    assert 4-max(Counter(zip(*rows)).values()) == 2
    # A fixed tensor point can hide a far row; tensor form alone is insufficient.
    rows = [[1,1,1,1],[0,1,2,3]]
    assert 4-max(Counter(zip(*rows)).values()) == 3
    accepted = sum(accepts(rows,(0,),1,1,1,cols,7) for cols in product(range(4),repeat=3))
    assert accepted == 4**3 and Fraction(4,7)+Fraction(1,8) < 1
    # Fix b=v=0 before queries; changing only u after a column defeats the miss bound.
    rows = [[0,1,2,3]]
    assert all(accepts(rows,(),rows[0][c],0,0,[c],7) for c in range(4))
    for u in range(7):
        accepted = sum(accepts(rows,(),u,1,u,cols,7) for cols in product(range(4),repeat=3))
        assert Fraction(accepted,4**3) == Fraction(rows[0].count(u),4)**3
        assert not accepts(rows,(),u,1,(u+1)%7,[],7)
    print(f'{len(cases)} exact toy matrix cases ({near_cases} near, {far_cases} far); fixed-point/late-row counterexamples pass.')
    for name, raw_id in [('circle/1024/rate-half',b'stele/circle-m31/v1'+bytes([10,1])),
                         ('circle/1024/rate-quarter',b'stele/circle-m31/v1'+bytes([10,2])),
                         ('expander/256',manifest(bytes(32),4)),('expander/2^30',largest)]:
        p=tensor_parameters(raw_id,8,20)
        print(f'{name}: e={p["radius"]}, hit={p["hit"]}, q={p["queries"]}; conditional arithmetic, not profile admission')


if __name__ == '__main__':
    check()
