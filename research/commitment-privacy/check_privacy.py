"""Q29 exact algebra/distribution checks; no production ZK or negative-control credit."""
from collections import Counter
from fractions import Fraction
from hashlib import sha256
from itertools import combinations, product
from math import comb
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'circle-code'))
from check_circle import encode, P
from privacy import rank, private, observe, randomized_row


def distribution(a, b, secret, p):
    return Counter(observe(a, b, secret, mask, p) for mask in product(range(p), repeat=len(b[0])))


def distance(left, right):
    # Exact statistical distance, with potentially different sample counts.
    l, r = sum(left.values()), sum(right.values())
    return sum(abs(Fraction(left[v], l)-Fraction(right[v], r)) for v in left.keys() | right.keys())/2


def check_rank_criterion():
    checked = conditioned = 0
    for m, n, h in product((1,2), (1,2), (0,1,2)):
        for entries in product(range(3), repeat=m*(n+h)):
            a = [entries[i*(n+h):i*(n+h)+n] for i in range(m)]
            b = [entries[i*(n+h)+n:(i+1)*(n+h)] for i in range(m)]
            views = {x: distribution(a,b,x,3) for x in product(range(3),repeat=n)}
            equal = all(v == views[(0,)*n] for v in views.values())
            assert private(a,b,3) == equal
            if n == 2:
                # Public output H*x=x_0; compare only equal-public-output views.
                conditional = all(views[(x,y)] == views[(x,0)] for x,y in product(range(3),repeat=2))
                assert private([[row[1]] for row in a],b,3) == conditional
                conditioned += 1
            checked += 1
    assert checked == 8346 and conditioned == 7488
    # Full-rank masks hide arbitrary shifts; exposing a mask destroys joint privacy.
    assert private([[1]], [[1]], P)
    assert not private([[1],[0]], [[1],[1]], P)
    assert not private([[1,0],[0,1]], [[1],[1]], P)
    assert private([[1,0],[0,1]], [[1,0],[0,1]], P)
    print(f'linear views: {checked} exhaustive F_3 matrix cases, {conditioned} public-output conditional cases')


def check_appended_rows():
    columns = 0
    for m, blowup in product(range(6), (1,2)):
        size = 1 << m
        zero, one = encode([0]*size, blowup), encode([1]*size, blowup)
        random_row = encode([(37*i+11) % P for i in range(size)], blowup)
        assert zero == [0]*len(zero) and one == [1]*len(one)
        for column in range(len(zero)):
            left = (zero[column], random_row[column])
            right = (one[column], random_row[column])
            assert left[0] == 0 and right[0] == 1
            columns += 1
    assert columns == 378
    # Every toy mask: appended rows and common additive pads leave disjoint views.
    appended_a, appended_b = [[1],[0]], [[0],[1]]
    assert distance(distribution(appended_a,appended_b,(0,),5), distribution(appended_a,appended_b,(1,),5)) == 1
    common_a, common_b = [[1],[0]], [[1],[1]]
    assert distance(distribution(common_a,common_b,(0,),5), distribution(common_a,common_b,(1,),5)) == 1
    print(f'appended row: {columns} Accepted-map Circle coordinates distinguish constant secret rows; common-pad leakage verified')


def check_extension_support():
    # F_9 = F_3[u]/(u^2+1); -1=2 is not a square in F_3.
    assert 2 not in {x*x % 3 for x in range(3)}
    add = lambda a,b: tuple((x+y) % 3 for x,y in zip(a,b))
    mul = lambda a,b: ((a[0]*b[0]+2*a[1]*b[1]) % 3, (a[0]*b[1]+a[1]*b[0]) % 3)
    base, extension = [(i,0) for i in range(3)], list(product(range(3),repeat=2))
    shift = (0,1)  # a=(1-u,u), source (0,1), lambda=1.
    assert distance(Counter(base), Counter(add(x,shift) for x in base)) == 1
    assert distance(Counter(extension), Counter(add(x,shift) for x in extension)) == 0
    for lam in extension:
        support = Counter(mul(lam,x) for x in base)
        shifted = Counter(add(mul(lam,x),shift) for x in base)
        assert distance(support,shifted) == (0 if shift in support else 1)
        full = Counter(mul(lam,x) for x in extension)
        full_shifted = Counter(add(mul(lam,x),shift) for x in extension)
        assert distance(full,full_shifted) == (1 if lam == (0,0) else 0)
    # Even full-extension masking fails for the public zero coefficient.
    assert distance(Counter(mul((0,0),x) for x in extension), Counter(add(mul((0,0),x),shift) for x in extension)) == 1
    print('extension support: base masks leak an extension shift; full masks hide it only for nonzero coefficients')


def check_reuse():
    p, checked = 7, 0
    for x, mask in product(range(p),repeat=2):
        first, second = (x+mask) % p, (x+2*mask) % p
        assert (2*first-second) % p == x
        # Digest equality is not a test of mask independence.
        one = sha256(bytes((1,first))).digest()
        two = sha256(bytes((2,second))).digest()
        assert one != two
        checked += 1
    joint_a, joint_b = [[1],[1]], [[1],[2]]
    assert private([joint_a[0]],[joint_b[0]],p) and private([joint_a[1]],[joint_b[1]],p)
    assert not private(joint_a,joint_b,p)
    assert distance(distribution(joint_a,joint_b,(0,),p),distribution(joint_a,joint_b,(1,),p)) == 1
    assert private(joint_a,[[1,0],[0,2]],p)
    # Exact fixed-oracle coverage; query freshness does not refresh hidden data.
    n, t = 4, 8
    complete = sum(len(set(draws)) == n for draws in product(range(n),repeat=t))
    inclusion = sum((-1)**k*comb(n,k)*(n-k)**t for k in range(n+1))
    assert complete == inclusion == 40824
    assert Fraction(complete,n**t) >= 1-n*Fraction(n-1,n)**t
    print(f'reuse: {checked} secret/mask pairs recovered despite different digests; independent masks repair this linear example')
    print('fixed oracle: exact 4-column/8-draw coverage matches inclusion-exclusion and the lifetime union bound')


def check_functional():
    p, original, checked, honest_old_check = 5, (1,2), 0, 0
    for b in product(range(p),repeat=2):
        if b == (0,0):
            continue
        target = sum(x*y for x,y in zip(original,b)) % p
        for mask in product(range(p),repeat=2):
            blinded = tuple((x+r) % p for x,r in zip(original,mask))
            value = sum(x*y for x,y in zip(blinded,b)) % p
            correction = sum(r*y for r,y in zip(mask,b)) % p
            assert (value-target) % p == correction
            honest_old_check += value == target
            checked += 1
    assert (checked,honest_old_check) == (600,120)
    print('functional: 600 masked cases; the unchanged original-value check accepts only the 120 zero-correction cases')


def check_randomized_rows():
    p, message_points, queries, h = 7, (0,1), (2,3,4,5,6), 2
    masks = list(product(range(p),repeat=h))
    count = 0
    for q in (1,2):
        for selected in combinations(queries,q):
            reference = None
            for secret in product(range(p),repeat=2):
                values = Counter(randomized_row(secret,message_points,mask,selected,p) for mask in masks)
                assert len(values) == p**q and set(values.values()) == {p**(h-q)}
                if reference is None:
                    reference = values
                assert values == reference
                count += 1
    assert count == 735
    for secret, mask in product(product(range(p),repeat=2),masks):
        assert randomized_row(secret,message_points,mask,message_points,p) == secret
    # A fixed one-mask row can answer one private query; two recover its secret.
    for secret, mask in product(range(p),repeat=2):
        y1,y2 = randomized_row((secret,),(0,),(mask,),(1,2),p)
        assert (2*y1-y2) % p == secret
    one0 = Counter(randomized_row((0,),(0,),(r,),(1,),p) for r in range(p))
    one1 = Counter(randomized_row((1,),(0,),(r,),(1,),p) for r in range(p))
    two0 = Counter(randomized_row((0,),(0,),(r,),(1,2),p) for r in range(p))
    two1 = Counter(randomized_row((1,),(0,),(r,),(1,2),p) for r in range(p))
    assert distance(one0,one1) == 0 and distance(two0,two1) == 1
    # Distance does not certify the chosen mask coordinates: code (x,x,r,r).
    words = [(x,x,r,r) for x,r in product(range(3),repeat=2)]
    assert min(sum(a != b for a,b in zip(x,y)) for x,y in combinations(words,2)) == 2
    assert not private([[1]],[[0]],3)
    assert rank([[1,0],[1,1]],p) == 2
    print(f'randomized rows: {count} full-distribution comparisons; message probes and lifetime-budget exhaustion leak')


if __name__ == '__main__':
    check_rank_criterion()
    check_appended_rows()
    check_extension_support()
    check_functional()
    check_reuse()
    check_randomized_rows()
    print('Q29 research only: no complete simulator, adaptive theorem, source consumer, NC credit, native ZK or profile')
