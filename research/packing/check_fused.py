# /// script
# requires-python = ">=3.12"
# dependencies = ["blake3==1.0.11"]
# ///
"""Q28 exact layout study; not a PCS implementation or native pass-count gate."""
from itertools import product
from pathlib import Path
import random
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'sumcheck'))
from check_sumcheck import scalar, add, mul, fold, P
from fused import Source, partial, dimensions, payload


def evaluate(table, point):
    # Independent half-table folding; no source kernel/index or eq-weight routine.
    for r in point:
        table = fold(table, r)
    assert len(table) == 1
    return table[0]


def rejects(reason, call):
    try:
        call()
    except ValueError as error:
        assert str(error) == reason, (reason, str(error))
    else:
        raise AssertionError(f'accepted instead of {reason}')


def check_rank():
    # Exhaust every possibly nonlinear map {0,1}^2 -> F_5 and every 2-by-1 D.
    # The affine offset is forced by x=0, so test the two basis differences.
    checked = 0
    for images in product(range(5), repeat=4):
        for d in product(range(5), repeat=2):
            basis = tuple(tuple(v*(images[i]-images[0]) % 5 for v in d) for i in (1, 2))
            assert basis != ((1, 0), (0, 1))
            checked += 1
    assert checked == 15625
    # One selected functional can factor through packing; the theorem is not stronger.
    for lam, x, y in product(range(5), range(2), range(2)):
        assert lam*(x+2*y) % 5 == (lam*x+2*lam*y) % 5
    print(f'rank obstruction: {checked} nonlinear map/affine-decoder cases; selected-functional exception verified')


def check_layouts():
    rng = random.Random(280029)
    cases = reads = 0
    for d in (4, 8):
        for case in range(1000):
            logical = (1+case % 3, 1+case//3 % 5, 1+case//15 % 9)
            lp, ip, jp = dimensions(logical)
            bits = [x.bit_length()-1 for x in (lp, ip, jp)]
            points = [[tuple(rng.randrange(P) for _ in range(d)) for _ in range(b)] for b in bits]
            if case % 17 == 0:
                points = [[scalar(rng.randrange(2), d) for _ in range(b)] for b in bits]
            width = (8, 16)[case % 2]
            bound = 1 << (width-1)
            source_values = tuple(rng.randrange(-bound, bound) for _ in range(logical[0]*logical[1]*logical[2]))
            # Independent dense canonical tensor and per-(ell,k) output rows.
            logical_values = dict(zip(product(*(range(n) for n in logical)), source_values))
            dense = [scalar(logical_values.get(index, 0), d) for index in product(range(lp), range(ip), range(jp))]
            expected_b = tuple(evaluate(dense[t*jp:(t+1)*jp], points[2]) for t in range(lp*ip))
            split = case % (bits[2]+1)
            source = Source(source_values)
            actual = partial(source, logical, width, points[2], split, d)
            assert actual.b == expected_b
            assert source.reads == len(source_values) and source.visits == 1
            assert len(actual.row) == (1 << split)*lp*ip
            assert (actual.row is actual.b) == (split == 0)
            assert actual.retained == len(actual.row)+(0 if split == 0 else len(actual.b))
            assert actual.coefficients == (jp >> split)+(1 << split)
            assert actual.source_macs == len(source_values)
            assert actual.fold_macs == (0 if split == 0 else len(actual.row))
            # Independently form every split column and fold only its high axis.
            high = points[2][:bits[2]-split]
            for low, t in product(range(1 << split), range(lp*ip)):
                column = [dense[t*jp+(hi << split)+low] for hi in range(jp >> split)]
                assert actual.row[low*lp*ip+t] == evaluate(column, high)
            full = evaluate(dense, points[0]+points[1]+points[2])
            assert evaluate(list(actual.b), points[0]+points[1]) == full
            assert evaluate(list(actual.row), points[2][bits[2]-split:]+points[0]+points[1]) == full
            # Arbitrary original b, not necessarily tensor-structured.
            b = [tuple(rng.randrange(P) for _ in range(d)) for _ in actual.b]
            left = scalar(0, d)
            for value, coefficient in zip(actual.b, b):
                left = add(left, mul(value, coefficient))
            low_values = []
            for low in range(1 << split):
                value = scalar(0, d)
                for t, coefficient in enumerate(b):
                    value = add(value, mul(actual.row[low*lp*ip+t], coefficient))
                low_values.append(value)
            assert evaluate(low_values, points[2][bits[2]-split:]) == left
            rejects('SourceReused', lambda: partial(source, logical, width, points[2], split, d))
            reads += source.reads
            cases += 1
    print(f'layouts: {cases} full-extension cases; {reads} logical source reads, one visit per case')


def check_boundaries():
    for d in (4, 8):
        z = scalar(0, d)
        # Independent axis padding matters: (3,3,1) needs 16 columns, not 16
        # contiguous entries with seven trailing zeros. The holes are internal.
        row = partial(Source(tuple(range(9))), (3, 3, 1), 8, [], 0, d).row
        assert row == tuple(scalar(x, d) for x in (0,1,2,0,3,4,5,0,6,7,8,0,0,0,0,0))
        assert row != tuple(scalar(x, d) for x in list(range(9))+[0]*7)
        assert partial(Source((-1,)), (1, 1, 1), 8, [], 0, d).b == (scalar(-1, d),)
        assert scalar(-1, d) != scalar(255, d)
        source = Source((3,))
        partial(source, (1,1,1), 8, [], 0, d)
        rejects('SourceReused', lambda: partial(source, (1,1,1), 8, [], 0, d))
        point = [scalar(x, d) for x in (2, 3, 5)]
        values = (0, 1, 4, 9, 16, 25, 36, 49)
        split = partial(Source(values), (1,1,8), 8, point, 2, d)
        expected = evaluate([scalar(x, d) for x in values], point)
        assert split.b == (expected,) and split.row is not split.b
        assert evaluate(list(split.row), point[1:]) == expected
        assert evaluate(list(split.row), list(reversed(point[1:]))) != expected
        for width in (8, 16):
            for value in (-(1 << (width-1)), (1 << (width-1))-1):
                assert partial(Source((value,)), (1, 1, 1), width, [], 0, d).row == (scalar(value, d),)
        for shape in ((0,1,1), (1,-1,1), (1,True,1), (1,1), (1,1,1,1)):
            rejects('Shape', lambda: partial(Source((0,)), shape, 8, [], 0, d))
        for split in (-1, 1, True):
            rejects('Split', lambda: partial(Source((0,)), (1,1,1), 8, [], split, d))
        rejects('Point', lambda: partial(Source((0,)), (1,1,1), 8, [z], 0, d))
        for point in (None, 0, [None], [(0,)], [(True,)+(0,)*(d-1)]):
            rejects('Point', lambda: partial(Source((0,0)), (1,1,2), 8, point, 0, d))
        rejects('Point', lambda: partial(Source((0,0)), (1,1,2), 8, [(P,)+(0,)*(d-1)], 0, d))
        rejects('SourceLength', lambda: partial(Source((0,0)), (1,1,1), 8, [], 0, d))
        for value in (-129, 128, True):
            rejects('SourceRange', lambda: partial(Source((value,)), (1,1,1), 8, [], 0, d))
        rejects('Width', lambda: partial(Source((0,)), (1,1,1), 32, [], 0, d))
    rejects('Field', lambda: partial(Source((0,)), (1,1,1), 8, [], 0, 2))
    print('boundaries: signed endpoints, axis holes, scalar axes, malformed points/ranges and repeated source rejected')


def check_costs():
    # Exact counts, not a measured performance result or admitted query policy.
    for d in (4, 8):
        for t, j, q in product((1, 8, 256), (1, 8, 1024), (1, 223, 5722)):
            for s in range(j.bit_length()):
                v = payload(t, j, s, d, q)
                assert v['message_symbols'] == t*j
                assert v['row_bytes'] == 4*d*t*(1 << s)
                assert v['column_bytes'] == 4*q*(j >> s)
                assert v['retained_symbols'] == (t if s == 0 else t*((1 << s)+1))
    # A split minimizing these two payload terms need not minimize the full proof.
    choices = [payload(256,1024,s,4,223) for s in range(11)]
    best = min(range(11), key=lambda s: choices[s]['row_bytes']+choices[s]['column_bytes'])
    assert best == 4
    print('cost counts: invariant message size; all 0..log J splits; payload-only optimum has s=4 in the fixed example')


if __name__ == '__main__':
    check_rank()
    check_layouts()
    check_boundaries()
    check_costs()
    print('Q28 research only: no private consumer, native timing/memory gate, NC credit, PCS, ZK or profile')
