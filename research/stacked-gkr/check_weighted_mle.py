# /// script
# requires-python = ">=3.12"
# dependencies = ["blake3==1.0.11"]
# ///
"""Q20 full-K weighted coefficient study; not production parity or source authentication."""
import copy
import itertools
import random
from check_statement import fixture, rejects
from statement import P, encode
from weighted_mle import evaluate, add, mul, neg, scalar


def boolean_table(s):
    """Materialize the canonical Boolean table; no evaluator DP/weights."""
    d, axes, c = s['field'], s['layout'], s['coefficient']
    one, zero = scalar(1, d), scalar(0, d)
    table = []
    for indices in itertools.product(*(range(1 << b) for b, _ in axes)):
        value = 1
        if any(i >= real for i, (_, real) in zip(indices, axes)):
            value = 0
        elif c['kind'] in (1, 2, 3, 4):
            a, b = (indices[i] for i in c['axes'])
            if c['kind'] in (1, 2):
                value = int(b <= a and (c['kind'] == 1 or a-b < c['width']))
            elif c['kind'] == 3:
                value = int(b == c['values'][a])
            else:
                h, g = (axes[i][1] for i in c['axes'])
                value = int(b == a//(h//g))
        elif c['kind'] == 5:
            index = 0
            for axis in c['axes']:
                index = index*axes[axis][1]+indices[axis]
            value = c['values'][index]
        term = scalar(value, d)
        if term != zero:
            for i, selector in zip(indices, c['selectors']):
                if selector is not None:
                    for bit, z in enumerate(reversed(selector)):
                        term = mul(term, z if i >> bit & 1 else add(one, neg(z)))
        table.append(term)
    return table


def direct(s, point):
    table = boolean_table(s)
    for r in point:
        half = len(table)//2
        table = [add(a, mul(r, add(b, neg(a)))) for a, b in zip(table[:half], table[half:])]
    return table[0]


def check(samples=10000):
    rng = random.Random(30621)
    for d in (4, 8):
        counts = [0]*6
        def element():
            return tuple(rng.randrange(P) for _ in range(d))
        for case in range(samples):
            bits = case % 3
            size = 1 << bits
            rows, columns = rng.randrange(1, size+1), rng.randrange(1, size+1)
            # Move the primitive across canonical axes; layer may share its mask.
            permutation = list(itertools.permutations(range(3)))[case % 6]
            axes = [(case % 2, 1), (bits, rows), (bits, columns)]
            layout = [axes[i] for i in permutation]
            a, b = permutation.index(1), permutation.index(2)
            point = [element() for _ in range(sum(v[0] for v in layout))]
            if case % 11 == 0:
                point = [scalar(rng.randrange(2), d) for _ in point]
            selectors = [[element() for _ in range(width)] if case >> i & 1 else None
                         for i, (width, _) in enumerate(layout)]
            for kind in range(6):
                s = fixture(d, kind)
                s['layout'] = list(layout)
                c = s['coefficient']
                c.update(selectors=selectors, axes=[] if kind == 0 else [a, b])
                if kind == 2:
                    c['width'] = (1, size, size+1, 2**64-1)[case % 4]
                if kind == 3:
                    c['values'] = [rng.randrange(columns) for _ in range(rows)]
                if kind == 4:
                    groups = rng.choice([g for g in range(1, rows+1) if rows % g == 0])
                    s['layout'][b] = (bits, groups)
                if kind == 5:
                    c['axes'] = sorted({a, b} if case % 2 else {a})
                    count = 1
                    for axis in c['axes']:
                        count *= s['layout'][axis][1]
                    c['values'] = [rng.randrange(P) for _ in range(count)]
                encode(s)
                actual = evaluate(s, point)
                assert actual == direct(s, point), (d, case, kind, actual)
                counts[kind] += 1
            if case and case % 1000 == 0:
                print(f'd={d}: {case} queries per kind checked', flush=True)
        # Shared-axis selector multiplication after extension is a different polynomial.
        s = fixture(d, 1)
        point = [element() for _ in range(5)]
        mask = evaluate(s, point)
        s['coefficient']['selectors'][1] = [element(), element()]
        joint = evaluate(s, point)
        separate = copy.deepcopy(s)
        separate['coefficient'].update(kind=0, axes=[])
        assert joint == direct(s, point)
        assert joint != mul(mask, evaluate(separate, point))
        # A single 63-bit axis with non-Boolean K selectors never materializes its domain.
        s = fixture(d)
        s.update(layout=[(63, 1 << 63)])
        s['coefficient']['selectors'] = [[element() for _ in range(63)]]
        point = [element() for _ in range(63)]
        expected = scalar(1, d)
        for r, z in zip(point, s['coefficient']['selectors'][0]):
            expected = mul(expected, add(mul(r, z), mul(add(scalar(1, d), neg(r)), add(scalar(1, d), neg(z)))))
        assert evaluate(s, point) == expected
        # Large full-K masks: the two causal regions partition the rectangle plus its diagonal.
        s = fixture(d, 1)
        s['layout'] = [(31, 1 << 31)]*2
        s['coefficient'].update(axes=[0, 1], selectors=[[element() for _ in range(31)] for _ in range(2)])
        point = [element() for _ in range(62)]
        rectangle, diagonal = scalar(1, d), scalar(1, d)
        for bit in range(31):
            pairs = []
            for axis in range(2):
                r, z = point[axis*31+bit], s['coefficient']['selectors'][axis][bit]
                pairs.append((mul(add(scalar(1, d), neg(r)), add(scalar(1, d), neg(z))), mul(r, z)))
            rectangle = mul(rectangle, mul(add(*pairs[0]), add(*pairs[1])))
            diagonal = mul(diagonal, add(mul(pairs[0][0], pairs[1][0]), mul(pairs[0][1], pairs[1][1])))
        forward = evaluate(s, point)
        s['coefficient']['axes'] = [1, 0]
        assert add(forward, evaluate(s, point)) == add(rectangle, diagonal)
        s['coefficient'].update(kind=2, width=1 << 31)
        assert evaluate(s, point) == add(add(rectangle, diagonal), neg(forward))
        # Unequal sparse domains and a source spanning all three irregular axes.
        for kind in (3, 4, 5):
            s = fixture(d, kind)
            s['layout'] = [(2, 3), (3, 6), (2, 3)]
            s['coefficient']['selectors'] = [[element() for _ in range(b)] for b, _ in s['layout']]
            if kind == 3:
                s['coefficient']['values'] = [2, 0, 1, 2, 0, 2]
            if kind == 5:
                s['coefficient'].update(axes=[0, 1, 2], values=[rng.randrange(P) for _ in range(54)])
            point = [element() for _ in range(7)]
            assert evaluate(s, point) == direct(s, point)
        s = fixture(d)
        s['layout'] = [(0, 1)]*64
        s['coefficient']['selectors'] = [None, []]*32
        assert evaluate(s, []) == scalar(1, d)
        s = fixture(d, 2)
        for changed in ([], [scalar(0, d)]*6, [(P,)+(0,)*(d-1)]*5, [(True,)+(0,)*(d-1)]*5):
            rejects(lambda: evaluate(s, changed))
        s['coefficient']['width'] = 0
        rejects(lambda: evaluate(s, [scalar(0, d)]*5))
        print(f'd={d}: per-kind direct-table agreements {counts}; malformed queries reject.', flush=True)
    print('Research algebra only; no Rust parity, authenticated sources, NC or performance credit.')


if __name__ == '__main__':
    check()
