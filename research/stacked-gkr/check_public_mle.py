"""Q20 algebra study: exact public tables vs factored M31 evaluators, not NC credit."""
import random
from check_stacking import P, mle
from public_mle import bounded_eq, causal, window, onehot, gqa, dense_table


def basis(point, index):
    value = 1
    for bit, r in enumerate(reversed(point)):
        value = value * (r if index >> bit & 1 else 1-r) % P
    return value


def check():
    rng = random.Random(30620)
    counts = dict(eq=0, causal_mask=0, window_mask=0, onehot_sparse=0,
                  gqa_broadcast=0, rope_tables=0)
    for case in range(10000):
        bits = case % 4
        size = 1 << bits
        rows, cols = rng.randrange(1, size+1), rng.randrange(1, size+1)
        width = rng.randrange(1, size+2)
        a, b, z = ([rng.randrange(P) for _ in range(bits)] for _ in range(3))
        if case % 7 == 0:
            a = [rng.randrange(2) for _ in range(bits)]
        if case % 11 == 0:
            b = [P-1]*bits
        eq_table = [basis(z, j) if j < rows else 0 for j in range(size)]
        assert bounded_eq(z, a, rows) == mle(eq_table, a)
        counts['eq'] += 1
        masks = [int(i < rows and j < cols and j <= i) for i in range(size) for j in range(size)]
        assert causal(a, b, rows, cols) == mle(masks, a+b)
        counts['causal_mask'] += 1
        masks = [int(i < rows and j < cols and j <= i and i-j < width) for i in range(size) for j in range(size)]
        assert window(a, b, rows, cols, width) == mle(masks, a+b)
        counts['window_mask'] += 1
        indices = [rng.randrange(cols) for _ in range(rows)]
        table = [int(i < rows and j < cols and indices[i] == j) for i in range(size) for j in range(size)]
        assert onehot(a, b, rows, cols, indices) == mle(table, a+b)
        counts['onehot_sparse'] += 1
        heads = rows
        groups = rng.choice([g for g in range(1, heads+1) if heads % g == 0])
        group_bits = (groups-1).bit_length()
        group_point = [rng.randrange(P) for _ in range(group_bits)]
        table = [int(h < heads and g < groups and h//(heads//groups) == g)
                 for h in range(size) for g in range(1 << group_bits)]
        assert gqa(a, group_point, heads, groups) == mle(table, a+group_point)
        counts['gqa_broadcast'] += 1
        values = [rng.randrange(P) if i < rows and j < cols else 0
                  for i in range(size) for j in range(size)]
        assert dense_table(values, a+b) == mle(values, a+b)
        counts['rope_tables'] += 1
    for _ in range(1000):
        a, b, z, w = ([rng.randrange(P) for _ in range(2)] for _ in range(4))
        rows, cols = rng.randrange(1, 5), rng.randrange(1, 5)
        table = [basis(z, i)*basis(w, j) % P if i < rows and j < cols else 0
                 for i in range(4) for j in range(4)]
        assert bounded_eq(z, a, rows)*bounded_eq(w, b, cols) % P == mle(table, a+b)
    # Non-power-of-two padding cannot be replaced by a separately extended selector.
    point, target = [2, 3], [5, 7]
    correct = bounded_eq(target, point, 3)
    unmasked = bounded_eq(target, point, 4)
    separate = unmasked * mle([1, 1, 1, 0], point) % P
    assert correct != separate
    # The dynamic program's state is independent of the padded table size.
    for bits in (0, 1, 31, 63):
        size = 1 << bits
        for i, j in ((0, 0), (size-1, 0), (size-1, size-1)):
            a = [(i >> k) & 1 for k in reversed(range(bits))]
            b = [(j >> k) & 1 for k in reversed(range(bits))]
            assert causal(a, b, size, size) == int(j <= i)
            for width in (1, size, size+1):
                assert window(a, b, size, size, width) == int(j <= i and i-j < width)
    a, b = ([rng.randrange(P) for _ in range(63)] for _ in range(2))
    equality = 1
    for r, s in zip(a, b):
        equality = equality*((1-r)*(1-s)+r*s) % P
    assert bounded_eq(a, b, 1 << 63) == equality
    assert (causal(a, b, 1 << 63, 1 << 63)+causal(b, a, 1 << 63, 1 << 63)-equality) % P == 1
    assert window(a, b, 1 << 63, 1 << 63, 1 << 63) == causal(a, b, 1 << 63, 1 << 63)
    for call in (lambda: causal([P], [0], 2, 2), lambda: causal([0], [], 1, 1), lambda: window([], [], 1, 1, 0),
                 lambda: bounded_eq([], [], 0), lambda: onehot([], [], 1, 1, [1]),
                 lambda: gqa([0, 0], [0], 3, 2), lambda: dense_table([0, 1], [])):
        try:
            call()
        except ValueError:
            pass
        else:
            raise AssertionError('malformed research descriptor accepted')
    print(counts)
    print('Padded equality differs from product of separately extended selectors:', correct, separate)
    print('M31 algebra only; no authenticated source, production NC, extension-field or performance evidence.')


if __name__ == '__main__':
    check()
