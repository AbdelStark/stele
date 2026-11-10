"""R1 exact check with two relations sharing a column (formal/zk-claims.md §§2.1a, 3).

Research helper, never protocol authority. Over F_97 with K = F_97[i]/(i^2 - 5)
(D = 2), one hiding source holds five columns and their per-claim mask blocks:
x, y, z (8 entries), w (4) and o (2). Two relations reveal masked claims:

- an identity `x·y − z = 0` on a 3-variable domain, with claims on x, y, z at
  one point (each factor with its own vanishing and mask coordinate);
- a matmul zero-sum `o(i) = Σ_k x(i,k)·w(k)` with free bit i and summed bits k,
  with claims on x (a second claim on the same column, correlated with nothing
  else only through its own mask block), w and o (carried by Ȯ on a summed bit).

The source adds the A2 certificate row, the zero-weight batch (Lemma 7) with a
Lemma 4 mask, the batch opening row and every queried column. For fixed honest
challenges the view is linear in (columns, randomness); privacy for every pair of
witnesses is exactly rank([B A]) == rank(B). Negative controls must leak.
"""
from pathlib import Path
import random
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'commitment-privacy'))
from privacy import rank

P = 97
NR = 5  # a quadratic non-residue mod 97, so K = F_97[i]/(i^2 - 5)
D = 2


def add(a, b):
    return ((a[0] + b[0]) % P, (a[1] + b[1]) % P)


def sub(a, b):
    return ((a[0] - b[0]) % P, (a[1] - b[1]) % P)


def mul(a, b):
    return ((a[0] * b[0] + NR * a[1] * b[1]) % P, (a[0] * b[1] + a[1] * b[0]) % P)


def inv(a):
    norm = (a[0] * a[0] - NR * a[1] * a[1]) % P
    n = pow(norm, -1, P)
    return (a[0] * n % P, -a[1] * n % P)


ZERO, ONE = (0, 0), (1, 0)


def base(v):
    return (v % P, 0)


def dot(ws, vs):
    total = ZERO
    for w, v in zip(ws, vs):
        total = add(total, mul(w, v))
    return total


def eq(point):
    """MSB-first eq table: coordinate 0 is the highest index bit."""
    table = [ONE]
    for x in point:
        table = [mul(t, sub(ONE, x)) for t in table] + [mul(t, x) for t in table]
    n = len(point)
    out = [None] * len(table)
    for index, value in enumerate(table):
        out[int(format(index, f'0{n}b')[::-1], 2) if n else 0] = value
    return out


def kappa(t):
    return mul(t, sub(ONE, t))


def lagrange(nodes, x):
    weights = []
    for i, xi in enumerate(nodes):
        num, den = ONE, ONE
        for j, xj in enumerate(nodes):
            if i != j:
                num = mul(num, sub(x, base(xj)))
                den = mul(den, base(xi - xj))
        weights.append(mul(num, inv(den)))
    return weights


R, C = 4, 16  # data rows (R = 2D) and data columns
ROWS, COLS = 2 * R, 2 * C
Z = list(range(1, COLS + 1))  # message points
DOMAIN = list(range(COLS + 1, 3 * COLS + 1))  # 64 codeword points, disjoint
ENC = [[w[0] for w in lagrange(Z, base(y))] for y in DOMAIN]


def encode(row):
    return [sum(c * v for c, v in zip(coefficients, row)) % P for coefficients in ENC]


# Data layout: flat data index -> (row, column) of the R x C data block.
LAYOUT = {}
cursor = 0
for name, length in (('x', 8), ('y', 8), ('z', 8), ('w', 4), ('o', 2),
                     ('rx', 4), ('ry', 2), ('rz', 2), ('rw', 2), ('ro', 2)):
    LAYOUT[name] = [divmod(cursor + j, C) for j in range(length)]
    cursor += length
SECRET = ('x', 'y', 'z', 'w', 'o')
MASKS = ('rx', 'ry', 'rz', 'rw', 'ro')


def claims_spec(ch):
    """Each claim: (column, point over its variables, mask name, block, lambda, u)."""
    a, b, c = ch.identity
    i, k0, k1 = ch.matmul
    return [
        # identity x·y − z: vanishing x→a, y→b, z→c; mask coordinates x→b, y→c, z→a.
        ('x', [a, b, c], 'rx', 0, kappa(a), b),
        ('y', [a, b, c], 'ry', 0, kappa(b), c),
        ('z', [a, b, c], 'rz', 0, kappa(c), a),
        # matmul: x(i,k) w(k) − Ȯ(i,k) on summed k; x→k0, w→k1, o→k0 vanishing.
        ('x', [i, k0, k1], 'rx', 1, kappa(k0), k1),
        ('w', [k0, k1], 'rw', 0, kappa(k1), i),
        ('o', [i], 'ro', 0, kappa(k0), k1),
    ]


def claim_weights(spec, with_masks):
    """The claim as a K weight on each data position (row, column)."""
    weights = {}
    for column, point, mask, block, lam, u in spec:
        entry = {}
        for j, w in enumerate(eq(point)):
            entry[LAYOUT[column][j]] = add(entry.get(LAYOUT[column][j], ZERO), w)
        if with_masks:
            for j, w in enumerate(eq([u])):  # c_D = 1: a block of 2 entries
                position = LAYOUT[mask][2 * block + j]
                entry[position] = add(entry.get(position, ZERO), mul(lam, w))
        weights.setdefault('claims', []).append(entry)
    return weights['claims']


def fold(table, r):
    half = len(table) // 2
    return [add(mul(sub(ONE, r), x), mul(r, y)) for x, y in zip(table[:half], table[half:])]


def batch_rounds(weight, values, g, alpha, challenges):
    """Masked A1 rounds of Σ W'(z) M(z) (Lemma 4), MSB first."""
    n = len(challenges)
    rounds, prefix = [], ZERO
    w_table, m_table = list(weight), list(values)
    inverse_two = pow(2, P - 2, P)
    for index in range(n):
        half = len(w_table) // 2
        scale = pow(2, n - index - 1, P)
        suffix = ZERO
        for j in range(index + 1, n):
            suffix = add(suffix, add(g[j][0], g[j][1]))
        values_t = []
        for t in range(3):
            tt = base(t)
            total = ZERO
            for j in range(half):
                w = add(mul(sub(ONE, tt), w_table[j]), mul(tt, w_table[half + j]))
                m = add(mul(sub(ONE, tt), m_table[j]), mul(tt, m_table[half + j]))
                total = add(total, mul(w, m))
            gamma = add(mul(base(scale), add(g[index][t], prefix)),
                        mul(base(scale * inverse_two), suffix))
            values_t.append(add(total, mul(alpha, gamma)))
        rounds.append(values_t)
        r = challenges[index]
        w_table, m_table = fold(w_table, r), fold(m_table, r)
        prefix = add(prefix, dot(lagrange([0, 1, 2], r), g[index]))
    mask_sum = ZERO
    for row in g:
        mask_sum = add(mask_sum, add(row[0], row[1]))
    return rounds, mul(base(pow(2, n - 1, P)), mask_sum), prefix


def rk(rng):
    return (rng.randrange(P), rng.randrange(P))


BATCH_VARS = 1 + 2 + 4  # (w, data row bits, data column bits)


class Challenges:
    def __init__(self, rng, queries):
        self.identity = [rk(rng) for _ in range(3)]
        self.matmul = [rk(rng) for _ in range(3)]
        self.gamma = [rk(rng) for _ in range(6)]
        self.certificate = [rk(rng) for _ in range(3)]
        self.alpha = rk(rng)
        self.batch = [rk(rng) for _ in range(BATCH_VARS)]
        self.queries = rng.sample(range(len(DOMAIN)), queries)


def message_of(secret, masks, rm, s):
    data = [[0] * C for _ in range(R)]
    for name, values in list(secret.items()) + list(masks.items()):
        for (row, column), v in zip(LAYOUT[name], values):
            data[row][column] = v
    return [data[row] + rm[row] for row in range(R)] + [list(s[row]) for row in range(R)]


def view(secret, masks, rm, s, g, ch, variant):
    if variant == 'no-claim-mask':
        masks = {name: [0] * len(values) for name, values in masks.items()}
    if variant == 'no-mask-rows':
        s = [[0] * COLS for _ in range(R)]
    if variant == 'shared-block':
        # The second x claim reuses block 0 instead of its own block.
        masks = dict(masks)
    message = message_of(secret, masks, rm, s)
    spec = claims_spec(ch)
    if variant == 'shared-block':
        spec = [entry if index != 3 else entry[:3] + (0,) + entry[4:]
                for index, entry in enumerate(spec)]
    out = []
    claims = claim_weights(spec, True)
    for entry in claims:
        value = ZERO
        for (row, column), w in entry.items():
            value = add(value, mul(w, base(message[row][column])))
        out.extend(value)
    certificate = eq(ch.certificate)
    for column in range(COLS):
        out.extend(dot(certificate, [base(message[row][column]) for row in range(ROWS)]))
    batched = {}
    for coefficient, entry in zip(ch.gamma, claims):
        for position, w in entry.items():
            batched[position] = add(batched.get(position, ZERO), mul(coefficient, w))
    weight, values = [], []
    for w_bit in range(2):
        for row in range(R):
            for column in range(C):
                values.append(base(message[w_bit * R + row][column]))
                weight.append(batched.get((row, column), ZERO) if w_bit == 0 else ZERO)
    g_used = g if variant != 'no-sumcheck-mask' else [[ZERO] * 3 for _ in g]
    rounds, mask_sum, mu = batch_rounds(weight, values, g_used, ch.alpha, ch.batch)
    out.extend(mask_sum)
    for row in rounds:
        for value in row:
            out.extend(value)
    out.extend(mu)
    opening = eq([ch.batch[0]] + ch.batch[1:3])
    for column in range(COLS):
        out.extend(dot(opening, [base(message[row][column]) for row in range(ROWS)]))
    for row in range(ROWS):
        codeword = encode(message[row])
        out.extend(codeword[q] for q in ch.queries)
    return out


def zero_state():
    return dict(secret={name: [0] * len(LAYOUT[name]) for name in SECRET},
                masks={name: [0] * len(LAYOUT[name]) for name in MASKS},
                rm=[[0] * C for _ in range(R)], s=[[0] * COLS for _ in range(R)],
                g=[[ZERO] * 3 for _ in range(BATCH_VARS)])


def columns(ch, variant):
    def run(state):
        return view(state['secret'], state['masks'], state['rm'], state['s'], state['g'],
                    ch, variant)

    a_columns, b_columns = [], []
    for name in SECRET:
        for j in range(len(LAYOUT[name])):
            state = zero_state()
            state['secret'][name][j] = 1
            a_columns.append(run(state))
    for name in MASKS:
        for j in range(len(LAYOUT[name])):
            state = zero_state()
            state['masks'][name][j] = 1
            b_columns.append(run(state))
    for row in range(R):
        for column in range(C):
            state = zero_state()
            state['rm'][row][column] = 1
            b_columns.append(run(state))
    for row in range(R):
        for column in range(COLS):
            state = zero_state()
            state['s'][row][column] = 1
            b_columns.append(run(state))
    for index in range(BATCH_VARS):
        for t in range(3):
            for coordinate in range(D):
                state = zero_state()
                state['g'][index][t] = (1, 0) if coordinate == 0 else (0, 1)
                b_columns.append(run(state))
    transpose = lambda cols: [list(row) for row in zip(*cols)]
    return transpose(a_columns), transpose(b_columns)


def private(ch, variant):
    a, b = columns(ch, variant)
    return rank([rb + ra for ra, rb in zip(a, b)], P) == rank(b, P)


def aborts(ch):
    """Public aborts: lambda = 0, block rank < D (u in F_p), mask-row rank < 2D,
    w* = 0, alpha = 0 (formal/zk-claims.md §3.1)."""
    for _, _, _, _, lam, u in claims_spec(ch):
        if lam == ZERO or u[1] == 0:
            return True
    coordinates = lambda vs: [[v[0] for v in vs], [v[1] for v in vs]]
    certificate = eq(ch.certificate)[R:]
    opening = eq([ch.batch[0]] + ch.batch[1:3])[R:]
    if rank(coordinates(certificate) + coordinates(opening), P) < 2 * D:
        return True
    return ch.batch[0] == ZERO or ch.alpha == ZERO


def main():
    rng = random.Random(20261111)
    trials = 12
    results = {}
    for variant, queries in (('honest', 6), ('no-claim-mask', 6), ('no-mask-rows', 6),
                             ('no-sumcheck-mask', 6), ('shared-block', 6), ('honest', 15),
                             ('honest', 17)):
        ok = n = 0
        while n < trials:
            ch = Challenges(rng, queries)
            if aborts(ch):
                continue
            n += 1
            ok += private(ch, variant)
        results[(variant, queries)] = ok
        print(f'{variant:17} |Q|={queries:2}: private in {ok}/{trials} non-aborting draws')
    assert results[('honest', 6)] == trials, 'LEAK: honest two-relation view is not private'
    assert results[('honest', 15)] == trials, 'LEAK at the budget |Q| = C - 1'
    for variant in ('no-claim-mask', 'no-mask-rows', 'no-sumcheck-mask', 'shared-block'):
        assert results[(variant, 6)] == 0, f'control {variant} did not leak'
    assert results[('honest', 17)] < trials, 'over-budget control did not leak'
    print('zk-claims two relations: honest view private (also at |Q| = C - 1); each '
          'removed mask, a shared mask block and an over-budget query set leak')


if __name__ == '__main__':
    main()
