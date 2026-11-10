"""R1 exact small-field check of the dev-zk linear view (formal/zk-claims.md §3).

Research helper, never protocol authority. Over F_31 with K = F_31[i]/(i^2+1)
(D = 2), a toy MDS code (Reed–Solomon by interpolation on message points Z and
evaluation on disjoint points), one committed column x (8 entries) with a claim
mask r (4 entries), one hiding source M' = [X | Rm ; S], the A2 certificate row,
masked claims c_a, the batching sumcheck masked as in Lemma 4, the batch opening
row and every queried column. For fixed honest-verifier challenges the view is
linear in (x, randomness); privacy for every pair of witnesses is exactly
rank([B A]) == rank(B) (commitment-privacy §2). Negative controls must leak.
"""
from pathlib import Path
import random
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'commitment-privacy'))
from privacy import rank

P = 31  # base field; -1 is a non-residue, so K = F_P[i]/(i^2 + 1)
D = 2


def k_add(a, b):
    return ((a[0] + b[0]) % P, (a[1] + b[1]) % P)


def k_sub(a, b):
    return ((a[0] - b[0]) % P, (a[1] - b[1]) % P)


def k_mul(a, b):
    return ((a[0] * b[0] - a[1] * b[1]) % P, (a[0] * b[1] + a[1] * b[0]) % P)


def k_scale(a, s):
    return (a[0] * s % P, a[1] * s % P)


def k_inv(a):
    norm = (a[0] * a[0] + a[1] * a[1]) % P
    inverse = pow(norm, -1, P)
    return (a[0] * inverse % P, -a[1] * inverse % P)


ZERO, ONE = (0, 0), (1, 0)


def k_dot(weights, values):
    total = ZERO
    for w, v in zip(weights, values):
        total = k_add(total, k_mul(w, v))
    return total


def eq_table(point):
    """MSB-first eq weights, as RFC-0005 §2: coordinate 0 is the highest bit."""
    table = [ONE]
    for x in point:
        table = [k_mul(t, k_sub(ONE, x)) for t in table] + [k_mul(t, x) for t in table]
        # Reorder so coordinate 0 ends as the most significant bit.
    return reorder(table, len(point))


def reorder(table, n):
    # The loop above makes coordinate 0 the least significant bit; reverse bits.
    out = [None] * len(table)
    for index, value in enumerate(table):
        reversed_index = int(format(index, f'0{n}b')[::-1], 2) if n else 0
        out[reversed_index] = value
    return out


def lagrange(nodes, x):
    """Weights of the values at `nodes` for the degree < len(nodes) interpolant at x."""
    weights = []
    for i, xi in enumerate(nodes):
        num, den = ONE, ONE
        for j, xj in enumerate(nodes):
            if i != j:
                num = k_mul(num, k_sub(x, (xj, 0)))
                den = k_mul(den, ((xi - xj) % P, 0))
        weights.append(k_mul(num, k_inv(den)))
    return weights


# Toy code: messages of length 8 are values on Z, codewords evaluate on 16 points.
Z = list(range(1, 9))
DOMAIN = list(range(9, 25))
ENC = [[w[0] for w in lagrange(Z, (y, 0))] for y in DOMAIN]  # base-field matrix


def encode(row):
    return [sum(c * v for c, v in zip(coefficients, row)) % P for coefficients in ENC]


R, C = 4, 4  # data rows/columns; R = 2D
ROWS, COLS = 2 * R, 2 * C  # M' rows (W, row) and columns (Y, col)


def build(x, r, rm, s):
    """M' = [X | Rm ; S] with X rows 0,1 = x (row-major) and rows 2,3 = r padded."""
    data = [x[0:4], x[4:8], r + [0, 0, 0, 0][:0] if False else r[0:4], [0, 0, 0, 0]]
    data[2] = list(r)
    message = []
    for row in range(R):
        message.append(list(data[row]) + list(rm[row]))
    for row in range(R):
        message.append(list(s[row]))
    return message


def position_x(i):
    return (i // 4, i % 4)  # (row, column) of x entry i within M'


def position_r(j):
    return (2, j)


def masked_claim(message, rho, kappa_on, pi):
    """c = x~(rho) + kappa(rho_2) r~(pi(rho)); kappa(t) = t(1 - t)."""
    weights_x = eq_table(rho)  # 3 variables over 8 entries
    value = ZERO
    for i, w in enumerate(weights_x):
        row, column = position_x(i)
        value = k_add(value, k_mul(w, (message[row][column], 0)))
    if kappa_on:
        kappa = k_mul(rho[2], k_sub(ONE, rho[2]))
        weights_r = eq_table(pi)  # 2 variables over 4 entries
        for j, w in enumerate(weights_r):
            row, column = position_r(j)
            value = k_add(value, k_mul(k_mul(kappa, w), (message[row][column], 0)))
    return value


def claim_functional(rho, kappa_on, pi):
    """The claim as a K-weight on each M' data position (for batching)."""
    weights = {}
    for i, w in enumerate(eq_table(rho)):
        weights[position_x(i)] = k_add(weights.get(position_x(i), ZERO), w)
    if kappa_on:
        kappa = k_mul(rho[2], k_sub(ONE, rho[2]))
        for j, w in enumerate(eq_table(pi)):
            weights[position_r(j)] = k_add(weights.get(position_r(j), ZERO), k_mul(kappa, w))
    return weights


def mle(table, point):
    return k_dot(eq_table(point), table)


def fold(table, challenge):
    half = len(table) // 2
    return [k_add(k_mul(k_sub(ONE, challenge), a), k_mul(challenge, b))
            for a, b in zip(table[:half], table[half:])]


def batch_rounds(weight, values, g, alpha, challenges):
    """Masked A1 rounds of sum W'(z) M(z) over z in {0,1}^n (MSB first), Lemma 4."""
    n = len(challenges)
    rounds = []
    w_table, m_table = list(weight), list(values)
    prefix = ZERO
    for index in range(n):
        half = len(w_table) // 2
        evaluations = []
        for t in range(3):
            tt = (t, 0)
            total = ZERO
            for j in range(half):
                w = k_add(k_mul(k_sub(ONE, tt), w_table[j]), k_mul(tt, w_table[half + j]))
                m = k_add(k_mul(k_sub(ONE, tt), m_table[j]), k_mul(tt, m_table[half + j]))
                total = k_add(total, k_mul(w, m))
            # Gamma_i(t) = 2^{n-i}(g_i(t) + prefix) + 2^{n-i-1} sum_{j>i}(g_j(0)+g_j(1)).
            scale = pow(2, n - index - 1, P)
            suffix = ZERO
            for j in range(index + 1, n):
                suffix = k_add(suffix, k_add(g[j][0], g[j][1]))
            gamma = k_add(k_scale(k_add(g[index][t], prefix), scale),
                          k_scale(suffix, scale * pow(2, P - 2, P) % P))
            evaluations.append(k_add(total, k_mul(alpha, gamma)))
        rounds.append(evaluations)
        challenge = challenges[index]
        w_table, m_table = fold(w_table, challenge), fold(m_table, challenge)
        prefix = k_add(prefix, k_dot(lagrange([0, 1, 2], challenge), g[index]))
    mask_sum = ZERO
    for row in g:
        mask_sum = k_add(mask_sum, k_add(row[0], row[1]))
    mask_sum = k_scale(mask_sum, pow(2, n - 1, P))
    return rounds, mask_sum, prefix


def random_k(rng):
    return (rng.randrange(P), rng.randrange(P))


class Challenges:
    def __init__(self, rng, queries):
        self.rho = [[random_k(rng) for _ in range(3)] for _ in range(2)]  # two claims
        self.gamma = [random_k(rng) for _ in range(2)]
        self.certificate = [random_k(rng) for _ in range(3)]  # (W, row bits)
        self.alpha = random_k(rng)
        self.batch = [random_k(rng) for _ in range(5)]  # (w, row bits, col bits)
        self.queries = rng.sample(range(len(DOMAIN)), queries)


def view(x, r, rm, s, g, ch, variant):
    """Every revealed value, flattened to base-field coordinates."""
    message = build(x, r if variant != 'no-claim-mask' else [0, 0, 0, 0], rm,
                    s if variant != 'no-mask-rows' else [[0] * COLS] * R)
    out = []
    kappa_on = variant != 'no-claim-mask'
    claims = []
    for rho in ch.rho:
        c = masked_claim(message, rho, kappa_on, rho[:2])
        claims.append(c)
        out.extend(c)
    # A2 certificate row: gamma = eq over (W, row bits).
    gamma = eq_table(ch.certificate)
    for column in range(COLS):
        out.extend(k_dot(gamma, [(message[row][column], 0) for row in range(ROWS)]))
    # Batch: W' = (1 - w) W on the Y = 0 face, over (w, row, col): 1 + 3 + 2 bits.
    weights = [ZERO] * (2 * R * C * 2)  # (w, row(3 bits incl. W? no), ...)
    # Index z = (w, row2, col2) with row in 0..3 data rows of the half, 5 bits.
    values = []
    weight = []
    batched = {}
    for coefficient, rho in zip(ch.gamma, ch.rho):
        for position, w in claim_functional(rho, kappa_on, rho[:2]).items():
            batched[position] = k_add(batched.get(position, ZERO), k_mul(coefficient, w))
    for w_bit in range(2):
        for row in range(R):
            for column in range(C):
                values.append((message[w_bit * R + row][column], 0))
                weight.append(batched.get((row, column), ZERO) if w_bit == 0 else ZERO)
    g_used = g if variant != 'no-sumcheck-mask' else [[ZERO] * 3 for _ in g]
    rounds, mask_sum, mu = batch_rounds(weight, values, g_used, ch.alpha, ch.batch)
    out.extend(mask_sum)
    for evaluations in rounds:
        for e in evaluations:
            out.extend(e)
    out.extend(mu)
    # Opening at (w*, row*) over M' rows and (Y = 0, col*) over columns.
    w_star = ch.batch[0] if variant != 'open-data-face' else ZERO
    a = eq_table([w_star] + ch.batch[1:3])
    for column in range(COLS):
        out.extend(k_dot(a, [(message[row][column], 0) for row in range(ROWS)]))
    # Every queried column of every row.
    for row in range(ROWS):
        codeword = encode(message[row])
        for q in ch.queries:
            out.append(codeword[q])
    return out


def linear_map(ch, variant):
    """Columns of A (secret x) and B (all randomness), as base-field vectors."""
    zero = dict(x=[0] * 8, r=[0] * 4, rm=[[0] * C for _ in range(R)],
                s=[[0] * COLS for _ in range(R)], g=[[ZERO] * 3 for _ in range(5)])

    def run(**changes):
        state = {k: (v if not isinstance(v, list) else [list(e) if isinstance(e, list) else e for e in v])
                 for k, v in zero.items()}
        state.update(changes)
        return view(state['x'], state['r'], state['rm'], state['s'], state['g'], ch, variant)

    a_columns = []
    for i in range(8):
        x = [0] * 8
        x[i] = 1
        a_columns.append(run(x=x))
    b_columns = []
    for j in range(4):
        r = [0] * 4
        r[j] = 1
        b_columns.append(run(r=r))
    for row in range(R):
        for column in range(C):
            rm = [[0] * C for _ in range(R)]
            rm[row][column] = 1
            b_columns.append(run(rm=rm))
    for row in range(R):
        for column in range(COLS):
            s = [[0] * COLS for _ in range(R)]
            s[row][column] = 1
            b_columns.append(run(s=s))
    for i in range(5):
        for t in range(3):
            for coordinate in range(D):
                g = [[ZERO] * 3 for _ in range(5)]
                g[i][t] = (1, 0) if coordinate == 0 else (0, 1)
                b_columns.append(run(g=g))
    transpose = lambda columns: [list(row) for row in zip(*columns)]
    return transpose(a_columns), transpose(b_columns)


def private(ch, variant):
    a, b = linear_map(ch, variant)
    combined = [list(rb) + list(ra) for ra, rb in zip(a, b)]
    return rank(combined, P) == rank(b, P)


def coordinates(values):
    return [[v[0] for v in values], [v[1] for v in values]]


def claim_rank(ch):
    """Lemma 6: rank of the D*t x L coordinates of lambda_a * eq(pi(rho^a))."""
    rows = []
    for rho in ch.rho:
        kappa = k_mul(rho[2], k_sub(ONE, rho[2]))
        rows += coordinates([k_mul(kappa, w) for w in eq_table(rho[:2])])
    return rank(rows, P)


def mask_rank(ch):
    """Lemma 2 (A2 rank check): mask-row coordinates of the certificate and opening."""
    certificate = eq_table(ch.certificate)[R:]
    opening = eq_table([ch.batch[0]] + ch.batch[1:3])[R:]
    return rank(coordinates(certificate) + coordinates(opening), P)


def degenerate(ch):
    """Public abort events of formal/zk-claims.md §3: kappa = 0, w* = 0, alpha = 0,
    and the rank conditions of Lemma 6 (D*t = 4) and Lemma 2 (2D = 4). All depend
    on public challenges only; in this tiny field they are frequent."""
    kappas = [k_mul(rho[2], k_sub(ONE, rho[2])) for rho in ch.rho]
    return (ZERO in kappas or ch.batch[0] == ZERO or ch.alpha == ZERO
            or claim_rank(ch) < D * len(ch.rho) or mask_rank(ch) < 2 * D)


def main():
    rng = random.Random(20261110)
    trials = 60
    counts = {}
    for variant, queries in (('honest', 3), ('no-claim-mask', 3), ('no-mask-rows', 3),
                             ('no-sumcheck-mask', 3), ('open-data-face', 3), ('honest', 5)):
        ok = skipped = 0
        for _ in range(trials):
            ch = Challenges(rng, queries)
            if degenerate(ch):
                skipped += 1
                # The aborts are necessary: on a rank failure the honest view leaks.
                if variant == 'honest' and queries == 3 and (
                        claim_rank(ch) < D * len(ch.rho) or mask_rank(ch) < 2 * D):
                    assert not private(ch, variant), 'rank abort was not needed'
                continue
            ok += private(ch, variant)
        counts[(variant, queries)] = (ok, trials - skipped)
        print(f'{variant:18} |Q|={queries}: private in {ok}/{trials - skipped} draws '
              f'({skipped} public aborts)')
    honest_ok, honest_n = counts[('honest', 3)]
    assert honest_ok == honest_n, 'LEAK: honest dev-zk view is not private'
    for variant in ('no-claim-mask', 'no-mask-rows', 'no-sumcheck-mask', 'open-data-face'):
        assert counts[(variant, 3)][0] == 0, f'control {variant} did not leak'
    assert counts[('honest', 5)][0] < counts[('honest', 5)][1], 'budget control did not leak'
    print('zk-claims view: honest view private in every non-aborting draw; every rank '
          'abort was needed; each removed mask, the data-face opening and an over-budget '
          'query set leak')


if __name__ == '__main__':
    main()
