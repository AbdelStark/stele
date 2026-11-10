"""ZK-GKR exact check: masked inter-layer claims of a two-layer LogUp fraction tree.

Research helper, never protocol authority (formal/zk-gkr.md). The A5 tree layers
are not committed. Each GKR step from layer k to k+1 reveals:
- the masked values `V̇(x*, t) = s_t + κ·r̃(t, x*_u)` of each layer polynomial
  (p and q) at `t ∈ {0, 1}`;
- the next step's selector final `f = r̃(t*, ρ'')`, a claim on the committed mask
  block, batched with the others.

Secrets are the true layer values `s_t`, treated as free (more freedom than the
real nonlinear tree). Each layer polynomial has one mask block of 8 entries with
coordinates `(T, u1, u2)` in a committed hiding source. The source adds the A2
certificate, the zero-weight batch of the `f` claims with a Lemma 4 mask, the
opening row and the queried columns. Privacy is exactly rank([B A]) == rank(B).
"""
from pathlib import Path
import random
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from check_two import (P, D, R, C, ROWS, COLS, ZERO, ONE, add, mul, base, dot, eq, kappa,
                       encode, batch_rounds, rk, rank, DOMAIN)

BLOCKS = 4  # two layers x (p, q)
BLOCK = 8   # coordinates (T, u1, u2)
BATCH_VARS = 1 + 2 + 4


def layout(j):
    """Mask entry j of the flat block area -> (data row, column)."""
    return divmod(j, C)


class Challenges:
    def __init__(self, rng, queries):
        # Per block: the step point x* (vanishing coordinate v, mask coordinates u),
        # the line challenge t* and the next step's selector point rho''.
        self.v = [rk(rng) for _ in range(BLOCKS)]
        self.u = [[rk(rng), rk(rng)] for _ in range(BLOCKS)]
        self.t_star = [rk(rng) for _ in range(BLOCKS)]
        self.next = [[rk(rng), rk(rng)] for _ in range(BLOCKS)]
        self.gamma = [rk(rng) for _ in range(BLOCKS)]
        self.certificate = [rk(rng) for _ in range(3)]
        self.alpha = rk(rng)
        self.batch = [rk(rng) for _ in range(BATCH_VARS)]
        self.queries = rng.sample(range(len(DOMAIN)), queries)


def functionals(ch, b, variant):
    """The K weights on block b's 8 entries of the three revealed functionals."""
    lam = kappa(ch.v[b])
    if variant == 'small-block':
        # (T, u1) only: 4 entries carry three K functionals.
        f0 = [mul(lam, w) for w in eq([base(0), ch.u[b][0]])] + [ZERO] * 4
        f1 = [mul(lam, w) for w in eq([base(1), ch.u[b][0]])] + [ZERO] * 4
        fn = eq([ch.t_star[b], ch.next[b][0]]) + [ZERO] * 4
        return f0, f1, fn
    t0, t1 = (base(0), base(1)) if variant != 'shared-t' else (base(0), base(0))
    f0 = [mul(lam, w) for w in eq([t0] + ch.u[b])]
    f1 = [mul(lam, w) for w in eq([t1] + ch.u[b])]
    fn = eq([ch.t_star[b]] + ch.next[b])
    return f0, f1, fn


def view(secret, masks, rm, s, g, ch, variant):
    if variant == 'no-mask':
        masks = [0] * len(masks)
    if variant == 'no-mask-rows':
        s = [[0] * COLS for _ in range(R)]
    data = [[0] * C for _ in range(R)]
    for j, v in enumerate(masks):
        row, column = layout(j)
        data[row][column] = v
    message = [data[row] + rm[row] for row in range(R)] + [list(s[row]) for row in range(R)]
    out = []
    claims = []
    for b in range(BLOCKS):
        f0, f1, fn = functionals(ch, b, variant)
        block = [base(message[layout(b * BLOCK + j)[0]][layout(b * BLOCK + j)[1]])
                 for j in range(BLOCK)]
        for t, weights in enumerate((f0, f1)):
            value = add(secret[b][t], dot(weights, block))
            out.extend(value)
        out.extend(dot(fn, block))
        claims.append({layout(b * BLOCK + j): fn[j] for j in range(BLOCK)})
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
    rounds, mask_sum, mu = batch_rounds(weight, values, g, ch.alpha, ch.batch)
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


def zero():
    return dict(secret=[[ZERO, ZERO] for _ in range(BLOCKS)], masks=[0] * (BLOCKS * BLOCK),
                rm=[[0] * C for _ in range(R)], s=[[0] * COLS for _ in range(R)],
                g=[[ZERO] * 3 for _ in range(BATCH_VARS)])


def private(ch, variant):
    def run(state):
        return view(state['secret'], state['masks'], state['rm'], state['s'], state['g'],
                    ch, variant)

    a, b = [], []
    for block in range(BLOCKS):
        for t in range(2):
            for coordinate in range(D):
                state = zero()
                state['secret'][block][t] = (1, 0) if coordinate == 0 else (0, 1)
                a.append(run(state))
    for j in range(BLOCKS * BLOCK):
        state = zero()
        state['masks'][j] = 1
        b.append(run(state))
    for row in range(R):
        for column in range(C):
            state = zero()
            state['rm'][row][column] = 1
            b.append(run(state))
    for row in range(R):
        for column in range(COLS):
            state = zero()
            state['s'][row][column] = 1
            b.append(run(state))
    for index in range(BATCH_VARS):
        for t in range(3):
            for coordinate in range(D):
                state = zero()
                state['g'][index][t] = (1, 0) if coordinate == 0 else (0, 1)
                b.append(run(state))
    a, b = [list(r) for r in zip(*a)], [list(r) for r in zip(*b)]
    return rank([rb + ra for ra, rb in zip(a, b)], P) == rank(b, P)


def aborts(ch):
    coordinates = lambda vs: [[v[0] for v in vs], [v[1] for v in vs]]
    for b in range(BLOCKS):
        if kappa(ch.v[b]) == ZERO:
            return True
        f0, f1, fn = functionals(ch, b, 'honest')
        if rank(coordinates(f0) + coordinates(f1) + coordinates(fn), P) < 3 * D:
            return True
    certificate = eq(ch.certificate)[R:]
    opening = eq([ch.batch[0]] + ch.batch[1:3])[R:]
    if rank(coordinates(certificate) + coordinates(opening), P) < 2 * D:
        return True
    return ch.batch[0] == ZERO or ch.alpha == ZERO


def main():
    rng = random.Random(20261112)
    trials = 10
    results = {}
    for variant in ('honest', 'no-mask', 'no-mask-rows', 'shared-t', 'small-block'):
        ok = n = 0
        while n < trials:
            ch = Challenges(rng, 6)
            if aborts(ch):
                continue
            n += 1
            ok += private(ch, variant)
        results[variant] = ok
        print(f'{variant:13}: private in {ok}/{trials} non-aborting draws')
    assert results['honest'] == trials, 'LEAK: honest ZK-GKR view is not private'
    for variant in ('no-mask', 'no-mask-rows', 'shared-t', 'small-block'):
        assert results[variant] == 0, f'control {variant} did not leak'
    print('zk-gkr: masked inter-layer claims private; removing masks or mask rows, '
          'sharing the t-blocks or shrinking the block leaks')


if __name__ == '__main__':
    main()
