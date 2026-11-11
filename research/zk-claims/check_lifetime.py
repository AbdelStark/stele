"""Exact small-field check of RFC-0013 A6 item 6 (P+1 revealed rows).

Toy: F_p, K = F_p[i]/(i^2 - NR) (D = 2). Source M' = [X | Rm ; S0 | S1], 2R x 2C,
RS-encoded (monomial basis) at n points. View: limbs of a^T M' for the
certificate and P openings, full codeword columns at Q (|Q| = q_c + P*q_o),
and P claim finals v_j = <eq(r_j), W> + kappa_j <eq(u_j), B_j>.
W hidden  <=>  span(V_W) subset span(V_rand) (random = blocks, Rm, S0, S1).
"""
import random, itertools, sys

p, NR, D = 61, 2, 2


def kmul(a, b):
    return ((a[0] * b[0] + NR * a[1] * b[1]) % p, (a[0] * b[1] + a[1] * b[0]) % p)


def krand():
    return (random.randrange(p), random.randrange(p))


def eq_table(pt):
    t = [(1, 0)]
    for r in pt:
        one_minus = ((1 - r[0]) % p, (-r[1]) % p)
        t = [kmul(x, one_minus) for x in t] + [kmul(x, r) for x in t]
    return t


def rank(rows):
    rows = [r[:] for r in rows]
    rk, ncol = 0, len(rows[0]) if rows else 0
    for c in range(ncol):
        piv = next((i for i in range(rk, len(rows)) if rows[i][c]), None)
        if piv is None:
            continue
        rows[rk], rows[piv] = rows[piv], rows[rk]
        inv = pow(rows[rk][c], p - 2, p)
        rows[rk] = [x * inv % p for x in rows[rk]]
        for i in range(len(rows)):
            if i != rk and rows[i][c]:
                f = rows[i][c]
                rows[i] = [(x - f * y) % p for x, y in zip(rows[i], rows[rk])]
        rk += 1
    return rk


def run(ell, logc, P, qc, qo, reuse=False, extra_open=0, dup_cert=True, extra_q=0):
    R, C = 1 << ell, 1 << logc
    rows2, cols2 = 2 * R, 2 * C
    nvar = rows2 * cols2
    var = lambda r, c: r * cols2 + c  # M' entry index
    # blocks: last P*D entries of X (row-major in data part), weights the rest
    xpos = [var(r, c) for r in range(R) for c in range(C)]
    block_pos = [xpos[len(xpos) - P * D + j * D: len(xpos) - P * D + (j + 1) * D] for j in range(P)]
    wpos = xpos[: len(xpos) - P * D]
    V = []
    # revealed row functionals: certificate + openings
    cert = eq_table([krand() for _ in range(ell + 1)])
    funcs = [cert] * (P if dup_cert else 1)
    nopen = P + extra_open
    for _ in range(nopen):
        funcs.append(eq_table([krand() for _ in range(ell + 1)]))
    for a in funcs:
        for d in range(D):
            for c in range(cols2):
                row = [0] * nvar
                for r in range(rows2):
                    row[var(r, c)] = a[r][d]
                V.append(row)
    # queried codeword columns
    pts = random.sample(range(1, p), 4 * C)
    nq = qc + P * qo + extra_q
    for x in pts[:nq]:
        for r in range(rows2):
            row = [0] * nvar
            for c in range(cols2):
                row[var(r, c)] = pow(x, c, p)
            V.append(row)
    # claim finals, one block per proof (reuse: proof P-1 reuses block 0)
    for j in range(P):
        blk = block_pos[0 if (reuse and j == P - 1) else j]
        w = eq_table([krand() for _ in range(ell + logc)])[: len(wpos)]
        u = eq_table([krand() for _ in range(1)])  # D = 2 block entries
        kap = krand()
        for d in range(D):
            row = [0] * nvar
            for i, pos in enumerate(wpos):
                row[pos] = w[i][d]
            for e, pos in enumerate(blk):
                row[pos] = kmul(kap, u[e])[d]
            V.append(row)
    rand_cols = [i for i in range(nvar) if i not in set(wpos)]
    Vr = [[row[i] for i in rand_cols] for row in V]
    Vall = [[row[i] for i in rand_cols] + [row[i] for i in wpos] for row in V]
    # also check A2's rank condition on mask rows
    A = [[f[r][d] for r in range(R, rows2)] for f in funcs[-(nopen + 1):] for d in range(D)]
    full = rank(A) == len(A)
    return rank(Vr) == rank(Vall), full


random.seed(int(sys.argv[1]) if len(sys.argv) > 1 else 1)
cases = [
    ("P=1 (A2 baseline)", dict(ell=2, logc=3, P=1, qc=1, qo=2)),
    ("P=3, R=(P+1)D, cert repeated", dict(ell=3, logc=3, P=3, qc=1, qo=2)),
    ("P=3, cert once", dict(ell=3, logc=3, P=3, qc=1, qo=2, dup_cert=False)),
    ("P=3, index reuse (block 0 twice)", dict(ell=3, logc=3, P=3, qc=1, qo=2, reuse=True)),
    ("P=3, one opening past rank budget", dict(ell=3, logc=3, P=3, qc=1, qo=2, extra_open=1)),
    ("P=3, queries = C (budget C-1 exceeded)", dict(ell=3, logc=3, P=3, qc=1, qo=2, extra_q=1)),
    ("P=3, queries = C+1", dict(ell=3, logc=3, P=3, qc=1, qo=2, extra_q=2)),
]
# Expected outcomes (RFC-0013 A6): within budget the weights stay hidden; index
# reuse, an opening past the rank budget, or C + 1 queries expose them. At
# exactly C queries hiding fails for some draws, so no outcome is asserted there.
expect = [True, True, True, False, False, None, False]
failed = False
for (name, kw), hidden in zip(cases, expect):
    res = [run(**kw) for _ in range(5)]
    print(f"{name:42s} hidden={[h for h, _ in res]} maskrank_full={[f for _, f in res]}")
    if hidden is not None and any(h != hidden for h, _ in res):
        print(f"  UNEXPECTED: {name} should give hidden={hidden}")
        failed = True
sys.exit(1 if failed else 0)
