#!/usr/bin/env python3
"""Q12 study: FS-aware PCS query counts, grinding and the stories42M proof size.

Governing note: formal/fs-composition.md (Theorem 1, Lemmas 2-6, condition A17).
Exact integer/Fraction arithmetic decides everything; floats are printed for reading only.
Inputs are the recorded stories42M development proof's PCS inventory and RFC-0026 §6 ledger
(stories42m-inventory.jsonl, stories42m-ledger.tsv; proof SHA-256 507b52b3...5381, commit e813ce1).

  python3 research/fs-pcs/study.py            # report tables (PARAMETERS.md reproduces them)
  python3 research/fs-pcs/study.py --check    # exact self-checks and pinned receipts
"""
from fractions import Fraction
import json
import math
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
P = 2**31 - 1
SETUP = Fraction(200431782, 2**160)  # RFC-0012 A7, once per ledger with a v2 source J>=4
# Profile parameters (formal/fs-composition.md §5): lambda, |K|, slack g, query grinding k_q.
PROFILES = {'standard': (100, P**4, 8, 16), 'treaty': (128, P**8, 8, 16)}
RECORDED_PROOF = 113422913


def log2(x):
    """Reading aid only."""
    x = Fraction(x)
    return math.log2(x.numerator) - math.log2(x.denominator)


# ---- codes (RFC-0010 A2 and A3 item 3) -----------------------------------------------------
def circle(m, b):
    c, n = 2**m, 2**(m + b)
    return {'code': f'circle(m={m},b={b})', 'C': c, 'N': n, 'D': n if c == 1 else n - c, 'v2': False}


def v2(j):
    k = 4**j
    return {'code': f'v2(J={j})', 'C': k, 'N': 2 * k, 'D': 64 if j == 3 else k // 25 + 1, 'v2': j >= 4}


def radius(code):
    return (code['D'] - 1) // 3


# ---- Policy 2 (RFC-0010 A14) ----------------------------------------------------------------
def least_q(n, miss, bits, cap=1 << 16):
    """Least q>=1 with 2^bits * miss^q <= n^q (exact). bits<=0 gives q=1."""
    if bits <= 0:
        return 1
    lhs, rhs = 2**bits, 1
    for q in range(1, cap + 1):
        lhs *= miss
        rhs *= n
        if lhs <= rhs:
            return q
    raise ValueError('UnsupportedParameters: query cap exceeded')


def counts(code, bits):
    n, d, e = code['N'], code['D'], radius(code)
    return least_q(n, n - e - 1, bits), least_q(n, n - d + e, bits)


def grind_bits(err, target_bits):
    """Least k>=0 with err * 2^-k <= 2^-target_bits (exact; err a Fraction)."""
    k = 0
    while err * 2**target_bits > 2**k:
        k += 1
    return k


def tensor_err(code, rows, field):
    """Certificate row-weight round, Diamond-Posen Theorem 2: 2*ell*(e+1)/|K|."""
    return Fraction(2 * (rows.bit_length() - 1) * (radius(code) + 1), field)


def query_err(code, q, kind):
    n, d, e = code['N'], code['D'], radius(code)
    miss = n - e - 1 if kind == 'certificate' else n - d + e
    return Fraction(miss, n) ** q


def proof_bytes(code, rows, q, degree, nonce):
    """stele-pcs Source::proof_size, plus one u64 nonce when the column round grinds."""
    stride = 4 * rows + 32 * (code['N'].bit_length() - 1)
    return 1 + 4 * degree * code['C'] + q * stride + (8 if nonce else 0)


def load():
    inv = [json.loads(line) for line in (HERE / 'stories42m-inventory.jsonl').read_text().splitlines()]
    ledger = []
    for line in (HERE / 'stories42m-ledger.tsv').read_text().splitlines():
        kind, name, term = line.split('\t')
        ledger.append((kind, name, int(term.split('/')[0])))
    return inv, ledger


def recorded_code(rec):
    return {'code': 'v2 (recorded J)', 'C': rec['columns'], 'N': rec['length'], 'D': rec['distance'],
            'v2': rec['code'] == 'v2' and rec['columns'] >= 256}


def best_split(bits, family, qbits, degree, nonce):
    """Shape minimizing certificate+opening bytes for a 2^bits message (A3 item 2, A9 §1 ranges)."""
    if family == 'v2':
        cands = [v2(j) for j in range(3, 15) if 2 * j <= bits and bits - 2 * j <= 30]
    else:
        b = 1 if family == 'circle1' else 2
        cands = [circle(m, b) for m in range(0, 30 - b + 1) if m <= bits and bits - m <= 30]
    best = None
    for code in cands:
        rows = 2**bits // code['C']
        qc, qo = counts(code, qbits)
        size = proof_bytes(code, rows, qc, degree, nonce) + proof_bytes(code, rows, qo, degree, nonce)
        if best is None or size < best[0]:
            best = (size, code, rows, qc, qo)
    return best[1:]


def configure(inv, family, profile):
    """Sources of the stories42M statement under one policy: (role, code, rows, q_c, q_o)."""
    lam, field, g, kq = PROFILES[profile]
    degree = 4 if field == P**4 else 8
    qbits = lam + g - kq
    v2_certs = [r for r in inv if r['code'] == 'v2' and r['kind'] == 'certificate']
    sources = []
    for role, rec in (('model', v2_certs[0]), ('stack', v2_certs[1])):
        if family == 'policy1':
            qo = next(r['queries'] for r in inv if r['kind'] == 'opening' and r['rows'] == rec['rows']
                      and r['columns'] == rec['columns'])
            sources.append((role, recorded_code(rec), rec['rows'], rec['queries'], qo))
        else:
            bits = (rec['rows'] * rec['columns']).bit_length() - 1
            code, rows, qc, qo = best_split(bits, family, qbits, degree, True)
            sources.append((role, code, rows, qc, qo))
    for r in inv:  # multiplicity sources keep A5's Circle rate-1/2 shape
        if r['code'] == 'circle' and r['kind'] == 'certificate':
            code = circle(r['columns'].bit_length() - 1, 1)
            assert (code['N'], code['D']) == (r['length'], r['distance'])
            qc, qo = (r['queries'], None) if family == 'policy1' else counts(code, qbits)
            sources.append(('mu', code, r['rows'], qc, qo))
    return sources


def price(inv, family, profile):
    """Proof bytes (public model certificate excluded) and the model certificate bytes."""
    _, field, _, _ = PROFILES[profile]
    degree = 4 if field == P**4 else 8
    nonce = family != 'policy1'
    sources = configure(inv, family, profile)
    pcs_recorded = sum(r['bytes'] for r in inv) - inv[0]['bytes']
    non_pcs = RECORDED_PROOF - pcs_recorded
    total, model_cert = non_pcs, 0
    mu_cert = [r for r in inv if r['code'] == 'circle' and r['kind'] == 'certificate']
    mu_open = [r for r in inv if r['code'] == 'circle' and r['kind'] == 'opening']
    for role, code, rows, qc, qo in sources:
        if role == 'model':
            model_cert = proof_bytes(code, rows, qc, degree, nonce)
            total += proof_bytes(code, rows, qo, degree, nonce)
        elif role == 'stack':
            total += proof_bytes(code, rows, qc, degree, nonce) + proof_bytes(code, rows, qo, degree, nonce)
    # Multiplicity certificates/openings: recorded bytes with the query count replaced (rows stay QM31-sized).
    for r in mu_cert + mu_open:
        code = circle(r['columns'].bit_length() - 1, 1)
        if family == 'policy1':
            total += r['bytes']
            continue
        lam, field, g, kq = PROFILES[profile]
        qc, qo = counts(code, lam + g - kq)
        q = qc if r['kind'] == 'certificate' else qo
        total += r['bytes'] + (q - r['queries']) * (4 * r['rows'] + 32 * (code['N'].bit_length() - 1)) + 8
    return total, model_cert, non_pcs


def lu_round_numerator(name, num):
    """One (beta, alpha) round (Lemma 4): the recorded numerator itself.

    Since E16-32 (RFC-0026 A13) the verifier records c*(N+t)-1, A17 item 3's round numerator,
    for every check; before it recorded N+c*t-1, exact only for c=1.
    """
    return num


def rounds(inv, ledger, family, profile):
    """Every FS round of one stories42M verification with its exact error and grinding bits.

    Per-round bounds (formal/fs-composition.md §4): SC records are sums of their per-round terms
    (Lemma 2) and enter the floor as sums; RLC and SZ entries are single rounds; each LU check is one
    (beta, alpha) round (Lemma 4); PCS tensor and column rounds per certificate and opening. Grinding
    applies to LU, PCS tensor and PCS column rounds only (A17). Entries: (family, error, bits, where)
    with where = 'public' for the one-time model certificate, else 'proof'.
    """
    lam, field, g, kq = PROFILES[profile]
    target = lam + g
    ground = family != 'policy1'
    out = []
    sc_total = sum(n for kind, _, n in ledger if kind == 'Sc')
    out.append(('SC (sum of records)', Fraction(sc_total, field), 0, 'proof'))
    for kind, name, num in ledger:
        if kind in ('Rlc', 'Sz'):
            out.append((kind.upper(), Fraction(num, field), 0, 'proof'))
        elif kind == 'Lu':
            err = Fraction(lu_round_numerator(name, num), field)
            out.append(('LU', err, grind_bits(err, target) if ground else 0, 'proof'))
    k = kq if ground else 0
    for role, code, rows, qc, qo in configure(inv, family, profile):
        where = 'public' if role == 'model' else 'proof'
        terr = tensor_err(code, rows, field)
        out.append(('PCS tensor', terr, grind_bits(terr, target) if ground else 0, where))
        out.append(('PCS column', query_err(code, qc, 'certificate'), k, where))
        if role in ('model', 'stack'):
            out.append(('PCS column', query_err(code, qo, 'opening'), k, 'proof'))
    for r in inv:
        if r['code'] == 'circle' and r['kind'] == 'opening':
            code = circle(r['columns'].bit_length() - 1, 1)
            q = r['queries'] if not ground else counts(code, lam + g - kq)[1]
            out.append(('PCS column', query_err(code, q, 'opening'), k, 'proof'))
    setup = any(s[1]['v2'] for s in configure(inv, family, profile))
    return out, setup


def admission(inv, ledger, family, profile):
    """(C1) worst single round and (C2) floor; C3/C4 are not computed here (not an admission)."""
    lam, field, g, kq = PROFILES[profile]
    rs, setup = rounds(inv, ledger, family, profile)
    worst = max(err / 2**k for fam, err, k, _ in rs if not fam.startswith('SC'))
    # Every SC round is at most its record's sum (Lemma 2), so the largest record bounds C1 for SC.
    worst = max(worst, Fraction(max(n for kind, _, n in ledger if kind == 'Sc'), field))
    floor = sum(err / 2**k for _f, err, k, _w in rs) + (SETUP if setup else 0)
    grind = sum(2**k for _f, _e, k, w in rs if k and w == 'proof')
    nonces = sum(1 for f, _e, k, w in rs if k and w == 'proof' and f != 'PCS column')
    c1 = worst * 2**(lam + g) <= 1
    c2 = floor * 2**lam <= 1
    return worst, floor, grind, c1, c2, nonces


def table(bits):
    """Compact Policy-2 tables: ranges of m (Circle) or J (v2) with equal (q_c, q_o)."""
    out = []
    for b in (1, 2):
        runs = []
        for m in range(0, 30 - b + 1):
            qc, qo = counts(circle(m, b), bits)
            if runs and runs[-1][2:] == [qc, qo]:
                runs[-1][1] = m
            else:
                runs.append([m, m, qc, qo])
        out.append((f'Circle b={b}', runs))
    runs = []
    for j in range(3, 15):
        qc, qo = counts(v2(j), bits)
        if runs and runs[-1][2:] == [qc, qo]:
            runs[-1][1] = j
        else:
            runs.append([j, j, qc, qo])
    out.append(('v2 J', runs))
    return out


def report():
    inv, ledger = load()
    for profile, (lam, field, g, kq) in PROFILES.items():
        qbits = lam + g - kq
        print(f'## {profile}: lambda={lam}, |K|=p^{4 if field == P**4 else 8}, g={g}, k_q={kq}, '
              f'column target 2^-{qbits} before grinding\n')
        print('| code | index range | q_c | q_o |')
        print('|---|---|---:|---:|')
        for name, runs in table(qbits):
            for lo, hi, qc, qo in runs:
                print(f'| {name} | {lo}..{hi} | {qc} | {qo} |')
        print()
    print('## stories42M development statement re-priced (proof excludes the public model certificate)\n')
    print('| policy | profile rule | stack | q_c/q_o | model | q_c/q_o | proof bytes | model cert | '
          'worst round | floor | per-proof grind hashes | C1 | C2 |')
    print('|---|---|---|---|---|---|---:|---:|---:|---:|---:|---|---|')
    for family, profile in (('policy1', 'standard'), ('v2', 'standard'), ('circle1', 'standard'),
                            ('circle2', 'standard'), ('v2', 'treaty'), ('circle2', 'treaty')):
        srcs = {s[0]: s for s in configure(inv, family, profile)}
        proof, mcert, _ = price(inv, family, profile)
        worst, floor, grind, c1, c2, nonces = admission(inv, ledger, family, profile)
        proof += 8 * nonces  # LU and tensor nonces; column-round nonces are priced in price()
        st, mo = srcs['stack'], srcs['model']
        print(f"| {family} | {profile} | {st[1]['code']} R={st[2]} | {st[3]}/{st[4]} | {mo[1]['code']} R={mo[2]} "
              f"| {mo[3]}/{mo[4]} | {proof:,} | {mcert:,} | 2^{log2(worst):.1f} | 2^{log2(floor):.1f} "
              f"| {grind:,} | {'pass' if c1 else 'FAIL'} | {'pass' if c2 else 'FAIL'} |")
    print('\nTreaty rows: OM31 for stack/model rows only; multiplicity rows, non-PCS bytes and the')
    print('LU/SC numerators are carried at their recorded QM31 values over p^8. Counts only; not admitted.')
    print('Policy 1 is evaluated under the standard rule with no grinding, for comparison.')


def check():
    inv, ledger = load()
    proof, mcert, non_pcs = price(inv, 'policy1', 'standard')
    assert (proof, mcert, non_pcs) == (113422913, 26175713, 994394), (proof, mcert, non_pcs)
    for r in inv:  # the size model and Policy 1 (target 130, no grinding) reproduce every record
        code = recorded_code(r)
        assert proof_bytes(code, r['rows'], r['queries'], 4, False) == r['bytes'], r
        qc, qo = counts(code, 130)
        assert r['queries'] == (qc if r['kind'] == 'certificate' else qo), r
    for bits in {lam + g - kq for lam, _, g, kq in PROFILES.values()}:
        for code in [circle(m, b) for b in (1, 2) for m in range(0, 31 - b)] + [v2(j) for j in range(3, 15)]:
            n, d, e = code['N'], code['D'], radius(code)
            qc, qo = counts(code, bits)
            for q, miss in ((qc, n - e - 1), (qo, n - d + e)):
                assert 2**bits * miss**q <= n**q
                assert q == 1 or 2**bits * miss**(q - 1) > n**(q - 1)
    std = admission(inv, ledger, 'circle2', 'standard')
    assert std[3] and std[4], std
    assert price(inv, 'circle2', 'standard')[0] + 8 * std[5] == 18325537
    v2s = admission(inv, ledger, 'v2', 'standard')
    assert v2s[3] and v2s[4], v2s
    p1 = admission(inv, ledger, 'policy1', 'standard')
    assert not p1[3], p1  # Policy 1 fails the per-round rule (its LU round alone is 2^-97)
    assert counts(circle(17, 2), 92) == (222, 92) and counts(v2(10), 92) == (9533, 4751)
    print('fs-pcs study: Policy 1 size model exact (113422913 proof bytes, 48 PCS records); '
          'Policy 2 least counts verified for all 59 Circle and 12 v2 identities at 92 and 120 bits; '
          'stories42M standard admission passes C1/C2 for v2 and Circle rate 1/4; '
          'Circle rate 1/4 proof 18325537 bytes')


if __name__ == '__main__':
    check() if '--check' in sys.argv else report()
