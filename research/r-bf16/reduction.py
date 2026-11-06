"""RFC-0019 R-BF16 (task E15-04): one exact serving-arithmetic accumulation step as M31 constraints.

Research prototype; nothing in crates/ imports it. Integer arithmetic only.
Step semantics (the cheapest well-defined "exact bf16 serving" rule, an FMA chain):

    s_out = RN_binary32(s_in + a * b)      a, b bfloat16; product exact; RN = round half to even

State: binary32 accumulator as (sign, m, e) with value (-1)^sign * m * 2^e, where either
m in [2^23, 2^24) and e in [-149, 104] (normal), or e = -149 and m < 2^23 (zero/subnormal).
Overflow to infinity is outside the statement: the checker rejects it.
bfloat16 inputs are pre-decoded (sign, m, e) with m < 2^8, e in [-133, 120]; decoding is per
tensor element, not per multiply-accumulate (MAC), so it is excluded from the per-MAC count.

The checker evaluates every identity in M31 and every range/table constraint on canonical
representatives, and counts: lookups (one per table row consumed), committed elements (witness
values that are not low-degree polynomials of earlier values, plus range limbs), and identities.
"""
from collections import Counter

P = 2**31 - 1
FLOOR = -149          # exponent of the binary32 subnormal grid
EMAX = 104            # largest finite binary32 ulp exponent: (2^24 - 1) * 2^104 < 2^128
GUARD = 3             # guard + round bits kept from the smaller operand (sticky is one more)
CAP = 27              # shift cap: for d >= 27 the truncated lo operand is 0 (m_lo * 8 < 2^27)
KPLUS = 5             # max right shift during rounding: |T| < 2^29, m0 >= 2^23
KMINUS = 24           # max left shift (exact cancellation): |T| >= 1, m0 < 2^24


def norm_row(mp):
    """T_norm[mp] = (2^k, k, zero) with mp * 2^k in [2^23, 2^24); zero products map to (1, 0, 1)."""
    if mp == 0:
        return 1, 0, 1
    k = 23 - (mp.bit_length() - 1)
    return 2**k, k, 0


NORM = {mp: norm_row(mp) for mp in range(255 * 255 + 1)}           # 65,026 rows, mp = m_a * m_b
SHIFT = {j: (2**j, 2**(CAP - j)) for j in range(CAP + 1)}           # (2^j, 2^(27-j))
SHIFT_INDEX = {v[0]: j for j, v in SHIFT.items()}
UP = {j: 2**j for j in range(KPLUS + 1)}                            # right shift 2^k+
DOWN = {j: (2**j, 2**29 if j == 0 else 2**(24 - j)) for j in range(KMINUS + 1)}  # (2^k-, |T| bound)


def bit(x):
    return x in (0, 1)


class Reject(Exception):
    pass


class Meter:
    """Counts per-MAC work. Range checks use 16-bit limb lookups; > 16 bits commits the limbs."""

    def __init__(self, skip=()):
        self.c = Counter()
        self.skip = skip                  # constraint reasons left unenforced (necessity controls only)

    def fail(self, why):
        if why not in self.skip:
            raise Reject(why)

    def eq(self, lhs, rhs, why):
        self.c['identities'] += 1
        if (lhs - rhs) % P:
            self.fail(why)

    def range(self, x, bits, why):
        limbs = -(-bits // 16)
        self.c['lookups'] += limbs
        if limbs > 1:
            self.c['committed'] += limbs
        if x % P >= 2**bits:
            self.fail(why)

    def table(self, table, key, row, why):
        self.c['lookups'] += 1
        if key % P not in table or table[key % P] != row:
            self.fail(why)

    def commit(self, n=1):
        self.c['committed'] += n


def honest(state, a, b, **forge):
    """Prover: the witness for one step, mirroring check()'s virtual formulas.

    `forge` (controls only) replaces any committed value; everything downstream is recomputed from
    it, so a forgery is consistent everywhere except where the constraints pin the forged value.
    """
    F = forge.get
    ss, ms, es = state
    sa, ma, ea = a
    sb, mb, eb = b
    sp, mp, ep = sa ^ sb, ma * mb, ea + eb
    pk, kp, zp = NORM[mp]
    pk, kp, zp = F('pk', pk), F('kp', kp), F('zp', zp)
    mq, eq = mp * pk, zp * FLOOR + (1 - zp) * (ep - kp)
    g = F('g', int(es >= eq))
    pick = lambda x, y: g * x + (1 - g) * y
    shi, mhi, ehi, slo, mlo = pick(ss, sp), pick(ms, mq), pick(es, eq), pick(sp, ss), pick(mq, ms)
    d = g * (es - eq) - (1 - g) * (es - eq)
    c = F('c', int(d >= CAP))
    D, Dc = SHIFT.get((c * CAP + (1 - c) * d) % P, (1, 1))
    D, Dc = F('D', D), F('Dc', Dc)
    q = F('q', mlo * 2**GUARD // D if D else 0)
    rem = F('rem', mlo * 2**GUARD - q * D)
    sticky = F('sticky', int(rem % P != 0))
    inv = F('inv', pow(rem, P - 2, P) if rem % P and sticky == 1 else 0)
    T = (16 * mhi + (1 - 2 * (shi + slo - 2 * shi * slo)) * (2 * q + sticky)) % P
    t = F('t', int(T > P // 2))
    A = (1 - 2 * t) * T % P
    zt = F('zt', int(A == 0))
    invt = F('invt', pow(A, P - 2, P) if A and zt != 1 else 0)
    natural = ehi - 4 + A.bit_length() - 24           # value ~ A * 2^(ehi-4); rounding ulp 2^r
    f = F('f', int(zt == 1 or natural <= FLOOR))
    r = ehi - 4 if zt == 1 else FLOOR if f == 1 else max(natural, FLOOR + 1)
    k = r - (ehi - 4)
    kplus, kminus = F('kplus', max(k, 0)), F('kminus', max(-k, 0))
    Pup = F('Pup', UP.get(kplus % P, 1))
    Pdn, Tb = DOWN.get(kminus % P, (1, 1))
    Pdn, Tb = F('Pdn', Pdn), F('Tb', Tb)
    up_pow, down_pow = Pup, Pdn
    m0 = F('m0', A * down_pow % P // up_pow if up_pow else 0)
    rem2 = F('rem2', A * down_pow % P - m0 * up_pow)
    b0 = F('b0', m0 % 2)
    up = F('up', int(2 * rem2 - up_pow + b0 >= 1))
    gap = (m0 + up - 2**24) % P
    c2 = F('c2', int(gap == 0))
    inv2 = F('inv2', pow(gap, P - 2, P) if gap and c2 != 1 else 0)
    return dict(pk=pk, kp=kp, zp=zp, g=g, c=c, D=D, Dc=Dc, q=q, rem=rem, sticky=sticky, inv=inv,
                t=t, zt=zt, invt=invt, f=f, kplus=kplus, kminus=kminus, Pup=Pup, Pdn=Pdn, Tb=Tb,
                m0=m0, rem2=rem2, b0=b0, up=up, c2=c2, inv2=inv2, _A=A)   # _A: prover-side only


COMMITTED = ('pk', 'kp', 'zp', 'g', 'c', 'D', 'Dc', 'q', 'rem', 'sticky', 'inv', 't', 'zt', 'invt',
             'f', 'kplus', 'kminus', 'Pup', 'Pdn', 'Tb', 'm0', 'rem2', 'b0', 'up', 'c2', 'inv2')


def check(state, a, b, w, meter=None):
    """Verifier of one step: returns the output state or raises Reject. Field arithmetic only."""
    M = meter or Meter()
    M.commit(len(COMMITTED))
    ss, ms, es = state
    sa, ma, ea = a
    sb, mb, eb = b
    for name in ('zp', 'g', 'c', 'sticky', 't', 'zt', 'f', 'b0', 'up', 'c2'):
        M.eq(w[name] * (1 - w[name]), 0, f'{name} is not a bit')
    # product (virtual): sign xor, exact significand product, exponent sum
    sp = sa + sb - 2 * sa * sb
    mp, ep = ma * mb, ea + eb
    M.table(NORM, mp, (w['pk'], w['kp'], w['zp']), 'product normalisation row')
    mq = mp * w['pk']
    eq = w['zp'] * FLOOR + (1 - w['zp']) * (ep - w['kp'])
    # order: g = [e_s >= e_q]. No range check is needed: a wrong g makes the shift d negative, which
    # the cap check (c = 1) or the shift table (c = 0, keys 0..27) rejects; at d = 0 both orders agree.
    g = w['g']
    delta = es - eq
    pick = lambda x, y: g * x + (1 - g) * y
    shi, mhi, ehi = pick(ss, sp), pick(ms, mq), pick(es, eq)
    slo, mlo = pick(sp, ss), pick(mq, ms)
    d = g * delta - (1 - g) * delta
    c = w['c']
    M.range(c * (d - CAP) + (1 - c) * (CAP - 1 - d), 16, 'shift cap')
    dc = c * CAP + (1 - c) * d
    M.table(SHIFT, dc, (w['D'], w['Dc']), 'shift row')
    # lo * 8 = q * D + rem with rem in [0, D), q in [0, 2^27 / D): both sides < 2^28 < P
    q, rem = w['q'], w['rem']
    M.range(rem, 27, 'rem >= 0')
    M.range(w['D'] - 1 - rem, 27, 'rem < D')
    M.range(q, 27, 'q >= 0')
    M.range(w['Dc'] - 1 - q, 27, 'q < 2^27 / D')
    M.eq(mlo * 2**GUARD, q * w['D'] + rem, 'aligned division')
    # sticky = [rem != 0]
    M.eq(rem * w['inv'], w['sticky'], 'sticky inverse')
    M.eq(rem * (1 - w['sticky']), 0, 'sticky zero')
    # signed sum at scale 2^(ehi - 4); |T| < 2^29
    sgn = 1 - 2 * (shi + slo - 2 * shi * slo)
    T = 16 * mhi + sgn * (2 * q + w['sticky'])
    A = (1 - 2 * w['t']) * T
    M.range(A, 29, 'sum magnitude sign')
    M.eq(A * w['invt'], 1 - w['zt'], 'zero-sum inverse')
    M.eq(w['zt'] * A, 0, 'zero-sum flag')
    sx = shi + w['t'] - 2 * shi * w['t']
    sy = w['zt'] * (ss * sp) + (1 - w['zt']) * sx                    # exact zero: -0 only if both -0
    # rounding position r = ehi - 4 + k+ - k-; k+ * k- = 0; r = FLOOR iff f, else r >= FLOOR + 1
    kp_, km = w['kplus'], w['kminus']
    w_up, w_dn = w['Pup'], (w['Pdn'], w['Tb'])
    M.table(UP, kp_, w_up, 'right-shift row')
    M.table(DOWN, km, w_dn, 'left-shift row')
    # k+ * k- = 0 is not required: shifting both ways gives the same r, m0 and rounding decision.
    r = ehi - 4 + kp_ - km
    nz = 1 - w['zt']
    M.eq(nz * w['f'] * (r - FLOOR), 0, 'floor exponent')
    M.range((1 - w['f']) * (r - FLOOR - 1), 16, 'normal exponent above floor')
    # |T| * 2^k- = m0 * 2^k+ + rem2; |T| < bound(k-) keeps |T| * 2^k- < 2^29; m0 * 2^5 < 2^29
    M.range(w_dn[1] - 1 - A, 29, 'left shift without wrap')
    m0, rem2 = w['m0'], w['rem2']
    M.range(rem2, 16, 'rem2 >= 0')
    M.range(w_up - 1 - rem2, 16, 'rem2 < 2^k+')
    M.range(m0 - nz * (1 - w['f']) * 2**23, 24, 'normalised significand lower bound')
    M.eq(A * w_dn[0], m0 * w_up + rem2, 'rounding division')
    # b0 = m0 mod 2; (m0 - b0) / 2 < 2^23 also enforces 0 <= m0 < 2^24
    M.range((m0 - w['b0']) * pow(2, P - 2, P), 23, 'parity')
    # round half to even: up = 1 iff 2 rem2 - 2^k+ + b0 >= 1
    u = 2 * rem2 - w_up
    M.range(w['up'] * (u + w['b0'] - 1) + (1 - w['up']) * (-u - w['b0']), 16, 'round half to even')
    my = m0 + w['up']
    M.eq(w['c2'] * (my - 2**24), 0, 'carry flag')
    M.eq((my - 2**24) * w['inv2'], 1 - w['c2'], 'carry inverse')
    mout = my - w['c2'] * 2**23
    rout = w['zt'] * FLOOR + nz * (r + w['c2'])
    M.range(EMAX - rout, 16, 'finite result')
    rout %= P
    return (sy % P, mout % P, rout - P if rout > P // 2 else rout)


def run(state, a, b, meter=None, **forge):
    return check(state, a, b, honest(state, a, b, **forge), meter)


# Static bound audit (INV-5 style): every identity's integer sides stay below P.
BOUNDS = {
    'aligned division': (2**24 * 2**GUARD, 2**CAP + 2**CAP),
    'rounding division': (2**29, 2**24 * 2**KPLUS + 2**KPLUS),
    'sum magnitude': (16 * 2**24 + 2 * 2**27 + 1, 2**29),
}
assert all(max(v) < P // 2 for v in BOUNDS.values()), 'identity may wrap in M31'
assert (2**24 - 1) * 2**GUARD < 2**CAP, 'shift cap does not zero the truncated operand'
