# /// script
# requires-python = ">=3.12"
# dependencies = []
# ///
"""RFC-0019 R-BF16 (task E15-04): validate the accumulation-step reduction; stdlib only.

Question: does reduction.py accept exactly RN_binary32(s + a*b) for every finite bf16 input, and
reject every tampered witness that would change the output? Kill criterion: any disagreement.

Oracles, independent of the reduction's guard/sticky construction:
  exact     rational s + a*b rounded to binary32 by its definition (round half to even).
  hardware  host binary64 addition then the C double->float conversion (struct 'f'). Both operands
            are binary32 numbers, so this double rounding equals direct binary32 rounding
            (Figueroa 1995: 53 >= 2*24 + 2); used only when a*b is exactly a binary32 number.
Usage: python3 research/r-bf16/check_reduction.py [--full]
"""
import math
import random
import struct
import sys
from fractions import Fraction
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import reduction as g

ZERO = (0, 0, g.FLOOR)


def bf16(bits):
    """Decode a finite bfloat16 bit pattern to (sign, m, e); None for inf/nan."""
    s, E, F = bits >> 15, (bits >> 7) & 0xFF, bits & 0x7F
    if E == 0xFF:
        return None
    return s, F + (128 if E else 0), max(E, 1) - 134


def value(x):
    s, m, e = x
    return (-1) ** s * Fraction(m) * Fraction(2) ** e


def rn32(x, zero_sign):
    """Definition of binary32 round-half-even; None on overflow."""
    if x == 0:
        return (zero_sign, 0, g.FLOOR)
    s, a = int(x < 0), abs(x)
    e = a.numerator.bit_length() - a.denominator.bit_length()
    while a >= Fraction(2) ** (e + 1):
        e += 1
    while a < Fraction(2) ** e:
        e -= 1
    e = max(e - 23, g.FLOOR)
    y = a / Fraction(2) ** e
    m, frac = divmod(y.numerator, y.denominator)
    if 2 * frac > y.denominator or (2 * frac == y.denominator and m & 1):
        m += 1
    if m == 2**24:
        m, e = 2**23, e + 1
    return None if e > g.EMAX else (s, m, e)


def exact(state, a, b):
    p = (a[0] ^ b[0], a[1] * b[1], a[2] + b[2])
    zero_sign = state[0] & p[0]                    # RN: exact zero is +0 unless both operands are -0
    return rn32(value(state) + value(p), zero_sign)


def f32(x):
    """Canonical (sign, m, e) of a Python float that holds a binary32 value."""
    bits = struct.unpack('<I', struct.pack('<f', x))[0]
    s, E, F = bits >> 31, (bits >> 23) & 0xFF, bits & 0x7FFFFF
    return s, F + (2**23 if E else 0), max(E, 1) - 150


def hardware(state, a, b):
    p = value(a) * value(b)
    if rn32(p, 0) is None or value(rn32(p, 0)) != p:
        return 'skip'
    native = lambda x: math.copysign(math.ldexp(x[1], x[2]), -1.0 if x[0] else 1.0)
    try:
        return f32(native(state) + native(a) * native(b))   # bf16 x bf16 is exact in binary64
    except OverflowError:
        return None


def step(state, a, b, stats):
    want = exact(state, a, b)
    hw = hardware(state, a, b)
    if hw != 'skip':
        stats['hardware'] += 1
        assert hw == want or (hw is None and want is None), ('hardware/exact', state, a, b, hw, want)
    try:
        got = g.run(state, a, b)
    except g.Reject as e:
        assert want is None, ('rejected a finite step', state, a, b, str(e))
        stats['overflow'] += 1
        return None
    assert want is not None, ('accepted an overflow', state, a, b, got)
    assert got == want, ('wrong result', state, a, b, got, want)
    stats['steps'] += 1
    return got


def chain(pairs, stats):
    s = ZERO
    for a, b in pairs:
        s = step(s, a, b, stats)
        if s is None:
            return


def rand_bf16(rng, lo, hi):
    while True:
        x = bf16((rng.getrandbits(1) << 15) | (rng.randint(lo, hi) << 7) | rng.getrandbits(7))
        if x:
            return x


def tamper(rng, state, a, b, stats):
    """Every single-value change of the witness is rejected or leaves the output unchanged."""
    w = g.honest(state, a, b)
    want = g.check(state, a, b, w)
    for name in g.COMMITTED:
        for delta in (1, -1, 2, 2**23, rng.randrange(1, g.P)):
            bad = dict(w, **{name: (w[name] + delta) % g.P})
            try:
                got = g.check(state, a, b, bad)
            except g.Reject:
                stats['tamper rejected'] += 1
                continue
            assert got == want, ('forged output', name, delta, state, a, b, got, want)
            stats['tamper inert'] += 1                 # e.g. an inverse whose operand is 0


REASONS = sorted({line.split("'")[-2] for line in Path(g.__file__).read_text().splitlines()
                  if line.lstrip().startswith(('M.eq(', 'M.range(', 'M.table(')) and line.rstrip().endswith("')")}
                 - {'{name} is not a bit'})
BITS = ('zp', 'g', 'c', 'sticky', 't', 'zt', 'f', 'b0', 'up', 'c2')


def forged(state, a, b, rng):
    """Consistent forgeries: one committed value moved, everything downstream recomputed."""
    w = g.honest(state, a, b)
    for name in g.COMMITTED:
        v = w[name]
        for x in (v + 1, v - 1, v + 2, v - 2, 2 * v, v // 2, v + 2**23, v - 2**23, -v, rng.randrange(g.P)):
            yield name, x, g.honest(state, a, b, **{name: x})
    yield 'q, rem kept', 0, g.honest(state, a, b, q=w['q'] + 1, rem=w['rem'])
    yield 'q, rem kept', 1, g.honest(state, a, b, q=w['q'] + 2**12, rem=w['rem'])
    yield 'f, kminus', 0, g.honest(state, a, b, f=0, kminus=w['kminus'] + 1)  # finer-than-floor grid
    # wrap attacks: pick (t, k-, k+) so that A * 2^k- wraps mod P into a normalised m0 * 2^k+
    for t in (w['t'], 1 - w['t']):
        A = g.honest(state, a, b, t=t)['_A']
        for km in range(g.KMINUS + 1):
            val = A * 2**km % g.P
            for kp in range(g.KPLUS + 1):
                if 2**23 <= val >> kp < 2**24:
                    yield 'wrap', (t, km, kp), g.honest(state, a, b, t=t, kminus=km, kplus=kp, f=0)


def necessity(rng, stats, full):
    """Every constraint is necessary: without it some consistent forgery is accepted with a wrong output.

    'finite result' is shown necessary by the overflow cases, which honest witnesses reach.
    """
    seeds = [((0, 2**23, -23), (0, 129, -7), (0, 128, -31)),       # 1 + 2^-24 * 129/128: sticky decides
             ((0, 2**24 - 1, -23), (0, 128, -7), (0, 128, -31)),     # rounding carry 2^24 -> 2^23
             ((0, 2**23 + 2**15, -23), (1, 129, -7), (0, 128, -7)),  # exact cancellation to zero
             ((1, 0, g.FLOOR), (0, 0, -133), (1, 0, -133)),          # -0 + -0
             ((1, 2**23 + 2**16, -23), (0, 129, -7), (0, 128, -7)),  # -x + x = +0, hi operand negative
             ((1, 2**22, g.FLOOR), (0, 128, -100), (0, 128, -41)),   # -x + x = +0 near the floor
             ((0, 0, g.FLOOR), (0, 128, -100), (0, 128, -41)),       # subnormal result, m0 = 2^22
             ((0, 0, g.FLOOR), (0, 200, -133), (0, 200, -20))]       # tiny subnormal result
    while len(seeds) < (400 if full else 120):
        st = (rng.getrandbits(1), rng.randrange(2**23, 2**24), rng.randint(-60, 40)) if rng.random() < .6 else \
            rng.choice([ZERO, (1, 0, g.FLOOR), (0, 5, g.FLOOR), (1, 2**23 - 3, g.FLOOR), (0, 2**24 - 1, -23)])
        a, b = rand_bf16(rng, 0, 200), rand_bf16(rng, 0, 200)
        if exact(st, a, b) is not None:
            seeds.append((st, a, b))
    missing = []
    for why in [r for r in REASONS if r != 'finite result'] + ['bits']:
        skip = {f'{n} is not a bit' for n in BITS} if why == 'bits' else {why}
        hit = None
        for state, a, b in seeds:
            want = g.run(state, a, b)
            for name, x, w in forged(state, a, b, rng):
                try:
                    g.check(state, a, b, w)
                    accepted_full = True
                except g.Reject:
                    accepted_full = False
                try:
                    out = g.check(state, a, b, w, g.Meter(skip=skip))
                except g.Reject:
                    continue
                if out != want:
                    assert not accepted_full, ('forgery accepted by the full reduction', name, x, state, a, b)
                    hit = (name, x)
                    break
            if hit:
                break
        if not hit:
            missing.append(why)
        stats['necessity controls'] += bool(hit)
    assert not missing, ('no necessity witness for', missing)


def main(full):
    rng = random.Random(0xBF16)
    stats = {'steps': 0, 'hardware': 0, 'overflow': 0, 'tamper rejected': 0, 'tamper inert': 0, 'ties': 0, 'necessity controls': 0}
    one = bf16(0x3F80)
    # 1. activation-like chains: K = 4096 with E in a serving range
    for _ in range(4 if full else 1):
        chain([(rand_bf16(rng, 112, 132), rand_bf16(rng, 100, 128)) for _ in range(4096)], stats)
    # 2. full exponent range (includes overflow, subnormal products and gaps beyond the cap)
    for _ in range(400 if full else 60):
        chain([(rand_bf16(rng, 0, 254), rand_bf16(rng, 0, 254)) for _ in range(64)], stats)
    # 3. subnormal accumulator regime
    for _ in range(200 if full else 30):
        chain([(rand_bf16(rng, 0, 70), rand_bf16(rng, 0, 70)) for _ in range(64)], stats)
    # 4. cancellation: each product followed by its negation and a perturbation
    for _ in range(200 if full else 30):
        pairs = []
        for _ in range(32):
            a, b = rand_bf16(rng, 100, 140), rand_bf16(rng, 100, 140)
            pairs += [(a, b), ((1 - a[0], a[1], a[2]), b), (rand_bf16(rng, 90, 140), b)]
        chain(pairs, stats)
    # 5. exact ties: s random normal, p = +-2^(e_s - 1) (half ulp) or +-3 * 2^(e_s - 1) (1.5 ulp)
    for _ in range(4000 if full else 600):
        s = (rng.getrandbits(1), rng.randrange(2**23, 2**24), rng.randint(g.FLOOR + 30, 60))
        for mb, offset in ((128, 15), (192, 14)):
            ea = rng.randint(-60, 60)
            eb = s[2] - offset - ea
            if -133 <= eb <= 120:
                a, b = (rng.getrandbits(1), 128, ea), (rng.getrandbits(1), mb, eb)
                x = value(s) + value(a) * value(b)
                stats['ties'] += (x / Fraction(2) ** (s[2] - 1)).denominator == 1 and (x / Fraction(2) ** s[2]).denominator == 2
                step(s, a, b, stats)
    # 6. every finite bf16 a against fixed b and accumulators (exhaustive in a)
    states = [ZERO, (1, 0, g.FLOOR), (0, 2**23, -23), (1, 2**24 - 1, -23), (0, 1, g.FLOOR),
              (0, 2**23 - 1, g.FLOOR), (1, 2**24 - 1, g.EMAX), (0, 12345678, 40)]
    patterns = range(1 << 16) if full else range(0, 1 << 16, 97)
    for bits in patterns:
        a = bf16(bits)
        if a:
            for s in states:
                step(s, a, one, stats)
    # 7. signed zeros: every sign of a zero accumulator against every sign of a zero product
    for zs in (0, 1):
        for bits in (0x0000, 0x8000, 0x3F80, 0xBF80):
            for bbits in (0x0000, 0x8000):
                step((zs, 0, g.FLOOR), bf16(bits), bf16(bbits), stats)
    # 8. tamper controls
    for _ in range(300 if full else 40):
        a, b = rand_bf16(rng, 60, 200), rand_bf16(rng, 60, 200)
        s = rng.choice(states[:6] + [(0, rng.randrange(2**23, 2**24), rng.randint(-80, 40))])
        if exact(s, a, b) is not None:
            tamper(rng, s, a, b, stats)
    necessity(rng, stats, full)
    m = g.Meter()
    g.run((0, 2**23, -23), one, one, m)
    print('per-MAC:', dict(sorted(m.c.items())))
    print('validated:', stats)
    assert stats['tamper rejected'] > 10 * max(stats['tamper inert'], 1)
    assert stats['ties'] > 1000 and stats['steps'] > 10000, stats


if __name__ == '__main__':
    main('--full' in sys.argv[1:])
