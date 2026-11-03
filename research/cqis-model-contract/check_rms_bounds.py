"""Independent exact arithmetic/framing for Draft RFC-0025 RMSNorm schema14."""
from dataclasses import replace
from fractions import Fraction as Q
from hashlib import sha256
import json
from math import gcd, isqrt
from random import Random
from struct import pack

from check_arithmetic_bounds import check_columns, column_oracle, rejects
from check_flow_bounds import check, encoded_oracle
from check_layernorm_bounds import actual
from check_numerics import nearest
from rms_bounds import RMSNorm, derive, encode, validate


def oracle(p):
    unit, statistic = p.d*2**(2*p.F), p.d*32768**2
    numerator, denominator = p.ed*statistic+p.en*unit, p.ed*unit
    branches = {}
    for a in range(-23, 10):
        normalized = Q(4)**(-a)
        output = Q(2)**(p.E-p.F-p.G-21-a)
        branches[a] = (normalized.numerator, normalized.denominator, output.numerator,
                       output.denominator, output.denominator//2)
    fa, fd, l, dr, bias = (max(row[i] for row in branches.values()) for i in range(5))
    aa, dd = numerator*fa, denominator*fd
    md, xy, t = 65535*dd, 32768**2, 32768**2*16384
    u, qd = t*l, 32768*dr
    pad = 2**((p.d-1).bit_length())
    scalars = (32768, 65535, unit, statistic, numerator, denominator, fa, fd, aa, dd, md,
               8192, 16384, xy, t, l, dr, bias, u, u+bias, 32768, qd,
               p.d-1, pad, 2*p.d-1, 131071, 65536, 32, 33, 64,
               16384, 65535, 49152, 65536, 49151, 524288, 524350, 3)
    shifts = (p.F+p.G-2-p.E, p.F+p.G+30-p.E)
    roles = [((1, 65535, 1), (1, 32768, 2)), ((1, 32768, 1), (1, 32768, 1)),
             ((p.d, 32768, 32768),), ((1, statistic, p.ed), (1, unit, p.en)),
             ((1, numerator, fa),), ((1, denominator, fd),), ((1, 65535, dd),),
             ((1, md, 1), (1, dd-1, 1)), ((1, dd-1, 1), (1, dd-1, 1), (1, 1, 1)),
             ((1, 32768, 32768),), ((1, xy, 16384),), ((1, t, l),),
             ((1, u, 1), (1, bias, 1)), ((1, 32768, dr),), ((1, qd, 1), (1, dr-1, 1)),
             ((1, dr-1, 1), (1, dr-1, 1), (1, 1, 1)),
             ((1, 65535, 1), (1, 32768, 2)), ((1, 32768, 1), (1, 32768, 1)),
             ((1, 49151, 1), (1, 16384, 1)), ((1, 32, 1),), ((1, 65535, 8),),
             ((1, 524280, 1), (1, 7, 1), (1, 62, 1)), ((1, 1, 1),),
             ((1, 1, 1), (1, 1, 1)), ((1, 1, 1), (1, 1, 2)), ((1, 1, 1),)]
    return (14, scalars, shifts, tuple(column_oracle(t) for t in roles)), branches


def witness(p, groups, record, branches):
    assert sum(n for n, _, _ in groups) == p.d and all(n > 0 for n, _, _ in groups)
    assert all(-32768 <= x <= 32767 and -32768 <= gain <= 32767 for _, x, gain in groups)
    roles = record[3]
    statistic = actual(roles[2], [[(n, abs(x), abs(x)) for n, x, _ in groups]])
    qreal = sum(n*Q(x, 2**p.F)**2 for n, x, _ in groups)/p.d+Q(p.en, p.ed)
    choices = [a for a in branches if 16384 <= qreal/Q(4)**a < 65536]
    assert len(choices) == 1
    a = choices[0]; fa, fd, l, dr, bias = branches[a]
    assert check(roles[19], (a+23, 1)) == a+23
    numerator = check(roles[3], (statistic, p.ed), (record[1][2], p.en))
    aa, dd = check(roles[4], (numerator, fa)), check(roles[5], (record[1][5], fd))
    scaled = qreal/Q(4)**a
    m = scaled.numerator//scaled.denominator; rem = aa-m*dd
    assert Q(aa, dd) == scaled and 16384 <= m <= 65535 and 0 <= rem < dd
    product = check(roles[6], (m, dd))
    assert check(roles[7], (product, 1), (rem, 1)) == aa
    assert check(roles[8], (rem, 1), (dd-rem-1, 1), (1, 1)) == dd
    root = isqrt((1 << 42)//m)
    j = root+int((1 << 44) >= m*(2*root+1)**2)
    assert m*(2*j-1)**2 <= 1 << 44 < m*(2*j+1)**2
    assert check(roles[18], (m-16384, 1), (16384, 1)) == m
    off = check(roles[20], (m-16384, 8))
    for lane in range(8):
        assert check(roles[21], (off, 1), (lane, 1), (62, 1)) == 62+8*(m-16384)+lane
    outcomes, zeros, ties, negative_zero = [0, 0], 0, 0, 0
    for _, x, gain in groups:
        for source in (x, gain):
            magnitude, sign = abs(source), int(source < 0)
            assert check(roles[0], (source+32768, 1), (magnitude, 2*sign)) == check(roles[1], (32768, 1), (magnitude, 1))
        xy = check(roles[9], (abs(x), abs(gain)))
        tmag = check(roles[10], (xy, j))
        sx, sg = int(x < 0), int(gain < 0)
        bit = check(roles[22], (sx, sg)); xor = sx ^ sg
        assert check(roles[23], (sx, 1), (sg, 1)) == check(roles[24], (xor, 1), (bit, 2))
        sign = check(roles[25], (xor, int(xy != 0)))
        assert sign == int(x*gain < 0)
        u = check(roles[11], (tmag, l))
        biased = check(roles[12], (u, 1), (bias, 1))
        rounded, remainder = divmod(biased, dr)
        y = (1-2*sign)*rounded
        exact = Q(x*gain*j)*Q(2)**(p.E-p.F-p.G-21-a)
        assert y == nearest(exact)
        zeros += xy == 0; ties += dr > 1 and (2*u) % (2*dr) == dr
        negative_zero += sign == 1 and y == 0
        if -32768 <= y <= 32767:
            product = check(roles[13], (rounded, dr))
            assert check(roles[14], (product, 1), (remainder, 1)) == biased
            assert check(roles[15], (remainder, 1), (dr-remainder-1, 1), (1, 1)) == dr
            assert check(roles[16], (y+32768, 1), (rounded, 2*sign)) == check(roles[17], (32768, 1), (rounded, 1))
            outcomes[0] += 1
        else:
            outcomes[1] += 1
    return outcomes, a, int(rem != 0), zeros, ties, negative_zero


def boundaries():
    selected = set()
    for a in range(-23, 10):
        epsilon = Q(2)**(14+2*a)
        en, ed, f = epsilon.numerator, epsilon.denominator, 30
        if a == -23:
            en, ed = 1, (1 << 32)-1
        elif a == 9:
            en, ed, f = (1 << 32)-1, 1, 0
        p = RMSNorm(1, f, 0, 14, en, ed)
        record, branches = oracle(p)
        assert derive(p) == record
        got = witness(p, [(1, 1, 1)], record, branches)
        assert got[1] == a; selected.add(a)
    assert selected == set(range(-23, 10))
    cases = [(RMSNorm(2, 0, 0, 14, 1, (1 << 32)-1), [(1, 1, 1), (1, 0, -32768)]),
             (RMSNorm(1, 0, 0, 14, 6145, 2048), [(1, 1, 1)]),
             (RMSNorm(1, 0, 0, 14, 6145, 2048), [(1, -1, 1)]),
             (RMSNorm(16384, 30, 30, 0, (1 << 32)-1, (1 << 32)-2), [(16384, -32768, -32768)]),
             (RMSNorm(16384, 0, 0, 14, 1, 1), [(16384, 0, -32768)]),
             (RMSNorm(1, 0, 0, 14, 1, 1), [(1, -32768, 0)])]
    for index, (p, groups) in enumerate(cases):
        record, branches = oracle(p); got = witness(p, groups, record, branches)
        assert derive(p) == record; check_columns(record[3])
        if index == 0:
            assert p.F+p.G+21+got[1]-p.E < 0 and got[0] == [2, 0]
        if index in (1, 2):
            assert got[4] == 1 and got[0] == [1, 0]
        if index >= 4:
            assert got[3] == 1 and got[0] == [1, 0]
    p = RMSNorm(16384, 30, 30, 14, 1, (1 << 32)-1)
    record, branches = oracle(p)
    assert max(record[3][2][4]+record[3][2][5]) == 1073709311
    off = check(record[3][20], (65535, 8))
    assert check(record[3][21], (off, 1), (7, 1), (62, 1)) == 524349
    # Each factor separately belongs to a permitted set; the mixed tuple does not.
    wrong = (branches[-23][0],)+branches[9][1:]
    assert all(v in {row[i] for row in branches.values()} for i, v in enumerate(wrong))
    assert wrong not in branches.values()
    # A high-word change by p cannot be detected by its single field residue.
    role = record[3][4]; high = check(role, (record[1][4], record[1][6]))
    assert high > 2147483647 and high != high-2147483647 and high % 2147483647 == (high-2147483647) % 2147483647


def main():
    rng, digest = Random(2679), sha256(); outcomes = [0, 0]; branches_seen = set()
    nondivisible = zeros = ties = negative_zero = 0; maxima = [0, 0]; first = None
    for _ in range(10000):
        en, ed = rng.randint(1, (1 << 32)-1), rng.randint(1, (1 << 32)-1)
        common = gcd(en, ed); en //= common; ed //= common
        p = RMSNorm(rng.choice([1, 16384, rng.randint(1, 16384)]), rng.randint(0, 30),
                    rng.randint(0, 30), rng.randint(0, 14), en, ed)
        record, branches = oracle(p); assert derive(p) == record
        data = encode(p); params = pack('<H3B2I', p.d, p.F, p.G, p.E, p.en, p.ed)
        assert data == encoded_oracle(record, params)
        check_columns(record[3]); assert len(data) < 76000
        maxima = [max(maxima[0], len(data)), max(maxima[1], max(len(role[2]) for role in record[3]))]
        for a, (fa, fd, l, dr, bias) in branches.items():
            assert fa <= record[1][6] and fd <= record[1][7] and l <= record[1][15] and dr <= record[1][16] and bias <= record[1][17]
            assert record[2][0]+a+23 == p.F+p.G+21+a-p.E
        cut = rng.randrange(p.d+1); cut2 = rng.randrange(cut, p.d+1)
        groups = [(n, rng.choice([-32768, 32767, 0, rng.randrange(-32768, 32768)]),
                   rng.choice([-32768, 32767, 0, rng.randrange(-32768, 32768)]))
                  for n in (cut, cut2-cut, p.d-cut2) if n]
        got, a, nondiv, zero, tie, negzero = witness(p, groups, record, branches)
        outcomes = [x+y for x, y in zip(outcomes, got)]; branches_seen.add(a)
        nondivisible += nondiv; zeros += zero; ties += tie; negative_zero += negzero
        digest.update(pack('<I', len(data))+data); first = first or (p, data)
    boundaries()
    p, data = first; validate(p, data)
    for offset in sorted({0, len(data)-1, *range(0, len(data), max(1, len(data)//64))}):
        damaged = data[:offset]+bytes([data[offset] ^ 1])+data[offset+1:]
        rejects(lambda damaged=damaged: validate(p, damaged), 'Encoding')
    for length in (0, 1, 32, len(data)//2, len(data)-1):
        rejects(lambda length=length: validate(p, data[:length]), 'Encoding')
    rejects(lambda: validate(p, data+b'\0'), 'Encoding')
    rejects(lambda: validate(replace(p, G=(p.G+1) % 31), data), 'Encoding')
    rejects(lambda: validate(p, bytearray(data)), 'Capacity')
    rejects(lambda: validate(p, bytes((1 << 17)+1)), 'Capacity')
    rejects(lambda: RMSNorm(16385, 0, 0, 0, 1, 1), 'Dimension')
    rejects(lambda: RMSNorm(1, 0, 0, 15, 1, 1), 'Units')
    rejects(lambda: RMSNorm(1, 0, True, 0, 1, 1), 'Units')
    rejects(lambda: RMSNorm(1, 0, 0, 0, 2, 2), 'Epsilon')
    rejects(lambda: RMSNorm(1, 0, 0, 0, 0, 1), 'Epsilon')
    print(json.dumps(dict(seed=2679, configurations=10000, output_coordinate_accept_reject=outcomes,
                         randomized_exponents=sorted(branches_seen), boundary_exponents=list(range(-23, 10)),
                         nondivisible_statistics=nondivisible, zero_products=zeros, exact_ties=ties,
                         negative_products_rounded_zero=negative_zero, maxima_bytes_columns=maxima,
                         corpus_sha256=digest.hexdigest()), sort_keys=True))


if __name__ == '__main__':
    main()
