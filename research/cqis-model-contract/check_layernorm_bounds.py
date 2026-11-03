"""Independent rational/column/framing evidence for Draft RFC-0025 schema 3."""
from dataclasses import replace
from fractions import Fraction as Q
from hashlib import sha256
import json
from math import gcd
from random import Random
from struct import pack

from arithmetic_bounds import derive, encode, validate
from check_arithmetic_bounds import big, check_columns, check_rounding, column_oracle, rejects
from numerics import LayerNorm


def oracle(p):
    h, o = 32768, 65535
    s, os, qs, c, v = p.d*h, p.d*o, p.d*h*h, (p.d-1)*o, (p.d*h)**2
    unit = p.d**2*2**(2*p.F)
    n, denominator = p.ed*v+p.en*unit, p.ed*unit
    branches = {}
    for a in range(-23, 10):
        lc, bc = Q(2)**(p.E-p.F-p.G-21-a), Q(2)**(p.E-p.Gb)
        common = max(lc.denominator, bc.denominator)
        factor = Q(4)**a
        branches[a] = (factor.denominator, factor.numerator, int(lc*common), int(bc*common), common)
    fa, fd, lt, lb, k = (max(row[i] for row in branches.values()) for i in range(5))
    aa, dd, md = n*fa, denominator*fd, 65535*denominator*fd
    ch, t, dlb = c*h, c*h*16384, p.d*lb
    u, dout = t*lt+h*dlb, p.d*k
    scalars = (h, o, s, os, qs, c, v, unit, n, denominator, fa, fd, aa, dd, md,
               16384, ch, t, lt, lb, k, dlb, u, dout, 32768, 32768*dout, 131071, 65536)
    es = [p.F+p.G+21+a-p.E for a in branches]
    ks = [row[4].bit_length()-1 for row in branches.values()]
    shifts = (min(es), max(es), min(ks), max(ks))
    terms = [
        ((p.d, o, 1),), ((p.d, h, h),),
        ((1, os, 1), (1, s, 2)), ((1, s, 1), (1, s, 1)),
        ((1, o, p.d), (1, c, 1)), ((1, 2*c, 1), (1, os, 1)),
        ((1, 2*c, 1), (1, c, 2)), ((1, c, 1), (1, c, 1)),
        ((1, s, s),), ((1, qs, p.d),), ((1, v, 1), (1, v, 1)),
        ((1, v, p.ed), (1, unit, p.en)), ((1, n, fa),), ((1, denominator, fd),),
        ((1, 65535, dd),), ((1, md, 1), (1, dd-1, 1)),
        ((1, dd-1, 1), (1, dd-1, 1), (1, 1, 1)),
        ((1, c, h),), ((1, ch, 16384),),
        ((1, 2*t, 1), (1, t, 2)), ((1, t, 1), (1, t, 1)),
        ((1, p.d, lb),), ((1, t, lt), (1, h, dlb)),
        ((1, 2*t, lt), (1, o, dlb)),
        ((1, 2*u, 1), (1, u, 2)), ((1, u, 1), (1, u, 1)),
        ((1, p.d, k),), ((1, 32768, dout),),
        ((1, 32768*dout, 1), (1, dout-1, 1)),
        ((1, dout-1, 1), (1, dout-1, 1), (1, 1, 1)),
        ((1, dout-1, 2),), ((1, 2*dout-2, 1), (1, dout-1, 1), (1, 1, 1)),
        ((1, dout, 1), (1, dout-1, 1)),
    ]
    return (3, scalars, shifts, tuple(column_oracle(t) for t in terms)), branches


def encoded_oracle(p, record):
    parameters = pack('<H4BII', p.d, p.F, p.G, p.E, p.Gb, p.en, p.ed)
    schema, scalars, shifts, roles = record
    chunks = [b'stele/v0.1/cqis/model-arithmetic', pack('<IBH', 1, schema, 14), parameters,
              pack('<IBB', 2147483647, 8, 28), *(big(x) for x in scalars),
              pack('<B4hB', 4, *shifts, 33)]
    for index, (terms, z, result, carries, left, right) in enumerate(roles, 1):
        chunks.append(pack('<BB', index, len(terms)))
        for count, a, b, ac, bc in terms:
            chunks.extend((pack('<I', count), big(a), big(b), pack('<HH', len(ac), len(bc)), bytes(ac), bytes(bc)))
        chunks.extend((big(z), pack('<H', len(result)), bytes(result),
                       pack('<'+'I'*(len(carries)+len(left)+len(right)), *(carries+left+right))))
    return b''.join(chunks)


def actual(role, groups):
    """Check actual bounded source products and every column, with grouped repeats."""
    terms, zmax, result, carry_caps, left, right = role
    assert len(groups) == len(terms)
    raw, total = [0]*len(result), 0
    for (n, amax, bmax, ac, bc), group in zip(terms, groups):
        assert sum(n for n, _, _ in group) == n
        for count, a, b in group:
            assert 0 <= a <= amax and 0 <= b <= bmax and count >= 0
            total += count*a*b
            for i in range(len(ac)):
                for j in range(len(bc)):
                    raw[i+j] += count*((a >> (8*i)) & 255)*((b >> (8*j)) & 255)
    assert 0 <= total <= zmax
    carry = 0
    for i, value in enumerate(raw):
        digit = (total >> (8*i)) & 255
        assert digit <= result[i] and value+carry <= left[i]
        assert (value+carry-digit) % 256 == 0
        carry = (value+carry-digit)//256
        assert 0 <= carry <= carry_caps[i+1] and digit+256*carry <= right[i]
    assert carry == 0
    return total


def witness(p, rows, gain, bias, record, branches):
    """rows contains (multiplicity, X); it represents exactly d original positions."""
    assert sum(n for n, _ in rows) == p.d
    h, o, sm, om, qm, cm, vm, unit, nm, denominator = record[1][:10]
    tm, ucap = record[1][17], record[1][22]
    roles = record[3]

    def check(index, *products):
        return actual(roles[index-1], [[(1, a, b)] for a, b in products])

    mean = sum(n*Q(x) for n, x in rows)/p.d
    variance = sum(n*(Q(x)-mean)**2 for n, x in rows)/p.d
    statistic = variance/Q(2)**(2*p.F)+Q(p.en, p.ed)
    choices = [a for a in branches if 16384 <= statistic/Q(4)**a < 65536]
    assert len(choices) == 1
    a = choices[0]
    fa, fd, lt, lb, k = branches[a]
    s, q = sum(n*x for n, x in rows), sum(n*x*x for n, x in rows)
    v, n = int(variance*p.d**2), int(statistic*denominator)
    aa, dd = n*fa, denominator*fd
    m, r = divmod(aa, dd)
    low, high = 0, 32768
    while low+1 < high:
        mid = (low+high)//2
        if m*(2*mid-1)**2 <= 1 << 44:
            low = mid
        else:
            high = mid
    j = low
    assert 16384 <= m <= 65535 and 8192 <= j <= 16384
    assert abs(s) <= sm and q <= qm and 0 <= v <= vm and 0 < n <= nm
    s0 = actual(roles[0], [[(count, x+h, 1) for count, x in rows]])
    assert actual(roles[1], [[(count, abs(x), abs(x)) for count, x in rows]]) == q
    assert s0 == s+p.d*h
    assert check(3, (s0, 1), (abs(s), 2*int(s < 0))) == check(4, (sm, 1), (abs(s), 1))
    square = check(9, (abs(s), abs(s)))
    assert check(10, (q, p.d)) == check(11, (v, 1), (square, 1))
    assert check(12, (v, p.ed), (unit, p.en)) == n
    assert check(13, (n, fa)) == aa and check(14, (denominator, fd)) == dd
    md = check(15, (m, dd))
    assert check(16, (md, 1), (r, 1)) == aa
    assert check(17, (r, 1), (dd-r-1, 1), (1, 1)) == dd
    dlb = check(22, (p.d, lb))
    ubar = check(23, (tm, lt), (h, dlb))
    dout = check(27, (p.d, k))
    counts = [0, 0]
    for _, x in rows:
        for source in (x, gain, bias):
            assert -32768 <= source <= 32767
            assert source+h+2*int(source < 0)*abs(source) == h+abs(source)
        c = p.d*x-s
        assert abs(c) <= cm
        assert check(5, (x+h, p.d), (cm, 1)) == check(6, (c+cm, 1), (s0, 1))
        assert check(7, (c+cm, 1), (abs(c), 2*int(c < 0))) == check(8, (cm, 1), (abs(c), 1))
        ch = check(18, (abs(c), abs(gain)))
        mag = check(19, (ch, j))
        t = c*gain*j
        assert abs(t) == mag and abs(t) <= tm
        assert check(20, (t+tm, 1), (mag, 2*int(t < 0))) == check(21, (tm, 1), (mag, 1))
        u0 = check(24, (t+tm, lt), (bias+h, dlb))
        u = t*lt+bias*dlb
        assert u0 == u+ubar and abs(u) <= ucap
        assert check(25, (u0, 1), (abs(u), 2*int(u < 0))) == check(26, (ubar, 1), (abs(u), 1))
        exact = (Q(x)-mean)*gain*j*Q(2)**(p.E-p.F-p.G-21-a)+bias*Q(2)**(p.E-p.Gb)
        assert Q(u, dout) == exact
        accepted = check_rounding(u, dout, ucap)
        counts[not accepted] += 1
        if accepted:
            quotient, remainder = divmod(abs(u), dout)
            qd = check(28, (quotient, dout))
            assert check(29, (qd, 1), (remainder, 1)) == abs(u)
            assert check(30, (remainder, 1), (dout-remainder-1, 1), (1, 1)) == dout
            doubled = check(31, (remainder, 2))
            if doubled < dout:
                assert check(32, (doubled, 1), (dout-doubled-1, 1), (1, 1)) == dout
            else:
                assert check(33, (dout, 1), (doubled-dout, 1)) == doubled
    return counts, a, ubar != ucap


def main():
    rng, digest = Random(2674), sha256()
    maximum_bytes = maximum_columns = maximum_bits = 0
    counts, branches_seen, differing_offsets = [0, 0], set(), 0
    first = None
    for i in range(10000):
        en, ed = rng.randrange(1, 1 << 32), rng.randrange(1, 1 << 32)
        common = gcd(en, ed)
        d = rng.choice([1, 16384, rng.randrange(1, 16385)])
        p = LayerNorm(d, rng.randrange(31), rng.randrange(31), rng.randrange(15),
                      rng.randrange(31), en//common, ed//common)
        expected, branches = oracle(p)
        assert derive(p) == expected
        data = encode(p)
        assert data == encoded_oracle(p, expected)
        check_columns(expected[3])
        split = rng.randrange(d+1)
        rows = [(split, rng.randrange(-32768, 32768)), (d-split, rng.randrange(-32768, 32768))]
        rows = [(n, x) for n, x in rows if n]
        found, a, distinct = witness(p, rows, rng.randrange(-32768, 32768), rng.randrange(-32768, 32768), expected, branches)
        counts = [x+y for x, y in zip(counts, found)]
        branches_seen.add(a)
        differing_offsets += distinct
        maximum_bytes = max(maximum_bytes, len(data))
        maximum_bits = max(maximum_bits, *(x.bit_length() for x in expected[1]))
        maximum_columns = max(maximum_columns, *(len(role[2]) for role in expected[3]))
        digest.update(pack('<I', len(data))+data)
        first = first or (p, data)
    for target in range(-23, 10):
        epsilon = Q(2)**(14+2*target)
        if target == -23:
            epsilon = Q(1, (1 << 32)-1)
        elif target == 9:
            epsilon = Q((1 << 32)-1)
        p = LayerNorm(2, 0, 0, 0, 0, epsilon.numerator, epsilon.denominator)
        expected, branches = oracle(p)
        assert derive(p) == expected and encode(p) == encoded_oracle(p, expected)
        rows = [(1, -32768), (1, 32767)] if target == 9 else [(2, 0)]
        _, a, _ = witness(p, rows, -1, 1, expected, branches)
        assert a == target
        branches_seen.add(a)
    extreme = LayerNorm(16384, 30, 30, 0, 0, (1 << 32)-1, (1 << 32)-2)
    expected, _ = oracle(extreme)
    assert derive(extreme) == expected and encode(extreme) == encoded_oracle(extreme, expected)
    assert max(expected[3][1][4]+expected[3][1][5]) == 1073709311
    assert max(len(role[2]) for role in expected[3]) == 21
    assert branches_seen == set(range(-23, 10)) and differing_offsets > 0
    p, data = first
    validate(p, data)
    for offset in sorted({0, len(data)-1, *range(0, len(data), max(1, len(data)//64))}):
        damaged = data[:offset]+bytes([data[offset] ^ 1])+data[offset+1:]
        rejects(lambda damaged=damaged: validate(p, damaged), 'Encoding')
    for length in [0, 1, 32, len(data)//2, len(data)-1]:
        rejects(lambda length=length: validate(p, data[:length]), 'Encoding')
    rejects(lambda: validate(p, data+b'\0'), 'Encoding')
    rejects(lambda: validate(replace(p, Gb=(p.Gb+1) % 31), data), 'Encoding')
    rejects(lambda: replace(p, en=2, ed=2), 'Epsilon')
    rejects(lambda: replace(p, d=16385), 'Dimension')
    rejects(lambda: replace(p, F=True), 'Units')
    print(json.dumps(dict(seed=2674, configurations=10000, boundary_normalization_branches=33,
                         sampled_output_accept_reject=counts, branch_offset_differs_from_cap=differing_offsets,
                         maximum_record_bytes=maximum_bytes, maximum_scalar_bits=maximum_bits,
                         maximum_columns=maximum_columns, corpus_sha256=digest.hexdigest()), sort_keys=True))


if __name__ == '__main__':
    main()
