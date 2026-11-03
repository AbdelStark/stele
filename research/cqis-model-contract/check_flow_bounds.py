"""Exact rational/column/byte evidence for Draft RFC-0025 flow schemas 4–6."""
from dataclasses import replace
from fractions import Fraction as Q
from hashlib import sha256
import json
from random import Random
from struct import pack

from check_arithmetic_bounds import big, check_columns, check_rounding, column_oracle, rejects
from check_layernorm_bounds import actual
from check_numerics import nearest
from flow_bounds import Gated, Residual, Row, derive, encode, validate


def oracle(p):
    if type(p) is Row:
        h = 2**(30 if p.kind else 15)
        high = h if p.kind else h-1
        s = p.scale if p.policy else -(-Q(h, 127).numerator//Q(h, 127).denominator)
        scalars = (h, high, h+high, s, s-1, p.d-1, 127, 254*s, 2*s-1,
                   4*s-1, 2*s, 254, 127, 508, 254, 2*p.d-1)
        roles = []
        if p.policy == 0:
            scalars += (126,)
            roles += [((1, s, 127),), ((1, h, 1), (1, 126, 1)),
                      ((1, h, 1), (1, h, 1), (1, 1, 1))]
        roles += [((1, h+high, 1), (1, h, 2)), ((1, h, 1), (1, h, 1)),
                  ((1, h, 2), (1, s, 1)), ((1, 127, 2*s),), ((1, 254*s, 1), (1, 2*s-1, 1))]
        parameters, schema, shifts = pack('<H3BI', p.d, p.kind, p.fraction, p.policy, p.scale), 4, ()
    elif type(p) is Residual:
        x, y = Q(2)**(p.fo-p.fx), Q(2)**(p.fo-p.fy)
        d = max(x.denominator, y.denominator)
        l, r = int(x*d), int(y*d)
        u = 32768*(l+r)
        q = min(32768, u//d)
        scalars = (p.d-1, 32768, 65535, l, r, d, u, q, 32768, 131071, 65536)
        c = p.fo+d.bit_length()-1
        shifts = (c, l.bit_length()-1, r.bit_length()-1, d.bit_length()-1)
        roles = [((1, 65535, l), (1, 65535, r)),
                 ((1, 2*u, 1), (1, u, 2)), ((1, u, 1), (1, u, 1)),
                 ((1, q, d),), ((1, q*d, 1), (1, d-1, 1)),
                 ((1, d-1, 1), (1, d-1, 1), (1, 1, 1)),
                 ((1, d-1, 2),), ((1, 2*d-2, 1), (1, d-1, 1), (1, 1, 1)),
                 ((1, d, 1), (1, d-1, 1))]
        parameters, schema = pack('<H3B', p.d, p.fx, p.fy, p.fo), 5
    else:
        scalars = (p.fu+p.E, 32768, 65535, 65535**2, 2**30, 2**31, p.d-1, 131071, 65536)
        roles = [((1, 65535, 65535),), ((1, 65535**2, 1), (1, 2**31, 1)),
                 ((1, 2**31, 1), (1, 65535, 32768), (1, 65535, 32768))]
        parameters, schema, shifts = pack('<H2B', p.d, p.fu, p.E), 6, ()
    return (schema, scalars, shifts, tuple(column_oracle(t) for t in roles)), parameters


def encoded_oracle(record, parameters):
    schema, scalars, shifts, roles = record
    chunks = [b'stele/v0.1/cqis/model-arithmetic', pack('<IBH', 1, schema, len(parameters)), parameters,
              pack('<IBB', 2147483647, 8, len(scalars)), *(big(x) for x in scalars),
              pack('<B', len(shifts)), pack('<'+'h'*len(shifts), *shifts), pack('<B', len(roles))]
    for index, (terms, z, result, carries, left, right) in enumerate(roles, 1):
        chunks.append(pack('<BB', index, len(terms)))
        for n, a, b, ac, bc in terms:
            chunks.extend((pack('<I', n), big(a), big(b), pack('<HH', len(ac), len(bc)), bytes(ac), bytes(bc)))
        chunks.extend((big(z), pack('<H', len(result)), bytes(result),
                       pack('<'+'I'*(len(carries)+len(left)+len(right)), *(carries+left+right))))
    return b''.join(chunks)


def check(role, *products):
    return actual(role, [[(1, a, b)] for a, b in products])


def row_case(p, groups, record):
    assert sum(count for count, _ in groups) == p.d and all(count > 0 for count, _ in groups)
    h, high, _, smax = record[1][:4]
    assert all(-h <= value <= high for _, value in groups)
    maximum = max(abs(x) for _, x in groups)
    start, selected = 0, None
    for count, x in groups:
        if selected is None and abs(x) == maximum:
            selected = start
        start += count
    s = p.scale if p.policy else -(-maximum//127)
    assert 0 <= s <= smax
    roles, n = record[3], int(s > 0)
    predecessor = s-1 if n else 0
    assert s == n*(predecessor+1) and (1-n)*predecessor == 0
    if not p.policy:
        slack = 127*s-maximum
        assert 0 <= slack <= 126 and 0 <= selected < p.d
        assert check(roles[0], (s, 127)) == check(roles[1], (maximum, 1), (slack, 1))
    offset, start, accepted = 0 if p.policy else 3, 0, True
    for count, x in groups:
        mag, sign = abs(x), int(x < 0)
        assert check(roles[offset], (x+h, 1), (mag, 2*sign)) == check(roles[offset+1], (h, 1), (mag, 1))
        if not p.policy:
            # Each group is constant; its endpoints cover both sides of selected.
            for index in {start, start+count-1}:
                before = int(index < selected)
                gap = maximum-mag-before
                assert 0 <= gap <= h
                assert check(roles[2], (mag, 1), (gap, 1), (before, 1)) == maximum
                if index == selected:
                    assert mag == maximum
        biased = check(roles[offset+2], (mag, 2), (s, 1))
        y = nearest(Q(x, s)) if s else 0
        q = abs(y)
        assert q == biased//(2*s) if s else biased == 0
        start += count
        if q > 127:
            assert p.policy == 1
            accepted = False
            continue
        r = biased-2*q*s
        g = 2*s-n-r
        z = 127*n-q
        assert 0 <= r <= 2*smax-1 and 0 <= g <= 2*smax-1 and 0 <= z <= 127
        qd = check(roles[offset+3], (q, 2*s))
        assert check(roles[offset+4], (qd, 1), (r, 1)) == biased
        assert r+g+n == 2*s and q+z == 127*n
        assert y+127+2*sign*q == 127+q
    return accepted, n == 0


def residual_case(p, x, y, record):
    _, h, _, l, r, d, umax, *_ = record[1]
    roles = record[3]
    u = x*l+y*r
    exact = x*Q(2)**(p.fo-p.fx)+y*Q(2)**(p.fo-p.fy)
    assert Q(u, d) == exact
    offset = check(roles[0], (x+h, l), (y+h, r))
    assert offset == u+umax
    assert check(roles[1], (offset, 1), (abs(u), 2*int(u < 0))) == check(roles[2], (umax, 1), (abs(u), 1))
    accepted = check_rounding(u, d, umax)
    assert accepted == (-32768 <= nearest(exact) <= 32767)
    if accepted:
        q, remainder = divmod(abs(u), d)
        qd = check(roles[3], (q, d))
        assert check(roles[4], (qd, 1), (remainder, 1)) == abs(u)
        assert check(roles[5], (remainder, 1), (d-remainder-1, 1), (1, 1)) == d
        twice = check(roles[6], (remainder, 2))
        if twice < d:
            assert check(roles[7], (twice, 1), (d-twice-1, 1), (1, 1)) == d
        else:
            assert check(roles[8], (d, 1), (twice-d, 1)) == twice
    return accepted


def gated_case(p, x, y, record):
    product = check(record[3][0], (x+32768, y+32768))
    t = x*y
    assert abs(t) <= 2**30 and record[1][0] == p.fu+p.E
    assert check(record[3][1], (product, 1), (2**31, 1)) == check(
        record[3][2], (t+2**30, 1), (x+32768, 32768), (y+32768, 32768))
    assert Q(t, 2**record[1][0]) == Q(x, 2**p.fu)*Q(y, 2**p.E)


def word_predicates(rng):
    valid, impossible_strict, zero = 0, 0, 0
    for _ in range(10000):
        maximum = rng.getrandbits(rng.randrange(2151))
        value = rng.choice([0, maximum, rng.randrange(maximum+1)])
        strict = rng.randrange(2)
        width = max(1, (maximum.bit_length()+7)//8)
        gap = maximum-value-strict
        if gap < 0:
            assert strict and value == maximum
            impossible_strict += 1
            continue
        carry = strict
        for i in range(width):
            left = ((value >> (8*i)) & 255)+((gap >> (8*i)) & 255)+carry
            carry = left//256
            right = ((maximum >> (8*i)) & 255)+256*carry
            assert left == right and max(left, right) <= 511 and carry in (0, 1)
        assert carry == 0 and value+gap+strict == maximum
        digits = value.to_bytes(width, 'little')
        if value == 0:
            assert not any(digits)
            zero += 1
        else:
            selected = next(i for i, digit in enumerate(digits) if digit)
            assert not any(digits[:selected]) and 1 <= digits[selected] <= 255
            assert 0 <= selected < width and 2*(2*width-1) < 2147483647
        valid += 1
    # Dropping the final zero carry would let 255+1 masquerade as upper bound zero.
    assert 255+1 == 0+256*1 and 1 != 0
    return dict(valid_ranges=valid, impossible_strict_ranges=impossible_strict, zero_words=zero)


def main():
    rng, digest = Random(2675), sha256()
    counts, zero_rows = {'row': [0, 0], 'residual': [0, 0]}, 0
    maxima, first = {}, {}
    for i in range(10000):
        d = rng.choice([1, 16384, rng.randrange(1, 16385)])
        kind, policy = rng.randrange(2), rng.randrange(2)
        scale = rng.choice([1, 8454661 if kind else 65535, rng.randrange(1, (8454661 if kind else 65535)+1)]) if policy else 0
        params = [Row(d, kind, rng.randrange(45 if kind else 31), policy, scale),
                  Residual(d, rng.randrange(31), rng.randrange(31), rng.randrange(31)),
                  Gated(d, rng.randrange(31), rng.randrange(15))]
        for p in params:
            expected, parameters = oracle(p)
            assert derive(p) == expected
            data = encode(p)
            assert data == encoded_oracle(expected, parameters)
            check_columns(expected[3])
            schema = expected[0]
            maxima.setdefault(schema, [0, 0])
            maxima[schema] = [max(maxima[schema][0], len(data)), max(maxima[schema][1], *(len(role[2]) for role in expected[3]))]
            if type(p) is Row:
                h, high = expected[1][:2]
                a = rng.randrange(d+1); b = rng.randrange(d-a+1)
                values = [0]*3 if i % 10 == 0 else [-1, 0, 1] if i % 10 == 1 else [rng.choice([-h, high, rng.randrange(-h, high+1)]) for _ in range(3)]
                groups = [(n, x) for n, x in zip([a, b, d-a-b], values) if n]
                accepted, zero = row_case(p, groups, expected)
                counts['row'][not accepted] += 1; zero_rows += zero
            elif type(p) is Residual:
                x, y = [rng.choice([-32768, 32767, rng.randrange(-32768, 32768)]) for _ in range(2)]
                counts['residual'][not residual_case(p, x, y, expected)] += 1
            else:
                x, y = [rng.choice([-32768, 32767, 0, rng.randrange(-32768, 32768)]) for _ in range(2)]
                gated_case(p, x, y, expected)
            digest.update(pack('<I', len(data))+data)
            first.setdefault(schema, (p, data))
    for p, groups in [(Row(2, 1, 44, 1, 8454661), [(1, -(1 << 30)), (1, 1 << 30)]),
                      (Row(2, 1, 44, 0, 0), [(1, -(1 << 30)), (1, 1 << 30)]),
                      (Row(2, 0, 0, 0, 0), [(2, 0)]), (Row(2, 0, 0, 1, 2), [(1, -1), (1, 1)])]:
        record, _ = oracle(p); assert derive(p) == record and row_case(p, groups, record)[0]
    # A later tied index would need a negative gap at the original earlier maximum.
    assert 5-abs(-5)-int(0 < 1) == -1 and 0-abs(0)-int(0 < 1) == -1
    for fx, fy, fo, x, y in [(1, 1, 0, 1, 1), (1, 1, 0, -1, -1), (0, 0, 30, 32767, -32767), (0, 0, 30, -32768, -32768)]:
        p = Residual(2, fx, fy, fo); record, _ = oracle(p)
        assert derive(p) == record; residual_case(p, x, y, record)
    p = Gated(16384, 30, 14); record, _ = oracle(p)
    gated_case(p, -32768, -32768, record)
    for p, data in first.values():
        validate(p, data)
        for offset in sorted({0, len(data)-1, *range(0, len(data), max(1, len(data)//48))}):
            damaged = data[:offset]+bytes([data[offset] ^ 1])+data[offset+1:]
            rejects(lambda damaged=damaged: validate(p, damaged), 'Encoding')
        for length in [0, 1, 32, len(data)//2, len(data)-1]:
            rejects(lambda length=length: validate(p, data[:length]), 'Encoding')
        rejects(lambda: validate(p, data+b'\0'), 'Encoding')
        rejects(lambda: validate(replace(p, d=1 if p.d != 1 else 2), data), 'Encoding')
    rejects(lambda: Row(2, 1, 44, 1, 8454662), 'Scale')
    rejects(lambda: Row(2, 0, 30, 1, 65536), 'Scale')
    rejects(lambda: Row(2, 0, 30, 0, 1), 'Scale')
    rejects(lambda: Residual(2, True, 0, 0), 'Fraction')
    rejects(lambda: Gated(16385, 0, 0), 'Shape')
    rejects(lambda: Gated(2, 0, 15), 'Fraction')
    rejects(lambda: validate(None, bytes((1 << 17)+1)), 'Capacity')
    print(json.dumps(dict(seed=2675, cases_per_schema=10000, outcomes_accept_reject=counts,
                         dynamic_zero_rows=zero_rows, word_predicates=word_predicates(rng),
                         maxima_bytes_columns=maxima, corpus_sha256=digest.hexdigest()), sort_keys=True))


if __name__ == '__main__':
    main()
