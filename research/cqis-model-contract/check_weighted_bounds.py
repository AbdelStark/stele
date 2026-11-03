"""Exact dense grouped sums/rounding/framing for Draft RFC-0025 schemas 12/13."""
from dataclasses import replace
from fractions import Fraction as Q
from hashlib import sha256
import json
from random import Random
from struct import pack

from check_arithmetic_bounds import rejects
from check_flow_bounds import encoded_oracle
from check_numerics import nearest
from weighted_bounds import Normalize, Weighted, derive, encode, validate


def caps(value):
    result = []
    while value:
        result.append(min(15, value)); value //= 16
    return tuple(result or [0])


def column(terms):
    operands = tuple((n, a, b, caps(a), caps(b)) for n, a, b in terms)
    z = sum(n*a*b for n, a, b in terms)
    k = max(len(caps(z)), *(len(a)+len(b)-1 for _, _, _, a, b in operands))
    polynomial = sum(n*sum(v << (40*i) for i, v in enumerate(a))*sum(v << (40*i) for i, v in enumerate(b)) for n, _, _, a, b in operands)
    raw = [(polynomial >> (40*i)) % 2**40 for i in range(k)]
    assert polynomial >> (40*k) == 0
    carry = [0]+[sum(raw[j]*16**j for j in range(i))//16**i for i in range(1, k)]+[0]
    result = tuple(min(15, z//16**i) for i in range(k))
    left, right = tuple(raw[i]+carry[i] for i in range(k)), tuple(result[i]+16*carry[i+1] for i in range(k))
    assert all(2*v < 2147483647 for v in left+right)
    return operands, z, result, tuple(carry), left, right


def actual(role, groups):
    terms, maximum, result, carries, left, right = role
    raw, total = [0]*len(result), 0
    assert len(terms) == len(groups)
    for (count, amax, bmax, ac, bc), group in zip(terms, groups):
        assert sum(n for n, _, _ in group) == count
        for n, a, b in group:
            assert n >= 0 and 0 <= a <= amax and 0 <= b <= bmax
            total += n*a*b
            for i in range(len(ac)):
                for j in range(len(bc)):
                    raw[i+j] += n*(a//16**i % 16)*(b//16**j % 16)
    assert total <= maximum
    carry = 0
    for i, value in enumerate(raw):
        digit = total//16**i % 16
        assert digit <= result[i] and value+carry <= left[i]
        assert (value+carry-digit) % 16 == 0
        carry = (value+carry-digit)//16
        assert 0 <= carry <= carries[i+1] and digit+16*carry <= right[i]
    assert carry == 0
    return total


def one(role, *pairs):
    return actual(role, [[(1, a, b)] for a, b in pairs])


def oracle(p):
    s = p.source if type(p) is Normalize else p
    code = min(127, nearest(Q(32768, s.scale))) if s.policy else 127
    low, scale = (s.scale, s.scale) if s.policy else (0, 259)
    restored, probability = code*scale, 2**s.E
    count, blocks = (1024, -(-s.n//1024)) if s.mode else (s.n, 0)
    zlocal, raw, divisor = count*probability, count*probability*restored, 2**s.drop
    rounded = nearest(Q(raw, divisor)) if s.mode else 0
    if rounded > 32767:
        raise ValueError('BlockBound')
    zmax, total = s.n*probability, blocks*rounded if s.mode else raw
    params = pack('<3HI3BH2B', s.h, s.g, s.w, s.n, s.f, s.E, s.policy, s.scale, s.mode, s.drop)
    if type(p) is Normalize:
        coefficient = Q(2)**(p.fo-s.f+s.drop)
        l, r = coefficient.numerator, coefficient.denominator
        u, dmin, d = total*l, probability*r, zmax*r
        q = min(32768, u//dmin)
        scalars = (total, 2*total, probability, zmax, l, r, u, dmin, d, q, q*d, d-1,
                   2*d-2, 32768, 65535, 131071, 65536, s.h*s.w, s.h*s.w-1, s.g*s.w, 2*max(s.n, s.h*s.w)-1)
        roles = [((1, total, l),), ((1, zmax, r),), ((1, q, d),), ((1, q*d, 1), (1, d-1, 1)),
                 ((1, d-1, 1), (1, d-1, 1), (1, 1, 1)), ((1, d-1, 2),),
                 ((1, 2*d-2, 1), (1, d-1, 1), (1, 1, 1)), ((1, d, 1), (1, d-1, 1)),
                 ((1, q, 1), (1, 1, 1)), ((1, 65535, 1), (1, 32768, 2)), ((1, 32768, 1), (1, 32768, 1))]
        schema, shifts, params = 13, (p.fo-s.f+s.drop,), params+pack('<B', p.fo)
    else:
        bias = divisor//2
        scalars = (s.h-1, s.g-1, s.w-1, s.n-1, s.h*s.w, s.g*s.w, s.h//s.g, code, low, scale,
                   restored, 2*restored, probability, count, zlocal, raw, 2*raw, zmax, blocks,
                   blocks-1 if s.mode else 0, divisor, bias, rounded, rounded*divisor, divisor-1,
                   total, 2*total, 2*max(s.n, s.h*s.w, 1024*blocks)-1)
        roles = [((1, code, scale),), ((1, 2*restored, 1), (1, restored, 2)), ((1, restored, 1), (1, restored, 1)),
                 ((count, probability, 1),), ((1, zlocal, restored),), ((count, probability, 2*restored),),
                 ((1, 2*raw, 1), (1, raw, 2)), ((1, raw, 1), (1, raw, 1)), ((1, raw, 1), (1, 1, 1))]
        if s.mode:
            roles += [((1, raw, 1), (1, bias, 1)), ((1, rounded, divisor),), ((1, rounded*divisor, 1), (1, divisor-1, 1)),
                      ((1, divisor-1, 1), (1, divisor-1, 1), (1, 1, 1)), ((1, 2*rounded, 1), (1, rounded, 2)),
                      ((1, rounded, 1), (1, rounded, 1)), ((blocks, 2*rounded, 1),), ((blocks, zlocal, 1),),
                      ((1, 2*total, 1), (1, total, 2)), ((1, total, 1), (1, total, 1)), ((1, total, 1), (1, 1, 1)),
                      ((1, blocks-1, 1024), (1, 1023, 1))]
        schema, shifts = 12, ()
    return (schema, scalars, shifts, tuple(column(t) for t in roles)), params


def dense_case(p, record, rng):
    roles, s, q = record[3], record[1][10], 2**p.E
    real = rng.choice([1, p.n, rng.randint(1, p.n)]); query = rng.randrange(real)
    end = ((p.n+1023)//1024)*1024 if p.mode else p.n
    boundaries = sorted({0, 1, query+1, real, p.n, end, rng.randrange(real+1)})
    head, channel = rng.randrange(p.h), rng.randrange(p.w)
    coordinate = (head//(p.h//p.g))*p.w+channel
    rows = []
    for lo, hi in zip(boundaries, boundaries[1:]):
        if lo == hi:
            continue
        limit = rng.choice([0, 32768, rng.randrange(32769)])
        if p.policy:
            limit = min(limit, 127*p.scale)
        pattern = [-limit, min(32767, limit), 0]
        scale = p.scale if p.policy else -(-limit//127)
        code = nearest(Q(pattern[coordinate % 3], scale)) if scale else 0
        if lo >= real:
            scale = code = 0
        probability = q if lo == 0 else rng.randrange(q+1) if lo <= query else 0
        magnitude = one(roles[0], (abs(code), scale))
        offset = s+code*scale
        assert one(roles[1], (offset, 1), (magnitude, 2*int(code < 0))) == one(roles[2], (s, 1), (magnitude, 1))
        rows.append((lo, hi, probability, offset))
    assert rows[0][0] == 0 and rows[-1][1] == end

    def local(lo, hi):
        groups = [(min(hi, b)-max(lo, a), probability, offset) for a, b, probability, offset in rows if max(lo, a) < min(hi, b)]
        z = actual(roles[3], [[(n, probability, 1) for n, probability, _ in groups]])
        base = one(roles[4], (z, s))
        a = actual(roles[5], [groups]); t = a-base; mag, sign = abs(t), int(t < 0)
        assert t == sum(n*probability*(offset-s) for n, probability, offset in groups)
        assert one(roles[6], (a, 1), (mag, 2*sign)) == one(roles[7], (base, 1), (mag, 1))
        assert one(roles[8], (mag-sign, 1), (sign, 1)) == mag
        return z, t

    if not p.mode:
        return (*local(0, end), 0)
    blocks, divisor, bias, bound = record[1][18], record[1][20], record[1][21], record[1][22]
    cuts = sorted({0, blocks, *(x//1024 for x in boundaries), *((x+1023)//1024 for x in boundaries)})
    runs = []; erased = 0
    for lo, hi in zip(cuts, cuts[1:]):
        z, t = local(1024*lo, 1024*(lo+1))
        if hi-lo > 1:
            assert local(1024*(hi-1), 1024*hi) == (z, t)
        mag, sign = abs(t), int(t < 0)
        bmag = abs(nearest(Q(t, divisor))); remainder = mag+bias-bmag*divisor
        biased = one(roles[9], (mag, 1), (bias, 1)); product = one(roles[10], (bmag, divisor))
        assert biased == one(roles[11], (product, 1), (remainder, 1))
        assert one(roles[12], (remainder, 1), (divisor-remainder-1, 1), (1, 1)) == divisor
        bvalue = (1-2*sign)*bmag; offset = bound+bvalue
        assert one(roles[13], (offset, 1), (bmag, 2*sign)) == one(roles[14], (bound, 1), (bmag, 1))
        for block in (lo, hi-1):
            assert one(roles[20], (block, 1024), (1023, 1)) == 1024*block+1023
        runs.append((hi-lo, z, offset, bvalue)); erased += (hi-lo)*int(t != 0 and bvalue == 0)
    total_offset = actual(roles[15], [[(n, offset, 1) for n, _, offset, _ in runs]])
    z = actual(roles[16], [[(n, z, 1) for n, z, _, _ in runs]])
    t = sum(n*bvalue for n, _, _, bvalue in runs); mag, sign = abs(t), int(t < 0)
    assert total_offset == record[1][25]+t
    assert one(roles[17], (total_offset, 1), (mag, 2*sign)) == one(roles[18], (record[1][25], 1), (mag, 1))
    assert one(roles[19], (mag-sign, 1), (sign, 1)) == mag
    return z, t, erased


def normalization(p, record, z, t):
    roles, s = record[3], record[1]
    assert s[2] <= z <= s[3] and abs(t) <= s[0]
    u, d = one(roles[0], (abs(t), s[4])), one(roles[1], (z, s[5]))
    q, rem = divmod(u, d); half = int(Q(rem, d) >= Q(1, 2)); mag = q+half
    y = (-1 if t < 0 else 1)*mag
    assert y == nearest(Q(t, z)*Q(2)**(p.fo-p.source.f+p.source.drop))
    if not -32768 <= y <= 32767:
        return False
    assert q <= s[9]
    product = one(roles[2], (q, d))
    assert one(roles[3], (product, 1), (rem, 1)) == u
    assert one(roles[4], (rem, 1), (d-rem-1, 1), (1, 1)) == d
    doubled = one(roles[5], (rem, 2))
    if half:
        assert one(roles[7], (d, 1), (doubled-d, 1)) == doubled
    else:
        assert one(roles[6], (doubled, 1), (d-doubled-1, 1), (1, 1)) == d
    assert one(roles[8], (q, 1), (half, 1)) == mag
    assert one(roles[9], (y+32768, 1), (mag, 2*int(t < 0))) == one(roles[10], (32768, 1), (mag, 1))
    return True


def main():
    rng, digest = Random(2678), sha256(); maxima = {}; first = {}; rejected = erased = zero_bounds = 0
    outcomes = [0, 0]; modes = [0, 0]
    for _ in range(10000):
        while True:
            h = rng.randint(1, 128); g = rng.choice([d for d in range(1, h+1) if h % d == 0])
            mode, policy = rng.randrange(2), rng.randrange(2)
            p = Weighted(h, g, rng.randint(1, 16384//h), rng.choice([1, 1 << 20, rng.randint(1, 1 << 20)]),
                         rng.randint(0, 30), rng.randint(0, 14), policy, rng.randint(1, 65535) if policy else 0,
                         mode, rng.randint(0, 62) if mode else 0)
            try:
                oracle(p)
            except ValueError as error:
                assert str(error) == 'BlockBound'; rejects(lambda: derive(p), 'BlockBound'); rejected += 1
            else:
                break
        norm = Normalize(p, rng.randint(0, 30))
        for spec in (p, norm):
            record, params = oracle(spec); assert derive(spec) == record
            data = encode(spec); expected = encoded_oracle(record, params)
            at = len(b'stele/v0.1/cqis/model-arithmetic')+7+len(params)+4
            assert data == expected[:at]+b'\x04'+expected[at+1:]
            for role in record[3]:
                actual(role, [[(n, a, b)] for n, a, b, _, _ in role[0]])
            schema = record[0]; old = maxima.get(schema, [0, 0])
            maxima[schema] = [max(old[0], len(data)), max(old[1], max(len(role[2]) for role in record[3]))]
            assert len(data) < (64000 if schema == 12 else 36000)
            first.setdefault((schema, mode), (spec, data)); digest.update(pack('<I', len(data))+data)
        z, t, lost = dense_case(p, derive(p), rng); erased += lost; modes[p.mode] += 1
        zero_bounds += p.mode == 1 and derive(p)[1][22] == 0
        outcomes[not normalization(norm, derive(norm), z, t)] += 1
    for p in (Weighted(1, 1, 16384, 1 << 20, 30, 14, 1, 65535, 0, 0),
              Weighted(1, 1, 1, 1, 0, 14, 1, 65535, 1, 62),
              Weighted(1, 1, 1, 1025, 0, 0, 1, 1, 1, 3)):
        record = derive(p); z, t, _ = dense_case(p, record, rng)
        norm = Normalize(p, 0); normalization(norm, derive(norm), z, t)
        if p.n == 1 << 20:
            assert max(record[3][5][4]+record[3][5][5]) <= 822083599
            assert derive(norm)[1][8] == 1 << 64
        if p.drop == 62:
            assert record[1][22] == 0 and t == 0
    p = Weighted(1, 1, 1, 1, 0, 0, 1, 1, 1, 0)
    rejects(lambda: derive(p), 'BlockBound')  # Full block, even though the actual single slot fits.
    norm = Normalize(replace(p, mode=0), 0); record = derive(norm)
    for z, t in ((1, -127), (1, 127), (1, 0)):
        assert normalization(norm, record, z, t)
    norm = Normalize(Weighted(1, 1, 1, 2, 0, 0, 1, 65535, 0, 0), 0)
    for t in (-32768, 32767, 32768, -32769):
        assert normalization(norm, derive(norm), 1, t) == (-32768 <= t <= 32767)
    for t in (-1, 1):
        assert normalization(norm, derive(norm), 2, t)  # Exact half ties.
    norm = Normalize(Weighted(1, 1, 1, 1024, 0, 0, 1, 1, 1, 3), 0)
    record = derive(norm)
    # One allowed P=1, original V=127: block R(127/8)=16, output 128.
    assert record[1][6]//record[1][8] == 127
    assert normalization(norm, record, 1, 16) and 16*record[1][4] == 128
    for p, data in first.values():
        validate(p, data)
        for offset in sorted({0, len(data)-1, *range(0, len(data), max(1, len(data)//48))}):
            damaged = data[:offset]+bytes([data[offset] ^ 1])+data[offset+1:]
            rejects(lambda damaged=damaged: validate(p, damaged), 'Encoding')
        for length in (0, 1, len(data)//2, len(data)-1):
            rejects(lambda length=length: validate(p, data[:length]), 'Encoding')
        rejects(lambda: validate(p, data+b'\0'), 'Encoding')
        changed = replace(p, fo=(p.fo+1) % 31) if type(p) is Normalize else replace(p, f=(p.f+1) % 31)
        rejects(lambda: validate(changed, data), 'Encoding')
    rejects(lambda: Weighted(3, 2, 1, 1, 0, 0, 0, 0, 0, 0), 'Groups')
    rejects(lambda: Weighted(1, 1, 1, 1, 0, 0, 0, 0, 0, 1), 'Drop')
    rejects(lambda: Normalize(norm.source, True), 'Fraction')
    print(json.dumps(dict(seed=2678, records_per_schema=10000, rejected_block_configurations=rejected,
                         exact_block_cases=modes, normalization_accept_reject=outcomes,
                         zero_block_bounds=zero_bounds, nonzero_blocks_rounded_zero=erased,
                         maxima_bytes_columns=maxima, corpus_sha256=digest.hexdigest()), sort_keys=True))


if __name__ == '__main__':
    main()
