"""Independent exact evidence for Draft RFC-0025 rotary/score/maximum records."""
from dataclasses import replace
from fractions import Fraction as Q
from hashlib import sha256
import json
from math import isqrt
from random import Random
from struct import pack

from attention_input_bounds import Maximum, Rotation, Score, derive, encode, validate
from check_arithmetic_bounds import check_columns, column_oracle, rejects
from check_flow_bounds import check, encoded_oracle
from check_numerics import nearest


def oracle(p):
    if type(p) is Rotation:
        h, u = 32768, 16384
        envelope = isqrt(2*u*u)+1
        maximum, size = h*envelope, p.n*p.r//2
        scalars = (p.h*p.w, p.h*p.r//2, p.h*(p.w-p.r), p.n-1, p.r//2-1, p.h-1,
                   size-1, 4*(size-1), 4*size-1, h, u, envelope, h*u, maximum,
                   u, u//2, maximum+u//2, h, u-1, h*u+u-1, h, 2*u, 2*max(p.n, p.h*p.w)-1)
        roles = [((1, p.n-1, p.r//2), (1, p.r//2-1, 1)),
                 ((1, size-1, 4),), ((1, 4*(size-1), 1), (1, 3, 1))]
        schema, shifts = 7, ()
        parameters = pack('<3HI2B', p.h, p.w, p.r, p.n, p.layout, p.f)
    elif type(p) is Score:
        def policy(mode, scale):
            return (min(127, nearest(Q(32768, scale))), scale, scale) if mode else (127, 0, 259)
        cq, qmin, sq = policy(p.qm, p.qs)
        ck, kmin, sk = policy(p.km, p.ks)
        a, shift = p.w*cq*ck, p.e-p.fq-p.fk+p.f
        pq, pk = a*sq, a*sq*sk
        pm = pk*p.m
        coefficient = Q(2)**shift
        l, d = coefficient.numerator, coefficient.denominator
        n, bias = pm*l, d//2
        b = nearest(pm*coefficient)
        if b >= 1 << 31:
            raise ValueError('ScoreBound')
        scalars = (p.h-1, p.g-1, p.w-1, p.n-1, p.h*p.w, p.g*p.w, p.h//p.g,
                   cq, ck, qmin, sq, kmin, sk, a, a+1, pq, pk, pm, l, d, bias,
                   n, b, b*d, d-1, 2*b, 2*max(p.n, p.h*p.w)-1)
        roles = [((1, a, sq),), ((1, pq, sk),), ((1, pk, p.m),), ((1, pm, l),),
                 ((1, n, 1), (1, bias, 1)), ((1, b, d),),
                 ((1, b*d, 1), (1, d-1, 1)), ((1, d-1, 1), (1, d-1, 1), (1, 1, 1)),
                 ((1, 2*b, 1), (1, b, 2)), ((1, b, 1), (1, b, 1))]
        schema, shifts = 8, (shift,)
        parameters = pack('<3HI4BHB2Hb', p.h, p.g, p.w, p.n, p.fq, p.fk, p.f, p.qm, p.qs, p.km, p.ks, p.m, p.e)
    else:
        o, u = 2*p.bound, 2**p.bits
        delta = min(o, u)
        scalars = (p.n-1, o, u, delta, 1, 2*p.n-1, u)
        roles = [((1, o, 1),), ((1, o, 1), (1, delta, 1)), ((1, o, 1),),
                 ((1, delta, 1), (1, 1, 1)), ((1, delta, 1), (1, u, 1)), ((1, u, 1),)]
        schema, shifts = 9, ()
        parameters = pack('<2I2B', p.n, p.bound, p.bits, p.f)
    return (schema, scalars, shifts, tuple(column_oracle(t) for t in roles)), parameters


def rotation_case(p, record, rng):
    position, pair, head = p.n-1, p.r//2-1, rng.randrange(p.h)
    idx = check(record[3][0], (position, p.r//2), (pair, 1))
    off = check(record[3][1], (idx, 4))
    assert idx == position*p.r//2+pair
    for lane in range(4):
        assert check(record[3][2], (off, 1), (lane, 1)) == off+lane
    left = head*p.w+(2*pair if p.layout == 0 else pair)
    right = left+(1 if p.layout == 0 else p.r//2)
    assert head*p.w <= left < right < head*p.w+p.r <= p.h*p.w
    # Rational unit-circle points test application/envelope, not configured frequencies.
    a, b = rng.randrange(1, 65536), rng.randrange(65536)
    cosine, sine = Q(a*a-b*b, a*a+b*b), Q(2*a*b, a*a+b*b)
    c, s = nearest(16384*cosine), nearest(16384*sine)
    assert abs(c) <= 16384 and abs(s) <= 16384 and abs(c)+abs(s) <= record[1][11]
    x, y = [rng.choice([-32768, 32767, rng.randrange(-32768, 32768)]) for _ in range(2)]
    outcomes = [0, 0]
    for z, exact in [(x*c-y*s, Q(x*c-y*s, 16384)), (x*s+y*c, Q(x*s+y*c, 16384))]:
        assert abs(z) <= record[1][13] and 2*abs(z) < 2147483647
        q, rem = divmod(abs(z)+8192, 16384)
        result = (-1 if z < 0 else 1)*q
        assert result == nearest(exact) and 0 <= rem < 16384
        outcomes[not -32768 <= result <= 32767] += 1
    return outcomes, idx > 2147483647


def converted_row(length, mode, configured, rng):
    limit = rng.choice([0, 32768, rng.randrange(32769)])
    if mode:
        limit = min(limit, 127*configured)
    high = min(limit, 32767)
    pattern = [-limit, high, rng.randrange(-limit, high+1)]
    scale = configured if mode else -(-limit//127)
    codes = [nearest(Q(x, scale)) if scale else 0 for x in pattern]
    assert all(-127 <= x <= 127 for x in codes)
    # The negative endpoint at position zero attains the actual complete-row bound.
    return [codes[i % 3] for i in range(length)], scale


def score_case(p, record, rng):
    qrow, qs = converted_row(p.h*p.w, p.qm, p.qs, rng)
    krow, ks = converted_row(p.g*p.w, p.km, p.ks, rng)
    head = rng.randrange(p.h)
    group = head//(p.h//p.g)
    q, k = qrow[head*p.w:(head+1)*p.w], krow[group*p.w:(group+1)*p.w]
    z = sum(x*y for x, y in zip(q, k))
    a, pq, pk, pm, l, d, bias, nmax, bound = (record[1][i] for i in (13, 15, 16, 17, 18, 19, 20, 21, 22))
    assert abs(z) <= a and abs(z)-int(z < 0) >= 0
    roles = record[3]
    query = check(roles[0], (abs(z), qs))
    key = check(roles[1], (query, ks))
    product = check(roles[2], (key, p.m))
    numerator = check(roles[3], (product, l))
    biased = check(roles[4], (numerator, 1), (bias, 1))
    quotient, remainder = divmod(biased, d)
    qd = check(roles[5], (quotient, d))
    assert check(roles[6], (qd, 1), (remainder, 1)) == biased
    assert check(roles[7], (remainder, 1), (d-remainder-1, 1), (1, 1)) == d
    output = (-1 if z < 0 else 1)*quotient
    assert abs(output) <= bound
    assert check(roles[8], (output+bound, 1), (quotient, 2*int(z < 0))) == check(roles[9], (bound, 1), (quotient, 1))
    assert output == nearest(z*qs*ks*p.m*Q(2)**(p.e-p.fq-p.fk+p.f))
    return qs == 0 or ks == 0


def maximum_case(p, groups, query, record):
    assert sum(n for n, _ in groups) == p.n and 0 <= query < p.n
    intervals, start = [], 0
    for count, score in groups:
        assert count > 0 and abs(score) <= p.bound
        intervals.append((start, start+count-1, score)); start += count
    allowed = [(start, score) for start, _, score in intervals if start <= query]
    m = max(score for _, score in allowed)
    selected = next(start for start, score in allowed if score == m)
    if any(m-score > 2**p.bits for _, score in allowed):
        return False
    roles = record[3]
    mo = check(roles[0], (m+p.bound, 1))
    assert mo == next(score+p.bound for start, end, score in intervals if start <= selected <= end)
    for start, end, score in intervals:
        positions = {start, end, *(x for x in (query, query+1, selected-1, selected) if start <= x <= end)}
        for j in positions:
            bit = int(j <= query)
            delta = m-score if bit else 0
            gap = delta-int(bit and j < selected)
            index = bit*((1 << p.bits)-delta)
            assert 0 <= delta <= record[1][3] and 0 <= gap <= record[1][3]
            assert check(roles[1], (score+p.bound, bit), (delta, 1)) == check(roles[2], (mo, bit))
            assert check(roles[3], (gap, 1), (int(bit and j < selected), 1)) == delta
            assert check(roles[4], (delta, 1), (index, 1)) == check(roles[5], (1 << p.bits, bit))
            assert index == ((1 << p.bits)+score-m if bit else 0)
    return True


def main():
    rng, digest = Random(2676), sha256()
    maxima, first = {}, {}
    rotations, maximum_outcomes, over_field_indices = [0, 0], [0, 0], 0
    rejected_scores = zero_scores = zero_score_bounds = 0
    for _ in range(10000):
        h = rng.choice([1, 128, rng.randrange(1, 129)])
        w = rng.randrange(2, 16384//h+1)
        r = 2*rng.randrange(1, w//2+1)
        n = rng.choice([1, 1 << 20, rng.randrange(1, (1 << 20)+1)])
        rotation = Rotation(h, w, r, n, rng.randrange(2), rng.randrange(31))
        while True:
            g = rng.choice([d for d in range(1, h+1) if h % d == 0])
            qm, km = rng.randrange(2), rng.randrange(2)
            score = Score(h, g, w, n, rng.randrange(31), rng.randrange(31), rng.randrange(31),
                          qm, rng.randrange(1, 65536) if qm else 0, km, rng.randrange(1, 65536) if km else 0,
                          rng.randrange(1, 65536), rng.randrange(-62, 31))
            try:
                oracle(score)
                break
            except ValueError as error:
                assert str(error) == 'ScoreBound'
                rejects(lambda: derive(score), 'ScoreBound')
                rejected_scores += 1
        maximum = Maximum(n, rng.choice([0, (1 << 31)-1, rng.randrange(1 << 31)]), rng.randrange(7, 32), rng.randrange(31))
        for p in (rotation, score, maximum):
            record, parameters = oracle(p)
            assert derive(p) == record
            data = encode(p)
            assert data == encoded_oracle(record, parameters)
            check_columns(record[3])
            schema = record[0]
            maxima.setdefault(schema, [0, 0])
            maxima[schema] = [max(maxima[schema][0], len(data)), max(maxima[schema][1], *(len(role[2]) for role in record[3]))]
            if type(p) is Rotation:
                found, wide = rotation_case(p, record, rng)
                rotations = [a+b for a, b in zip(rotations, found)]; over_field_indices += wide
            elif type(p) is Score:
                zero_scores += score_case(p, record, rng)
                zero_score_bounds += record[1][22] == 0
            else:
                a = rng.randrange(n+1); b = rng.randrange(n-a+1)
                groups = [(count, rng.randrange(-p.bound, p.bound+1)) for count in (a, b, n-a-b) if count]
                maximum_outcomes[not maximum_case(p, groups, rng.randrange(n), record)] += 1
            digest.update(pack('<I', len(data))+data)
            first.setdefault(schema, (p, data))
    extremes = [Rotation(1, 16384, 16384, 1 << 20, 1, 30),
                Score(1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0),
                Score(1, 1, 16384, 1 << 20, 30, 30, 0, 1, 65535, 1, 65535, 65535, -62),
                Maximum(2, (1 << 31)-1, 31, 0)]
    for p in extremes:
        record, parameters = oracle(p)
        assert derive(p) == record and encode(p) == encoded_oracle(record, parameters)
        check_columns(record[3])
        if type(p) is Rotation:
            assert record[1][6] == (1 << 33)-1 and record[1][8] == (1 << 35)-1
        elif type(p) is Score and p.w == 1:
            bound = record[1][22]
            assert 2147483647 < 2*bound < (1 << 32)
            wrong = check(record[3][8], (2*bound-2147483647, 1), (bound, 0))
            expected = check(record[3][9], (bound, 1), (bound, 1))
            assert wrong != expected and (wrong-expected) % 2147483647 == 0
        elif type(p) is Maximum:
            assert maximum_case(p, [(1, -p.bound), (1, 0)], 1, record)
            assert (1 << 31)-p.bound == 1 and ((1 << 31)-1) % 2147483647 == 0
    rejects(lambda: derive(Score(1, 1, 16384, 1, 0, 0, 30, 0, 0, 0, 0, 65535, 30)), 'ScoreBound')
    for p, data in first.values():
        validate(p, data)
        for offset in sorted({0, len(data)-1, *range(0, len(data), max(1, len(data)//48))}):
            damaged = data[:offset]+bytes([data[offset] ^ 1])+data[offset+1:]
            rejects(lambda damaged=damaged: validate(p, damaged), 'Encoding')
        for length in (0, 1, 32, len(data)//2, len(data)-1):
            rejects(lambda length=length: validate(p, data[:length]), 'Encoding')
        rejects(lambda: validate(p, data+b'\0'), 'Encoding')
        rejects(lambda: validate(replace(p, f=(p.f+1) % 31), data), 'Encoding')
    rejects(lambda: Rotation(1, 2, 0, 1, 0, 0), 'Rotation')
    rejects(lambda: Rotation(1, 4, 3, 1, 0, 0), 'Rotation')
    rejects(lambda: Score(3, 2, 4, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0), 'Groups')
    rejects(lambda: Maximum(1, 0, 32, 0), 'Domain')
    rejects(lambda: Maximum(1, 0, 31, True), 'Fraction')
    print(json.dumps(dict(seed=2676, records_per_schema=10000, rejected_score_configurations=rejected_scores,
                         rotation_coordinate_accept_reject=rotations, sampled_pair_zero_scales=zero_scores,
                         zero_score_bounds=zero_score_bounds,
                         maximum_domain_accept_reject=maximum_outcomes, rotation_indices_above_field=over_field_indices,
                         maxima_bytes_columns=maxima, corpus_sha256=digest.hexdigest()), sort_keys=True))


if __name__ == '__main__':
    main()
