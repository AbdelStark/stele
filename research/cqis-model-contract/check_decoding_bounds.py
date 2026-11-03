"""Independent integer/rational/framing evidence for Draft RFC-0025 schemas15–17."""
from dataclasses import replace
from fractions import Fraction as Q
from hashlib import sha256
import json
from math import gcd
from random import Random
from struct import pack

from check_arithmetic_bounds import check_columns, column_oracle, rejects
from check_decoding import oracle as selection_oracle
from check_flow_bounds import check, encoded_oracle
from check_layernorm_bounds import actual
from check_numerics import nearest
from decoding import select, temperature
from decoding_bounds import Logits, Sampling, Temperature, derive, encode, validate
from function_bounds import Exponential


def oracle(p):
    if type(p) is Logits:
        v = p.v
        scalars = (32768, 65535, v-1, 2**((v-1).bit_length()), 2**((v-1).bit_length()+1)-1)
        terms = [((1, 65535, 1), (1, 65535, 1)), ((1, 65535, 1), (1, 1, 1)),
                 ((1, 65535, 1), (1, 32768, 2)), ((1, 32768, 1), (1, 32768, 1))]
        schema, params = 15, pack('<IB', v, p.fl)
    elif type(p) is Temperature:
        e = p.exp
        coefficient = Q(p.td, p.tn)*Q(2)**(e.F-p.fl)
        d = p.tn*2**p.fl
        pre, n = 65535*p.td, 65535*p.td*2**e.F
        bias = d//2
        rounded = nearest(65535*coefficient)
        q = min(2**e.bits, rounded)
        scalars = (65535, pre, 2**e.F, n, d, bias, n+bias, 2**e.bits, q, q*d,
                   d-1, e.n-1, 2**((e.n-1).bit_length()), 2**((e.n-1).bit_length()+1)-1)
        terms = [((1, 65535, p.td),), ((1, pre, 2**e.F),),
                 ((1, n, 1), (1, bias, 1)), ((1, q, d),),
                 ((1, q*d, 1), (1, d-1, 1)), ((1, d-1, 1), (1, d-1, 1), (1, 1, 1)),
                 ((1, q, 1), (1, 2**e.bits, 1))]
        params = pack('<IBII4B', e.n, p.fl, p.tn, p.td, e.bits, e.F, e.E, e.mode)
        if e.mode:
            params += pack('<B', e.k)
        schema = 16
    else:
        v, q, j = p.v, 2**p.E, 2**32
        mass = v*q
        threshold, upper = mass*p.pn, mass*p.pd
        scalars = (q, mass, j, j-1, threshold, upper, j*mass, mass-1, v-1,
                   2**((v-1).bit_length()), 2**((v-1).bit_length()+1)-1, 255, 2**24)
        terms = [((v, q, 1),), ((1, q, 1), (1, q, 1)),
                 ((1, v-1, 1), (1, v-1, 1), (1, 1, 1)), ((1, v-1, 1),),
                 ((1, mass, 1), (1, q, 1)), ((1, mass, p.pn),),
                 ((1, mass, p.pd),), ((1, mass, p.pd),),
                 ((1, threshold, 1), (1, upper, 1)),
                 ((1, upper, 1), (1, threshold-1, 1), (1, 1, 1)),
                 ((1, mass, 1),), ((1, mass, j),), ((1, j, mass),),
                 ((1, j*mass, 1), (1, mass-1, 1)),
                 ((1, mass-1, 1), (1, mass-1, 1), (1, 1, 1)), ((1, mass, 1),),
                 ((1, j, 1), (1, j-1, 1)),
                 ((1, j-1, 1), (1, j-1, 1), (1, 1, 1)),
                 tuple((1, 255, 256**i) for i in range(4))]
        schema, params = 17, pack('<IBII', v, p.E, p.pn, p.pd)
    return (schema, scalars, (), tuple(column_oracle(t) for t in terms)), params


def logits_witness(p, values, record):
    assert len(values) == p.v
    maximum = max(values); first = values.index(maximum)
    roles = record[3]
    for j, x in enumerate(values):
        assert -32768 <= x <= 32767
        delta, before = maximum-x, int(j < first)
        assert check(roles[0], (x+32768, 1), (delta, 1)) == maximum+32768
        assert check(roles[1], (delta-before, 1), (before, 1)) == delta
        assert check(roles[2], (x+32768, 1), (abs(x), 2*int(x < 0))) == check(roles[3], (32768, 1), (abs(x), 1))
    assert values[first] == maximum
    return first


def temperature_witness(p, values, record):
    roles, e = record[3], p.exp
    d, bias = p.tn*2**p.fl, (p.tn*2**p.fl)//2
    expected = [nearest(Q(x-max(values))*Q(p.td, p.tn)*Q(2)**(e.F-p.fl)) for x in values]
    accepted = min(expected) >= -2**e.bits
    for x, z in zip(values, expected):
        pre = check(roles[0], (max(values)-x, p.td))
        n = check(roles[1], (pre, 2**e.F))
        biased = check(roles[2], (n, 1), (bias, 1))
        quotient, rem = divmod(biased, d)
        assert -quotient == z
        if quotient <= 2**e.bits:
            product = check(roles[3], (quotient, d))
            assert check(roles[4], (product, 1), (rem, 1)) == biased
            assert check(roles[5], (rem, 1), (d-rem-1, 1), (1, 1)) == d
            assert check(roles[6], (quotient, 1), (2**e.bits-quotient, 1)) == 2**e.bits
    call = lambda: temperature(values, p.fl, p.tn, p.td, e.F, e.bits)
    if accepted:
        assert call() == expected
    else:
        rejects(call, 'ExpDomain')
    return accepted, sum(x != max(values) and z == 0 for x, z in zip(values, expected))


def sampling_witness(p, weights, draw, record):
    assert len(weights) == p.v and max(weights) == 2**p.E
    got = select(weights, p.pn, p.pd, draw)
    assert got == selection_oracle(weights, p.pn, p.pd, draw)
    token, order, cdf = got
    roles, total = record[3], sum(weights)
    assert actual(roles[0], [[(1, w, 1) for w in weights]]) == total
    inverse = [order.index(j) for j in range(p.v)]
    assert all(0 <= inverse[j] < p.v and order[inverse[j]] == j for j in range(p.v))
    prefixes = []; running = 0
    for r, token_id in enumerate(order):
        running = check(roles[4], (running, 1), (weights[token_id], 1))
        prefixes.append(running)
        if r+1 < p.v:
            following = order[r+1]
            diff = weights[token_id]-weights[following]; tie = int(diff == 0)
            assert check(roles[1], (weights[following], 1), (diff, 1)) == weights[token_id]
            gap = tie*(following-token_id-1)
            assert check(roles[2], (token_id, tie), (gap, 1), (tie, 1)) == check(roles[3], (following, tie))
    assert running == total
    k = len(cdf); mass, prior = prefixes[k-1], prefixes[k-2] if k > 1 else 0
    threshold = check(roles[5], (total, p.pn))
    top, prev = check(roles[6], (mass, p.pd)), check(roles[7], (prior, p.pd))
    assert check(roles[8], (threshold, 1), (top-threshold, 1)) == top
    assert check(roles[9], (prev, 1), (threshold-prev-1, 1), (1, 1)) == threshold
    assert 2**p.E <= mass <= total and weights[order[k-1]] > 0
    for r, prefix in enumerate(prefixes):
        active = int(r < k); c = cdf[r] if active else 0
        selected_prefix = check(roles[10], (prefix, active))
        numerator = check(roles[11], (selected_prefix, 2**32))
        product = check(roles[12], (c, mass)); rem = numerator-product
        assert check(roles[13], (product, 1), (rem, 1)) == numerator
        gap = active*(mass-1)-rem
        assert check(roles[14], (rem, 1), (gap, 1), (active, 1)) == check(roles[15], (mass, active))
    selected = inverse[token]; lower = cdf[selected-1] if selected else 0
    assert selected < k and cdf[-1] == 2**32
    assert check(roles[16], (lower, 1), (draw-lower, 1)) == draw
    assert check(roles[17], (draw, 1), (cdf[selected]-draw-1, 1), (1, 1)) == cdf[selected]
    assert check(roles[18], *((byte, 256**i) for i, byte in enumerate(draw.to_bytes(4, 'little')))) == draw
    return sum(a == b for a, b in zip((0,)+cdf[:-1], cdf)), p.v-k


def boundaries():
    for values in ([-32768], [32767, 32767], [-32768, 32767, 32767], [0, -32768, 0]):
        p = Logits(len(values), 30); assert logits_witness(p, values, derive(p)) == values.index(max(values))
    for p, values in ((Temperature(0, 2, 1, Exponential(2, 7, 0, 0, 0)), [0, -1]),
                      (Temperature(0, 1, 1, Exponential(2, 7, 0, 14, 0)), [0, -128]),
                      (Temperature(0, 1, 1, Exponential(2, 7, 0, 14, 0)), [0, -129]),
                      (Temperature(30, 2**32-1, 1, Exponential(2, 31, 0, 0, 1, 16)), [-32768, 32767]),
                      (Temperature(0, 1, 2**32-1, Exponential(2, 31, 30, 14, 1, 16)), [-32768, 32767])):
        assert derive(p) == oracle(p)[0]; temperature_witness(p, values, derive(p))
    for weights, pn, pd, draw in (([1], 1, 1, 2**32-1), ([8, 8, 0], 1, 2, 0),
                                 ([1, 1], 1, 1, 2**31), ([0, 4, 4, 1], 1, 1, 2**32-1)):
        p = Sampling(len(weights), max(weights).bit_length()-1, pn, pd)
        sampling_witness(p, weights, draw, derive(p))
    v, q = 2**20, 2**14
    p = Sampling(v, 14, 1, 1); record, params = oracle(p)
    assert derive(p) == record and encode(p) == encoded_oracle(record, params)
    check_columns(record[3])
    weights = [q]*(v-2)+[1, 1]
    selected, order, cdf = select(weights, 1, 1, 2**32-1)
    total = (v-2)*q+2
    # Full linear fixture oracle: no quadratic rank calculation at full vocabulary.
    assert order == tuple(range(v)) and selected == v-1 and len(cdf) == v
    assert all(c == (2**32*min((r+1)*q, total-2)+2**32*max(0, r-(v-3)))//total for r, c in enumerate(cdf))
    assert cdf[-3:] == (2**32-1, 2**32-1, 2**32)
    assert actual(record[3][0], [[(v-2, q, 1), (2, 1, 1)]]) == total
    assert check(record[3][12], (cdf[-1], total)) == total*2**32
    assert check(record[3][17], (2**32-1, 1), (0, 1), (1, 1)) == 2**32
    assert check(record[3][18], *((255, 256**i) for i in range(4))) == 2**32-1
    assert (2**32-1) % 2147483647 == 1 and 2**32 % 2147483647 == 2
    # Config-wide maxima are checked independently of the smaller witness cases.
    for p in (Logits(v, 30), Temperature(30, 2**32-1, 2**32-2, Exponential(v, 31, 30, 14, 1, 16)),
              Sampling(v, 14, 2**32-2, 2**32-1)):
        record, params = oracle(p)
        assert derive(p) == record and encode(p) == encoded_oracle(record, params)
        check_columns(record[3])
    return dict(vocabulary=v, empty_bucket_rank=v-2, final_endpoint=2**32)


def main():
    rng, digest = Random(2680), sha256(); maxima = {15: [0, 0], 16: [0, 0], 17: [0, 0]}
    outcomes = [0, 0]; zeros = empty = unretained = 0; first = {}
    for _ in range(10000):
        v, fl = rng.randint(1, 32), rng.randint(0, 30)
        values = [rng.choice([-32768, 32767, 0, rng.randrange(-32768, 32768)]) for _ in range(v)]
        tn, td = rng.randint(1, 2**32-1), rng.randint(1, 2**32-1)
        common = gcd(tn, td); tn //= common; td //= common
        mode = rng.randrange(3); bits = rng.randint(7, 31 if mode == 1 else 15)
        e = Exponential(v, bits, rng.randrange(31), rng.randrange(15), mode,
                        rng.randint(max(1, bits-15), min(16, bits)) if mode else 0)
        pd = rng.randint(1, 2**32-1); pn = rng.randint(1, pd)
        common = gcd(pn, pd); pn //= common; pd //= common
        for p in (Logits(v, fl), Temperature(fl, tn, td, e), Sampling(v, e.E, pn, pd)):
            record, params = oracle(p); assert derive(p) == record
            data = encode(p); assert data == encoded_oracle(record, params)
            check_columns(record[3]); schema = record[0]
            assert len(data) < {15: 12000, 16: 20000, 17: 40000}[schema]
            maxima[schema] = [max(maxima[schema][0], len(data)), max(maxima[schema][1], max(len(r[2]) for r in record[3]))]
            digest.update(pack('<I', len(data))+data); first.setdefault(schema, (p, data))
            if schema == 15:
                logits_witness(p, values, record)
            elif schema == 16:
                accepted, zero = temperature_witness(p, values, record)
                outcomes[int(not accepted)] += 1; zeros += zero
            else:
                weights = [rng.randrange(2**e.E+1) for _ in range(v)]
                weights[rng.randrange(v)] = 2**e.E
                a, b = sampling_witness(p, weights, rng.randrange(2**32), record)
                empty += a; unretained += b
    full = boundaries()
    for schema, (p, data) in first.items():
        validate(p, data)
        for offset in sorted({0, len(data)-1, *range(0, len(data), max(1, len(data)//64))}):
            damaged = data[:offset]+bytes([data[offset] ^ 1])+data[offset+1:]
            rejects(lambda damaged=damaged: validate(p, damaged), 'Encoding')
        for length in (0, 1, 32, len(data)//2, len(data)-1):
            rejects(lambda length=length: validate(p, data[:length]), 'Encoding')
        rejects(lambda: validate(p, data+b'\0'), 'Encoding')
        rejects(lambda: validate(p, bytearray(data)), 'Capacity')
        rejects(lambda: validate(p, bytes((1 << 17)+1)), 'Capacity')
        changed = replace(p, E=(p.E+1) % 15) if schema == 17 else replace(p, fl=(p.fl+1) % 31)
        rejects(lambda: validate(changed, data), 'Encoding')
    rejects(lambda: Logits(0, 0), 'Vocabulary')
    rejects(lambda: Logits(2**20+1, 0), 'Vocabulary')
    rejects(lambda: Logits(1, True), 'Fraction')
    rejects(lambda: Temperature(0, 2, 2, e), 'Rational')
    rejects(lambda: Temperature(0, 0, 1, e), 'Rational')
    rejects(lambda: Temperature(0, 1, 1, None), 'Parameters')
    rejects(lambda: Sampling(1, 15, 1, 1), 'Fraction')
    rejects(lambda: Sampling(1, 0, 2, 1), 'Rational')
    rejects(lambda: Sampling(1, 0, 1, 2**32), 'Rational')
    print(json.dumps(dict(seed=2680, configurations_per_schema=10000, temperature_accept_reject=outcomes,
                         nonmaximum_logits_rounded_zero=zeros, empty_buckets=empty, unretained_ranks=unretained,
                         maxima_bytes_columns=maxima, full_vocabulary=full, corpus_sha256=digest.hexdigest()), sort_keys=True))


if __name__ == '__main__':
    main()
