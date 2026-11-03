"""Exact rational/polynomial oracle for Draft RFC-0025's affine/position bounds."""
from dataclasses import replace
from fractions import Fraction as Q
from hashlib import sha256
import json
from random import Random
from struct import pack

from arithmetic_bounds import Affine, Embedding, derive, encode, validate


def caps(maximum):
    result = []
    while maximum:
        result.append(min(255, maximum))
        maximum //= 256
    return tuple(result or [0])


def column_oracle(terms):
    """Polynomial multiplication in radix 2^40 separates every raw coefficient."""
    operands = tuple((n, a, c, caps(a), caps(c)) for n, a, c in terms)
    z = sum(n*a*c for n, a, c in terms)
    size = max(len(caps(z)), *(len(a)+len(c)-1 for _, _, _, a, c in operands))
    polynomial = 0
    for n, _, _, a, c in operands:
        polynomial += n*sum(v << (40*i) for i, v in enumerate(a))*sum(v << (40*i) for i, v in enumerate(c))
    raw = tuple((polynomial >> (40*i)) % (1 << 40) for i in range(size))
    assert polynomial >> (40*size) == 0
    result = tuple(min(255, z//256**i) for i in range(size))
    carries, weighted = [0], 0
    for i in range(size-1):
        weighted += raw[i]*256**i
        carries.append(weighted//256**(i+1))
    carries.append(0)
    left = tuple(a+b for a, b in zip(raw, carries))
    right = tuple(a+256*b for a, b in zip(result, carries[1:]))
    assert all(2*x < (1 << 31)-1 for x in left+right)
    return operands, z, result, tuple(carries), left, right


def scalar_oracle(p):
    if type(p) is Affine:
        w = 2**(p.bits-1)-1
        s = p.scale if p.policy else -(-(2**30 if p.kind else 32768)//127)
        a = 127*w*p.inner
        product = a*p.mantissa
        total = product*s
        lc = Q(2)**p.exponent/Q(2)**p.fraction*Q(2)**p.output_fraction
        bc = Q(0) if p.bias_fraction is None else Q(2)**(p.output_fraction-p.bias_fraction)
        d = max(lc.denominator, bc.denominator)
        left, bias = int(lc*d), int(bc*d)
        maximum = total*left+32768*bias
        shift = (d.bit_length()-1)
        shifts = (lc.numerator.bit_length()-lc.denominator.bit_length(),
                  bc.numerator.bit_length()-bc.denominator.bit_length() if bc else 0, shift)
        scalars = (w, s, a, product, total, d, left, bias, maximum, min(32768, maximum//d),
                   32768, 4*a, 2*a, 131071, 65536)
        terms = [((1, a, p.mantissa),), ((1, product, s),),
                 ((1, 2*total, 1), (1, total, 2)), ((1, total, 1), (1, total, 1)),
                 ((1, 2*total, left),)+(((1, 65535, bias),) if bias else ())]
        metadata = (a, total, s, d, left, bias, maximum)
        schema = 1
    else:
        sources = [(p.bits, p.exponent, p.mantissa)] + ([] if p.position is None else [p.position])
        limits = tuple((2**(b-1)-1)*m for b, _, m in sources)
        coefficients = tuple(Q(2)**e*Q(2)**p.output_fraction for _, e, _ in sources)
        d = max(c.denominator for c in coefficients)
        factors = tuple(int(c*d) for c in coefficients)
        maximum = sum(a*f for a, f in zip(limits, factors))
        shifts = tuple(c.numerator.bit_length()-c.denominator.bit_length() for c in coefficients)+(d.bit_length()-1,)
        scalars = ((p.vocabulary-1, p.context-1)+limits+(d,)+factors+
                   (maximum, min(32768, maximum//d), 32768)+
                   tuple(side for a in limits for side in (4*a, 2*a))+(131071, 65536))
        terms = [((1, 2**(b-1)-1, m),) for b, _, m in sources]
        terms.append(tuple((1, 2*a, f) for a, f in zip(limits, factors)))
        metadata = (sources, limits, coefficients, d, factors, maximum)
        schema = 2
    q = min(32768, maximum//d)
    terms.extend([((1, 2*maximum, 1), (1, maximum, 2)),
                  ((1, maximum, 1), (1, maximum, 1)), ((1, q, d),),
                  ((1, q*d, 1), (1, d-1, 1)),
                  ((1, d-1, 1), (1, d-1, 1), (1, 1, 1)),
                  ((1, d-1, 2),), ((1, 2*d-2, 1), (1, d-1, 1), (1, 1, 1)),
                  ((1, d, 1), (1, d-1, 1))])
    return (schema, scalars, shifts, tuple(column_oracle(t) for t in terms)), metadata


def big(value):
    assert 0 <= value < 1 << 2304
    return pack('<72I', *((value >> (32*i)) % (1 << 32) for i in range(72)))


def encode_oracle(p, derived):
    if type(p) is Affine:
        parameters = pack('<HBhH4BIB', p.inner, p.bits, p.exponent, p.mantissa, p.kind,
                          p.fraction, p.output_fraction, p.policy, p.scale, int(p.bias_fraction is not None))
        if p.bias_fraction is not None:
            parameters += pack('<B', p.bias_fraction)
    else:
        parameters = pack('<IIBBhHB', p.vocabulary, p.context, p.output_fraction, p.bits,
                          p.exponent, p.mantissa, int(p.position is not None))
        if p.position is not None:
            parameters += pack('<BhH', *p.position)
    schema, scalars, shifts, roles = derived
    result = [b'stele/v0.1/cqis/model-arithmetic', pack('<IBH', 1, schema, len(parameters)), parameters,
              pack('<IBB', (1 << 31)-1, 8, len(scalars)), *(big(x) for x in scalars),
              pack('<B', len(shifts)), pack('<'+'h'*len(shifts), *shifts), pack('<B', len(roles))]
    for index, (terms, z, out, carries, left, right) in enumerate(roles, 1):
        result.append(pack('<BB', index, len(terms)))
        for n, a, c, ac, cc in terms:
            result.extend([pack('<I', n), big(a), big(c), pack('<HH', len(ac), len(cc)), bytes(ac), bytes(cc)])
        result.extend([big(z), pack('<H', len(out)), bytes(out),
                       pack('<'+'I'*(len(carries)+len(left)+len(right)), *(carries+left+right))])
    return b''.join(result)


def check_columns(roles):
    """Use actual maximal whole operands, not independently saturated digit caps."""
    for terms, z, output_caps, carry_caps, lhs_caps, rhs_caps in roles:
        raw = [0]*len(output_caps)
        for n, a, c, ac, cc in terms:
            left = [(a >> (8*i)) % 256 for i in range(len(ac))]
            right = [(c >> (8*i)) % 256 for i in range(len(cc))]
            for i, x in enumerate(left):
                for j, y in enumerate(right):
                    raw[i+j] += n*x*y
        carry = 0
        for i, value in enumerate(raw):
            digit = (z >> (8*i)) % 256
            assert digit <= output_caps[i]
            assert value+carry <= lhs_caps[i]
            assert (value+carry-digit) % 256 == 0
            carry = (value+carry-digit)//256
            assert 0 <= carry <= carry_caps[i+1]
            assert digit+256*carry <= rhs_caps[i]
        assert carry == 0


def check_rounding(numerator, denominator, maximum):
    assert abs(numerator) <= maximum
    q, r = divmod(abs(numerator), denominator)
    magnitude = q+int(Q(r, denominator) >= Q(1, 2))
    y = (-1 if numerator < 0 else 1)*magnitude
    if -32768 <= y <= 32767:
        assert q <= min(32768, maximum//denominator)
        assert 0 <= denominator-r-1 <= denominator-1
        gap = 2*r-denominator if 2*r >= denominator else denominator-2*r-1
        assert 0 <= gap <= denominator-1
        assert (y+32768)+2*int(numerator < 0)*magnitude == 32768+magnitude
    return -32768 <= y <= 32767


def rejects(call, reason):
    try:
        call()
    except ValueError as error:
        assert str(error) == reason, (error, reason)
    else:
        raise AssertionError(reason)


def main():
    rng, digest = Random(2673), sha256()
    counts = {'affine': [0, 0], 'embedding': [0, 0]}
    max_bytes, max_bits, max_columns = 0, 0, 0
    first = {}
    for i in range(10000):
        kind, policy = rng.randrange(2), rng.randrange(2)
        exponent = rng.choice([-1099, 1024, rng.randrange(-1099, 1025)])
        affine = Affine(rng.randrange(1, 16385), rng.choice([4, 8]), exponent, rng.randrange(1, 65536),
                        kind, rng.randrange(45 if kind else 31), rng.randrange(31), policy,
                        rng.randrange(1, (8454661 if kind else 65535)+1) if policy else 0,
                        rng.randrange(31) if rng.randrange(2) else None)
        position = (rng.choice([4, 8]), rng.choice([-1099, 1024, rng.randrange(-1099, 1025)]),
                    rng.randrange(1, 65536)) if rng.randrange(2) else None
        embedding = Embedding(rng.randrange(1, (1 << 20)+1), rng.randrange(1, (1 << 20)+1),
                              rng.randrange(31), rng.choice([4, 8]), exponent, rng.randrange(1, 65536), position)
        for name, p in [('affine', affine), ('embedding', embedding)]:
            reference, metadata = scalar_oracle(p)
            assert derive(p) == reference
            data = encode(p)
            assert data == encode_oracle(p, reference)
            check_columns(reference[3])
            if name == 'affine':
                a, total, s, d, left, bias, maximum = metadata
                scale = p.scale if p.policy else rng.randrange(s+1)
                acc = rng.randrange(-a, a+1) if scale else 0
                m = rng.randrange(1, p.mantissa+1)
                b = rng.randrange(-32768, 32768) if bias else 0
                product = acc*m*scale
                u = product*left+b*bias
                offset = (product+total)*left+(b+32768)*bias
                assert offset == u+maximum and 0 <= offset <= 2*maximum
                exact = Q(acc*m*scale)*Q(2)**(p.exponent-p.fraction+p.output_fraction)
                if bias:
                    exact += Q(b)*Q(2)**(p.output_fraction-p.bias_fraction)
                assert Q(u, d) == exact
            else:
                sources, limits, coefficients, d, factors, maximum = metadata
                products = [rng.randrange(-(2**(b-1)-1), 2**(b-1))*rng.randrange(1, m+1) for b, _, m in sources]
                u = sum(x*f for x, f in zip(products, factors))
                offset = sum((x+a)*f for x, a, f in zip(products, limits, factors))
                assert offset == u+maximum and 0 <= offset <= 2*maximum
                assert Q(u, d) == sum(x*c for x, c in zip(products, coefficients))
            accepted = check_rounding(u, d, maximum)
            counts[name][not accepted] += 1
            max_bytes = max(max_bytes, len(data))
            max_bits = max(max_bits, *(x.bit_length() for x in reference[1]))
            max_columns = max(max_columns, *(len(role[2]) for role in reference[3]))
            digest.update(pack('<I', len(data))+data)
            first.setdefault(name, (p, data))
    extreme = Embedding(1 << 20, 1 << 20, 0, 8, 1024, 65535, (8, -1099, 65535))
    extreme_reference, _ = scalar_oracle(extreme)
    assert derive(extreme) == extreme_reference
    assert max(x.bit_length() for x in extreme_reference[1]) > 2145
    assert max(len(role[2]) for role in extreme_reference[3]) == 269
    check_columns(extreme_reference[3])
    assert encode(extreme) == encode_oracle(extreme, extreme_reference)
    for p, data in first.values():
        validate(p, data)
        for offset in sorted({0, len(data)-1, *range(0, len(data), max(1, len(data)//48))}):
            damaged = data[:offset]+bytes([data[offset] ^ 1])+data[offset+1:]
            rejects(lambda damaged=damaged: validate(p, damaged), 'Encoding')
        for length in [0, 1, 32, len(data)//2, len(data)-1]:
            rejects(lambda length=length: validate(p, data[:length]), 'Encoding')
        rejects(lambda: validate(p, data+b'\0'), 'Encoding')
        changed = replace(p, output_fraction=(p.output_fraction+1) % 31)
        rejects(lambda: validate(changed, data), 'Encoding')
    rejects(lambda: validate(None, bytes((1 << 17)+1)), 'Capacity')
    rejects(lambda: replace(extreme, bits=True), 'Weight')
    rejects(lambda: replace(extreme, exponent=-1100), 'Weight')
    rejects(lambda: replace(extreme, position=(8, 1025, 1)), 'Weight')
    rejects(lambda: replace(first['affine'][0], inner=16385), 'Shape')
    rejects(lambda: replace(first['affine'][0], policy=0, scale=1), 'Scale')
    print(json.dumps({'seed': 2673, 'cases_per_schema': 10000, 'outcomes_accept_reject': counts,
                      'maximum_record_bytes': max_bytes, 'maximum_scalar_bits': max_bits,
                      'maximum_columns': max_columns, 'corpus_sha256': digest.hexdigest()}, sort_keys=True))


if __name__ == '__main__':
    main()
