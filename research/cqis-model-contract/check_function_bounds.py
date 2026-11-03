"""Exact columns/framing/source arithmetic for Draft RFC-0025 schemas 10/11."""
from dataclasses import replace
from fractions import Fraction as Q
from hashlib import sha256
import json
from pathlib import Path
from random import Random
from struct import pack
import sys

from check_arithmetic_bounds import check_columns, column_oracle, rejects
from check_flow_bounds import check, encoded_oracle
from function_bounds import Activation, Exponential, derive, encode, validate

sys.path.insert(0, str(Path(__file__).resolve().parents[1]/'cqis-tables'))
from certified_exp import certify as exp_entry
from certified_activations import Parameters, certify as activation_entry


def oracle(p):
    def power_rows(n):
        return 2**((n-1).bit_length())

    if type(p) is Exponential:
        u, q = 2**p.bits, 2**p.E
        h, low = (2**(p.bits-p.k), 2**p.k-1) if p.mode else (0, 0)
        rows = [u+1] if p.mode == 0 else [h+1, low+1]+([u+1] if p.mode == 2 else [])
        a = power_rows(p.n)
        scalars = [u, q, q*q, q-1, h, low, len(rows), 2*u, q*q+q-1, q+3, 2*q-1,
                   p.n-1, a, 2*a-1, 62]
        terms = [((1, u, 1), (1, u, 1)), ((1, u, 1),)]
        if p.mode:
            terms += [((1, h, 2**p.k), (1, low, 1)), ((1, q, q),), ((1, q, q),),
                      ((1, q*q, 1), (1, q-1, 1)), ((1, q-1, 1), (1, q-1, 1), (1, 1, 1))]
        if p.mode == 2:
            terms += [((1, q, 1), (1, 3, 1)), ((1, q, 1), (1, 1, 1))]
        parameters = pack('<I4B', p.n, p.bits, p.F, p.E, p.mode)+(pack('<B', p.k) if p.mode else b'')
        schema = 10
    else:
        a = power_rows(p.d)
        scalars = [p.d-1, a, 2*a-1, 32768, 65535, 65536, 98303, 131071, 2**32-1, 65535*65536]
        rows = [65536]
        terms = [((1, 65535, 1), (1, 32768, 1)), ((1, 65535, 1), (1, 1, 65536)),
                 ((1, 65535, 1), (1, 1, 65535*65536))]
        parameters = pack('<H3B', p.d, p.kind, p.F, p.E)
        if p.kind == 2:
            parameters += pack('<HB', p.cap_m, p.cap_f)
        schema = 11
    for n in rows:
        padded = power_rows(n)
        scalars += [n, padded, n-1, padded-1, 8*padded, 62+8*padded]
        terms += [((1, padded-1, 8),), ((1, 8*(padded-1), 1), (1, 7, 1), (1, 62, 1))]
    return (schema, tuple(scalars), (), tuple(column_oracle(t) for t in terms)), parameters, rows


def address(record, start, component, row, lane):
    roles = record[3]
    offset = check(roles[start+2*component], (row, 8))
    result = check(roles[start+2*component+1], (offset, 1), (lane, 1), (62, 1))
    assert result == 62+8*row+lane
    return result


def exp_case(p, record, delta, sigma):
    roles, u, q = record[3], 2**p.bits, 2**p.E
    delta = delta if sigma else 0
    index = sigma*u-delta
    assert check(roles[0], (delta, 1), (index, 1)) == check(roles[1], (u, sigma))
    # Certified point entries are data for recombination, not whole-table admission.
    direct = exp_entry(Q(delta, 2**p.F), p.E)['value'] if sigma else 0
    correction = None
    if p.mode:
        h, low = divmod(delta, 2**p.k)
        assert check(roles[2], (h, 2**p.k), (low, 1)) == delta
        assert h <= sigma*2**(p.bits-p.k) and low <= sigma*(2**p.k-1)
        assert h != 2**(p.bits-p.k) or low == 0
        high_value = exp_entry(Q(h*2**p.k, 2**p.F), p.E)['value'] if sigma else 0
        low_value = exp_entry(Q(low, 2**p.F), p.E)['value'] if sigma else 0
        exact_product = Q(high_value*low_value, q)
        quotient = exact_product.numerator//exact_product.denominator
        remainder = high_value*low_value-quotient*q
        gap = sigma*(q-1)-remainder
        product = check(roles[3], (high_value, low_value))
        scaled = check(roles[4], (quotient, q))
        assert product == check(roles[5], (scaled, 1), (remainder, 1))
        assert check(roles[6], (remainder, 1), (gap, 1), (sigma, 1)) == sigma*q
        assert 0 <= quotient <= sigma*q and 0 <= remainder <= sigma*(q-1)
        output, indices, start = quotient, [h, low], 7
        if p.mode == 2:
            correction = direct-quotient
            coff = correction+sigma
            assert 0 <= coff <= 3*sigma
            assert check(roles[7], (quotient, 1), (coff, 1)) == check(roles[8], (direct, 1), (sigma, 1))
            output, indices, start = direct, indices+[index], 9
    else:
        output, indices, start = direct, [index], 2
    assert sigma or output == 0
    assert delta or output == sigma*q
    for component, row in enumerate(indices):
        address(record, start, component, row, 7)
    return correction, output


def activation_case(p, record, t):
    names = ('sigmoid', 'silu', 'softcap', 'gelu', 'gelu_tanh')
    config = Parameters(names[p.kind], p.F, p.E, p.cap_m, p.cap_f)
    try:
        y = activation_entry(config, t)['value']
    except ValueError as error:
        assert str(error) in ('Overflow', 'Precision')
        return str(error)
    for signed in (t, y):
        raw16 = int.from_bytes(pack('<h', signed), 'little')
        raw32 = int.from_bytes(pack('<i', signed), 'little')
        sign, offset = int(signed < 0), signed+32768
        left = check(record[3][0], (raw16, 1), (32768, 1))
        assert left == check(record[3][1], (offset, 1), (sign, 65536))
        assert raw32 == check(record[3][2], (raw16, 1), (sign, 65535*65536))
        assert raw16-65536*sign == offset-32768 == signed
        if sign:
            assert raw32 % 2147483647 != signed % 2147483647
    address(record, 3, 0, t+32768, 7)
    return 'admitted_point'


def boundaries():
    for mode in range(3):
        p = Exponential(1 << 20, 15 if mode != 1 else 31, 30, 14, mode, 0 if mode == 0 else 16 if mode == 1 else 7)
        record, params, rows = oracle(p)
        assert derive(p) == record and encode(p) == encoded_oracle(record, params)
        for sigma in (0, 1):
            for delta in (0, 1, 2**p.bits-1, 2**p.bits):
                exp_case(p, record, delta, sigma)
        start = (2, 7, 9)[mode]
        for component, count in enumerate(rows):
            padded = 2**((count-1).bit_length())
            assert address(record, start, component, padded-1, 7) == 62+8*padded-1
            # Real membership ends before canonical padding, even for all-zero rows.
            assert count-1 < count and (padded == count or count < padded)
        if mode == 1:
            wrong = check(record[3][0], (1, 1), (0, 1))
            expected = check(record[3][1], (2**31, 1))
            assert wrong != expected and (wrong-expected) % 2147483647 == 0
            assert 2**p.bits+1 > 2**31 and max(rows) <= 65536
    for kind in range(5):
        p = Activation(16384, kind, 0, 0, 3 if kind == 2 else 0, 0)
        record, _, _ = oracle(p)
        for t in (-32768, -1, 0, 1, 32767):
            assert activation_case(p, record, t) == 'admitted_point'
        assert address(record, 3, 0, 65535, 7) == 524349
    # A successful input-zero lookup cannot admit the whole overflowing table.
    for kind in (1, 3, 4):
        p = Activation(1, kind, 0, 14)
        assert activation_case(p, derive(p), 0) == 'admitted_point'
        assert activation_case(p, derive(p), 32767) == 'Overflow'
    assert activation_entry(Parameters('sigmoid', 0, 0), 0)['value'] == 1


def main():
    rng, digest = Random(2677), sha256()
    maxima, first, corrections = {}, {}, set()
    modes, kinds, outcomes = [0]*3, [0]*5, {}
    masked, zero_remainder_configs = 0, 0
    for i in range(10000):
        mode = rng.randrange(3)
        bits = rng.randint(7, 31 if mode == 1 else 15)
        k = rng.randint(max(1, bits-15), min(16, bits)) if mode else 0
        exp = Exponential(rng.choice([1, 1 << 20, rng.randint(1, 1 << 20)]), bits,
                          rng.randint(0, 30), rng.randint(0, 14), mode, k)
        kind = rng.randrange(5)
        cap_f = rng.randint(0, 30) if kind == 2 else 0
        act = Activation(rng.choice([1, 16384, rng.randint(1, 16384)]), kind,
                         rng.randint(0, 30), rng.randint(0, 14),
                         rng.randrange(1, 65536, 2) if kind == 2 else 0, cap_f)
        for p in (exp, act):
            record, parameters, _ = oracle(p)
            assert derive(p) == record
            data = encode(p)
            assert data == encoded_oracle(record, parameters)
            check_columns(record[3])
            schema = record[0]
            maxima[schema] = [max(maxima.get(schema, [0, 0])[0], len(data)),
                              max(maxima.get(schema, [0, 0])[1], max(len(role[2]) for role in record[3]))]
            assert len(data) < (42000 if schema == 10 else 16000)
            digest.update(pack('<I', len(data))+data)
            first.setdefault((schema, p.mode if schema == 10 else p.kind), (p, data))
            if type(p) is Exponential:
                modes[p.mode] += 1
                sigma = int(i % 7 != 0)
                masked += not sigma
                zero_remainder_configs += p.E == 0 and p.mode != 0
                correction, _ = exp_case(p, record, rng.choice([0, 1, 2**p.bits, rng.randrange(2**p.bits+1)]), sigma)
                if correction is not None:
                    corrections.add(correction)
            else:
                kinds[p.kind] += 1
                result = activation_case(p, record, rng.choice([-32768, 32767, 0, rng.randrange(-32768, 32768)]))
                outcomes[result] = outcomes.get(result, 0)+1
    boundaries()
    for p, data in first.values():
        validate(p, data)
        for offset in sorted({0, len(data)-1, *range(0, len(data), max(1, len(data)//48))}):
            damaged = data[:offset]+bytes([data[offset] ^ 1])+data[offset+1:]
            rejects(lambda damaged=damaged: validate(p, damaged), 'Encoding')
        for length in (0, 1, 32, len(data)//2, len(data)-1):
            rejects(lambda length=length: validate(p, data[:length]), 'Encoding')
        rejects(lambda: validate(p, data+b'\0'), 'Encoding')
        rejects(lambda: validate(replace(p, F=(p.F+1) % 31), data), 'Encoding')
        rejects(lambda: validate(p, bytearray(data)), 'Capacity')
        rejects(lambda: validate(p, bytes((1 << 17)+1)), 'Capacity')
    rejects(lambda: Exponential(1, 31, 0, 0, 0), 'Domain')
    rejects(lambda: Exponential(1, 31, 0, 0, 2, 16), 'Domain')
    rejects(lambda: Exponential(1, 14, 0, 0, 0, 7), 'Split')
    rejects(lambda: Exponential(1, 31, 0, 0, 1, 15), 'Split')
    rejects(lambda: Exponential(1, 31, True, 0, 1, 16), 'Fraction')
    rejects(lambda: Activation(16385, 1, 0, 0), 'Shape')
    rejects(lambda: Activation(1, 2, 0, 0, 2, 1), 'Cap')
    rejects(lambda: Activation(1, 1, 0, 0, 1, 0), 'Cap')
    rejects(lambda: Activation(1, 5, 0, 0), 'Kind')
    print(json.dumps(dict(seed=2677, records_per_schema=10000, exponential_modes=modes,
                         activation_kinds=kinds, activation_point_outcomes=outcomes,
                         masked_exp_cases=masked, unit_exp_output_scale_configs=zero_remainder_configs,
                         sampled_corrections=sorted(corrections), maxima_bytes_columns=maxima,
                         corpus_sha256=digest.hexdigest()), sort_keys=True))


if __name__ == '__main__':
    main()
