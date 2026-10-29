#!/usr/bin/env python3
"""Q26: exact independent checkpoint source-format evidence, no host floats."""
from fractions import Fraction as Q
import hashlib
import json
from pathlib import Path
import random
import struct
import sys
from scalars import FORMATS, decode


def rejects(reason, call):
    try:
        call()
    except ValueError as error:
        assert str(error) == reason
    else:
        raise AssertionError(f'accepted instead of {reason}')


def value(pair):
    n, e = pair
    return Q(n)*Q(2)**e


def reference(name, raw):
    """Independent rational bit contributions, parsed in textual MSB order."""
    size, eb, fb = FORMATS[name]
    bits = ''.join(format(byte, '08b') for byte in reversed(raw))
    sign, exp, fraction = bits[0], bits[1:1+eb], bits[1+eb:]
    assert len(fraction) == fb and len(bits) == size*8
    if exp == '1'*eb:
        raise ValueError('Nonfinite')
    power = int(exp, 2)-((1 << (eb-1))-1)
    result = Q(1) if '1' in exp else Q(0)
    if '1' not in exp:
        power += 1
    for index, bit in enumerate(fraction, 1):
        if bit == '1':
            result += Q(1, 1 << index)
    return result*Q(2)**power*(-1 if sign == '1' else 1)


def encode_exact(name, x):
    """Independent inverse using rational scale selection, not decoder fields."""
    size, eb, fb = FORMATS[name]
    if not x:
        return bytes(size)
    sign, x = int(x < 0), abs(x)
    bias = (1 << (eb-1))-1
    normal_min = Q(2)**(1-bias)
    if x < normal_min:
        exponent, fraction = 0, x/Q(2)**(1-bias-fb)
    else:
        power = x.numerator.bit_length()-x.denominator.bit_length()
        if x < Q(2)**power:
            power -= 1
        assert Q(2)**power <= x < Q(2)**(power+1)
        exponent, fraction = power+bias, (x/Q(2)**power-1)*(1 << fb)
    assert fraction.denominator == 1 and 0 <= fraction < 1 << fb
    assert 0 <= exponent < (1 << eb)-1
    word = (sign << (size*8-1)) | (exponent << fb) | int(fraction)
    return word.to_bytes(size, 'little')


def report():
    cases, rng = [], random.Random(2601)
    for name, (size, eb, fb) in FORMATS.items():
        # Every sign/exponent/fraction bit pattern in both 16-bit formats.
        if size == 2:
            words = list(range(1 << 16))
        else:
            words = [rng.getrandbits(size*8) for _ in range(10000)]
            # Every exponent boundary with zero, minimal and maximal fractions.
            words += [(s << (size*8-1)) | (e << fb) | f
                      for s in (0, 1) for e in range(1 << eb)
                      for f in (0, 1, (1 << fb)-1)]
        accepted = rejected = zeros = 0
        checksum = hashlib.sha256()
        for word in words:
            raw = word.to_bytes(size, 'little')
            if ((word >> fb) & ((1 << eb)-1)) == (1 << eb)-1:
                rejects('Nonfinite', lambda: decode(name, raw))
                rejects('Nonfinite', lambda: reference(name, raw))
                checksum.update(raw+b'R'); rejected += 1
                continue
            result = decode(name, raw)
            n, e = result
            expected = reference(name, raw)
            assert value(result) == expected
            assert (result == (0, 0)) if n == 0 else (abs(n) % 2 == 1)
            assert abs(n) < 1 << (fb+1) and -1074 <= e <= 1023
            # Signed source zeros become one numerical zero; every nonzero
            # finite encoding remains exactly recoverable in its original format.
            assert encode_exact(name, expected) == (bytes(size) if n == 0 else raw)
            checksum.update(raw+b'A'+struct.pack('<qh', n, e))
            accepted += 1; zeros += n == 0
        for raw in (b'', bytes(size-1), bytes(size+1), bytearray(size), True, 0):
            rejects('Length', lambda: decode(name, raw))
        cases.append(dict(format=name, checked=len(words), accepted=accepted,
                          rejected_nonfinite=rejected, zeros=zeros, sha256=checksum.hexdigest()))
    for name in ('fp8', '', True, [], 16):
        rejects('Format', lambda: decode(name, b'\0\0'))
    # Same exact value, distinct scalar formats, identical canonical dyadic pair.
    cross = [Q(0), Q(1), Q(-1), Q(3, 2), -Q(3, 2), Q(1, 1 << 20)]
    for x in cross:
        pairs = {decode(name, encode_exact(name, x)) for name in FORMATS}
        assert len(pairs) == 1
    # Source dtype is semantic authority, not an optional decoding hint.
    assert decode('binary16', bytes.fromhex('003c')) == (1, 0)
    assert decode('bfloat16', bytes.fromhex('003c')) == (1, -7)
    return dict(version=1, scope='research scalar conversion only; quantiser/certificates remain Draft',
                cases=cases, cross_format_values=len(cross))


if __name__ == '__main__':
    result = report()
    path = Path(__file__).with_name('scalar-candidates.json')
    if sys.argv[1:] == ['--write']:
        with path.open('x') as output:
            json.dump(result, output, indent=2); output.write('\n')
    else:
        assert not sys.argv[1:] and json.loads(path.read_text()) == result
    for case in result['cases']:
        print(case['format'], case['checked'], 'exact decisions; nonfinite rejected:', case['rejected_nonfinite'])
