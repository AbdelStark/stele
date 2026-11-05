"""RFC-0025 §2/6: 10000 new exact cases per composed scalar rounding operation."""
from fractions import Fraction as Q
import json
from pathlib import Path
from struct import pack
from blake3 import blake3

ROOT = Path(__file__).resolve().parents[4]
state = 50427


def word():
    global state
    state = (state*6364136223846793005+1442695040888963407) & ((1 << 64)-1)
    return state >> 32


def signed():
    x = word() & 65535
    return x-65536 if x >= 32768 else x


groups = []
for kind in range(5):
    digest = blake3()
    accepted = 0
    for i in range(10000):
        x, y, m, scale, f, fo = signed(), signed(), 1+word()%65535, word()%8454662, word()%45, word()%31
        e, fb, divisor = int(word()%2124)-1099, word()%31, 1+word()%((1 << 32)-1)
        if i % 2:
            e = -(e % 32)
        if kind == 0:  # affine: includes wide gated scales and original bias units
            left, le, right, re, den, bits = x*y*m*scale, e-f+fo, signed(), fo-fb, 1, 16
        elif kind == 1:  # learned token/position alignment, including cancellation
            left, le, right, re, den, bits = (x % 255-127)*m, e+fo, (y % 255-127)*divisor % 65535, int(word()%2124)-1099+fo, 1, 16
            if i % 19 == 0:
                right, re = -left, le
        elif kind == 2:  # residual alignment with independently selected units
            left, le, right, re, den, bits = x, fo-f%31, y, fo-fb, 1, 16
        elif kind == 3:  # scaled score before signed int32 output admission
            left, le, right, re, den, bits = x*y*m*(scale%65536), int(word()%183)-122, 0, 0, 1, 32
        else:  # restored weighted numerator and variable positive normalization
            left, le, right, re, den, bits = x*y*scale, int(word()%123)-30, 0, 0, divisor, 16
        digest.update(left.to_bytes(16, 'little', signed=True)+pack('<i', le)+right.to_bytes(16, 'little', signed=True)+pack('<iQI', re, den, bits))
        value = (Q(left)*Q(2)**le+Q(right)*Q(2)**re)/den
        low = value.numerator//value.denominator
        result = min((low, low+1), key=lambda v: (abs(value-v), -abs(v)))
        if -(1 << (bits-1)) <= result < 1 << (bits-1):
            accepted += 1
            digest.update(b'\1'+pack('<q', result))
        else:
            digest.update(b'\0')
    groups.append(dict(kind=kind, cases=10000, accepted=accepted, rejected=10000-accepted, digest=digest.hexdigest()))
receipt = dict(seed=50427, groups=groups)
(ROOT/'crates/stele-cqis/tests/fixtures/runtime-arithmetic.json').write_text(json.dumps(receipt, indent=2)+'\n')
print(json.dumps(receipt))
