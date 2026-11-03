"""Draft RFC-0025 function-bound appendix: schemas 10/11, no table/proof API."""
from dataclasses import dataclass

from arithmetic_bounds import CAPACITY, _column, _encode_record, _unsigned
from numerics import integer


@dataclass(frozen=True)
class Exponential:
    n: int
    bits: int
    F: int
    E: int
    mode: int
    k: int = 0

    def __post_init__(self):
        integer(self.n, 1, 1 << 20, 'Shape')
        integer(self.mode, 0, 2, 'Mode')
        integer(self.bits, 7, 31 if self.mode == 1 else 15, 'Domain')
        integer(self.F, 0, 30, 'Fraction')
        integer(self.E, 0, 14, 'Fraction')
        integer(self.k, max(1, self.bits-15) if self.mode else 0,
                min(16, self.bits) if self.mode else 0, 'Split')


@dataclass(frozen=True)
class Activation:
    d: int
    kind: int
    F: int
    E: int
    cap_m: int = 0
    cap_f: int = 0

    def __post_init__(self):
        integer(self.d, 1, 16384, 'Shape')
        integer(self.kind, 0, 4, 'Kind')
        integer(self.F, 0, 30, 'Fraction')
        integer(self.E, 0, 14, 'Fraction')
        integer(self.cap_m, 1 if self.kind == 2 else 0, 65535 if self.kind == 2 else 0, 'Cap')
        integer(self.cap_f, 0, 30 if self.kind == 2 else 0, 'Cap')
        if self.cap_f and self.cap_m % 2 == 0:
            raise ValueError('Cap')


def derive(p):
    if type(p) is Exponential:
        u, q = 1 << p.bits, 1 << p.E
        high, low = (1 << (p.bits-p.k), (1 << p.k)-1) if p.mode else (0, 0)
        counts = [u+1] if not p.mode else [high+1, low+1]+([u+1] if p.mode == 2 else [])
        padded = 1 << (p.n-1).bit_length()
        scalars = [u, q, q*q, q-1, high, low, len(counts), 2*u, q*q+q-1, q+3, 2*q-1,
                   p.n-1, padded, 2*padded-1, 62]
        roles = [((1, u, 1), (1, u, 1)), ((1, u, 1),)]
        if p.mode:
            roles += [((1, high, 1 << p.k), (1, low, 1)), ((1, q, q),), ((1, q, q),),
                      ((1, q*q, 1), (1, q-1, 1)), ((1, q-1, 1), (1, q-1, 1), (1, 1, 1))]
        if p.mode == 2:
            roles += [((1, q, 1), (1, 3, 1)), ((1, q, 1), (1, 1, 1))]
        schema = 10
    elif type(p) is Activation:
        padded = 1 << (p.d-1).bit_length()
        scalars = [p.d-1, padded, 2*padded-1, 32768, 65535, 65536, 98303, 131071,
                   (1 << 32)-1, 65535*65536]
        roles = [((1, 65535, 1), (1, 32768, 1)), ((1, 65535, 1), (1, 1, 65536)),
                 ((1, 65535, 1), (1, 1, 65535*65536))]
        counts, schema = [65536], 11
    else:
        raise ValueError('Parameters')
    for n in counts:
        padded = 1 << (n-1).bit_length()
        scalars += [n, padded, n-1, padded-1, 8*padded, 62+8*padded]
        roles += [((1, padded-1, 8),), ((1, 8*(padded-1), 1), (1, 7, 1), (1, 62, 1))]
    return schema, tuple(scalars), (), tuple(_column(terms) for terms in roles)


def encode(p):
    record = derive(p)
    if type(p) is Exponential:
        params = _unsigned(p.n, 4)+bytes((p.bits, p.F, p.E, p.mode))
        if p.mode:
            params += bytes((p.k,))
    else:
        params = _unsigned(p.d, 2)+bytes((p.kind, p.F, p.E))
        if p.kind == 2:
            params += _unsigned(p.cap_m, 2)+bytes((p.cap_f,))
    return _encode_record(params, *record)


def validate(expected, supplied):
    if type(supplied) is not bytes or len(supplied) > CAPACITY:
        raise ValueError('Capacity')
    if supplied != encode(expected):
        raise ValueError('Encoding')
