"""Draft RFC-0025 decoding bounds: schemas15–17, no proof or request admission."""
from dataclasses import dataclass
from math import gcd

from arithmetic_bounds import CAPACITY, _column, _encode_record, _unsigned
from function_bounds import Exponential
from numerics import integer


def _rational(n, d, *, probability=False):
    integer(n, 1, (1 << 32)-1, 'Rational')
    integer(d, 1, (1 << 32)-1, 'Rational')
    if gcd(n, d) != 1 or (probability and n > d):
        raise ValueError('Rational')


@dataclass(frozen=True)
class Logits:
    v: int
    fl: int

    def __post_init__(self):
        integer(self.v, 1, 1 << 20, 'Vocabulary')
        integer(self.fl, 0, 30, 'Fraction')


@dataclass(frozen=True)
class Temperature:
    fl: int
    tn: int
    td: int
    exp: Exponential

    def __post_init__(self):
        integer(self.fl, 0, 30, 'Fraction')
        _rational(self.tn, self.td)
        if type(self.exp) is not Exponential:
            raise ValueError('Parameters')


@dataclass(frozen=True)
class Sampling:
    v: int
    E: int
    pn: int
    pd: int

    def __post_init__(self):
        integer(self.v, 1, 1 << 20, 'Vocabulary')
        integer(self.E, 0, 14, 'Fraction')
        _rational(self.pn, self.pd, probability=True)


def derive(p):
    if type(p) is Logits:
        pad = 1 << (p.v-1).bit_length()
        scalars = (32768, 65535, p.v-1, pad, 2*pad-1)
        roles = [((1, 65535, 1), (1, 65535, 1)), ((1, 65535, 1), (1, 1, 1)),
                 ((1, 65535, 1), (1, 32768, 2)), ((1, 32768, 1), (1, 32768, 1))]
        schema = 15
    elif type(p) is Temperature:
        e = p.exp
        pre, factor = 65535*p.td, 1 << e.F
        n, d = pre*factor, p.tn << p.fl
        bias, domain = d//2, 1 << e.bits
        q = min(domain, (n+bias)//d)
        pad = 1 << (e.n-1).bit_length()
        scalars = (65535, pre, factor, n, d, bias, n+bias, domain, q, q*d, d-1, e.n-1, pad, 2*pad-1)
        roles = [((1, 65535, p.td),), ((1, pre, factor),),
                 ((1, n, 1), (1, bias, 1)), ((1, q, d),),
                 ((1, q*d, 1), (1, d-1, 1)), ((1, d-1, 1), (1, d-1, 1), (1, 1, 1)),
                 ((1, q, 1), (1, domain, 1))]
        schema = 16
    elif type(p) is Sampling:
        q, j, pad = 1 << p.E, 1 << 32, 1 << (p.v-1).bit_length()
        mass = p.v*q
        threshold, upper = p.pn*mass, p.pd*mass
        scalars = (q, mass, j, j-1, threshold, upper, j*mass, mass-1, p.v-1, pad, 2*pad-1, 255, 1 << 24)
        roles = [((p.v, q, 1),), ((1, q, 1), (1, q, 1)),
                 ((1, p.v-1, 1), (1, p.v-1, 1), (1, 1, 1)), ((1, p.v-1, 1),),
                 ((1, mass, 1), (1, q, 1)), ((1, mass, p.pn),),
                 ((1, mass, p.pd),), ((1, mass, p.pd),),
                 ((1, threshold, 1), (1, upper, 1)),
                 ((1, upper, 1), (1, threshold-1, 1), (1, 1, 1)),
                 ((1, mass, 1),), ((1, mass, j),), ((1, j, mass),),
                 ((1, j*mass, 1), (1, mass-1, 1)),
                 ((1, mass-1, 1), (1, mass-1, 1), (1, 1, 1)), ((1, mass, 1),),
                 ((1, j, 1), (1, j-1, 1)),
                 ((1, j-1, 1), (1, j-1, 1), (1, 1, 1)),
                 tuple((1, 255, 1 << (8*i)) for i in range(4))]
        schema = 17
    else:
        raise ValueError('Parameters')
    return schema, scalars, (), tuple(_column(t) for t in roles)


def encode(p):
    record = derive(p)
    if type(p) is Logits:
        params = _unsigned(p.v, 4)+bytes((p.fl,))
    elif type(p) is Temperature:
        e = p.exp
        params = (_unsigned(e.n, 4)+bytes((p.fl,))+_unsigned(p.tn, 4)+_unsigned(p.td, 4)
                  +bytes((e.bits, e.F, e.E, e.mode)))
        if e.mode:
            params += bytes((e.k,))
    else:
        params = _unsigned(p.v, 4)+bytes((p.E,))+_unsigned(p.pn, 4)+_unsigned(p.pd, 4)
    return _encode_record(params, *record)


def validate(expected, supplied):
    if type(supplied) is not bytes or len(supplied) > CAPACITY:
        raise ValueError('Capacity')
    if supplied != encode(expected):
        raise ValueError('Encoding')
