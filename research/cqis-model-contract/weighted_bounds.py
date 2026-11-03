"""Draft RFC-0025 weighted attention appendix: fixed radix-16 schemas 12/13."""
from dataclasses import dataclass

from arithmetic_bounds import CAPACITY, _column, _encode_record, _unsigned
from attention_input_bounds import _policy, _shape
from numerics import integer


@dataclass(frozen=True)
class Weighted:
    h: int
    g: int
    w: int
    n: int
    f: int
    E: int
    policy: int
    scale: int
    mode: int
    drop: int

    def __post_init__(self):
        _shape(self.h, self.w, self.n)
        integer(self.g, 1, self.h, 'Groups')
        if self.h % self.g:
            raise ValueError('Groups')
        integer(self.f, 0, 30, 'Fraction')
        integer(self.E, 0, 14, 'Fraction')
        _policy(self.policy, self.scale)
        integer(self.mode, 0, 1, 'Mode')
        integer(self.drop, 0, 62 if self.mode else 0, 'Drop')


@dataclass(frozen=True)
class Normalize:
    source: Weighted
    fo: int

    def __post_init__(self):
        if type(self.source) is not Weighted:
            raise ValueError('Parameters')
        integer(self.fo, 0, 30, 'Fraction')


def _constants(p):
    code, low, scale = _policy(p.policy, p.scale)
    s, q = code*scale, 1 << p.E
    count = 1024 if p.mode else p.n
    zl, h = count*q, count*q*s
    blocks, divisor = (p.n+1023)//1024 if p.mode else 0, 1 << p.drop
    bias = divisor//2
    rounded = (h+bias)//divisor if p.mode else 0
    if rounded > 32767:
        raise ValueError('BlockBound')
    total = blocks*rounded if p.mode else h
    return code, low, scale, s, q, count, zl, h, p.n*q, blocks, divisor, bias, rounded, total


def derive(p):
    if type(p) not in (Weighted, Normalize):
        raise ValueError('Parameters')
    source = p.source if type(p) is Normalize else p
    code, low, scale, s, q, count, zl, h, z, blocks, d, bias, b, total = _constants(source)
    if type(p) is Normalize:
        e = p.fo-source.f+source.drop
        l, r = 1 << max(e, 0), 1 << max(-e, 0)
        u, dmin, dm = total*l, q*r, z*r
        quotient = min(32768, u//dmin)
        scalars = (total, 2*total, q, z, l, r, u, dmin, dm, quotient, quotient*dm, dm-1,
                   2*dm-2, 32768, 65535, 131071, 65536, source.h*source.w, source.h*source.w-1,
                   source.g*source.w, 2*max(source.n, source.h*source.w)-1)
        roles = [((1, total, l),), ((1, z, r),), ((1, quotient, dm),), ((1, quotient*dm, 1), (1, dm-1, 1)),
                 ((1, dm-1, 1), (1, dm-1, 1), (1, 1, 1)), ((1, dm-1, 2),),
                 ((1, 2*dm-2, 1), (1, dm-1, 1), (1, 1, 1)), ((1, dm, 1), (1, dm-1, 1)),
                 ((1, quotient, 1), (1, 1, 1)), ((1, 65535, 1), (1, 32768, 2)), ((1, 32768, 1), (1, 32768, 1))]
        schema, shifts = 13, (e,)
    else:
        scalars = (p.h-1, p.g-1, p.w-1, p.n-1, p.h*p.w, p.g*p.w, p.h//p.g,
                   code, low, scale, s, 2*s, q, count, zl, h, 2*h, z, blocks, blocks-1 if p.mode else 0,
                   d, bias, b, b*d, d-1, total, 2*total, 2*max(p.n, p.h*p.w, 1024*blocks)-1)
        roles = [((1, code, scale),), ((1, 2*s, 1), (1, s, 2)), ((1, s, 1), (1, s, 1)),
                 ((count, q, 1),), ((1, zl, s),), ((count, q, 2*s),),
                 ((1, 2*h, 1), (1, h, 2)), ((1, h, 1), (1, h, 1)), ((1, h, 1), (1, 1, 1))]
        if p.mode:
            roles += [((1, h, 1), (1, bias, 1)), ((1, b, d),), ((1, b*d, 1), (1, d-1, 1)),
                      ((1, d-1, 1), (1, d-1, 1), (1, 1, 1)), ((1, 2*b, 1), (1, b, 2)), ((1, b, 1), (1, b, 1)),
                      ((blocks, 2*b, 1),), ((blocks, zl, 1),), ((1, 2*total, 1), (1, total, 2)),
                      ((1, total, 1), (1, total, 1)), ((1, total, 1), (1, 1, 1)), ((1, blocks-1, 1024), (1, 1023, 1))]
        schema, shifts = 12, ()
    return schema, scalars, shifts, tuple(_column(t, 4) for t in roles)


def encode(p):
    record = derive(p)
    s = p.source if type(p) is Normalize else p
    params = (b''.join(_unsigned(v, 2) for v in (s.h, s.g, s.w))+_unsigned(s.n, 4)+
              bytes((s.f, s.E, s.policy))+_unsigned(s.scale, 2)+bytes((s.mode, s.drop)))
    if type(p) is Normalize:
        params += bytes((p.fo,))
    return _encode_record(params, *record, bits=4)


def validate(expected, supplied):
    if type(supplied) is not bytes or len(supplied) > CAPACITY:
        raise ValueError('Capacity')
    if supplied != encode(expected):
        raise ValueError('Encoding')
