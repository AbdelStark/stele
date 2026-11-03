"""Draft RFC-0025 attention-input appendix: closed schemas 7–9, no proof API."""
from dataclasses import dataclass
from math import isqrt

from arithmetic_bounds import CAPACITY, P, _column, _encode_record, _unsigned
from numerics import integer


def _shape(h, w, n):
    integer(h, 1, 128, 'Shape')
    integer(w, 1, 16384//h, 'Shape')
    integer(n, 1, 1 << 20, 'Shape')


def _policy(mode, scale):
    integer(mode, 0, 1, 'Policy')
    integer(scale, 1 if mode else 0, 65535 if mode else 0, 'Scale')
    return (min(127, (65536+scale)//(2*scale)), scale, scale) if mode else (127, 0, 259)


@dataclass(frozen=True)
class Rotation:
    h: int
    w: int
    r: int
    n: int
    layout: int
    f: int

    def __post_init__(self):
        _shape(self.h, self.w, self.n)
        integer(self.r, 2, self.w, 'Rotation')
        if self.r % 2:
            raise ValueError('Rotation')
        integer(self.layout, 0, 1, 'Layout')
        integer(self.f, 0, 30, 'Fraction')


@dataclass(frozen=True)
class Score:
    h: int
    g: int
    w: int
    n: int
    fq: int
    fk: int
    f: int
    qm: int
    qs: int
    km: int
    ks: int
    m: int
    e: int

    def __post_init__(self):
        _shape(self.h, self.w, self.n)
        integer(self.g, 1, self.h, 'Groups')
        if self.h % self.g:
            raise ValueError('Groups')
        for fraction in (self.fq, self.fk, self.f):
            integer(fraction, 0, 30, 'Fraction')
        _policy(self.qm, self.qs)
        _policy(self.km, self.ks)
        integer(self.m, 1, 65535, 'Multiplier')
        integer(self.e, -62, 30, 'Multiplier')


@dataclass(frozen=True)
class Maximum:
    n: int
    bound: int
    bits: int
    f: int

    def __post_init__(self):
        integer(self.n, 1, 1 << 20, 'Shape')
        integer(self.bound, 0, (1 << 31)-1, 'Score')
        integer(self.bits, 7, 31, 'Domain')
        integer(self.f, 0, 30, 'Fraction')


def derive(p):
    if type(p) is Rotation:
        h, u = 32768, 16384
        envelope = isqrt(2*u*u)+1
        maximum = h*envelope
        size = p.n*(p.r//2)
        index_side = 2*max(p.n, p.h*p.w)-1
        if any(2*b >= P for b in (h*u, maximum, maximum+u//2, h*u+u-1, h, 2*u, index_side)):
            raise ValueError('FieldBound')
        scalars = (p.h*p.w, p.h*(p.r//2), p.h*(p.w-p.r), p.n-1, p.r//2-1, p.h-1,
                   size-1, 4*(size-1), 4*size-1, h, u, envelope, h*u, maximum, u,
                   u//2, maximum+u//2, h, u-1, h*u+u-1, h, 2*u, index_side)
        roles = (((1, p.n-1, p.r//2), (1, p.r//2-1, 1)), ((1, size-1, 4),),
                 ((1, 4*(size-1), 1), (1, 3, 1)))
        schema, shifts = 7, ()
    elif type(p) is Score:
        cq, qmin, sq = _policy(p.qm, p.qs)
        ck, kmin, sk = _policy(p.km, p.ks)
        a = p.w*cq*ck
        pq, pk = a*sq, a*sq*sk
        pm = pk*p.m
        shift = p.e-p.fq-p.fk+p.f
        l, d = 1 << max(shift, 0), 1 << max(-shift, 0)
        bias, maximum = d//2, pm*l
        bound = (maximum+bias)//d
        if bound >= 1 << 31:
            raise ValueError('ScoreBound')
        if 2*(a+1) >= P:
            raise ValueError('FieldBound')
        scalars = (p.h-1, p.g-1, p.w-1, p.n-1, p.h*p.w, p.g*p.w, p.h//p.g,
                   cq, ck, qmin, sq, kmin, sk, a, a+1, pq, pk, pm, l, d, bias,
                   maximum, bound, bound*d, d-1, 2*bound, 2*max(p.n, p.h*p.w)-1)
        roles = (((1, a, sq),), ((1, pq, sk),), ((1, pk, p.m),), ((1, pm, l),),
                 ((1, maximum, 1), (1, bias, 1)), ((1, bound, d),),
                 ((1, bound*d, 1), (1, d-1, 1)), ((1, d-1, 1), (1, d-1, 1), (1, 1, 1)),
                 ((1, 2*bound, 1), (1, bound, 2)), ((1, bound, 1), (1, bound, 1)))
        schema, shifts = 8, (shift,)
    elif type(p) is Maximum:
        offset, domain = 2*p.bound, 1 << p.bits
        delta = min(offset, domain)
        scalars = (p.n-1, offset, domain, delta, 1, 2*p.n-1, domain)
        roles = (((1, offset, 1),), ((1, offset, 1), (1, delta, 1)), ((1, offset, 1),),
                 ((1, delta, 1), (1, 1, 1)), ((1, delta, 1), (1, domain, 1)), ((1, domain, 1),))
        schema, shifts = 9, ()
    else:
        raise ValueError('Parameters')
    return schema, scalars, shifts, tuple(_column(t) for t in roles)


def encode(p):
    record = derive(p)
    if type(p) is Rotation:
        params = b''.join(_unsigned(x, 2) for x in (p.h, p.w, p.r))+_unsigned(p.n, 4)+bytes((p.layout, p.f))
    elif type(p) is Score:
        params = (b''.join(_unsigned(x, 2) for x in (p.h, p.g, p.w))+_unsigned(p.n, 4)+
                  bytes((p.fq, p.fk, p.f, p.qm))+_unsigned(p.qs, 2)+bytes((p.km,))+
                  _unsigned(p.ks, 2)+_unsigned(p.m, 2)+p.e.to_bytes(1, 'little', signed=True))
    else:
        params = _unsigned(p.n, 4)+_unsigned(p.bound, 4)+bytes((p.bits, p.f))
    return _encode_record(params, *record)


def validate(expected, supplied):
    if type(supplied) is not bytes or len(supplied) > CAPACITY:
        raise ValueError('Capacity')
    if supplied != encode(expected):
        raise ValueError('Encoding')
