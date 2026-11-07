"""Draft RFC-0025 flow appendix: closed row/residual/gated metadata, no proof API."""
from dataclasses import dataclass

from arithmetic_bounds import CAPACITY, P, _column, _encode_record, _rounding_roles, _unsigned
from numerics import integer


@dataclass(frozen=True)
class Row:
    d: int
    kind: int
    fraction: int
    policy: int
    scale: int

    def __post_init__(self):
        integer(self.d, 1, 16384, 'Shape')
        integer(self.kind, 0, 1, 'Kind')
        integer(self.fraction, 0, 44 if self.kind else 30, 'Fraction')
        integer(self.policy, 0, 1, 'Policy')
        integer(self.scale, 1 if self.policy else 0,
                (8454661 if self.kind else 65535) if self.policy else 0, 'Scale')


@dataclass(frozen=True)
class Residual:
    d: int
    fx: int
    fy: int
    fo: int
    bits: int = 16  # 24 is RFC-0004 A14's wide residual alignment, schema 22

    def __post_init__(self):
        integer(self.bits, 16, 24, 'Width')
        if self.bits not in (16, 24):
            raise ValueError('Width')
        integer(self.d, 1, 16384, 'Shape')
        for value in (self.fx, self.fy, self.fo):
            integer(value, 0, 30, 'Fraction')


@dataclass(frozen=True)
class Gated:
    d: int
    fu: int
    E: int

    def __post_init__(self):
        integer(self.d, 1, 16384, 'Shape')
        integer(self.fu, 0, 30, 'Fraction')
        integer(self.E, 0, 14, 'Fraction')


def derive(p):
    """All operands/counts are fixed by the checked role; no supplied bounds."""
    if type(p) is Row:
        h = 1 << 30 if p.kind else 32768
        high = h if p.kind else h-1
        s = p.scale if p.policy else (h+126)//127
        small = (4*s-1, 2*s, 254, 127, 508, 254, 2*p.d-1)
        if any(2*x >= P for x in small):
            raise ValueError('FieldBound')
        scalars = (h, high, h+high, s, s-1, p.d-1, 127, 254*s, 2*s-1)+small
        roles = ()
        if p.policy == 0:
            scalars += (126,)
            roles = (((1, s, 127),), ((1, h, 1), (1, 126, 1)),
                     ((1, h, 1), (1, h, 1), (1, 1, 1)))
        roles += (((1, h+high, 1), (1, h, 2)), ((1, h, 1), (1, h, 1)),
                  ((1, h, 2), (1, s, 1)), ((1, 127, 2*s),),
                  ((1, 254*s, 1), (1, 2*s-1, 1)))
        schema, shifts = 4, ()
    elif type(p) is Residual:
        common = max(p.fx, p.fy, p.fo)
        l, r, d = 1 << (common-p.fx), 1 << (common-p.fy), 1 << (common-p.fo)
        h = 1 << (p.bits-1)
        maximum = h*(l+r)
        scalars = (p.d-1, h, 2*h-1, l, r, d, maximum, min(h, maximum//d),
                   h, 4*h-1, 2*h)
        shifts = (common, common-p.fx, common-p.fy, common-p.fo)
        roles = (((1, 2*h-1, l), (1, 2*h-1, r)),)+_rounding_roles(maximum, d, h)
        schema = 5 if p.bits == 16 else 22
    elif type(p) is Gated:
        scalars = (p.fu+p.E, 32768, 65535, 65535**2, 1 << 30, 1 << 31, p.d-1, 131071, 65536)
        roles = (((1, 65535, 65535),), ((1, 65535**2, 1), (1, 1 << 31, 1)),
                 ((1, 1 << 31, 1), (1, 65535, 32768), (1, 65535, 32768)))
        schema, shifts = 6, ()
    else:
        raise ValueError('Parameters')
    return schema, scalars, shifts, tuple(_column(t) for t in roles)


def encode(p):
    record = derive(p)
    if type(p) is Row:
        params = _unsigned(p.d, 2)+bytes((p.kind, p.fraction, p.policy))+_unsigned(p.scale, 4)
    elif type(p) is Residual:
        params = _unsigned(p.d, 2)+bytes((p.fx, p.fy, p.fo))
    else:
        params = _unsigned(p.d, 2)+bytes((p.fu, p.E))
    return _encode_record(params, *record)


def validate(expected, supplied):
    if type(supplied) is not bytes or len(supplied) > CAPACITY:
        raise ValueError('Capacity')
    if supplied != encode(expected):
        raise ValueError('Encoding')
