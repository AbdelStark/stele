"""RFC-0025 RMSNorm appendix: closed schema 14 for RFC-0021 §2.3 (int16 inputs), and
RFC-0004 A14's schema 20 for rmsnorm_q version 2 (int24 inputs X, int16 gains, d <= 8192)."""
from dataclasses import dataclass
from math import gcd

from arithmetic_bounds import CAPACITY, _column, _encode_record, _unsigned
from numerics import integer


@dataclass(frozen=True)
class RMSNorm:
    d: int
    F: int
    G: int
    E: int
    en: int
    ed: int
    version: int = 1

    def __post_init__(self):
        integer(self.version, 1, 2, 'Version')
        integer(self.d, 1, 16384 if self.version == 1 else 8192, 'Dimension')
        for value in (self.F, self.G):
            integer(value, 0, 30, 'Units')
        integer(self.E, 0, 14, 'Units')
        for value in (self.en, self.ed):
            integer(value, 1, (1 << 32)-1, 'Epsilon')
        if gcd(self.en, self.ed) != 1:
            raise ValueError('Epsilon')


def derive(p):
    if type(p) is not RMSNorm:
        raise ValueError('Parameters')
    wide = p.version == 2
    h, o = 32768, 65535
    hx = 1 << 23 if wide else h  # input X magnitude bound; gains and outputs stay int16
    amax = 16 if wide else 9
    unit, statistic = p.d << (2*p.F), p.d*hx*hx
    n, denominator = p.ed*statistic+p.en*unit, p.ed*unit
    fa, fd = 1 << 46, 1 << (2*amax)
    aa, dd = n*fa, denominator*fd
    md, xy, t = o*dd, hx*h, hx*h*16384
    emin, emax = p.F+p.G-2-p.E, p.F+p.G+21+amax-p.E
    l, dr = 1 << max(-emin, 0), 1 << max(emax, 0)
    bias, u, qd = dr//2, t*l, h*dr
    padded = 1 << (p.d-1).bit_length()
    scalars = (h, o, unit, statistic, n, denominator, fa, fd, aa, dd, md, 8192, 16384,
               xy, t, l, dr, bias, u, u+bias, h, qd, p.d-1, padded, 2*p.d-1,
               131071, 65536, amax+23, amax+24, 64, 16384, 65535, 49152, 65536, 49151, 524288, 524350, 3)
    ox = 2*hx-1
    roles = [((1, ox, 1), (1, hx, 2)), ((1, hx, 1), (1, hx, 1)),
             ((p.d, hx, hx),), ((1, statistic, p.ed), (1, unit, p.en)),
             ((1, n, fa),), ((1, denominator, fd),), ((1, o, dd),),
             ((1, md, 1), (1, dd-1, 1)), ((1, dd-1, 1), (1, dd-1, 1), (1, 1, 1)),
             ((1, hx, h),), ((1, xy, 16384),), ((1, t, l),),
             ((1, u, 1), (1, bias, 1)), ((1, h, dr),), ((1, qd, 1), (1, dr-1, 1)),
             ((1, dr-1, 1), (1, dr-1, 1), (1, 1, 1)),
             ((1, o, 1), (1, h, 2)), ((1, h, 1), (1, h, 1)),
             ((1, 49151, 1), (1, 16384, 1)), ((1, amax+23, 1),), ((1, 65535, 8),),
             ((1, 524280, 1), (1, 7, 1), (1, 62, 1)), ((1, 1, 1),),
             ((1, 1, 1), (1, 1, 1)), ((1, 1, 1), (1, 1, 2)), ((1, 1, 1),)]
    if wide:  # roles 1/2 bind X; roles 27/28 bind the int16 gain source separately
        scalars += (hx, ox, 4*hx-1, 2*hx)
        roles += [((1, o, 1), (1, h, 2)), ((1, h, 1), (1, h, 1))]
    return (20 if wide else 14), scalars, (emin, emax), tuple(_column(t) for t in roles)


def encode(p):
    record = derive(p)
    params = _unsigned(p.d, 2)+bytes((p.F, p.G, p.E))+_unsigned(p.en, 4)+_unsigned(p.ed, 4)
    return _encode_record(params, *record)


def validate(expected, supplied):
    if type(supplied) is not bytes or len(supplied) > CAPACITY:
        raise ValueError('Capacity')
    if supplied != encode(expected):
        raise ValueError('Encoding')
