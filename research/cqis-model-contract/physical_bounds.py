"""Draft RFC-0025 physical appendix: schema 19, canonical record/address bounds."""
from dataclasses import dataclass

from arithmetic_bounds import _column, _encode_record
from numerics import integer
from source_map import Shape, uint

LIMIT = 36000
TENSOR = b'stele/v0.1/cqis/tensor'


@dataclass(frozen=True)
class Physical:
    shape: Shape
    record: int
    bits: int
    parameter: int

    def __post_init__(self):
        if type(self.shape) is not Shape:
            raise ValueError('Shape')
        roles = self.shape.roles(); integer(self.record, 0, len(roles)-1, 'Record')
        matrix = len(roles[self.record][2]) == 2
        integer(self.bits, 4, 16, 'Format')
        if self.bits not in ((4, 8) if matrix else (16,)):
            raise ValueError('Format')
        integer(self.parameter, 0, 0 if matrix else 30, 'Format')

    def descriptor(self):
        dims = self.shape.roles()[self.record][2]
        return uint(self.record, 2)+bytes((len(dims),))+b''.join(uint(d, 4) for d in dims)+bytes((self.bits, self.parameter))


def derive(p):
    if type(p) is not Physical:
        raise ValueError('Parameters')
    dims = p.shape.roles()[p.record][2]; matrix = len(dims) == 2
    rows, columns = dims if matrix else (1, dims[0]); n = rows*columns
    size = (n*p.bits+7)//8
    first = (n-1)//2 if p.bits == 4 else (n-1)*(p.bits//8)
    scale_start = len(TENSOR)+4+len(p.descriptor())
    header = scale_start+(2+2*rows if matrix else 0)+8
    full, half = 1 << p.bits, 1 << (p.bits-1)
    negative = half-1 if matrix else half; offset = negative+half-1
    lane, tail, odd = int(p.bits == 4), int(p.bits == 16), n % 2 if p.bits == 4 else 0
    scalars = (rows, columns, n, n-1, size, size-1, first, header, header+size, header+size-1,
               full-1, half, negative, offset, lane, tail, odd)
    roles = [((1, rows-1, columns), (1, columns-1, 1)),
             ((1, first, 2), (1, 1, 1)) if p.bits == 4 else ((1, n-1, p.bits//8),),
             ((1, first, 1), (1, tail, 1)), ((1, size-1, 1), (1, header, 1))]
    roles += [(((1, 15, 1), (1, 15, 16)) if p.bits == 4 else
               ((1, 255, 1), (1, 255, 256)) if p.bits == 16 else ((1, 255, 1),)),
              ((1, half-1, 1), (1, 1, half)),
              ((1, full-1, 1), (1, negative, 1)), ((1, offset, 1), (1, 1, full))]
    if p.bits == 4: roles.append(((1, 1, 15), (1, 1, 15)))
    if matrix:
        ms = scale_start+2; last = ms+2*(rows-1)
        scalars += (scale_start, scale_start+1, ms, last, last+1, header-8,
                    65535, 65534, 1099, 1024, 2123, 65536, 32768)
        roles += [((1, rows-1, 2), (1, ms, 1)), ((1, last, 1), (1, 1, 1)),
                  ((1, 255, 1), (1, 255, 256)), ((1, 65534, 1), (1, 1, 1)),
                  ((1, 255, 1), (1, 255, 256)), ((1, 32767, 1), (1, 1, 32768)),
                  ((1, 65535, 1), (1, 1099, 1)), ((1, 2123, 1), (1, 1, 65536))]
    return 19, scalars, (), tuple(_column(terms) for terms in roles)


def encode(p):
    record = derive(p)
    raw = _encode_record(p.shape.encode()+p.descriptor(), *record)
    if len(raw) >= LIMIT:
        raise ValueError('Capacity')
    return raw


def validate(expected, raw):
    if type(raw) is not bytes or len(raw) >= LIMIT:
        raise ValueError('Capacity')
    if raw != encode(expected):
        raise ValueError('Encoding')
