"""Q26 candidate physical tensor bytes; no admitted checkpoint or PCS format."""
from dataclasses import dataclass
from fractions import Fraction as Q
import math
import re
from scalars import FORMATS, decode
from quantiser import require, weights
from alignment import round_i16

CONFIG = b'stele/research/q26/tensor-config/v1'
DATA = b'stele/research/q26/tensor-data/v1'
SOURCES = ('binary16','bfloat16','binary32','binary64')
MAX_LENGTH = (1 << 64)-1


@dataclass(frozen=True)
class Spec:
    name: str
    source: str
    shape: tuple
    bits: int
    parameter: int  # Channel axis for int4/int8; fractional bits for int16.


def count(spec):
    require(type(spec) is Spec, 'Config')
    require(type(spec.shape) is tuple and 1 <= len(spec.shape) <= 255, 'Shape')
    product = 1
    for dimension in spec.shape:
        require(type(dimension) is int and 1 <= dimension < 1 << 32, 'Shape')
        product *= dimension
        require(product <= MAX_LENGTH, 'Capacity')
    return product


def config(spec):
    count(spec)
    require(type(spec.name) is str and re.fullmatch(r'[A-Za-z0-9_.-]{1,255}',spec.name), 'Name')
    require(type(spec.source) is str and spec.source in SOURCES, 'Source')
    require(count(spec) <= MAX_LENGTH//FORMATS[spec.source][0], 'Capacity')
    require(type(spec.bits) is int and spec.bits in (4,8,16), 'Format')
    limit = 31 if spec.bits == 16 else len(spec.shape)
    require(type(spec.parameter) is int and 0 <= spec.parameter < limit, 'Parameter')
    name = spec.name.encode('ascii')
    return (CONFIG+len(name).to_bytes(2,'little')+name+
            bytes([SOURCES.index(spec.source)+1,len(spec.shape)])+
            b''.join(d.to_bytes(4,'little') for d in spec.shape)+bytes([spec.bits,spec.parameter]))


def length(spec):
    total = (count(spec)*spec.bits+7)//8
    require(total <= MAX_LENGTH, 'Capacity')
    return total


def encode(spec, exponent, mantissas, values):
    descriptor = config(spec)
    size = length(spec)
    require(type(values) is list and len(values) == count(spec), 'Shape')
    require(all(type(x) is int for x in values), 'Format')
    require(type(mantissas) is list, 'Scale')
    scales = b''
    if spec.bits == 16:
        require(exponent is None and mantissas == [], 'Scale')
        low,high = -32768,32767
    else:
        require(type(exponent) is int and -1099 <= exponent <= 1024, 'Exponent')
        require(len(mantissas) == spec.shape[spec.parameter] and
                all(type(m) is int and 1 <= m <= 65535 for m in mantissas), 'Scale')
        scales = exponent.to_bytes(2,'little',signed=True)+b''.join(m.to_bytes(2,'little') for m in mantissas)
        high = (1 << (spec.bits-1))-1
        low = -high
    require(all(low <= x <= high for x in values), 'Range')
    if spec.bits == 4:
        payload = bytearray(size)
        for i,x in enumerate(values): payload[i//2] |= (x & 15) << (4*(i%2))
    else:
        payload = b''.join(x.to_bytes(spec.bits//8,'little',signed=True) for x in values)
    return DATA+len(descriptor).to_bytes(4,'little')+descriptor+scales+size.to_bytes(8,'little')+payload


def prepare(spec, raw):
    """Exact finite source conversion; return nothing if any element overflows."""
    config(spec)
    length(spec)
    n,width = count(spec),FORMATS[spec.source][0]
    require(n <= MAX_LENGTH//width, 'Capacity')
    require(type(raw) is bytes and len(raw) == n*width, 'SourceLength')
    pairs = [decode(spec.source,raw[i:i+width]) for i in range(0,len(raw),width)]
    if spec.bits == 16:
        values = [round_i16(significand,-power-spec.parameter) for significand,power in pairs]
        return encode(spec,None,[],values)
    axis = spec.parameter
    stride = math.prod(spec.shape[axis+1:])
    channels = [[] for _ in range(spec.shape[axis])]
    for i,(significand,power) in enumerate(pairs):
        channels[(i//stride)%len(channels)].append(significand*Q(2)**power)
    out = weights(channels,spec.bits)
    iterators = [iter(row) for row in out['output']]
    values = [next(iterators[(i//stride)%len(channels)]) for i in range(n)]
    return encode(spec,out['exponent'],out['mantissas'],values)


def parse(spec, raw):
    """Validate against independently expected configuration, not source origin."""
    descriptor = config(spec)
    size = length(spec)
    require(type(raw) is bytes, 'Bytes')
    position = 0

    def take(n):
        nonlocal position
        require(n <= len(raw)-position, 'Truncated')
        out = raw[position:position+n]
        position += n
        return out

    require(take(len(DATA)) == DATA, 'Prefix')
    require(int.from_bytes(take(4),'little') == len(descriptor), 'Config')
    require(take(len(descriptor)) == descriptor, 'Config')
    exponent,mantissas = None,[]
    if spec.bits != 16:
        exponent = int.from_bytes(take(2),'little',signed=True)
        require(-1099 <= exponent <= 1024, 'Exponent')
        # Check the whole scale span before any loop/allocation for untrusted size.
        scales = take(2*spec.shape[spec.parameter])
        mantissas = [int.from_bytes(scales[i:i+2],'little') for i in range(0,len(scales),2)]
        require(all(1 <= m <= 65535 for m in mantissas), 'Scale')
    require(int.from_bytes(take(8),'little') == size, 'PayloadLength')
    payload = take(size)
    require(position == len(raw), 'Trailing')
    if spec.bits == 4:
        if count(spec)%2: require(payload[-1] >> 4 == 0, 'Padding')
        values = []
        for i in range(count(spec)):
            word = (payload[i//2] >> (4*(i%2))) & 15
            values.append(word if word < 8 else word-16)
    else:
        width = spec.bits//8
        values = [int.from_bytes(payload[i:i+width],'little',signed=True) for i in range(0,len(payload),width)]
    high = (1 << (spec.bits-1))-1
    low = -32768 if spec.bits == 16 else -high
    require(all(low <= x <= high for x in values), 'Range')
    return dict(exponent=exponent,mantissas=mantissas,values=values)
