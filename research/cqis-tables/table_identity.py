"""Q25 / Draft RFC-0004 A2: candidate canonical component-table bytes."""
from dataclasses import dataclass
from fractions import Fraction as Q
from functools import lru_cache
import struct
from blake3 import blake3
import certified_exp as exp
import certified_activations as act
import certified_rmsnorm as norm
from certified_exp import require

IDENTITY = b'stele/v0.1/table/identity'
DATA = b'stele/v0.1/table/data'
ACTIVATIONS = ('silu_q','sigmoid_q','gelu_q','gelu_tanh_q','softcap_q')
EXP = ('exp_q/hi','exp_q/lo','exp_q/direct','exp_q/correction')
RANGES = ('range_8','range_12','range_16')


@dataclass(frozen=True)
class Descriptor:
    name: str
    version: int
    params: bytes

    def __post_init__(self):
        require(type(self.name) is str and self.name in EXP+ACTIVATIONS+RANGES+('rsqrt_q',),'Name')
        require(type(self.version) is int and self.version == 1,'Version')
        require(type(self.params) is bytes,'Parameters')
        p = self.params
        if self.name in EXP:
            require(len(p) == (3 if self.name == 'exp_q/direct' else 4),'Parameters')
            exp.Parameters(*p)
            if self.name in ('exp_q/direct','exp_q/correction'):
                require(p[0] <= 15,'Parameters')
        elif self.name in ACTIVATIONS:
            require(len(p) == (5 if self.name == 'softcap_q' else 2),'Parameters')
            args = struct.unpack('<BBHB',p) if self.name == 'softcap_q' else tuple(p)
            act.Parameters(self.name.removesuffix('_q'),*args)
        else:
            require(not p,'Parameters')


def encode(d):
    require(type(d) is Descriptor,'Descriptor')
    name = d.name.encode('ascii')
    return IDENTITY+struct.pack('<H',len(name))+name+struct.pack('<IH',d.version,len(d.params))+d.params


def decode(raw):
    require(type(raw) is bytes and len(raw) <= 128 and raw.startswith(IDENTITY),'Descriptor')
    pos = len(IDENTITY)
    def take(n):
        nonlocal pos
        require(pos+n <= len(raw),'Descriptor')
        value = raw[pos:pos+n];pos += n
        return value
    n = int.from_bytes(take(2),'little')
    require(1 <= n <= 32,'Descriptor')
    name = take(n)
    require(name.isascii(),'Descriptor')
    version = int.from_bytes(take(4),'little')
    n = int.from_bytes(take(2),'little')
    require(n <= 64,'Descriptor')
    params = take(n)
    require(pos == len(raw),'Descriptor')
    return Descriptor(name.decode('ascii'),version,params)


def table_id(d):
    """An identity describes a function; it does not admit unvalidated table data."""
    return blake3(encode(d)).digest()


def shape(d):
    require(type(d) is Descriptor,'Descriptor')
    if d.name in EXP:
        b = d.params[0]
        n = ((1 << (b-d.params[3]))+1 if d.name == 'exp_q/hi'
             else (1 << d.params[3]) if d.name == 'exp_q/lo' else (1 << b)+1)
    elif d.name in ACTIVATIONS:
        n = 65536
    elif d.name == 'rsqrt_q':
        n = 49152
    else:
        n = 1 << int(d.name.removeprefix('range_'))
    return n,1 << (n-1).bit_length(),1 if d.name in RANGES else 2


@lru_cache(maxsize=16,typed=True)
def canonical_rows(d):
    """Immutable research cache; rows are derived, never supplied as hash authority."""
    n,padded,c = shape(d)
    if d.name in RANGES:
        rows = tuple((i,) for i in range(n))
    elif d.name == 'rsqrt_q':
        rows = tuple((m,norm.rsqrt_certificate(m)['value']) for m in range(16384,65536))
    elif d.name in ACTIVATIONS:
        args = struct.unpack('<BBHB',d.params) if d.name == 'softcap_q' else tuple(d.params)
        p = act.Parameters(d.name.removesuffix('_q'),*args)
        rows = tuple((t,act.certify(p,t)['value']) for t in range(-32768,32768))
    else:
        p = exp.Parameters(*d.params)
        if d.name in ('exp_q/hi','exp_q/lo'):
            multiplier = (1 << p.split) if d.name == 'exp_q/hi' else 1
            rows = tuple((i,exp.certify(Q(i*multiplier,1 << p.F),p.E)['value']) for i in range(n))
        elif d.name == 'exp_q/direct':
            rows = tuple((t,exp.certify(Q(-t,1 << p.F),p.E)['value']) for t in range(-(1 << p.B),1))
        else:
            table = exp.corrected(p)
            rows = tuple((t,v) for t,v in zip(range(-(1 << p.B),1),table['corrections']))
    return rows+((0,)*c,)*(padded-n)


def encode_data(d):
    n,padded,c = shape(d)
    return (DATA+table_id(d)+struct.pack('<IIB',n,padded,c)
            +b''.join(struct.pack('<i',v) for row in canonical_rows(d) for v in row))


def decode_data(d,raw):
    """Validate against the complete definition, not just a self-consistent digest."""
    n,padded,c = shape(d)
    offset = len(DATA)+32+9
    require(type(raw) is bytes and len(raw) >= offset,'Length')
    require(raw.startswith(DATA),'DataHeader')
    require(raw[len(DATA):len(DATA)+32] == table_id(d),'Identity')
    require(struct.unpack_from('<IIB',raw,len(DATA)+32) == (n,padded,c),'Shape')
    require(len(raw) == offset+padded*c*4,'Length')
    rows = tuple(struct.iter_unpack('<'+'i'*c,raw[offset:]))
    require(all(not any(row) for row in rows[n:]),'Padding')
    require(rows == canonical_rows(d),'Entry')
    return rows
