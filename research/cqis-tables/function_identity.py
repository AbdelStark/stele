"""Q25 / Draft RFC-0004 A2: function semantics and selected component closure."""
from dataclasses import dataclass
import struct
from blake3 import blake3
import table_identity as table
from certified_exp import require
from certified_rmsnorm import Parameters as NormParameters

FUNCTION = b'stele/v0.1/function/identity'
REPRESENTATION = b'stele/v0.1/function/representation'
MANIFEST = b'stele/v0.1/cqis/functions'


@dataclass(frozen=True)
class Function:
    name: str
    version: int
    params: bytes

    def __post_init__(self):
        require(type(self.name) is str and self.name in table.ACTIVATIONS+table.RANGES
                +('exp_q/product','exp_q/nearest','rmsnorm_q'),'FunctionName')
        require(type(self.version) is int and self.version == 1,'Version')
        require(type(self.params) is bytes,'Parameters')
        if self.name == 'rmsnorm_q':
            require(len(self.params) == 13,'Parameters')
            NormParameters(*struct.unpack('<HBBBII',self.params))
        else:
            name = {'exp_q/product':'exp_q/hi','exp_q/nearest':'exp_q/direct'}.get(self.name,self.name)
            table.Descriptor(name,1,self.params)


def encode(f):
    require(type(f) is Function,'Function')
    name = f.name.encode('ascii')
    return FUNCTION+struct.pack('<H',len(name))+name+struct.pack('<IH',1,len(f.params))+f.params


def decode(raw):
    require(type(raw) is bytes and len(raw) <= 128 and raw.startswith(FUNCTION),'Function')
    pos = len(FUNCTION)
    def take(n):
        nonlocal pos
        require(pos+n <= len(raw),'Function')
        value = raw[pos:pos+n];pos += n
        return value
    n = int.from_bytes(take(2),'little');require(1 <= n <= 32,'Function')
    name = take(n);require(name.isascii(),'Function')
    version = int.from_bytes(take(4),'little')
    n = int.from_bytes(take(2),'little');require(n <= 64,'Function')
    params = take(n);require(pos == len(raw),'Function')
    return Function(name.decode('ascii'),version,params)


def function_id(f):
    return blake3(encode(f)).digest()


@dataclass(frozen=True)
class Representation:
    function: Function
    mode: int
    params: bytes

    def __post_init__(self):
        require(type(self.function) is Function and type(self.mode) is int
                and type(self.params) is bytes,'Representation')
        name = self.function.name
        if name == 'exp_q/product':
            require(self.mode == 1 and not self.params,'Representation')
        elif name == 'exp_q/nearest':
            require((self.mode == 0 and not self.params)
                    or (self.mode == 2 and len(self.params) == 1),'Representation')
            if self.mode == 2:
                try:
                    table.Descriptor('exp_q/correction',1,self.function.params+self.params)
                except ValueError as error:
                    raise ValueError('Representation') from error
        elif name == 'rmsnorm_q':
            require(self.mode == 3 and not self.params,'Representation')
        else:
            require(self.mode == 0 and not self.params,'Representation')


def dependencies(r):
    require(type(r) is Representation,'Representation')
    f = r.function
    if r.mode in (1,2):
        p = f.params if r.mode == 1 else f.params+r.params
        names = ('exp_q/hi','exp_q/lo') if r.mode == 1 else ('exp_q/hi','exp_q/lo','exp_q/correction')
        return tuple(table.Descriptor(name,1,p) for name in names)
    if r.mode == 3:
        return (table.Descriptor('rsqrt_q',1,b''),)
    name = 'exp_q/direct' if f.name == 'exp_q/nearest' else f.name
    return (table.Descriptor(name,1,f.params),)


def encode_representation(r):
    deps = dependencies(r)
    return (REPRESENTATION+function_id(r.function)+bytes([r.mode,len(r.params)])+r.params
            +bytes([len(deps)])+b''.join(table.table_id(d) for d in deps))


def decode_representation(f,raw):
    require(type(raw) is bytes and raw.startswith(REPRESENTATION),'Representation')
    pos = len(REPRESENTATION)
    require(len(raw) >= pos+35,'Representation')
    require(raw[pos:pos+32] == function_id(f),'FunctionIdentity');pos += 32
    mode,size = raw[pos:pos+2];pos += 2
    require(size <= 1 and len(raw) >= pos+size+1,'Representation')
    r = Representation(f,mode,raw[pos:pos+size])
    require(raw == encode_representation(r),'Representation')
    return r


def verify_representation(expected,raw):
    require(decode_representation(expected.function,raw) == expected,'Representation')


def representation_id(r):
    return blake3(encode_representation(r)).digest()


def closure(expected):
    """Expected function/representation choices come from the verifier-owned config."""
    require(type(expected) in (list,tuple) and len(expected) < 1 << 32
            and all(type(r) is Representation for r in expected),'Manifest')
    functions,components = {},{}
    for r in expected:
        fid = function_id(r.function)
        require(fid not in functions,'DuplicateFunction')
        functions[fid] = r
        for d in dependencies(r):
            tid = table.table_id(d)
            require(tid not in components or components[tid] == d,'IdentityCollision')
            components[tid] = d
    require(len(components) < 1 << 32,'Manifest')
    return [functions[k] for k in sorted(functions)],[components[k] for k in sorted(components)]


def encode_manifest(expected):
    functions,components = closure(expected)
    out = bytearray(MANIFEST+struct.pack('<I',len(functions)))
    for r in functions:
        d,rep = encode(r.function),encode_representation(r)
        out += struct.pack('<H',len(d))+d+struct.pack('<H',len(rep))+rep
    out += struct.pack('<I',len(components))
    for d in components:
        encoded = table.encode(d)
        # Canonical table generation is mandatory before accepting its data digest.
        out += struct.pack('<H',len(encoded))+encoded+blake3(table.encode_data(d)).digest()
    return bytes(out)


def verify_manifest(expected,raw):
    """No config, shape, table digest or representation choice is adopted from raw."""
    require(type(raw) is bytes and raw == encode_manifest(expected),'Manifest')
