"""Draft RFC-0025 encoding §3: streaming Artifact syntax, not source admission."""
from dataclasses import dataclass
from struct import pack

from blake3 import blake3

from model_codec import encode as encode_model
from numerics import integer
import scales_codec
import source_map

PREPARATION = b'stele/v0.1/cqis/quantiser'
ARTIFACT = b'cqis-weights-v1'
TENSOR = b'stele/v0.1/cqis/tensor'
PREPARATION_LIMIT = 17 << 20
CHUNK = 1 << 16


def _configurations(model):
    encode_model(model)
    return tuple(pack('<HB',i,len(dims))+b''.join(pack('<I',d) for d in dims)+bytes(model.formats[i])
                 for i,(_,_,dims) in enumerate(model.shape.roles()))


def encode_preparation(model, mapping):
    configs = _configurations(model)
    if type(mapping) is not source_map.SourceMap or mapping.shape != model.shape:
        raise ValueError('Shape')
    raw = mapping.encode()
    result = PREPARATION+pack('<I',len(raw))+raw+b''.join(configs)
    if len(result)>PREPARATION_LIMIT: raise ValueError('Capacity')
    return result


def decode_preparation(model, raw):
    if type(raw) is not bytes or len(raw)>PREPARATION_LIMIT:
        raise ValueError('Capacity')
    configs = _configurations(model); pos = 0
    def take(n):
        nonlocal pos
        if n>len(raw)-pos: raise ValueError('Truncated')
        result=raw[pos:pos+n]; pos+=n; return result
    if take(len(PREPARATION))!=PREPARATION: raise ValueError('Header')
    length=int.from_bytes(take(4),'little')
    if length>source_map.LIMIT: raise ValueError('Capacity')
    mapping=source_map.decode(take(length))
    if mapping.shape!=model.shape: raise ValueError('Shape')
    for config in configs:
        if take(len(config))!=config: raise ValueError('Configuration')
    if pos!=len(raw): raise ValueError('Trailing')
    return mapping


def _digest_length(expected):
    if type(expected) is not bytes or len(expected)!=32: raise ValueError('Digest')


def decode_preparation_expected(model, expected, raw):
    _digest_length(expected)
    result=decode_preparation(model,raw)
    if blake3(raw).digest()!=expected: raise ValueError('Identity')
    return result


def _u64(value):
    integer(value,0,(1<<64)-1,'Length')
    return value


@dataclass(frozen=True)
class Record:
    ordinal: int
    config: bytes
    dimensions: tuple[int,...]
    bits: int
    elements: int
    record_offset: int
    payload_offset: int
    payload_length: int
    record_length: int


def layout(model):
    configs=_configurations(model); offset=len(ARTIFACT)+32+2; records=[]
    for i,((_,_,dims),config) in enumerate(zip(model.shape.roles(),configs)):
        bits=model.formats[i][0]; elements=_u64(dims[0]*(dims[1] if len(dims)==2 else 1))
        payload=_u64(elements*bits+7)//8
        header=len(TENSOR)+4+len(config)+8+(2+2*dims[0] if len(dims)==2 else 0)
        length=_u64(header+payload); start=_u64(offset+8)
        records.append(Record(i,config,dims,bits,elements,start,_u64(start+header),payload,length))
        offset=_u64(start+length)
    if offset>=1<<39: raise ValueError('Capacity')
    return tuple(records),offset


def _context(model, mapping, scales_raw):
    preparation=encode_preparation(model,mapping)
    scales=scales_codec.decode(model,scales_raw)
    records,total=layout(model)
    header=(ARTIFACT,blake3(preparation).digest(),pack('<H',len(records)))
    return header,records,scales,total


def _header(record, scale):
    parts=[(pack('<Q',record.record_length),'RecordLength'),(TENSOR,'Record'),
           (pack('<I',len(record.config)),'Configuration'),(record.config,'Configuration')]
    if scale is not None: parts += [(pack('<h',scale.exponent),'Scales'),(scale.mantissas,'Scales')]
    return parts+[(pack('<Q',record.payload_length),'PayloadLength')]


def _read(stream, count):
    if not callable(getattr(stream,'read',None)): raise ValueError('Stream')
    value=stream.read(count)
    if type(value) is not bytes or len(value)>count: raise ValueError('Read')
    return value


def _blocks(stream, size):
    while size:
        value=_read(stream,min(CHUNK,size))
        if not value: raise ValueError('Truncated')
        size-=len(value); yield value


def _end(stream):
    if _read(stream,1): raise ValueError('Trailing')


def _payload(stream, record):
    remaining=record.payload_length
    for raw in _blocks(stream,remaining):
        remaining-=len(raw)
        if record.bits==8 and 128 in raw: raise ValueError('Code')
        if record.bits==4:
            if any((b&15)==8 or (b>>4)==8 for b in raw): raise ValueError('Code')
            if remaining==0 and record.elements%2 and raw[-1]>>4: raise ValueError('Padding')
        yield raw


def iterencode(model, mapping, scales_raw, payloads):
    """Only exhaustion validates every payload; no partial output is admitted."""
    header,records,scales,total=_context(model,mapping,scales_raw)
    if type(payloads) is not tuple or len(payloads)!=len(records): raise ValueError('Records')
    written=0
    for part in header: written+=len(part); yield part
    scales=iter(scales)
    for record,stream in zip(records,payloads):
        scale=next(scales) if len(record.dimensions)==2 else None
        for part,_ in _header(record,scale):
            for at in range(0,len(part),CHUNK):
                chunk=part[at:at+CHUNK]; written+=len(chunk); yield chunk
        for chunk in _payload(stream,record): written+=len(chunk); yield chunk
        _end(stream)
    assert written==total


def digest(model, mapping, scales_raw, stream):
    header,records,scales,total=_context(model,mapping,scales_raw); result=blake3(); consumed=0
    def expect(part, reason):
        nonlocal consumed
        pos=0
        for chunk in _blocks(stream,len(part)):
            if chunk!=part[pos:pos+len(chunk)]: raise ValueError(reason)
            pos+=len(chunk); consumed+=len(chunk); result.update(chunk)
    for part,reason in zip(header,('Header','Quantiser','Count')): expect(part,reason)
    scales=iter(scales)
    for record in records:
        scale=next(scales) if len(record.dimensions)==2 else None
        for part,reason in _header(record,scale): expect(part,reason)
        for chunk in _payload(stream,record): consumed+=len(chunk); result.update(chunk)
    _end(stream); assert consumed==total
    return result.digest()


def verify(model, mapping, scales_raw, stream, expected):
    _digest_length(expected)
    if digest(model,mapping,scales_raw,stream)!=expected: raise ValueError('Identity')
