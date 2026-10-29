"""Q26 source-file candidate; no passport admission or publisher authentication."""
import hashlib
import json
from blake3 import blake3
import artifact as a
from quantiser import require

MAX_HEADER = 100_000_000
MAX_U64 = (1 << 64)-1
BITS = dict(BOOL=8,F4=4,F6_E2M3=6,F6_E3M2=6,U8=8,I8=8,F8_E5M2=8,F8_E4M3=8,
            F8_E8M0=8,I16=16,U16=16,F16=16,BF16=16,I32=32,U32=32,F32=32,F64=64,I64=64,U64=64)
SOURCE = dict(binary16='F16',bfloat16='BF16',binary32='F32',binary64='F64')
CONFIG = b'stele/research/q26/source/v1'


class SourceError(ValueError):
    pass


def unique(pairs):
    out = {}
    for key,value in pairs:
        if key in out: raise SourceError('Duplicate')
        out[key] = value
    return out


def no_number(_):
    raise SourceError('JSON')


def utf8(text):
    require(type(text) is str, 'Unicode')
    try:
        return text.encode('utf8')
    except UnicodeError as error:
        raise SourceError('Unicode') from error


def unsigned(value):
    return type(value) is int and 0 <= value <= MAX_U64


def parse(raw):
    require(type(raw) is bytes, 'Bytes')
    require(len(raw) <= MAX_U64, 'Capacity')
    require(len(raw) >= 8, 'Truncated')
    size = int.from_bytes(raw[:8],'little')
    require(size <= MAX_HEADER, 'HeaderLimit')
    require(size <= len(raw)-8, 'Truncated')
    header = raw[8:8+size]
    require(header.startswith(b'{'), 'HeaderStart')
    try:
        text = header.decode('utf8')
    except UnicodeError as error:
        raise SourceError('UTF8') from error
    try:
        content = json.loads(text,object_pairs_hook=unique,parse_float=no_number,parse_constant=no_number)
    except SourceError:
        raise
    except (ValueError,RecursionError) as error:
        raise SourceError('JSON') from error
    require(type(content) is dict, 'JSON')
    metadata = content.pop('__metadata__',{})
    require(type(metadata) is dict and all(type(v) is str for v in metadata.values()), 'Metadata')
    for key,value in metadata.items(): utf8(key); utf8(value)
    payload_size = len(raw)-8-size
    entries = []
    for name,info in content.items():
        utf8(name)
        require(type(info) is dict and set(info) == {'dtype','shape','data_offsets'}, 'TensorSchema')
        dtype,shape,offsets = info['dtype'],info['shape'],info['data_offsets']
        require(type(dtype) is str and dtype in BITS, 'Dtype')
        require(type(shape) is list and all(unsigned(d) for d in shape), 'Shape')
        require(type(offsets) is list and len(offsets) == 2 and all(unsigned(x) for x in offsets), 'Offsets')
        start,end = offsets
        require(start <= end <= payload_size, 'Offsets')
        count = 1
        for dimension in shape:
            count *= dimension
            require(count <= MAX_U64, 'Capacity')
        bits = count*BITS[dtype]
        require(bits <= MAX_U64, 'Capacity')
        require(bits%8 == 0, 'Alignment')
        require(end-start == bits//8, 'Size')
        entries.append((start,end,name,dtype,tuple(shape)))
    cursor = 0
    for start,end,*_ in sorted(entries):
        require(start == cursor, 'Offsets')
        cursor = end
    require(cursor == payload_size, 'Coverage')
    # No tensor data is exposed until every descriptor and coverage relation passed.
    tensors = {name:dict(dtype=dtype,shape=shape,data=raw[8+size+start:8+size+end])
               for start,end,name,dtype,shape in entries}
    return dict(metadata=metadata,tensors=tensors)


def selection(specs, ignored):
    specs = a.ordered(specs)
    require(type(ignored) is list and len(ignored) < 1 << 32, 'Ignored')
    require(all(type(name) is str for name in ignored), 'Ignored')
    names = sorted(utf8(name) for name in ignored)
    require(len(set(names)) == len(names), 'Ignored')
    require(not ({spec.name for spec in specs} & set(ignored)), 'Selection')
    require(all(len(name) < 1 << 32 for name in names), 'Capacity')
    require(len(CONFIG)+32+4+sum(4+len(name) for name in names) <= MAX_U64, 'Capacity')
    # This composes source selection with the complete offline tensor policy;
    # it is deliberately separate from the research artifact's v1 quantiser id.
    return CONFIG+a.quantiser_id(specs)+len(names).to_bytes(4,'little')+b''.join(
        len(name).to_bytes(4,'little')+name for name in names)


def prepare(specs, ignored, raw, expected_digest):
    config = selection(specs,ignored)
    require(type(raw) is bytes, 'Bytes')
    require(type(expected_digest) is bytes and len(expected_digest) == 32, 'Digest')
    require(hashlib.sha256(raw).digest() == expected_digest, 'SourceDigest')
    tensors = parse(raw)['tensors']
    require(set(tensors) == {spec.name for spec in specs} | set(ignored), 'Selection')
    source = {}
    for spec in a.ordered(specs):
        found = tensors[spec.name]
        require((found['dtype'],found['shape']) == (SOURCE[spec.source],spec.shape), 'SourceMetadata')
        source[spec.name] = found['data']
    output = a.prepare(specs,source)
    return dict(digest_hf=expected_digest,source_preparation_id=blake3(config).digest(),
                quantiser_id=a.quantiser_id(specs),artifact=output,digest_cqis=a.digest(specs,output))
