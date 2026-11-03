"""Draft RFC-0025 §2.7 / encoding §3: complete Artifact and Preparation codecs."""
from collections import Counter
from dataclasses import replace
from hashlib import sha256
from io import BytesIO
import json
from random import Random
from struct import pack

from blake3 import blake3

import artifact_codec as c
from check_arithmetic_bounds import rejects
from check_model_codec import make, roles
from check_scales_codec import make_scales, oracle as scales_oracle
from check_source_map import encode_oracle as map_oracle
from model_codec import encode as encode_model
from scales_codec import encode as encode_scales
from scales_codec import Scale
from source_map import Entry, Shape, SourceMap


def configurations(model):
    return [pack('<HB',i,len(ds))+pack('<'+'I'*len(ds),*ds)+pack('<BB',*model.formats[i])
            for i,(_,_,ds) in enumerate(roles(model.shape))]


def preparation(model, mapping):
    raw = map_oracle(mapping)
    return b'stele/v0.1/cqis/quantiser'+pack('<I',len(raw))+raw+b''.join(configurations(model))


def artifact(model, mapping, scales, payloads):
    configs = configurations(model); result = [b'cqis-weights-v1',blake3(preparation(model,mapping)).digest(),pack('<H',len(configs))]
    scale = iter(scales)
    for (_,_,dims),ci,payload in zip(roles(model.shape),configs,payloads):
        parts = [b'stele/v0.1/cqis/tensor',pack('<I',len(ci)),ci]
        if len(dims) == 2:
            value = next(scale); parts += [pack('<h',value.exponent),value.mantissas]
        parts += [pack('<Q',len(payload)),payload]; raw = b''.join(parts)
        result += [pack('<Q',len(raw)),raw]
    return b''.join(result)


def mapping(model, rng, fused):
    entries = []; dtype_by_name = {}
    for name, layer, dims in roles(model.shape):
        source, tag, part, shape = f'{layer}.{name}',0,None,dims
        if fused and name.removesuffix('.bias') in ('Q','K','V'):
            tag = 3 if name.endswith('.bias') else 2; part = ('Q','K','V').index(name.removesuffix('.bias'))
            source = f'{layer}.fused.{tag}'; shape = (3*model.shape.width,) if tag == 3 else (model.shape.width,3*model.shape.width)
        elif len(dims) == 2 and name not in ('token','position') and rng.randrange(2):
            tag,shape = 1,dims[::-1]
        dtype = dtype_by_name.setdefault(source,rng.randint(1,4))
        entries.append(Entry(source,dtype,shape,tag,part))
    aliases = (('head.alias',0),) if not model.shape.family and rng.randrange(2) else ()
    return SourceMap(model.shape,tuple(entries),aliases,('mask.buffer',))


def payloads(model, rng):
    result = []
    for (_,_,dims),(bits,_) in zip(roles(model.shape),model.formats):
        count = dims[0]*(dims[1] if len(dims) == 2 else 1)
        if bits == 16: raw = b''.join(pack('<h',rng.randint(-32768,32767)) for _ in range(count))
        elif bits == 8: raw = b''.join(pack('<b',rng.randint(-127,127)) for _ in range(count))
        else:
            words = [rng.randint(-7,7)%16 for _ in range(count)]+([0] if count%2 else [])
            raw = bytes(lo+16*hi for lo,hi in zip(words[::2],words[1::2]))
        result.append(raw)
    return tuple(result)


class ShortReader(BytesIO):
    def read(self, n):
        assert 0 < n <= 65536
        return super().read(min(n,3))


def layout_oracle(model):
    offset, result = 49, []
    for (_,_,dims),(bits,_) in zip(roles(model.shape),model.formats):
        count = dims[0]*(dims[1] if len(dims)==2 else 1)
        size = (count*bits+7)//8; header = 49+2*dims[0] if len(dims)==2 else 43
        result.append((offset+8,offset+8+header,size,header+size)); offset += 8+header+size
    return result,offset


def boundaries():
    rng = Random(26870); m = make(rng,0,Shape(0,1,1,1,1,1,4,3,3))
    m = replace(m,formats=tuple((4,0) if len(ds)==2 else fmt for (_,_,ds),fmt in zip(roles(m.shape),m.formats)))
    mp = mapping(m,rng,True); scales = make_scales(rng,m); sr = encode_scales(m,scales); pp = payloads(m,rng)
    prep = c.encode_preparation(m,mp); raw = artifact(m,mp,scales,pp); expected = blake3(raw).digest()
    assert c.decode_preparation(m,prep)==mp
    assert c.decode_preparation_expected(m,blake3(prep).digest(),prep)==mp
    assert b''.join(c.iterencode(m,mp,sr,tuple(ShortReader(p) for p in pp)))==raw
    assert c.digest(m,mp,sr,ShortReader(raw))==expected
    c.verify(m,mp,sr,BytesIO(raw),expected)
    for end in (0,1,len(prep)//2,len(prep)-1):
        try: c.decode_preparation(m,prep[:end])
        except ValueError: pass
        else: raise AssertionError('PreparationTruncation')
    rejects(lambda:c.decode_preparation(m,prep+b'\0'),'Trailing')
    rejects(lambda:c.decode_preparation(m,bytearray(prep)),'Capacity')
    rejects(lambda:c.decode_preparation(m,bytes((17<<20)+1)),'Capacity')
    rejects(lambda:c.decode_preparation_expected(m,bytes(32),prep),'Identity')
    rejects(lambda:c.decode_preparation_expected(m,bytes(31),prep),'Digest')
    other = replace(m,logits_fraction=(m.logits_fraction+1)%31)
    assert encode_model(other)!=encode_model(m) and c.encode_preparation(other,mp)==prep
    wrong_shape=make(rng,0,Shape(0,1,2,1,1,2,8,3,3))
    rejects(lambda:c.encode_preparation(wrong_shape,mp),'Shape')
    rejects(lambda:c.decode_preparation(wrong_shape,prep),'Shape')
    other_format=replace(m,formats=((8,0),)+m.formats[1:])
    rejects(lambda:c.decode_preparation(other_format,prep),'Configuration')
    changed_map = replace(mp,ignored=('another.buffer',))
    assert c.encode_preparation(m,changed_map)!=prep
    rejects(lambda:c.digest(m,changed_map,sr,BytesIO(raw)),'Quantiser')
    recs,total = c.layout(m); assert total==len(raw)
    for i,r in enumerate(recs):
        for end in (r.record_offset-8,r.record_offset,r.payload_offset,r.payload_offset+r.payload_length-1):
            rejects(lambda:c.digest(m,mp,sr,BytesIO(raw[:end])),'Truncated')
    rejects(lambda:c.digest(m,mp,sr,BytesIO(raw+b'\0')),'Trailing')
    for pos,reason in ((0,'Header'),(15,'Quantiser'),(47,'Count'),(49,'RecordLength'),
                       (recs[0].record_offset,'Record'),(recs[0].record_offset+26,'Configuration'),
                       (recs[0].record_offset+39,'Scales'),(recs[0].payload_offset-8,'PayloadLength')):
        changed = raw[:pos]+bytes((raw[pos]^1,))+raw[pos+1:]
        rejects(lambda:c.digest(m,mp,sr,BytesIO(changed)),reason)
    huge = raw[:49]+pack('<Q',2**64-1)+raw[57:]
    rejects(lambda:c.digest(m,mp,sr,ShortReader(huge)),'RecordLength')
    # Both nibbles are real except the one final odd-element high nibble.
    pos = recs[0].payload_offset
    for byte,reason,at in ((8,'Code',pos),(128,'Code',pos),(16,'Padding',pos+1)):
        changed = raw[:at]+bytes((byte,))+raw[at+1:]
        rejects(lambda:c.digest(m,mp,sr,BytesIO(changed)),reason)
    changed = raw[:pos]+bytes(((raw[pos]&240)|((raw[pos]+1)%8),))+raw[pos+1:]
    assert c.digest(m,mp,sr,BytesIO(changed))!=expected
    rejects(lambda:c.verify(m,mp,sr,BytesIO(changed),expected),'Identity')
    rejects(lambda:c.verify(m,mp,sr,BytesIO(raw),bytes(31)),'Digest')
    rejects(lambda:b''.join(c.iterencode(m,mp,sr,tuple(BytesIO(p) for p in pp[:-1]))),'Records')
    rejects(lambda:b''.join(c.iterencode(m,mp,sr,(BytesIO(pp[0]+b'\0'),)+tuple(BytesIO(p) for p in pp[1:]))),'Trailing')
    class BadReader:
        def __init__(self,value): self.value=value
        def read(self,n): return self.value(n)
    for fn in (lambda n:bytearray(n),lambda n:bytes(n+1)):
        rejects(lambda:c.digest(m,mp,sr,BadReader(fn)),'Read')
    # Real payloads and per-channel scale bytes cross the 64 KiB stream boundary.
    streaming=[]
    for bits in (4,8):
        large=make(rng,0,Shape(0,1,3,1,1,3,12,43693,3))
        large=replace(large,formats=tuple((bits,0) if len(ds)==2 else fmt for (_,_,ds),fmt in zip(roles(large.shape),large.formats)))
        lm=mapping(large,rng,False); values=[]; data=[]
        for _,_,dims in roles(large.shape):
            n=dims[0]*(dims[1] if len(dims)==2 else 1)
            if len(dims)==1: data.append(pack('<h',-32768)*n)
            else:
                values.append(Scale(-1099,pack('<H',65535)*dims[0]))
                data.append(bytes((127,))*n if bits==8 else bytes((121,))*(n//2)+(bytes((9,)) if n%2 else b''))
        ls=encode_scales(large,tuple(values)); chunks=list(c.iterencode(large,lm,ls,tuple(BytesIO(v) for v in data)))
        encoded=b''.join(chunks); assert encoded==artifact(large,lm,tuple(values),data)
        assert max(map(len,chunks))==65536
        c.verify(large,lm,ls,BytesIO(encoded),blake3(encoded).digest())
        first=c.layout(large)[0][0]; at=first.payload_offset+65536
        invalid=encoded[:at]+bytes((8 if bits==4 else 128,))+encoded[at+1:]
        rejects(lambda:c.digest(large,lm,ls,BytesIO(invalid)),'Code')
        if bits==4:
            at=first.payload_offset+first.payload_length-1
            invalid=encoded[:at]+bytes((25,))+encoded[at+1:]
            rejects(lambda:c.digest(large,lm,ls,BytesIO(invalid)),'Padding')
        streaming.append([bits,first.elements,first.payload_length,len(encoded)])
    # Fill a legal Map exactly to 16 MiB; its Preparation does not inherit Model's cap.
    base = replace(mp,ignored=()); remaining=(1<<24)-len(base.encode()); lengths=[]
    while remaining>4098: lengths.append(4096); remaining-=4098
    if remaining<12: lengths[-1]-=12-remaining; remaining=12
    lengths.append(remaining-2)
    ignored=tuple(f'i{i:07d}'+('x'*(n-8)) for i,n in enumerate(lengths))
    large=replace(mp,ignored=ignored); assert len(large.encode())==1<<24
    large_prep=c.encode_preparation(m,large); assert c.decode_preparation(m,large_prep)==large
    full=[]
    for shape in (Shape(0,12,768,12,12,64,3072,50257,1024),Shape(1,32,4096,32,8,128,14336,128256,131072),
                  Shape(0,128,4096,128,128,32,16384,2**20,2**20),Shape(1,128,16384,128,128,128,16384,2**20,2**20)):
        model=make(rng,shape.family,shape)
        model=replace(model,formats=tuple((8,0) if len(ds)==2 else fmt for (_,_,ds),fmt in zip(roles(shape),model.formats)))
        records,size=c.layout(model); entries,expected_size=layout_oracle(model)
        assert [(r.record_offset,r.payload_offset,r.payload_length,r.record_length) for r in records]==entries
        assert size==expected_size<2**39
        full.append([len(records),size,max(r.payload_length for r in records)])
    assert full[-1][1]>2**38 and full[-1][2]==2**34
    return dict(metadata_only_named_and_maximal_layouts=full,maximum_map_preparation_bytes=len(large_prep),
                odd_int4_elements=3,complete_stream_boundaries=streaming)


def main():
    rng,corpus=Random(2687),sha256(); reasons=Counter(); families=[0,0]; maximum=[0,0]; formats=Counter()
    for i in range(10000):
        family=i%2; h=rng.randint(1,3); a=rng.randint(2,4); d=h*a
        s=Shape(family,rng.randint(1,3),d,h,h if not family else 1,a,4*d if not family else rng.randint(1,16),rng.randint(1,7),rng.randint(1,5))
        m=make(rng,family,s); mp=mapping(m,rng,not family and i%4==0); scales=make_scales(rng,m)
        sr=encode_scales(m,scales); assert sr==scales_oracle(m,scales)
        pp=payloads(m,rng); pr=c.encode_preparation(m,mp); assert pr==preparation(m,mp) and c.decode_preparation(m,pr)==mp
        expected=artifact(m,mp,scales,pp); got=b''.join(c.iterencode(m,mp,sr,tuple(BytesIO(p) for p in pp)))
        assert got==expected; digest=blake3(expected).digest(); c.verify(m,mp,sr,BytesIO(got),digest)
        records,size=c.layout(m); entries,total=layout_oracle(m)
        assert size==total==len(got) and [(r.record_offset,r.payload_offset,r.payload_length,r.record_length) for r in records]==entries
        pos=rng.randrange(len(got)); changed=got[:pos]+bytes((got[pos]^1,))+got[pos+1:]
        try: c.verify(m,mp,sr,BytesIO(changed),digest)
        except ValueError as error: reasons[str(error)]+=1
        else: raise AssertionError(('Mutation',i,pos))
        for raw in (pr,got): corpus.update(pack('<I',len(raw))+raw)
        families[family]+=1; maximum=[max(maximum[0],len(pr)),max(maximum[1],len(got))]
        formats.update(bits for bits,_ in m.formats)
        if (i+1)%2000==0: print(json.dumps(dict(completed=i+1)),flush=True)
    print(json.dumps(dict(seed=2687,configurations=10000,families=families,format_records=formats,
                         maximum_preparation_artifact_bytes=maximum,mutation_reasons=reasons,
                         corpus_sha256=corpus.hexdigest(),boundaries=boundaries()),sort_keys=True))


if __name__=='__main__': main()
