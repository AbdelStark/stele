"""Draft RFC-0025 §2.1: original bytes through independent rational conversion."""
from dataclasses import replace
from fractions import Fraction as Q
from hashlib import sha256
from io import BytesIO
import json
from random import Random
from struct import pack

from blake3 import blake3
import safetensors

import source_conversion as c
import source_codec
import artifact_codec
import quantiser as reference
from check_arithmetic_bounds import rejects
from check_artifact_codec import artifact, mapping
from check_model_codec import make, roles
from check_scales_codec import oracle as scales_frame
from check_source_codec import auxiliary
from scales_codec import Scale
from source_map import Shape

FORMATS={1:(2,5,10,'float16'),2:(2,8,7,'bfloat16'),3:(4,8,23,'float32'),4:(8,11,52,'float64')}


def number(dtype,raw):
    size,eb,fb,_=FORMATS[dtype]; word=int.from_bytes(raw,'little'); exponent=(word>>fb)&((1<<eb)-1)
    assert exponent!=(1<<eb)-1
    fraction=word&((1<<fb)-1); bias=(1<<(eb-1))-1
    value=Q(fraction+(1<<fb if exponent else 0))*Q(2)**((exponent if exponent else 1)-bias-fb)
    return -value if word>>(size*8-1) else value


def dyadic(dtype,n,p):
    size,eb,fb,_=FORMATS[dtype]; bias=(1<<(eb-1))-1; value=abs(Q(n)*Q(2)**p)
    if not value: return bytes(size)
    e=value.numerator.bit_length()-value.denominator.bit_length()
    if value<Q(2)**e: e-=1
    exponent=max(e,1-bias); significand=value/Q(2)**(exponent-fb)
    assert significand.denominator==1
    normal=value>=Q(2)**(1-bias)
    word=((exponent+bias)<<fb if normal else 0)+int(significand)-(1<<fb if normal else 0)
    return (word+(int(n<0)<<(size*8-1))).to_bytes(size,'little')


def tensors(model,mp,rng=None):
    fractions={}
    for entry,fmt in zip(mp.entries,model.formats):
        if fmt[0]==16: fractions[entry.name]=max(fractions.get(entry.name,0),fmt[1])
    result={}
    for entry in mp.entries:
        if entry.name in result: continue
        size,eb,fb,dtype=FORMATS[entry.dtype]; count=entry.shape[0]*(entry.shape[1] if len(entry.shape)==2 else 1)
        words=[]
        for _ in range(count):
            if rng is None: raw=bytes(size)
            else:
                maximum=(1<<eb)-2
                if entry.name in fractions: maximum=max(0,min(maximum,14-fractions[entry.name]+(1<<(eb-1))-1))
                while True:
                    word=(rng.randrange(2)<<(size*8-1))+(rng.randint(0,maximum)<<fb)+rng.getrandbits(fb)
                    raw=word.to_bytes(size,'little')
                    if entry.name not in fractions or abs(number(entry.dtype,raw))*Q(2)**fractions[entry.name]<=32767: break
            words.append(raw)
        result[entry.name]=dict(dtype=dtype,shape=list(entry.shape),data=b''.join(words))
    for alias,target in mp.aliases: result[alias]=dict(result[mp.entries[target].name])
    result['mask.buffer']=dict(dtype='bool',shape=[],data=b'\0')
    return result


def package(ts,groups):
    names=list(ts); files={}; locations={}
    for i in range(groups):
        selected=names[i::groups]; label=f'model-{i}.safetensors'
        files[label]=safetensors.serialize({n:ts[n] for n in selected}); locations.update((n,label) for n in selected)
    index=None
    if groups>1:
        index='model.index.json'; files[index]=json.dumps(dict(metadata=dict(total_size=sum(len(t['data']) for t in ts.values())),weight_map=locations),separators=(',',':')).encode()
    source=source_codec.describe_source(files,index); assets,af=auxiliary(True)
    return source,assets,{**files,**af}


def oracle(model,mp,ts):
    scales=[]; payloads=[]
    for entry,(_,_,dims),(bits,fraction) in zip(mp.entries,roles(model.shape),model.formats):
        size=FORMATS[entry.dtype][0]; raw=ts[entry.name]['data']
        values=[number(entry.dtype,raw[at:at+size]) for at in range(0,len(raw),size)]
        if entry.transform==3: values=values[entry.part*dims[0]:(entry.part+1)*dims[0]]
        elif entry.transform in (1,2):
            rows=[values[at:at+entry.shape[1]] for at in range(0,len(values),entry.shape[1])]
            if entry.transform==2: rows=[row[entry.part*dims[0]:(entry.part+1)*dims[0]] for row in rows]
            values=[v for row in zip(*rows) for v in row]
        if bits==16: codes=[reference.round_away(x*Q(2)**fraction) for x in values]
        else:
            rows=[values[at:at+dims[1]] for at in range(0,len(values),dims[1])]
            result=reference.weights(rows,bits); e=result['exponent']; ms=result['mantissas']
            scales.append(Scale(e,b''.join(pack('<H',m) for m in ms)))
            codes=[v for row in result['output'] for v in row]
            for row,m,output in zip(rows,ms,result['output']):
                assert all(abs(x-Q(v*m)*Q(2)**e)<=Q(m)*Q(2)**(e-1) for x,v in zip(row,output))
        if bits==4:
            words=[v%16 for v in codes]+([0] if len(codes)%2 else [])
            payloads.append(bytes(a+16*b for a,b in zip(words[::2],words[1::2])))
        else: payloads.append(b''.join(pack('<h' if bits==16 else '<b',v) for v in codes))
    return tuple(scales),artifact(model,mp,tuple(scales),payloads)


class Sink(BytesIO):
    maximum=0
    def write(self,raw):
        assert type(raw) is bytes and 0<len(raw)<=65536
        self.maximum=max(self.maximum,len(raw)); return super().write(raw)


def check(model,mp,ts,groups=1):
    source,assets,files=package(ts,groups); sink=Sink(); result=c.convert(model,mp,source,assets,files,sink)
    scales,expected=oracle(model,mp,ts); raw=sink.getvalue()
    assert raw==expected and result.scales==scales_frame(model,scales)
    assert result.digest==blake3(raw).digest() and result.length==len(raw)
    assert result.source_identity==source_codec.identity(source)
    assert result.assets_id==blake3(source_codec.encode_assets(assets)).digest()
    assert result.quantiser_id==blake3(artifact_codec.encode_preparation(model,mp)).digest()
    artifact_codec.verify(model,mp,result.scales,BytesIO(raw),result.digest)
    return result,raw


def boundaries():
    rng=Random(26890); model=make(rng,0,Shape(0,1,3,1,1,3,12,3,3)); mp=replace(mapping(model,rng,True),aliases=())
    scalar_cases=0
    for dtype,(size,eb,fb,label) in FORMATS.items():
        entry=replace(mp.entries[0],dtype=dtype); selected=replace(mp,entries=(entry,)+mp.entries[1:])
        for bits in (4,8):
            m=replace(model,formats=((bits,0),)+model.formats[1:])
            for word in (0,1,1<<(size*8-1),(((1<<eb)-2)<<fb)+((1<<fb)-1)):
                ts=tensors(m,selected); ts[entry.name]['data']=word.to_bytes(size,'little')*9
                check(m,selected,ts); scalar_cases+=1
        for word in (((1<<eb)-1)<<fb,(((1<<eb)-1)<<fb)+1):
            ts=tensors(model,selected); ts[entry.name]['data']=word.to_bytes(size,'little')+bytes(8*size)
            source,assets,files=package(ts,1); sink=Sink()
            rejects(lambda:c.convert(model,selected,source,assets,files,sink),'Nonfinite'); assert sink.getvalue()==b''
    vector=next(i for i,(_,_,ds) in enumerate(roles(model.shape)) if len(ds)==1)
    entry=replace(mp.entries[vector],dtype=4); selected=replace(mp,entries=mp.entries[:vector]+(entry,)+mp.entries[vector+1:])
    fraction=model.formats[vector][1]
    for n in (1,-1,65534,-65536,65535,-65537):
        ts=tensors(model,selected); ts[entry.name]['data']=dyadic(4,n,-1-fraction)*3
        if n in (65535,-65537):
            source,assets,files=package(ts,1); sink=Sink()
            rejects(lambda:c.convert(model,selected,source,assets,files,sink),'Overflow'); assert not sink.getvalue()
        else: check(model,selected,ts)
    ts=tensors(model,mp); first,raw=check(model,mp,ts); second,other=check(model,mp,ts,3)
    assert raw==other and first.scales==second.scales and first.source_identity!=second.source_identity
    # Equal decoded signed zeros keep different source bytes; ignored nonfinite data is not selected.
    zero=dict(ts[mp.entries[0].name]); size=FORMATS[mp.entries[0].dtype][0]
    ts[mp.entries[0].name]={**zero,'data':(1<<(size*8-1)).to_bytes(size,'little')*9}
    signed,other=check(model,mp,ts); assert other==raw and signed.source_identity!=first.source_identity
    ts=tensors(model,mp); ts['mask.buffer']=dict(dtype='float32',shape=[],data=pack('<I',0x7f800000))
    assert check(model,mp,ts)[1]==raw
    # A peak in only Q must not give K/V that exponent; zero token rows keep their matrix's e.
    ts=tensors(model,mp); qi=next(i for i,e in enumerate(mp.entries) if e.transform==2 and e.part==0)
    entry=mp.entries[qi]; size=FORMATS[entry.dtype][0]
    ts[entry.name]['data']=dyadic(entry.dtype,1,0)+bytes(len(ts[entry.name]['data'])-size)
    token=mp.entries[0]; size=FORMATS[token.dtype][0]
    ts[token.name]['data']=dyadic(token.dtype,1,0)+bytes(len(ts[token.name]['data'])-size)
    derived,_=check(model,mp,ts); scales=c.scales_codec.decode(model,derived.scales)
    selected_scales={i:s for (i,_),s in zip(c.scales_codec.layout(model)[1],scales)}
    assert selected_scales[qi].exponent!=0 and selected_scales[qi+2].exponent==selected_scales[qi+4].exponent==0
    assert selected_scales[0].exponent!=0 and list(selected_scales[0].values())[1:]==[1,1]
    # Nonfinite input in the final fused-bias partition is checked before any output.
    entry=next(e for e in mp.entries if e.transform==3 and e.part==2); size,eb,fb,_=FORMATS[entry.dtype]
    ts=tensors(model,mp); ts[entry.name]['data']=bytes(8*size)+(((1<<eb)-1)<<fb).to_bytes(size,'little')
    source,assets,files=package(ts,1); sink=Sink()
    rejects(lambda:c.convert(model,mp,source,assets,files,sink),'Nonfinite'); assert not sink.getvalue()
    ts=tensors(model,mp)
    source,assets,files=package(ts,1)
    class ShortSink:
        def write(self,raw): return len(raw)-1
    rejects(lambda:c.convert(model,mp,source,assets,files,ShortSink()),'Write')
    rejects(lambda:c.convert(model,mp,source,assets,files,object()),'Sink')
    changed=dict(files); name=source.files[0].name; changed[name]=changed[name][:-1]+bytes((changed[name][-1]^1,)); sink=Sink()
    rejects(lambda:c.convert(model,mp,source,assets,changed,sink),'FileDigest'); assert not sink.getvalue()
    return dict(extreme_scalar_cases=scalar_cases,vector_halfway_endpoint_cases=6,repartition_equal_artifact=True,
                separate_fused_exponents=True,zero_rows_preserve_exponent=True,late_partition_rejects_before_output=True)


def large():
    # A real odd-row conversion above the old 2^22 cap, with alternating nonzero codes.
    rng=Random(26891); model=make(rng,0,Shape(0,1,5,1,1,5,20,838861,1)); mp=mapping(model,rng,False)
    entries=tuple(replace(e,dtype=1) for e in mp.entries); mp=replace(mp,entries=entries,aliases=())
    model=replace(model,formats=tuple((4,0) if len(ds)==2 else fmt for (_,_,ds),fmt in zip(roles(model.shape),model.formats)))
    ts={e.name:dict(dtype='float16',shape=list(e.shape),data=bytes(2*e.shape[0]*(e.shape[1] if len(e.shape)==2 else 1))) for e in entries}
    count=4194305; ts[entries[0].name]['data']=b'\1\0\1\x80'*(count//2)+b'\1\0'
    ts['mask.buffer']=dict(dtype='bool',shape=[],data=b'\0'); source,assets,files=package(ts,1); sink=Sink()
    result=c.convert(model,mp,source,assets,files,sink); scales=[]; pp=[]
    for i,(_,_,dims) in enumerate(roles(model.shape)):
        if i==0: scales.append(Scale(-42,pack('<H',37450)*dims[0])); pp.append(bytes((151,))*(count//2)+bytes((7,)))
        elif len(dims)==2: scales.append(Scale(0,pack('<H',1)*dims[0])); pp.append(bytes((dims[0]*dims[1]+1)//2))
        else: pp.append(bytes(2*dims[0]))
    expected=artifact(model,mp,tuple(scales),pp)
    assert sink.getvalue()==expected and result.digest==blake3(expected).digest() and sink.maximum==65536
    assert result.scales==scales_frame(model,tuple(scales))
    return dict(token_elements=count,token_row_width=5,artifact_bytes=len(expected),maximum_chunk=sink.maximum)


def main():
    rng=Random(2689); corpus=sha256(); formats={4:0,8:0,16:0}; transformed=[0]*4; maximum=0
    for i in range(10000):
        family=i%2; d=rng.randint(2 if family else 1,4); model=make(rng,family,Shape(family,rng.randint(1,2),d,1,1,d,4*d if not family else rng.randint(1,8),rng.randint(1,5),rng.randint(1,4)))
        mp=mapping(model,rng,not family and i%4==0); ts=tensors(model,mp,rng)
        result,raw=check(model,mp,ts,1 if i%3==0 else 2)
        for fmt,entry in zip(model.formats,mp.entries): formats[fmt[0]]+=1; transformed[entry.transform]+=1
        for frame in (result.source_identity,result.scales,raw): corpus.update(pack('<I',len(frame))+frame)
        maximum=max(maximum,len(raw))
        if (i+1)%2000==0: print(json.dumps(dict(completed=i+1)),flush=True)
    print(json.dumps(dict(seed=2689,configurations=10000,families=[5000,5000],formats=formats,transforms=transformed,maximum_artifact_bytes=maximum,corpus_sha256=corpus.hexdigest(),boundaries=boundaries(),large=large()),sort_keys=True))


if __name__=='__main__': main()
