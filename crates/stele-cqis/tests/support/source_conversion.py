"""RFC-0025 conversion: new bounded fixtures; never run historical campaigns."""
from dataclasses import replace
from fractions import Fraction as Q
from hashlib import sha256
from io import BytesIO
import json
from pathlib import Path
from random import Random
from struct import pack
import sys
from blake3 import blake3

root=Path(__file__).resolve().parents[4]
sys.path.insert(0,str(root/'research/cqis-model-contract'))
import source_conversion as c
import source_codec
import scalars
import quantiser
from check_source_conversion import FORMATS, number, dyadic, tensors, package, oracle
from check_artifact_codec import mapping, preparation, artifact
from check_model_codec import make, oracle as model_frame, roles
from check_scales_codec import oracle as scales_frame
from source_map import Shape
from scales_codec import Scale

rng=Random(50480);data=bytearray();spans={};cases=[];scalar_cases=[]
def store(raw):
    if raw not in spans:spans[raw]=dict(offset=len(data),length=len(raw));data.extend(raw)
    return spans[raw]
def record(label,m,mp,ts,groups=1,error=None,unaligned=False,analytic=None,pattern=None):
    src,assets,files=package(ts,groups);sink=BytesIO()
    if unaligned:
        for name,raw in list(files.items()):
            if name.endswith('.safetensors'):
                length=int.from_bytes(raw[:8],'little');files[name]=(length+1).to_bytes(8,'little')+raw[8:8+length]+b' '+raw[8+length:]
        src=source_codec.describe_source({f.name:files[f.name] for f in src.files}|({src.index.name:files[src.index.name]} if src.index else {}),src.index.name if src.index else None)
    if analytic is not None:
        source_codec.verify(mp,src,assets,files)
        scales,expected=analytic;sr=scales_frame(m,scales) if error is None else b''
    else:
        try:result=c.convert(m,mp,src,assets,files,sink)
        except ValueError as failure:
            assert error==str(failure),(label,str(failure));assert sink.getvalue()==b'';sr=expected=b''
        else:
            assert error is None,label
            scales,expected=oracle(m,mp,ts);sr=scales_frame(m,scales)
            assert result.scales==sr and sink.getvalue()==expected and result.digest==blake3(expected).digest()
    described=[]
    for name,raw in sorted(files.items()):
        prefix=raw;period=b'';start=length=0;patches=[]
        if pattern and name.endswith('.safetensors'):
            header=int.from_bytes(raw[:8],'little');info=json.loads(raw[8:8+header]);prefix=raw[:8+header]
            if pattern[0] in info:
                first,last=info[pattern[0]]['data_offsets'];start=8+header+first;length=last-first;period=pattern[1]
                for i,byte in enumerate(raw[start:start+length]):
                    if byte!=period[i%len(period)]:patches.append((start+i,byte))
                assert len(patches)<=2
            expected_raw=bytearray(len(raw));expected_raw[:len(prefix)]=prefix
            if period:expected_raw[start:start+length]=(period*((length+len(period)-1)//len(period)))[:length]
            for at,byte in patches:expected_raw[at]=byte
            assert raw==expected_raw
        described.append(dict(name=name,prefix=store(prefix),length=len(raw),period=store(period),start=start,pattern_length=length,patches=patches))
    wrong=replace(mp,entries=(replace(mp.entries[0],name=mp.entries[0].name+'.wrong'),)+mp.entries[1:])
    cases.append(dict(label=label,model=store(model_frame(m)),other_model=store(model_frame(replace(m,logits_fraction=(m.logits_fraction+1)%31))),
        preparation=store(preparation(m,mp)),other_preparation=store(preparation(m,wrong)),source=store(source_codec.encode_source(src)),assets=store(source_codec.encode_assets(assets)),
        files=described,scales=store(sr),artifact=store(expected),error=error))

for i in range(24):
    family=i%2;d=rng.choice((2,4,6));shape=Shape(family,1+i%2,d,1,1,d,4*d if not family else 7,5,3)
    m=make(rng,family,shape);mp=mapping(m,rng,not family and i%4==0)
    record('random '+str(i),m,mp,tensors(m,mp,rng),1 if i%3==0 else 3)

m=make(rng,0,Shape(0,1,3,1,1,3,12,3,3));mp=replace(mapping(m,rng,True),aliases=())
for dtype,(size,eb,fb,_) in FORMATS.items():
    entry=replace(mp.entries[0],dtype=dtype);selected=replace(mp,entries=(entry,)+mp.entries[1:])
    for bits in (4,8):
        model=replace(m,formats=((bits,0),)+m.formats[1:])
        for word in [0,1,1<<(size*8-1),(((1<<eb)-2)<<fb)+((1<<fb)-1)]:
            ts=tensors(model,selected);ts[entry.name]['data']=word.to_bytes(size,'little')*9
            record(f'extreme {dtype} {bits} {word}',model,selected,ts)
    for sign in (0,1):
        for fraction in (0,1,(1<<fb)-1):
            ts=tensors(m,selected);word=(sign<<(size*8-1))+(((1<<eb)-1)<<fb)+fraction
            ts[entry.name]['data']=bytes(8*size)+word.to_bytes(size,'little')
            record(f'nonfinite last token {dtype} {sign} {fraction}',m,selected,ts,error='Nonfinite')

vector=next(i for i,(_,_,dims) in enumerate(roles(m.shape)) if len(dims)==1)
entry=replace(mp.entries[vector],dtype=4);selected=replace(mp,entries=mp.entries[:vector]+(entry,)+mp.entries[vector+1:]);fraction=m.formats[vector][1]
for n in (1,-1,65534,-65536,65535,-65537):
    ts=tensors(m,selected);ts[entry.name]['data']=dyadic(4,n,-1-fraction)*3
    record('vector half endpoint '+str(n),m,selected,ts,error='Overflow' if n in (65535,-65537) else None)
for label,ts in [('zero',tensors(m,mp)),('finite random',tensors(m,mp,rng))]:
    record(label+' single',m,mp,ts);record(label+' sharded',m,mp,ts,3)
ts=tensors(m,mp);token=mp.entries[0];size=FORMATS[token.dtype][0]
ts[token.name]['data']=(1<<(size*8-1)).to_bytes(size,'little')*9
record('negative zeros',m,mp,ts)
ts=tensors(m,mp);ts['mask.buffer']=dict(dtype='float32',shape=[],data=pack('<I',0x7f800000));record('ignored nonfinite',m,mp,ts)
ts=tensors(m,mp)
for entry in (mp.entries[0],next(e for e in mp.entries if e.transform==2 and e.part==0)):
    size=FORMATS[entry.dtype][0];ts[entry.name]['data']=dyadic(entry.dtype,1,0)+bytes(len(ts[entry.name]['data'])-size)
record('separate fused scales and zero rows',m,mp,ts)
for tag in (2,3):
    entry=next(e for e in mp.entries if e.transform==tag and e.part==2);size,eb,fb,_=FORMATS[entry.dtype]
    ts=tensors(m,mp);ts[entry.name]['data']=ts[entry.name]['data'][:-size]+(((1<<eb)-1)<<fb).to_bytes(size,'little')
    record('late fused nonfinite '+str(tag),m,mp,ts,error='Nonfinite')

# Both cache layouts span several original chunks. Deliberately unaligned header
# lengths force selected scalars to cross authenticated chunk boundaries.
for shape,dtype in [(Shape(0,1,129,1,1,129,516,3,1),1),(Shape(1,1,2,1,1,2,8192,3,1),4)]:
    model=make(rng,shape.family,shape);model=replace(model,formats=tuple((4,0) if len(ds)==2 else fmt for (_,_,ds),fmt in zip(roles(shape),model.formats)))
    mp2=mapping(model,rng,False);es=list(mp2.entries)
    ordinal=next(i for i,(role,_,_) in enumerate(roles(shape)) if role=='up');_,_,dims=list(roles(shape))[ordinal]
    es[ordinal]=replace(es[ordinal],dtype=dtype,shape=dims[::-1],transform=1);mp2=replace(mp2,entries=tuple(es),aliases=())
    ts=tensors(model,mp2);size=FORMATS[dtype][0];period=(1).to_bytes(size,'little')+((1<<(size*8-1))+1).to_bytes(size,'little')
    count=dims[0]*dims[1];ts[es[ordinal].name]['data']=(period*((count+1)//2))[:count*size]
    record('transposed chunk stride '+str(dtype),model,mp2,ts,unaligned=True)

# Complete odd 4194305-element source with analytically repeated exact rows.
# Only the tiny row oracle is called; no frozen research large/main campaign.
shape=Shape(0,1,5,1,1,5,20,838861,1);model=make(rng,0,shape)
model=replace(model,formats=tuple((4,0) if len(ds)==2 else fmt for (_,_,ds),fmt in zip(roles(shape),model.formats)))
mp2=mapping(model,rng,False);mp2=replace(mp2,entries=tuple(replace(e,dtype=1) for e in mp2.entries),aliases=())
ts=tensors(model,mp2);period=b'\1\0\1\x80';count=4194305;name=mp2.entries[0].name;ts[name]['data']=period*(count//2)+period[:2]
small=quantiser.weights([[Q(1,1<<24),-Q(1,1<<24)]],4)
assert small==dict(bits=4,exponent=-42,mantissas=[37450],output=[[7,-7]])
scales=[];payloads=[]
for i,(_,_,dims) in enumerate(roles(shape)):
    if i==0:scales.append(Scale(-42,pack('<H',37450)*dims[0]));payloads.append(bytes([151])*(count//2)+b'\7')
    elif len(dims)==2:scales.append(Scale(0,pack('<H',1)*dims[0]));payloads.append(bytes((dims[0]*dims[1]+1)//2))
    else:payloads.append(bytes(2*dims[0]))
expected=artifact(model,mp2,tuple(scales),payloads)
record('full odd source above former cap',model,mp2,ts,analytic=(tuple(scales),expected),pattern=(name,period))
ts[name]['data']=ts[name]['data'][:-2]+b'\0\x7c'
try:scalars.decode('binary16',ts[name]['data'][-2:])
except ValueError:pass
else:raise AssertionError('late nonfinite')
record('full odd final scalar nonfinite',model,mp2,ts,error='Nonfinite',analytic=((),b''),pattern=(name,period))

# Independent exact scalar corpus plus exhaustive finite/nonfinite 16-bit domains.
exhaustive=[]
for dtype in (1,2):
    digest=blake3();accepted=0
    for word in range(65536):
        try:n,p=scalars.decode(c.FORMATS[dtype-1],word.to_bytes(2,'little'))
        except ValueError:digest.update(b'\0')
        else:digest.update(b'\1'+pack('<qh',n,p));accepted+=1
    exhaustive.append(dict(dtype=dtype,digest=digest.hexdigest(),accepted=accepted))
for dtype,(size,eb,fb,_) in FORMATS.items():
    for word in [0,1,(1<<fb)-1,1<<fb,((1<<eb)-2)<<fb,(((1<<eb)-2)<<fb)+(1<<fb)-1]+[rng.getrandbits(size*8) for _ in range(2600)]:
        raw=word.to_bytes(size,'little')
        try:n,p=scalars.decode(c.FORMATS[dtype-1],raw)
        except ValueError:scalar_cases.append(dict(dtype=dtype,raw=raw.hex(),error='Nonfinite'));continue
        value=number(dtype,raw);assert value==Q(n)*Q(2)**p
        fraction=rng.randrange(31);rounded=c._rounded(n,p+fraction,1)
        scalar_cases.append(dict(dtype=dtype,raw=raw.hex(),n=n,p=p,fraction=fraction,rounded=rounded if -32768<=rounded<=32767 else None,error=None))

assert sum(v['error'] is None for v in scalar_cases)>=10000
out=root/'crates/stele-cqis/tests/fixtures'
(out/'source-conversion.bin').write_bytes(data)
(out/'source-conversion.json').write_text(json.dumps(dict(seed=50480,cases=cases,scalars=scalar_cases,exhaustive=exhaustive),separators=(',',':'))+'\n')
print(json.dumps(dict(cases=len(cases),valid=sum(v['error'] is None for v in cases),scalar_cases=len(scalar_cases),bytes=len(data))))
