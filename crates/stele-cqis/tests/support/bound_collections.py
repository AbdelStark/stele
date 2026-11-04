"""RFC-0025 collection: independent ordered records and bounded native fixtures.

Python3.12, python-flint==0.9.0, blake3==1.0.11. No historical campaign main.
Large cases qualify record layout only, never a Registry or completed Bounds.
"""
from dataclasses import replace
from hashlib import sha256
import json
from pathlib import Path
from random import Random
from struct import pack
import sys
from blake3 import blake3

ROOT=Path(__file__).resolve().parents[4]
sys.path.insert(0,str(ROOT/'research/cqis-model-contract'))
from check_bound_collection import fixture, expected_records, record_oracle, score_bound
from check_model_codec import oracle as model_oracle
from check_registry_codec import oracle as registry_oracle
from check_scales_codec import oracle as scales_oracle
from function_bounds import Exponential
from model_codec import Rotation, Sampled, encode as model_encode
from scales_codec import Scale
from source_map import Shape

rng=Random(50340)
pattern=pack('<4H',1,65535,32768,255)
cases=[]; models=bytearray(); registries=bytearray()


def blob(raw): return pack('<I',len(raw))+raw


def configured(shape,sampled):
    m=fixture(rng,shape.family,shape,0); blocks=[]
    for i,b in enumerate(m.blocks):
        f=list(b.fractions); f[5 if shape.family else 4]=7
        mode=i%3
        exp=Exponential(shape.context,8 if mode==2 else 7,7,7,mode,4 if mode else 0)
        policies=list(b.policies)
        if shape.family and i%2==0: policies[6]=(1,8454661)
        rotation=None if not shape.family else Rotation(shape.head_width,shape.context,2,i%2,8192,
                                                       ((500000,1),(8,1),(1,1),(4,1)))
        b=replace(b,fractions=tuple(f),activation=replace(b.activation,F=7,E=7),exp=exp,
                  policies=tuple(policies),rotation=rotation,accumulation=i%2,drop=0)
        choices=[e for e in range(-62,31) if score_bound(shape,replace(b,score_e=e))<2**31]
        b=replace(b,score_e=choices[-1])
        if b.accumulation:
            mode,scale=b.policies[3]
            restored=min(127,(65536+scale)//(2*scale))*scale if mode else 127*259
            drop=next(k for k in range(63) if (1024*(1<<b.exp.E)*restored+(1<<k)//2)//(1<<k)<=32767)
            b=replace(b,drop=drop)
        blocks.append(b)
    sample=Sampled(3,2,9,10,Exponential(shape.vocabulary,8,7,7,2,4)) if sampled else None
    return replace(m,blocks=tuple(blocks),decoding=sample)


def scales(m):
    return tuple(Scale(-1099 if j%2 else 1024,(pattern*((dims[0]+3)//4))[:2*dims[0]])
                 for j,(_,_,dims) in enumerate(r for r in m.shape.roles() if len(r[2])==2))


def add(m,full,error=None):
    mr=model_oracle(m); assert mr==model_encode(m)
    ss=scales(m); sr=scales_oracle(m,ss)
    rr=registry_oracle(m) if full else b''
    models.extend(blob(mr)); registries.extend(blob(rr))
    case=dict(model_id=blake3(mr).hexdigest(),scales_id=blake3(sr).hexdigest(),registry_id=blake3(rr).hexdigest() if full else None,
              scope='complete' if full else 'record-layout-only',error=error)
    if error is None:
        records=expected_records(m,ss); digest=blake3(); length=0; summaries=[]
        header=b'stele/v0.1/cqis/bounds'+blake3(mr).digest()+blake3(sr).digest()+blake3(rr).digest()+pack('<H',len(records)) if full else b''
        complete=blake3(header)
        for i,(name,layer,p) in enumerate(records):
            raw=record_oracle(p); chunk=pack('<HI',i,len(raw))+raw
            digest.update(chunk); complete.update(chunk); length+=len(chunk)
            if full:
                offset=len(b'stele/v0.1/cqis/model-arithmetic')
                n=int.from_bytes(raw[offset+5:offset+7],'little')
                summaries.append(dict(role=name,layer=layer,schema=raw[offset+4],parameters=raw[offset+7:offset+7+n].hex(),
                                      length=len(raw),digest=blake3(raw).hexdigest()))
        case.update(count=len(records),record_bytes=length,records_digest=digest.hexdigest())
        if full: case.update(length=len(header)+length,identity=complete.hexdigest(),records=summaries)
    cases.append(case)
    print(json.dumps({k:case[k] for k in ('scope','error','count','record_bytes') if k in case}),flush=True)


for family in (0,1):
    shape=Shape(family,2,4,2,2 if not family else 1,2,16 if not family else 7,5,1 if not family else 5)
    for sampled in (False,True):
        m=configured(shape,sampled); add(m,True)
        if family==0 and not sampled:
            b=m.blocks[0]
            add(replace(m,blocks=(replace(b,fractions=(0,0)+b.fractions[2:],score_m=65535,score_e=30),)+m.blocks[1:]),True,'ScoreBound')
            add(replace(m,blocks=(replace(b,accumulation=1,drop=0),)+m.blocks[1:]),True,'BlockBound')

for shape in (Shape(0,12,768,12,12,64,3072,50257,1024),Shape(1,32,4096,32,8,128,14336,128256,131072),
              Shape(0,128,4096,128,128,32,16384,1<<20,1<<20),Shape(1,128,16384,128,128,128,16384,1<<20,1<<20)):
    add(configured(shape,True),False)

out=ROOT/'crates/stele-cqis/tests/fixtures'
files={'bound-models.bin':bytes(models),'bound-registries.bin':bytes(registries)}
for name,raw in files.items(): (out/name).write_bytes(raw)
names=['check_bound_collection.py','check_model_codec.py','check_registry_codec.py','check_scales_codec.py','bound_collection.py','model_codec.py','scales_codec.py','source_map.py']
receipt=dict(seed=50340,scale_pattern=[1,65535,32768,255],cases=cases,
             sources={'research/cqis-model-contract/'+p:sha256((ROOT/'research/cqis-model-contract'/p).read_bytes()).hexdigest() for p in names},
             fixtures={name:sha256(raw).hexdigest() for name,raw in files.items()})
(out/'bound-collections.json').write_text(json.dumps(receipt,separators=(',',':'))+'\n')
