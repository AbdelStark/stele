"""RFC-0025 encoding §§2–3: bounded native Map/Preparation fixture generation.

Calls qualified pure metadata helpers only; never a historical campaign main.
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
from check_model_codec import make, oracle as model_oracle
from check_artifact_codec import mapping, preparation
from check_source_map import encode_oracle
from source_map import Shape, decode

rng=Random(50350)
data=bytearray(); cases=[]; invalid=[]; samples={}
def blob(raw): return pack('<I',len(raw))+raw

shapes=[Shape(0,12,768,12,12,64,3072,50257,1024),Shape(1,32,4096,32,8,128,14336,128256,131072),
        Shape(0,128,4096,128,128,32,16384,1<<20,1<<20),Shape(1,128,16384,128,128,128,16384,1<<20,1<<20)]
for i in range(68):
    family=i%2
    shape=shapes[i] if i<4 else Shape(family,2,4,2,2 if family==0 else 1,2,16 if family==0 else 7,5,9)
    m=make(rng,family,shape); mp=mapping(m,rng,family==0 and i%4==0)
    if i==4:
        mp=replace(mp,aliases=(('head.alias',0),),ignored=('a.buffer','z.buffer'))
        samples['fused']=mp
    if i==6: samples['separate']=mp
    if i==5: samples['llama']=mp
    if i==8:
        es=list(mp.entries); es[0]=replace(es[0],name='x'*4096)
        mp=replace(mp,entries=tuple(es),ignored=('e\u0301','é'))
    raw=encode_oracle(mp); assert raw==mp.encode() and decode(raw)==mp
    model=model_oracle(m); prep=preparation(m,mp)
    data.extend(blob(model)+blob(raw)+blob(prep))
    cases.append(dict(map_id=blake3(raw).hexdigest(),preparation_id=blake3(prep).hexdigest(),
                      entries=[dict(name=e.name,dtype=e.dtype,dimensions=e.shape,transform=e.transform,part=e.part) for e in mp.entries],
                      aliases=mp.aliases,ignored=mp.ignored))

def bad(raw,reason):
    try: decode(raw)
    except ValueError: pass
    else: raise AssertionError('reference accepted invalid Map')
    invalid.append(dict(raw=raw.hex(),error=reason))

def entry(mp,i,reason,**changes):
    es=list(mp.entries);es[i]=replace(es[i],**changes)
    bad(encode_oracle(replace(mp,entries=tuple(es))),reason)

f=samples['fused'];s=samples['separate'];l=samples['llama']
for name in ('','bad\0name','x'*4097): entry(f,0,'SourceName',name=name)
raw=bytearray(encode_oracle(f));raw[len(b'stele/v0.1/cqis/source-map')+4+21+2]=255;bad(bytes(raw),'SourceName')
for dtype in (0,5):entry(f,0,'SourceDtype',dtype=dtype)
for ds in ((),(0,4),(5,5),(1,2,3),(2**32-1,2**32-1)):entry(f,0,'SourceShape',shape=ds)
entry(f,0,'SourceTransform',transform=4)
entry(f,0,'SourceTransform',transform=1,shape=f.entries[0].shape[::-1])
for i,e in enumerate(f.entries):
    if e.transform in (2,3):
        entry(f,i,'SourceTransform',part=(e.part+1)%3)
        entry(f,i,'SourcePartition',name=e.name+'.missing')
        entry(f,i,'SourcePartition',dtype=e.dtype%4+1)
entry(f,20,'SourcePartition',name=f.entries[4].name)
entry(s,2,'SourceAlias',name=s.entries[0].name)
for aliases in ((('a',0),('b',0)),(('a',1),),((f.entries[0].name,0),)):
    bad(encode_oracle(replace(f,aliases=aliases)),'SourceAlias')
bad(encode_oracle(replace(l,aliases=(('a',0),))),'SourceAlias')
for ignored in (('z','a'),('a','a'),(f.entries[0].name,),('head.alias',)):
    bad(encode_oracle(replace(f,ignored=ignored)),'SourceIgnored')
raw=encode_oracle(f)
bad(raw+b'\0','Encoding')
for end in (0,1,24,27,len(raw)//2,len(raw)-1):bad(raw[:end],'Encoding')
raw=encode_oracle(replace(f,ignored=()))
bad(raw[:-4]+pack('<I',2**32-1),'Capacity')

out=ROOT/'crates/stele-cqis/tests/fixtures'
(out/'source-preparation.bin').write_bytes(data)
names=['check_model_codec.py','check_artifact_codec.py','check_source_map.py','source_map.py','artifact_codec.py']
receipt=dict(seed=50350,cases=cases,invalid=invalid,
             sources={'research/cqis-model-contract/'+p:sha256((ROOT/'research/cqis-model-contract'/p).read_bytes()).hexdigest() for p in names},
             fixture_sha256=sha256(data).hexdigest())
(out/'source-preparation.json').write_text(json.dumps(receipt,separators=(',',':'))+'\n')
print(json.dumps(dict(valid=len(cases),invalid=len(invalid),bytes=len(data))))
