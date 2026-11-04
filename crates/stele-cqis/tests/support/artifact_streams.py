"""RFC-0025 encoding §3: bounded independent native Artifact stream fixtures.

Full named/maximal cases derive layout only; no source or conversion admission.
Qualified pure helpers only; no historical campaign entry point is run.
"""
from dataclasses import replace
from hashlib import sha256
from io import BytesIO
import json
from pathlib import Path
from random import Random
from struct import pack
import sys
from blake3 import blake3

ROOT=Path(__file__).resolve().parents[4]
sys.path.insert(0,str(ROOT/'research/cqis-model-contract'))
from check_model_codec import make, oracle as model_oracle, roles
from check_artifact_codec import mapping, preparation, artifact, payloads, layout_oracle
from check_scales_codec import make_scales, oracle as scales_oracle
from artifact_codec import digest
from scales_codec import Scale
from source_map import Shape

rng=Random(50360); cases=[]; data=bytearray()
def blob(raw):return pack('<I',len(raw))+raw
def add(m,full,pattern=False,generated=False):
    records,total=layout_oracle(m)
    mr=model_oracle(m); data.extend(blob(mr))
    if full:
        mp=mapping(m,rng,m.shape.family==0)
        if pattern:
            ss=[]; pp=[]
            for (_,_,ds),(bits,_) in zip(roles(m.shape),m.formats):
                count=ds[0]*(ds[1] if len(ds)==2 else 1)
                if len(ds)==1:pp.append(pack('<h',-32768)*count)
                else:
                    ss.append(Scale(-1099,pack('<H',65535)*ds[0]))
                    pp.append(bytes([127])*count if bits==8 else bytes([121])*(count//2)+(bytes([9]) if count%2 else b''))
            ss=tuple(ss); pp=tuple(pp)
        else:ss=make_scales(rng,m); pp=payloads(m,rng)
        prep=preparation(m,mp); sr=scales_oracle(m,ss); raw=artifact(m,mp,ss,pp)
        identity=blake3(raw).hexdigest(); assert digest(m,mp,sr,BytesIO(raw)).hex()==identity
        data.extend(blob(prep))
        if not generated:
            for part in (sr,raw):data.extend(blob(part))
            data.extend(pack('<H',len(pp)))
            for p in pp:data.extend(blob(p))
        assert total==len(raw)
    else:identity=None
    cases.append(dict(scope='generated-complete' if generated else 'complete' if full else 'layout-only',length=total,identity=identity,
                      records=[dict(ordinal=i,record_offset=r[0],payload_offset=r[1],payload_length=r[2],record_length=r[3],
                                    bits=fmt[0],elements=ds[0]*(ds[1] if len(ds)==2 else 1))
                               for i,(r,(_,_,ds),fmt) in enumerate(zip(records,roles(m.shape),m.formats))]))

for i in range(32):
    family=i%2; h=rng.randint(1,4); a=rng.choice((2,4,6)); d=h*a
    s=Shape(family,rng.randint(1,3),d,h,h if not family else 1,a,4*d if not family else rng.randint(1,48),rng.randint(1,17),rng.randint(1,17))
    if i==0:s=Shape(0,1,1,1,1,1,4,3,3)
    m=make(rng,family,s)
    if i==0:m=replace(m,formats=tuple((4,0) if len(ds)==2 else fmt for (_,_,ds),fmt in zip(roles(s),m.formats)))
    add(m,True)
for bits in (4,8):
    s=Shape(0,1,3,1,1,3,12,43693,3);m=make(rng,0,s)
    m=replace(m,formats=tuple((bits,0) if len(ds)==2 else fmt for (_,_,ds),fmt in zip(roles(s),m.formats)))
    add(m,True,True)
s=Shape(0,1,5,1,1,5,20,1<<20,3);m=make(rng,0,s)
m=replace(m,formats=tuple((8,0) if len(ds)==2 else fmt for (_,_,ds),fmt in zip(roles(s),m.formats)))
add(m,True,True,True)
for s in (Shape(0,12,768,12,12,64,3072,50257,1024),Shape(1,32,4096,32,8,128,14336,128256,131072),
          Shape(0,128,4096,128,128,32,16384,1<<20,1<<20),Shape(1,128,16384,128,128,128,16384,1<<20,1<<20)):
    m=make(rng,s.family,s)
    m=replace(m,formats=tuple((8,0) if len(ds)==2 else fmt for (_,_,ds),fmt in zip(roles(s),m.formats)))
    add(m,False)
out=ROOT/'crates/stele-cqis/tests/fixtures'
(out/'artifact-streams.bin').write_bytes(data)
names=['check_model_codec.py','check_artifact_codec.py','check_scales_codec.py','artifact_codec.py']
receipt=dict(seed=50360,cases=cases,sources={'research/cqis-model-contract/'+p:sha256((ROOT/'research/cqis-model-contract'/p).read_bytes()).hexdigest() for p in names},fixture_sha256=sha256(data).hexdigest())
(out/'artifact-streams.json').write_text(json.dumps(receipt,separators=(',',':'))+'\n')
print(json.dumps(dict(complete=34,generated_complete=1,layout_only=4,bytes=len(data),layout_lengths=[c['length'] for c in cases[-4:]])))
