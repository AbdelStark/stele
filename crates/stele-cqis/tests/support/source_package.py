"""RFC-0025 source §§1–4: complete native package fixtures, no campaign mains."""
from dataclasses import replace
from hashlib import sha256
import json
from pathlib import Path
from random import Random
import sys
from blake3 import blake3
import safetensors

root=Path(__file__).resolve().parents[4]
sys.path.insert(0,str(root/'research/cqis-model-contract'))
import source_codec as c
from check_source_codec import package, auxiliary
from check_source_map import fixture, encode_oracle
from source_map import Entry, Shape, SourceMap

data=bytearray();cases=[];rng=Random(50440)
def store(raw):
    span=dict(offset=len(data),length=len(raw));data.extend(raw);return span
def record(label,mapping,source,assets,files,error=None,reason=None,virtual=False):
    try: result=c.verify(mapping,source,assets,files)
    except ValueError as failure:
        assert error is not None and str(failure)==reason,(label,str(failure),reason)
        selected=[]
    else:
        assert error is None,label
        selected=[dict(length=len(result.tensors[e.name].data),sha256=sha256(result.tensors[e.name].data).hexdigest()) for e in mapping.entries]
    raw=encode_oracle(mapping);assert raw==mapping.encode()
    described=[]
    for name,rawfile in sorted(files.items()):
        prefix=rawfile;patches=[]
        if virtual and name.endswith('.safetensors'):
            end=8+int.from_bytes(rawfile[:8],'little');payload=rawfile[end:];prefix=rawfile[:end]
            if any(payload):patches=[(end+i,b) for i,b in enumerate(payload) if b]
            assert len(patches)<=1
        described.append(dict(name=name,prefix=store(prefix),length=len(rawfile),patches=patches))
    sr=c.encode_source(source);ar=c.encode_assets(assets)
    cases.append(dict(label=label,map=store(raw),source=store(sr),assets=store(ar),files=described,error=error,selected=selected,
                      source_identity=c.identity(source).hex(),source_frame_identity=blake3(sr).hexdigest(),assets_identity=blake3(ar).hexdigest(),map_identity=blake3(raw).hexdigest()))

for i in range(24):
    family=i%2;h=rng.randrange(1,4);a=rng.randrange(2,5);d=h*a
    shape=Shape(family,rng.randrange(1,3),d,h,h if not family else 1,a,4*d if not family else 13,7,5)
    mapping,sources,_=fixture(rng,shape,not family and i%4==0)
    if i==0:
        mapping=replace(mapping,aliases=(('head.alias',0),));sources.pop('published_head',None);sources['head.alias']=sources[mapping.entries[0].name]
    source,files,tensors=package(mapping,sources,1 if i%3==0 else 3);assets,af=auxiliary(i%2==0);files.update(af)
    record('complete '+str(i),mapping,source,assets,files)
    if i==0: base=(mapping,sources,source,assets,files,af)

m,sources,s,a,files,af=base
record('unlisted ignored tensor',replace(m,ignored=()),s,a,files,'SourceSelection','Selection')
record('missing expected tensor',replace(m,ignored=('buffer','missing')),s,a,files,'SourceSelection','Selection')
es=list(m.entries);es[0]=replace(es[0],dtype=es[0].dtype%4+1)
record('selected dtype',replace(m,entries=tuple(es)),s,a,files,'SourceDtype','SourceMetadata')

def changed_sources(label,changed,error,reason,groups=1):
    source,fs,_=package(m,changed,groups);record(label,m,source,a,{**fs,**af},error,reason)

changed=dict(sources);dtype,shape,raw=changed['head.alias'];changed['head.alias']=(dtype,shape,bytes((raw[0]^1,))+raw[1:])
changed_sources('raw alias byte',changed,'SourceAlias','AliasData')
changed=dict(sources);dtype,shape,raw=changed[m.entries[0].name];changed[m.entries[0].name]=(dtype,shape[::-1],raw)
changed_sources('selected shape',changed,'SourceShape','SourceMetadata')
changed=dict(sources);dtype,shape,raw=changed['head.alias'];changed['head.alias']=(2 if dtype==1 else 1,shape,bytes(len(raw)//({1:2,2:2,3:4,4:8}[dtype])*2))
changed_sources('alias metadata',changed,'SourceAlias','AliasData')

sharded,sf,tensors=package(m,sources,3);index=json.loads(sf[sharded.index.name]);key=next(iter(index['weight_map']))
index['weight_map'][key]=next(f.name for f in sharded.files if f.name!=index['weight_map'][key])
changed={**sf,sharded.index.name:json.dumps(index).encode()};described=c.describe_source(changed,sharded.index.name)
record('wrong shard assignment',m,described,a,{**changed,**af},'SourceShard','ShardContents')
index=json.loads(sf[sharded.index.name]);index['metadata']['total_size']+=1
changed={**sf,sharded.index.name:json.dumps(index).encode()};described=c.describe_source(changed,sharded.index.name)
record('wrong total payload',m,described,a,{**changed,**af},'SourceTotalSize','TotalSize')
index=json.loads(sf[sharded.index.name]);first,second=sharded.files[:2];duplicated=next(n for n,label in index['weight_map'].items() if label==first.name)
selected={n:tensors[n] for n,label in index['weight_map'].items() if label==second.name};selected[duplicated]=tensors[duplicated]
changed={**sf,second.name:safetensors.serialize(selected,metadata={'format':'pt'})};described=c.describe_source(changed,sharded.index.name)
record('duplicate across shards',m,described,a,{**changed,**af},'SourceDuplicate','DuplicateTensor')
changed={**sf,'empty.safetensors':(2).to_bytes(8,'little')+b'{}'};described=c.describe_source(changed,sharded.index.name)
record('unused declared shard',m,described,a,{**changed,**af},'SourceShard','FileSet')
changed={'bad.safetensors':b'not a container'};described=c.describe_source(changed)
record('hash valid malformed container',m,described,a,{**changed,**af},'SourceHeader','HeaderLimit')
other=replace(a,tokenizers=tuple(sorted((s.files[0],a.tokenizers[1]),key=lambda f:f.name)))
changed=dict(files);del changed[a.tokenizers[0].name]
record('checkpoint auxiliary collision',m,s,other,changed,'FileSet','FileSet')
overflow=c.Source(0,None,(c.File('overflow.safetensors',(1<<64)-1,bytes(32)),))
record('joint u64 overflow',m,overflow,a,files,'FileLength','Length')

# Full selected raw tensors above the former research element cap, without a
# large checked-in payload. The native reader emits the independently hashed
# original zero payload after each stored original header.
shape=Shape(0,1,8,1,1,8,32,600000,1);entries=[];sources={}
for role,layer,dims in shape.roles():
    name=f'{layer}.{role}';count=dims[0]*(dims[1] if len(dims)==2 else 1)
    entries.append(Entry(name,1,dims,0));sources[name]=(1,dims,bytes(2*count))
sources['head.alias']=sources[entries[0].name]
mapping=SourceMap(shape,tuple(entries),(('head.alias',0),),('buffer',));source,fs,_=package(mapping,sources,3)
record('large original raw alias',mapping,source,a,{**fs,**af},virtual=True)
dtype,dims,raw=sources['head.alias'];sources['head.alias']=(dtype,dims,raw[:-1]+b'\x01')
source,fs,_=package(mapping,sources,3)
record('large alias final byte',mapping,source,a,{**fs,**af},'SourceAlias','AliasData',virtual=True)

out=root/'crates/stele-cqis/tests/fixtures'
(out/'source-package.bin').write_bytes(data)
(out/'source-package.json').write_text(json.dumps(dict(seed=50440,cases=cases),separators=(',',':'))+'\n')
print(json.dumps(dict(cases=len(cases),valid=sum(c['error'] is None for c in cases),bytes=len(data),large_selected_elements=4800000)))
