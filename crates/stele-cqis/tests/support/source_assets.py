"""RFC-0025 source §§1,3: independent complete native Source/Assets frames.

Metadata only; declared SHA-256 values do not validate any original file.
Calls qualified pure framers/decoders, never historical campaign entry points.
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
from check_source_codec import source_frame, assets_frame
import source_codec as c

rng=Random(50370); cases=[]; invalid=[]; data=bytearray()
def blob(raw):return pack('<I',len(raw))+raw
def f(name,length=None):return c.File(name,rng.randrange(1<<40) if length is None else length,rng.randbytes(32))
def meta(x):return dict(name=x.name,length=x.length,sha256=x.sha256.hex())
def add(source,assets):
    sr=source_frame(source); ar=assets_frame(assets)
    assert sr==c.encode_source(source) and c.decode_source(sr)==source
    assert ar==c.encode_assets(assets) and c.decode_assets(ar)==assets
    data.extend(blob(sr)+blob(ar))
    cases.append(dict(source_identity=c.identity(source).hex(),source_frame_identity=blake3(sr).hexdigest(),assets_identity=blake3(ar).hexdigest(),
                      kind=source.kind,index=meta(source.index) if source.index else None,files=[meta(v) for v in source.files],
                      config=meta(assets.config),tokenizers=[meta(v) for v in assets.tokenizers],generation=meta(assets.generation) if assets.generation else None))
for i in range(64):
    kind=int(i%3!=0);count=rng.randint(1,8) if kind else 1
    files=tuple(f(f'model-{j:04d}.safetensors') for j in range(count))
    source=c.Source(kind,f('model.index.json',100000000 if i==1 else rng.randint(512,1000000)) if kind else None,files)
    tokens=tuple(f(n) for n in sorted(('tokens-e\u0301.json','tokens-é.bin') if i==2 else tuple(f'tokens-{j}.bin' for j in range(rng.randint(1,6)))))
    assets=c.Assets(f('config.json'),tokens,f('generation.json') if i%2 else None)
    add(source,assets)
source=c.Source(0,None,(f('x'*(65535-len('.safetensors'))+'.safetensors',(1<<64)-1),))
assets=c.Assets(f('x'*(65535-5)+'.json',(1<<64)-1),(f('tokenizer.bin',0),),f('generation.json',0))
add(source,assets)
single=c.Source(0,None,(f('model.safetensors',0),))
source=c.Source(1,f('model.index.json',128),(f('a.safetensors',0),f('b.safetensors',0)))
assets=c.Assets(f('config.json',0),(f('a.bin',0),f('b.bin',0)),f('generation.json',0))
add(source,assets)

def bad(kind,raw,error):
    try:(c.decode_source if kind=='source' else c.decode_assets)(raw)
    except ValueError:pass
    else:raise AssertionError('reference accepted invalid frame')
    invalid.append(dict(kind=kind,raw=raw.hex(),error=error))
def bs(s,error):bad('source',source_frame(s),error)
def ba(a,error):bad('assets',assets_frame(a),error)
for name in ('','.', '..','a/b.safetensors','a\\b.safetensors','a\0b.safetensors'):
    bs(replace(single,files=(replace(single.files[0],name=name),)),'FileName')
raw=bytearray(source_frame(single));raw[len(c.SOURCE)+3]=255;bad('source',bytes(raw),'FileName')
raw=source_frame(single);bad('source',raw[:len(c.SOURCE)]+b'\2'+raw[len(c.SOURCE)+1:],'SourceKind')
bs(replace(single,files=(replace(single.files[0],name='model.json'),)),'SourceFiles')
bs(replace(source,index=replace(source.index,name='index.bin')),'SourceIndex')
bs(replace(source,files=()),'SourceFiles')
bs(replace(source,files=source.files[::-1]),'FileOrder')
bs(replace(source,files=(source.files[0],source.files[0])),'FileSet')
bs(replace(source,index=replace(source.index,length=100000001)),'Capacity')
bs(replace(source,index=replace(source.index,length=16)),'Capacity')
bs(replace(source,index=replace(source.index,length=16),files=(replace(source.files[0],name='x'*32+'.safetensors'),)),'Capacity')
bs(replace(source,files=(replace(source.files[0],length=(1<<64)-1),source.files[1])),'FileLength')
raw=source_frame(source);at=len(c.SOURCE)+1+2+len(source.index.name)+8+32
bad('source',raw[:at]+pack('<I',2**32-1)+raw[at+4:],'Capacity')
ba(replace(assets,config=replace(assets.config,name='config.bin')),'Assets')
ba(replace(assets,tokenizers=()),'Assets')
ba(replace(assets,tokenizers=assets.tokenizers[::-1]),'FileOrder')
ba(replace(assets,tokenizers=(assets.tokenizers[0],assets.tokenizers[0])),'FileSet')
ba(replace(assets,tokenizers=(assets.config,)),'FileSet')
ba(replace(assets,generation=assets.config),'FileSet')
ba(replace(assets,tokenizers=(assets.generation,)),'FileSet')
ba(replace(assets,generation=replace(assets.generation,name='generation.bin')),'Assets')
ba(replace(assets,config=replace(assets.config,length=(1<<64)-1),tokenizers=(replace(assets.tokenizers[0],length=1),)),'FileLength')
raw=assets_frame(replace(assets,generation=None));bad('assets',raw[:-1]+b'\2','Assets')
at=len(c.ASSETS)+2+len(assets.config.name)+8+32
bad('assets',raw[:at]+pack('<I',2**32-1)+raw[at+4:],'Capacity')
for kind,raw in (('source',source_frame(source)),('assets',assets_frame(assets))):
    bad(kind,b'X'+raw[1:],'Encoding');bad(kind,raw+b'\0','Encoding')
    for end in (0,1,len(raw)-1):bad(kind,raw[:end],'Encoding')
out=ROOT/'crates/stele-cqis/tests/fixtures'
(out/'source-assets.bin').write_bytes(data)
names=['check_source_codec.py','source_codec.py']
receipt=dict(seed=50370,cases=cases,invalid=invalid,sources={'research/cqis-model-contract/'+p:sha256((ROOT/'research/cqis-model-contract'/p).read_bytes()).hexdigest() for p in names},fixture_sha256=sha256(data).hexdigest())
(out/'source-assets.json').write_text(json.dumps(receipt,separators=(',',':'))+'\n')
print(json.dumps(dict(valid=len(cases),invalid=len(invalid),bytes=len(data))))
