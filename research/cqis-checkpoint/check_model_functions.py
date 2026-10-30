"""Q26 / RFC-0021 §4, Draft RFC-0004 A3/A10: model role/manifest evidence."""
from dataclasses import replace
from math import gcd
from pathlib import Path
import hashlib
import json
import random
import struct
import subprocess
import tempfile
from blake3 import blake3
import model_functions as m
import model_config as c
from check_model_config import fixture
from check_causal_model import make
from check_attention import reject

ROOT=Path(__file__).resolve().parents[2]
TAG=b'stele/research/q26/model-functions/v1\0'
fn=c.fn


def norm(p):
    return fn.Representation(fn.Function('rmsnorm_q',1,struct.pack('<HBBBII',p.d,p.F,p.G,p.E,p.en,p.ed)),3,b'')


def roles(p):
    result=[]
    for i,b in enumerate(p.blocks):
        prefix='layer.'+str(i)+'.'
        result.extend([(prefix+'norm1',norm(b.norm1)),(prefix+'attention_exp',b.projection.representation),
                       (prefix+'norm2',norm(b.norm2)),(prefix+'silu',fn.Representation(b.silu,0,b''))])
    return tuple(result+[('final_norm',norm(p.final_norm))])


def frame(identity,refs,manifest):
    raw=TAG+identity+struct.pack('<H',len(refs))
    for name,r in refs:
        raw+=struct.pack('<H',len(name))+name.encode('ascii')+fn.function_id(r.function)+fn.representation_id(r)
    return raw+struct.pack('<I',len(manifest))+manifest


def shape(d):
    if d.name=='rsqrt_q': n=49152
    elif d.name=='silu_q': n=65536
    elif d.name=='exp_q/hi': n=2**(d.params[0]-d.params[3])+1
    elif d.name=='exp_q/lo': n=2**d.params[3]
    else:
        assert d.name in ('exp_q/direct','exp_q/correction'); n=2**d.params[0]+1
    return n,2**(n-1).bit_length(),2


def metadata(p):
    refs,selected,components=m.selection(p)
    assert refs==roles(p) and len(refs)==4*len(p.blocks)+1
    assert selected==c.representations(p)
    union={fn.table.table_id(d):d for _,r in refs for d in fn.dependencies(r)}
    assert components==tuple(union[k] for k in sorted(union))
    assert len(components)<=4*len(p.blocks)+1
    for d in components: assert shape(d)==fn.table.shape(d) and shape(d)[1]<=65536
    return refs,selected,components


def inspect_manifest(selected,raw):
    """Independent outer framing/closure; accepted inner table generators are shared."""
    functions=sorted(selected,key=lambda r:fn.function_id(r.function))
    components={fn.table.table_id(d):d for r in selected for d in fn.dependencies(r)}
    expected=b'stele/v0.1/cqis/functions'+struct.pack('<I',len(functions))
    for r in functions:
        f=fn.encode(r.function); rep=fn.encode_representation(r)
        expected+=struct.pack('<H',len(f))+f+struct.pack('<H',len(rep))+rep
    expected+=struct.pack('<I',len(components))
    for tid,d in sorted(components.items()):
        data=fn.table.encode_data(d); desc=fn.table.encode(d)
        assert data[len(fn.table.DATA):len(fn.table.DATA)+32]==tid
        expected+=struct.pack('<H',len(desc))+desc+blake3(data).digest()
    assert raw==expected


def full(p):
    refs,selected,components=metadata(p); identity=c.identity(p); config=c.encode(p)
    manifest=fn.encode_manifest(selected); inspect_manifest(selected,manifest)
    expected=frame(identity,refs,manifest); assert m.encode(identity,config)==expected
    m.validate(identity,config,expected)
    return (identity,config),refs,selected,components,manifest,expected


def native(cases):
    subprocess.run(['cargo','build','-p','stele-cqis','--example','function_manifests','--locked','--offline'],cwd=ROOT,check=True)
    info=json.loads(subprocess.check_output(['cargo','metadata','--no-deps','--format-version','1','--offline'],cwd=ROOT,text=True))
    binary=Path(info['target_directory'])/'debug/examples/function_manifests'
    with tempfile.TemporaryFile() as source:
        for selected,_ in cases:
            source.write(struct.pack('<H',len(selected)))
            for r in selected:
                f=fn.encode(r.function); rep=fn.encode_representation(r)
                source.write(struct.pack('<H',len(f))+f+struct.pack('<H',len(rep))+rep)
        source.seek(0)
        with subprocess.Popen([str(binary)],stdin=source,stdout=subprocess.PIPE,text=True,cwd=ROOT) as child:
            try:
                for _,expected in cases: assert child.stdout.readline(1<<21)==expected+'\n'
                assert child.stdout.read(1)=='' and child.wait()==0
            finally:
                if child.poll() is None: child.terminate();child.wait()


def configurations():
    p,_=fixture(make(random.Random(2662),0)); b=p.blocks[0]; q=b.projection
    direct=fn.Function('exp_q/nearest',1,bytes([7,7,8]))
    for f,mode,params in ((direct,0,b''),(direct,2,bytes([6])),
                         (fn.Function('exp_q/product',1,bytes([7,7,8,6])),1,b''),
                         (fn.Function('exp_q/product',1,bytes([31,7,8,16])),1,b'')):
        a=replace(q.attention,function=f); rep=fn.Representation(f,mode,params)
        yield replace(p,blocks=(replace(b,projection=replace(q,attention=a,representation=rep)),))
    f=fn.Function('exp_q/nearest',1,bytes([15,7,12])); a=replace(q.attention,function=f)
    yield replace(p,blocks=(replace(b,silu=fn.Function('silu_q',1,bytes([12,12])),
        projection=replace(q,attention=a,representation=fn.Representation(f,0,b''))),))
    model=make(random.Random(2662),1); maximum,_=fixture(replace(model,blocks=(model.blocks[0],)*128))
    yield maximum


def controls(p=None):
    p=next(configurations()) if p is None else p
    args,refs,selected,components,manifest,raw=full(p); check=lambda v:m.validate(*args,v)
    assert len(refs)==5 and refs[0][1]==refs[2][1]==refs[4][1]
    for changed in (refs[:-1],refs+(refs[-1],),refs[::-1],refs[:2]+refs[3:],
                    ((refs[0][0],refs[1][1]),)+refs[1:],(('wrong.role',refs[0][1]),)+refs[1:]):
        reject('FunctionSet',lambda:check(frame(args[0],changed,manifest)))
    for changed in (manifest[:-1],manifest+b'\0',manifest[:-1]+bytes([manifest[-1]^1]),
                    fn.encode_manifest(selected[:-1])):
        reject('FunctionSet',lambda:check(frame(args[0],refs,changed)))
    offsets=set(range(len(TAG)+34)); offsets.update(random.Random(2663).sample(range(len(raw)),128))
    offset=len(TAG)+34
    for name,_ in refs:
        offsets.update((offset,offset+1,offset+2,offset+2+len(name),offset+34+len(name)))
        offset+=2+len(name)+64
    offsets.update(range(offset,offset+4))
    for i in sorted(offsets): reject('FunctionSet',lambda:check(raw[:i]+bytes([raw[i]^1])+raw[i+1:]))
    for value in (raw[:-1],raw+b'\0',bytearray(raw),None): reject('FunctionSet',lambda:check(value))
    reject('Capacity',lambda:check(b'\0'*((1<<20)+1)))
    reject('Identity',lambda:m.encode(bytes(32),args[1])); reject('Digest',lambda:m.encode(args[0][:-1],args[1]))
    reject('Config',lambda:m.selection(None))
    b=p.blocks[0]; q=b.projection
    changed=replace(p,blocks=(replace(b,projection=replace(q,representation=fn.Representation(q.attention.function,2,bytes([6])))),))
    other=full(changed); assert other[1][1][1].function==refs[1][1].function and other[-2]!=manifest
    reject('FunctionSet',lambda:check(other[-1])); reject('FunctionSet',lambda:m.validate(*other[0],raw))
    changed=replace(p,blocks=(replace(b,gain1=b.gain2,gain2=b.gain1),))
    other=full(changed); assert other[1:5]==(refs,selected,components,manifest) and other[-1]!=raw
    reject('FunctionSet',lambda:m.validate(*other[0],raw))
    return len(offsets)


def check():
    rng=random.Random(2661); digest=hashlib.sha256(); references=0
    for i in range(10000):
        p,_=fixture(make(rng,i)); blocks=[]
        for j,b in enumerate(p.blocks):
            en,ed=1+(i+j)%257,1000003; common=gcd(en,ed)
            n=replace(b.norm1,G=(i+j)%31,E=i%15,en=en//common,ed=ed//common)
            n2=replace(b.norm2,G=(i+2*j)%31,E=(i+j)%15,en=en//common,ed=ed//common)
            blocks.append(replace(b,norm1=n,norm2=n2,gain1=replace(b.gain1,parameter=n.G),gain2=replace(b.gain2,parameter=n2.G)))
        p=replace(p,blocks=tuple(blocks)); refs,selected,components=metadata(p)
        digest.update(c.encode(p)+b''.join(fn.function_id(r.function)+fn.representation_id(r) for _,r in refs)); references+=len(refs)
    maximum=list(configurations())[-1]; activations=[(f,e) for f in range(31) for e in range(min(f,14)+1)]
    blocks=[]
    for i,b in enumerate(maximum.blocks):
        f=fn.Function('exp_q/nearest',1,bytes([7,i//15,i%15]))
        a=replace(b.projection.attention,function=f,accumulation='exact',drop=0)
        a=replace(a,accumulation='block1024',drop=c.a.minimum_drop(a))
        blocks.append(replace(b,norm1=replace(b.norm1,en=2*i+1,ed=1000003),norm2=replace(b.norm2,en=2*i+2,ed=1000003),
            projection=replace(b.projection,attention=a,representation=fn.Representation(f,2,bytes([6]))),
            silu=fn.Function('silu_q',1,bytes(activations[i]))))
    blocks=tuple(blocks)
    maximum=replace(maximum,blocks=blocks,final_norm=replace(maximum.final_norm,en=257,ed=1000003))
    refs,selected,components=metadata(maximum); assert (len(refs),len(selected),len(components))==(513,513,513)
    cases=[]; complete=hashlib.sha256()
    for p in configurations():
        args,refs,selected,components,manifest,raw=full(p); cases.append((selected,manifest.hex())); complete.update(raw)
    selected=cases[0][0]; cases.extend([((),fn.encode_manifest([]).hex()),((selected[0],selected[0]),'error DuplicateFunction'),
        ((fn.Representation(fn.Function('silu_q',1,bytes([0,1])),0,b''),),'error Table(Overflow)')])
    mutations=controls(); native(cases)
    assert (references,len(cases),mutations)==(89996,9,220)
    assert digest.hexdigest()=='d5ded583511f94d2e7e5972966e0da8d6110ad6d8584ab1f3379f088af7d0feb'
    assert complete.hexdigest()=='b0c345912fe50df2391aefe89a9776b5b247a654e71423f4f35941e3460bd7cd'
    print(json.dumps(dict(seed=2661,models=10000,roles=references,sha256=digest.hexdigest(),
        full_models=6,full_sha256=complete.hexdigest(),native_cases=len(cases),byte_mutations=mutations,
        maximum_functions=513,maximum_components=513),sort_keys=True))
