"""Q26 canonical configuration controls; run via the locked causal-model script."""
from dataclasses import fields, is_dataclass, replace
from fractions import Fraction as Q
import hashlib
import json
import random
import struct
import model_config as c
from check_causal_model import make, reference
from check_attention import reject


def fixture(p):
    records = {}
    def weight(name,w):
        s = c.r.Spec(name,'binary32',(len(w.codes),len(w.codes[0])),w.bits,0)
        records[name] = c.r.encode(s,w.exponent,list(w.mantissas),[v for row in w.codes for v in row])
        return s
    def gain(name,values,n):
        s = c.r.Spec(name,'binary32',(n.d,),16,n.G)
        records[name] = c.r.encode(s,None,[],list(values)); return s
    layers = []
    for i,b in enumerate(p.blocks):
        a=b.attention; prefix='layer.'+str(i)+'.'
        rotation=c.rope.Parameters(a.rotary,len(a.rotations),Q(10000),layout=a.layout) if a.rotary else None
        projection=c.Projection(a.heads,a.groups,a.width,a.fq,a.fk,a.q_mode,a.q_scale,a.k_mode,a.k_scale,
            a.score_m,a.score_e,a.attention,c.fn.Representation(a.attention.function,0,b''),rotation)
        layers.append(c.Block(b.norm1,b.norm2,gain(prefix+'norm1',b.gains1,b.norm1),gain(prefix+'norm2',b.gains2,b.norm2),
            tuple(weight(prefix+name,w) for name,w in zip(('q','k','v','o','up','gate','down'),b.weights)),projection,
            b.silu,b.fu,b.fo,b.fd,b.fout,b.first,b.second,b.gated))
    config=c.Config(len(p.blocks[0].attention.rotations),weight('embedding',p.embedding),
        None if p.head is None else weight('head',p.head),tuple(layers),p.final_norm,
        gain('final_norm',p.gains,p.final_norm),p.policy,p.logits_fraction)
    return config,c.artifact.assemble(c.specs(config),records)


def independent(config):
    """Explicit struct oracle for outer framing; existing inner codecs are shared."""
    def blob(raw): return struct.pack('<H',len(raw))+raw
    def spec(s): return blob(c.r.config(s))
    def norm(n): return struct.pack('<HBBBII',*n.metadata())
    def policy(p): return struct.pack('<BH',{'dynamic':0,'static':1}[p[0]],p[1])
    raw=b'stele/research/q26/model/v1\0'+struct.pack('<IH',config.length,len(config.blocks))
    raw+=spec(config.embedding)+bytes([config.head is not None])
    if config.head is not None: raw+=spec(config.head)
    raw+=norm(config.final_norm)+spec(config.gain)+policy(config.policy)+bytes([config.logits_fraction])
    for b in config.blocks:
        raw+=norm(b.norm1)+norm(b.norm2)+spec(b.gain1)+spec(b.gain2)+b''.join(spec(w) for w in b.weights)
        a=b.projection; v=a.attention
        raw+=struct.pack('<HHHBB',a.heads,a.groups,a.width,a.fq,a.fk)
        raw+=policy((a.q_mode,a.q_scale))+policy((a.k_mode,a.k_scale))+struct.pack('<Hb',a.score_m,a.score_e)
        raw+=blob(b'' if a.rotation is None else c.rope.encode(a.rotation))
        raw+=bytes([v.fv,v.fo])+policy((v.value_mode,v.value_scale))+policy((v.output_mode,v.output_scale))
        raw+=bytes([{'exact':0,'block1024':1}[v.accumulation],v.drop])
        raw+=blob(c.fn.encode(v.function))+blob(c.fn.encode_representation(a.representation))+blob(c.fn.encode(b.silu))
        raw+=bytes([b.fu,b.fo,b.fd,b.fout])+policy(b.first)+policy(b.second)+policy(b.gated)
    return raw


def check():
    rng=random.Random(2632); digest=hashlib.sha256(); executed=rejected=0
    for case in range(10000):
        p=make(rng,case); blocks=[]
        for j,b in enumerate(p.blocks):
            q=b.attention; v=q.attention
            vp=('static',259) if case%5==0 else ('dynamic',0)
            op=('static',260) if case%7==0 else ('dynamic',0)
            v=replace(v,fv=6+case%5,fo=7+(case//3)%5,value_mode=vp[0],value_scale=vp[1],output_mode=op[0],output_scale=op[1])
            qp=('static',261) if case%11==0 else ('dynamic',0)
            kp=('static',262) if case%13==0 else ('dynamic',0)
            q=replace(q,fq=6+case%5,fk=7+(case//2)%5,q_mode=qp[0],q_scale=qp[1],k_mode=kp[0],k_scale=kp[1],
                      score_m=1+case%3,score_e=-(case%4),attention=v)
            if case%19==0: q=replace(q,rotary=0,layout='adjacent',rotations=((),)*8)
            blocks.append(replace(b,norm1=replace(b.norm1,F=6+(case+j)%5,E=6+(case//5)%5),
                norm2=replace(b.norm2,F=7+(case+j)%5,E=6+(case//7)%5),attention=q,
                fu=5+case%8,fo=6+(case//3)%5,fd=6+(case//9)%5,fout=6+(case+j+1)%5,
                silu=c.fn.Function('silu_q',1,bytes([6+case%7,min(6+case%7,4+(case//13)%7)])),
                first=('static',259) if case%23==0 else b.first,gated=('static',65535) if case%29==0 else b.gated))
        p=replace(p,blocks=tuple(blocks),final_norm=replace(p.final_norm,F=blocks[-1].fout,G=6+case%5,E=6+(case//11)%5),
                  policy=('static',259) if case%31==0 else p.policy)
        config,artifact=fixture(p); raw=c.encode(config)
        assert raw==independent(config) and c.decode(raw)==config
        identity=c.identity(config); content=c.artifact.digest(c.specs(config),artifact)
        loaded=c.load(identity,raw,content,artifact); assert loaded==p
        digest.update(raw+identity+content+c.instance_identity(identity,content))
        # Existing numerical corpus owns per-op coverage; this checks the new load boundary.
        if case%100==0:
            try: expected=reference(p,[0,1])
            except ValueError as error:
                reject(str(error),lambda:c.m.full(loaded,[0,1])); rejected+=1; continue
            actual=c.m.full(loaded,[0,1]); assert {k:actual[k] for k in expected}==expected
            cache=None
            for j,t in enumerate([0,1]):
                row,cache=c.m.step(loaded,t,cache); assert row['head']==expected['heads'][j]
            assert cache==actual['cache']; executed+=1
    p=make(random.Random(1),0); config,artifact=fixture(p); raw=c.encode(config)
    identity=c.identity(config); content=c.artifact.digest(c.specs(config),artifact)
    for end in range(len(raw)): reject('Truncated',lambda:c.decode(raw[:end]))
    reject('Trailing',lambda:c.decode(raw+b'\0'))
    reject('Prefix',lambda:c.decode(b'x'+raw[1:]))
    reject('Capacity',lambda:c.decode(b'\0'*((1<<20)+1)))
    reject('Identity',lambda:c.load(bytes(32),raw,content,artifact))
    reject('ArtifactDigest',lambda:c.load(identity,raw,bytes(32),artifact))
    block=config.blocks[0]
    swapped=replace(block,weights=(block.weights[1],block.weights[0])+block.weights[2:])
    changed=replace(config,blocks=(swapped,)+config.blocks[1:])
    assert c.identity(changed)!=identity
    reject('Identity',lambda:c.load(identity,c.encode(changed),content,artifact))
    assert c.load(c.identity(changed),c.encode(changed),content,artifact).blocks[0].weights[0]==p.blocks[0].weights[1]
    reject('Duplicate',lambda:replace(config,head=config.embedding))
    reject('Record',lambda:replace(block,weights=(replace(block.weights[0],parameter=1),)+block.weights[1:]))
    reject('Record',lambda:replace(block,gain1=replace(block.gain1,parameter=9)))
    reject('Units',lambda:replace(config,final_norm=replace(config.final_norm,F=9)))
    reject('Length',lambda:replace(config,length=7))
    reject('Identity',lambda:c.load(identity,c.encode(replace(config,logits_fraction=7)),content,artifact))
    # A legal payload mutation keeps the quantiser id, but must not keep the model instance.
    physical=c.artifact.parse(c.specs(config),artifact); s=config.embedding
    parsed=c.r.parse(s,physical[s.name]); parsed['values'][0]=0 if parsed['values'][0] else 1
    physical[s.name]=c.r.encode(s,parsed['exponent'],parsed['mantissas'],parsed['values'])
    tampered=c.artifact.assemble(c.specs(config),physical)
    reject('ArtifactDigest',lambda:c.load(identity,raw,content,tampered))
    other=c.artifact.digest(c.specs(config),tampered)
    assert c.instance_identity(identity,content)!=c.instance_identity(identity,other)
    assert c.load(identity,raw,other,tampered)!=p  # Self-chosen identity does not authenticate a publisher.
    assert (executed,rejected)==(67,33)
    assert digest.hexdigest()=='d348f520db57d6d3b8047b4f9d178c2d611cf8ea366295d30460aee8e681b46a'
    print(json.dumps(dict(seed=2632,cases=10000,executed=executed,rejected=rejected,sha256=digest.hexdigest()),sort_keys=True))


def controls():
    p=replace(make(random.Random(2632),0),logits_fraction=8)
    config,data=fixture(p); raw=c.encode(config); identity=c.identity(config)
    content=c.blake3(data).digest(); rng=random.Random(2633); valid=invalid=0
    # Untrusted bytes may define another legal config, but never inherit the expected id.
    for _ in range(10000):
        index=rng.randrange(len(raw)); changed=raw[:index]+bytes([raw[index]^rng.randrange(1,256)])+raw[index+1:]
        try: parsed=c.decode(changed)
        except ValueError: invalid+=1; continue
        assert independent(parsed)==changed and c.identity(parsed)!=identity
        reject('Identity',lambda:c.load(identity,changed,content,data)); valid+=1
    def mutations(value):
        if is_dataclass(value):
            for field in fields(value):
                for changed in mutations(getattr(value,field.name)):
                    try: yield replace(value,**{field.name:changed})
                    except ValueError: pass
        elif type(value) is tuple:
            for i,v in enumerate(value):
                for changed in mutations(v): yield value[:i]+(changed,)+value[i+1:]
        elif type(value) is Q: yield value+1
        elif type(value) is int:
            yield value+1; yield value-1
            if value in (4,8): yield 12-value
        elif type(value) is str:
            for v in ('dynamic','static','exact','block1024','adjacent','split','base','linear','llama3')+c.r.SOURCES:
                if v!=value: yield v
            yield value+'x'
        elif type(value) is bytes:
            for i in range(len(value)): yield value[:i]+bytes([value[i]^1])+value[i+1:]
    changes=0
    for changed in mutations(config):
        assert c.encode(changed)==independent(changed) and c.identity(changed)!=identity; changes+=1
        reject('Identity',lambda:c.load(identity,c.encode(changed),content,data))
    for size in (0,129):
        pos=len(c.TAG)+4; reject('Blocks',lambda:c.decode(raw[:pos]+struct.pack('<H',size)+raw[pos+2:]))
    for name,value,reason in (('length',True,'Length'),('blocks',list(config.blocks),'Blocks'),('logits_fraction',True,'Units')):
        reject(reason,lambda:replace(config,**{name:value}))
    b=config.blocks[0]; q=b.projection
    reject('ScoreScale',lambda:replace(q,score_m=True)); reject('Heads',lambda:replace(q,heads=0))
    reject('Representation',lambda:replace(q,representation=c.fn.Representation(b.silu,0,b'')))
    # Same nearest function, different selected proof representation; execution stays identical.
    correction=c.fn.Representation(q.attention.function,2,bytes([7]))
    changed=replace(config,blocks=(replace(b,projection=replace(q,representation=correction)),))
    assert c.identity(changed)!=identity and c.load(c.identity(changed),c.encode(changed),content,data)==p
    reject('Representation',lambda:replace(config,blocks=(b,replace(changed.blocks[0],
        gain1=replace(b.gain1,name='n1'),gain2=replace(b.gain2,name='n2'),
        weights=tuple(replace(s,name=s.name+'x') for s in b.weights)))))
    # Absence, base/linear/llama3 and product exp all survive the outer codec and loader.
    for rotation in (None,replace(q.rotation,mode='linear',factor=Q(2)),
                     replace(q.rotation,mode='llama3',factor=Q(8),low=Q(1),high=Q(4),original=2048)):
        projection=replace(q,rotation=rotation)
        changed=replace(config,blocks=(replace(b,projection=projection),))
        loaded=c.load(c.identity(changed),c.encode(changed),content,data)
        expected=reference(loaded,[0,1]); actual=c.m.full(loaded,[0,1]); assert {k:actual[k] for k in expected}==expected
        assert (loaded.blocks[0].attention.rotary==0)==(rotation is None)
    f=c.fn.Function('exp_q/product',1,bytes([15,7,8,7]))
    projection=replace(q,attention=replace(q.attention,function=f),representation=c.fn.Representation(f,1,b''))
    changed=replace(config,blocks=(replace(b,projection=projection),))
    loaded=c.load(c.identity(changed),c.encode(changed),content,data)
    expected=reference(loaded,[0,1]); actual=c.m.full(loaded,[0,1]); assert {k:actual[k] for k in expected}==expected
    # Valid descriptors can exceed the research materialization cap; reject before reading data.
    huge=replace(config,embedding=replace(config.embedding,shape=(1<<20,config.final_norm.d)),
                 head=replace(config.head,shape=(1<<20,config.final_norm.d)))
    reject('Capacity',lambda:c.load(c.identity(huge),c.encode(huge),content,b''))
    maximum=replace(config,blocks=tuple(replace(b,gain1=replace(b.gain1,name='n1.'+str(i)),gain2=replace(b.gain2,name='n2.'+str(i)),
        weights=tuple(replace(s,name=s.name+'.'+str(i)) for s in b.weights)) for i in range(128)))
    assert c.decode(c.encode(maximum))==maximum
    pos=len(c.artifact.DATA)
    malformed=data[:pos]+bytes(32)+data[pos+32:]
    reject('Quantiser',lambda:c.load(identity,raw,c.blake3(malformed).digest(),malformed))
    malformed=data[:pos+32]+struct.pack('<I',0)+data[pos+36:]
    reject('Count',lambda:c.load(identity,raw,c.blake3(malformed).digest(),malformed))
    assert (valid,invalid,changes)==(518,9482,268)
    print(json.dumps(dict(mutations=10000,valid=valid,invalid=invalid,configuration_changes=changes),sort_keys=True))
