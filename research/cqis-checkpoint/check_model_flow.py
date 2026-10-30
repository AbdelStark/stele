"""Q26 explicit numerical dependencies; locked causal-model entry point."""
from dataclasses import replace
import hashlib
import json
import random
import model_flow as f
import model_config as c
import model_functions as functions
from check_model_config import fixture
from check_model_bound_set import arguments, roles
from check_causal_model import make, reference
from check_attention import reject

TAG=b'stele/research/q26/model-flow/v1\0'


def frame(identity,nodes):
    return TAG+identity+json.dumps(nodes,sort_keys=True,separators=(',',':'),ensure_ascii=True).encode('ascii')


def inspect(config):
    nodes=f.derive(config); by={n['role']:n for n in nodes}; length=config.length; d=config.final_norm.d
    assert len(by)==len(nodes)==27*len(config.blocks)+9+int(config.head is not None)
    seen=set(); bindings=[]; selected=[]
    for n in nodes:
        assert set(n)=={'role','kind','layer','shape','inputs','source','function','bounds'}
        assert len(n['role'])<=64 and all(v in seen for v in n['inputs'])
        assert all(type(v) is int and v>0 for v in n['shape'])
        bindings.extend(tuple(v) for v in n['bounds'])
        if n['function'] is not None: selected.append(n['function'])
        seen.add(n['role'])
    assert len(set(bindings))==len(bindings) and set(bindings)==set(roles(config))
    expected=functions.selection(config)[0]
    assert selected==[[name,c.fn.function_id(r.function).hex(),c.fn.representation_id(r).hex()] for name,r in expected]
    assert by['positions']['inputs']==['tokens'] and by['cut.0']['inputs']==['tokens','physical.embedding']
    assert by['head']['inputs']==['final','physical.embedding' if config.head is None else 'physical.head']
    assert ('physical.head' in by)==(config.head is not None)
    assert by['final_norm']['inputs']==['cut.'+str(len(config.blocks)),'physical.final_norm']
    for i,b in enumerate(config.blocks):
        p='layer.'+str(i)+'.'; physical='physical.'+p
        assert by[p+'norm1']['inputs']==['cut.'+str(i),physical+'norm1']
        assert by[p+'norm2']['inputs']==[p+'mid',physical+'norm2']
        assert by[p+'attention']['inputs']==[p+'q',p+'k',p+'v','positions','rotation.'+str(i)]
        assert by[p+'mid']['inputs']==['cut.'+str(i),p+'o']
        assert by['cut.'+str(i+1)]['inputs']==[p+'mid',p+'down']
        assert by[p+'product']['inputs']==[p+'up',p+'silu']
        assert by[p+'silu']['inputs']==[p+'gate']
        for key,s in zip(('q','k','v','o','up','gate','down'),b.weights):
            source=by[physical+key]
            assert source['source']==c.r.config(s).hex() and source['shape']==list(s.shape)
            assert by[p+key]['inputs'][1]==physical+key
        assert by[physical+'norm1']['source']==c.r.config(b.gain1).hex()
        assert by[physical+'norm2']['source']==c.r.config(b.gain2).hex()
        assert by[p+'q']['shape']==[length,b.projection.heads*b.projection.width]
        assert by[p+'k']['shape']==by[p+'v']['shape']==[length,b.projection.groups*b.projection.width]
        assert by[p+'up']['shape']==[length,b.weights[4].shape[0]]
        assert by['cut.'+str(i+1)]['shape']==[length,d]
        assert by['rotation.'+str(i)]['source']==('' if b.projection.rotation is None else c.rope.encode(b.projection.rotation).hex())
    identity=c.identity(config); raw=frame(identity,nodes)
    assert f.encode(identity,c.encode(config))==raw
    f.validate(identity,c.encode(config),raw)
    return nodes,raw


def execute(config,data,tokens):
    args=arguments(config,data); model=c.load(*args)
    try: expected=reference(model,tokens)
    except ValueError as error:
        reject(str(error),lambda:f.execute(*args,tokens)); return False
    actual=f.execute(*args,tokens,supplied=f.encode(*args[:2]))
    assert {k:actual[k] for k in expected}==expected
    assert actual['selected']==[sorted(range(len(h['logits'])),key=lambda j:(-h['logits'][j],j))[0] for h in expected['heads']]
    return True


def controls():
    config,data=fixture(replace(make(random.Random(2663),0),logits_fraction=8))
    args=arguments(config,data); nodes,raw=inspect(config); by={v['role']:i for i,v in enumerate(nodes)}
    def change(role,key,value):
        altered=[dict(n) for n in nodes]; altered[by[role]][key]=value; return altered
    variants=[nodes[:-1],nodes+[nodes[-1]],nodes[::-1],
        change('layer.0.q','inputs',['layer.0.first','physical.layer.0.k']),
        change('layer.0.norm1','inputs',['cut.0','physical.layer.0.norm2']),
        change('layer.0.product','inputs',['layer.0.up','layer.0.gate']),
        change('cut.1','inputs',['cut.0','layer.0.down']),
        change('layer.0.attention','inputs',['layer.0.k','layer.0.q','layer.0.v','positions','rotation.0']),
        change('head','inputs',['final','physical.embedding']),
        change('layer.0.norm1','function',nodes[by['layer.0.silu']]['function']),
        change('layer.0.q','bounds',nodes[by['layer.0.k']]['bounds']),
        change('layer.0.q','shape',[config.length+1,config.final_norm.d]),
        change('physical.layer.0.q','source',nodes[by['physical.layer.0.k']]['source']),
        change('rotation.0','source',''),change('layer.0.q','layer',1)]
    for changed in variants:
        altered=frame(args[0],changed)
        reject('Flow',lambda:f.validate(*args[:2],altered))
        reject('Flow',lambda:f.execute(*args,[0,1],supplied=altered))
    offsets=set(range(len(TAG)+32)); offsets.update(random.Random(2664).sample(range(len(raw)),192))
    for i in sorted(offsets): reject('Flow',lambda:f.validate(*args[:2],raw[:i]+bytes([raw[i]^1])+raw[i+1:]))
    for bad in (raw[:-1],raw+b'\0',bytearray(raw),None): reject('Flow',lambda:f.validate(*args[:2],bad))
    reject('Capacity',lambda:f.validate(*args[:2],b'\0'*((1<<24)+1)))
    reject('Digest',lambda:f.encode(bytes(31),args[1]))
    reject('Identity',lambda:f.execute(bytes(32),args[1],args[2],data,[0]))
    reject('ArtifactDigest',lambda:f.execute(args[0],args[1],bytes(32),data,[0]))
    reject('Token',lambda:f.execute(*args,[True])); reject('Length',lambda:f.execute(*args,[]))
    # Equal numerical gains and functions do not make their physical roles interchangeable.
    b=config.blocks[0]; twin=replace(config,blocks=(replace(b,gain1=b.gain2,gain2=b.gain1),))
    twin_args=arguments(twin,data); _,other=inspect(twin)
    assert c.load(*twin_args)==c.load(*args) and raw!=other
    reject('Flow',lambda:f.validate(*twin_args[:2],raw))
    assert execute(twin,data,[0,1])
    q=b.projection
    twin=replace(config,blocks=(replace(b,projection=replace(q,
        representation=c.fn.Representation(q.attention.function,2,b'\7'))),))
    twin_args=arguments(twin,data); _,other=inspect(twin)
    assert c.load(*twin_args)==c.load(*args) and other!=raw
    reject('Flow',lambda:f.validate(*twin_args[:2],raw))
    assert execute(twin,data,[0,1])
    # A valid changed payload cannot reuse the expected artifact identity.
    physical=c.artifact.parse(c.specs(config),data); s=config.gain
    parsed=c.r.parse(s,physical[s.name]); parsed['values'][0]+=1
    physical[s.name]=c.r.encode(s,None,[],parsed['values']); changed=c.artifact.assemble(c.specs(config),physical)
    reject('ArtifactDigest',lambda:f.execute(args[0],args[1],args[2],changed,[0]))
    return len(offsets)


def mixed_units():
    accepted=rejected=0; rng=random.Random(2666)
    for case in range(30):
        model=make(rng,case); blocks=[]
        for j,b in enumerate(model.blocks):
            q=b.attention; a=q.attention
            a=replace(a,fv=7,fo=10,value_mode='static',value_scale=259,output_mode='static',output_scale=260,
                      accumulation='exact',drop=0)
            if case%2: a=replace(a,accumulation='block1024',drop=c.a.minimum_drop(a))
            q=replace(q,fq=6,fk=9,q_mode='static',q_scale=261,k_mode='static',k_scale=262,
                      score_m=2,score_e=-3,attention=a)
            blocks.append(replace(b,norm1=replace(b.norm1,F=6+j,E=7),norm2=replace(b.norm2,F=10-j,E=9),
                attention=q,fu=6,fo=9,fd=7,fout=7+j,silu=c.fn.Function('silu_q',1,bytes([9,7])),
                first=('static',259) if case%3 else ('dynamic',0),second=('static',260),gated=('static',65535)))
        model=replace(model,blocks=tuple(blocks),final_norm=replace(model.final_norm,F=6+len(blocks),E=9),
                      policy=('static',259),logits_fraction=8)
        config,data=fixture(model); inspect(config); ok=execute(config,data,[0,1,2])
        accepted+=ok; rejected+=not ok
    return accepted,rejected


def check():
    rng=random.Random(2662); digest=hashlib.sha256(); count=accepted=rejected=0
    for index in range(1000):
        model=make(rng,index); config,data=fixture(model)
        if index%11==0:
            config=replace(config,blocks=tuple(replace(b,projection=replace(b.projection,rotation=None)) for b in config.blocks))
        nodes,raw=inspect(config); count+=len(nodes); digest.update(raw)
        if index<100:
            success=execute(config,data,[j%config.embedding.shape[0] for j in range(1+index%3)])
            accepted+=success; rejected+=not success
    model=make(random.Random(2665),1); config,data=fixture(replace(model,blocks=(model.blocks[0],)*128))
    nodes,raw=inspect(config); assert len(nodes)==3465
    untied=replace(config,head=replace(config.embedding,name='head'))
    largest,_=inspect(untied); assert len(largest)==3466
    mutations=controls()
    mixed=mixed_units()
    assert mixed==(30,0)
    assert (count,accepted,rejected,len(raw),mutations)==(63473,94,6,804973,255)
    assert digest.hexdigest()=='8abf2b21a816ac8ce403a6556a705c7a7647fc949329406ee43232642b1753ce'
    print(json.dumps(dict(seed=2662,models=1000,nodes=count,accepted=accepted,rejected=rejected,
        sha256=digest.hexdigest(),maximum_nodes=len(nodes),maximum_bytes=len(raw),byte_mutations=mutations,
        mixed_accepted=mixed[0],mixed_rejected=mixed[1]),sort_keys=True))
