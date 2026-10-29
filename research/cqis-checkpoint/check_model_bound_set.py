"""Q26 / Draft RFC-0004 A3/A10: scoped collection membership and identity controls."""
from dataclasses import replace
import hashlib
import json
import random
import struct
import model_bound_set as s
import model_config as c
from check_model_config import fixture
from check_causal_model import make
from check_attention import reject
import model_scaled_bounds as scaled
import model_row_bounds as row
import model_rotary_bounds as rotary
import model_residual_bounds as residual
import model_greedy_bounds as greedy
import model_attention_sum_bounds as total
import model_attention_normalization_bounds as normalization
import model_attention_block_bounds as block
import model_attention_score_bounds as score
import model_attention_max_bounds as maximum
import model_gated_product_bounds as gated
import model_norm_bounds as norm

TAG=b'stele/research/q26/model-bounds/v1\0'


def arguments(config,data):
    return c.identity(config),c.encode(config),c.artifact.digest(c.specs(config),data),data


def roles(config):
    prefixes=['layer.'+str(i)+'.' for i in range(len(config.blocks))]
    groups=[['embedding']+[p+r for p in prefixes for r in ('q','k','v','o','up','gate','down')]+['head'],
            [p+r for p in prefixes for r in ('first','query','key','value','attention','second','gated')]+['final'],
            [p+r for p in prefixes for r in ('query','key')],
            [p+r for p in prefixes for r in ('attention_residual','ffn_residual')],['decoding.greedy']]
    for name in ('attention_sum','attention_normalization','attention_block','attention_score','attention_max','gated_product'):
        groups.append([p+name for p,b in zip(prefixes,config.blocks)
                       if name!='attention_block' or b.projection.attention.accumulation=='block1024'])
    groups.append([p+r for p in prefixes for r in ('norm1','norm2')]+['final_norm'])
    return tuple((i,name) for i,names in enumerate(groups,1) for name in names)


def entries(model):
    # Existing inner codecs are shared; family order and role-set oracle are explicit.
    return tuple((i,name,raw) for i,module in enumerate((scaled,row,rotary,residual,greedy,total,
                 normalization,block,score,maximum,gated,norm),1) for name,_,raw in module.records(model))


def frame(config_id,artifact_id,records):
    raw=TAG+config_id+artifact_id+struct.pack('<I',len(records))
    for family,name,data in records:
        name=name.encode('ascii'); raw+=struct.pack('<BH',family,len(name))+name+struct.pack('<I',len(data))+data
    return raw


def case(config,data):
    args=arguments(config,data); model=c.load(*args); records=entries(model)
    assert tuple((i,name) for i,name,_ in records)==roles(config)
    blocks=sum(b.projection.attention.accumulation=='block1024' for b in config.blocks)
    assert len(records)==25*len(config.blocks)+blocks+5
    assert len({(i,name) for i,name,_ in records})==len(records)
    assert all(1<=i<=12 and len(name)<=64 and len(raw)<=8192 for i,name,raw in records)
    expected=frame(args[0],args[2],records); assert s.encode(*args)==expected
    s.validate(*args,expected)
    return args,model,records,expected


def controls():
    config,data=fixture(make(random.Random(2658),0)); args,model,records,raw=case(config,data)
    check=lambda value:s.validate(*args,value)
    # Rebuild count/framing after mutations, so malformed syntax is not the only control.
    for changed in (records[:-1],records+(records[-1],),records[::-1],
                    (records[1],records[0])+records[2:],((0,*records[0][1:]),)+records[1:],
                    ((13,*records[0][1:]),)+records[1:],((1,'embedding.other',records[0][2]),)+records[1:]):
        reject('BoundSet',lambda:check(frame(args[0],args[2],changed)))
    norms=[(i,name,record) for i,name,record in records if i==12]
    assert len(norms)==3 and len({v[2] for v in norms})==1
    reject('BoundSet',lambda:check(frame(args[0],args[2],tuple(v for v in records if v!=norms[1]))))
    reject('BoundSet',lambda:check(frame(args[0],args[2],records[:-3]+(norms[1],norms[0],norms[2]))))
    # Family is essential: query/key names also occur in the row family.
    assert (2,'layer.0.query') in roles(config) and (3,'layer.0.query') in roles(config)
    changed=tuple((2 if i==3 else i,name,v) for i,name,v in records)
    reject('BoundSet',lambda:check(frame(args[0],args[2],changed)))
    rng=random.Random(2659); offsets=set(range(len(TAG)+68))
    offsets.update(rng.sample(range(len(raw)),256)); offset=len(TAG)+68
    for _,name,value in records:
        offsets.update(range(offset,offset+3)); offset+=3+len(name)
        offsets.update(range(offset,offset+4)); offset+=4+len(value)
    assert offset==len(raw)
    for i in sorted(offsets):
        reject('BoundSet',lambda:check(raw[:i]+bytes([raw[i]^1])+raw[i+1:]))
    for end in (0,1,len(TAG),len(TAG)+63,len(TAG)+67,len(raw)-1): reject('BoundSet',lambda:check(raw[:end]))
    for bad in (raw+b'\0',bytearray(raw),None): reject('BoundSet',lambda:check(bad))
    reject('Capacity',lambda:check(b'\0'*((1<<25)+1)))
    reject('Digest',lambda:s.encode(args[0][:-1],args[1],args[2],data))
    reject('Identity',lambda:s.encode(bytes(32),args[1],args[2],data))
    reject('ArtifactDigest',lambda:s.encode(args[0],args[1],bytes(32),data))
    # Different representation, source-role mapping and rotation definition can
    # produce exactly the same numerical Model. Their collection scopes must differ.
    b=config.blocks[0]; q=b.projection
    twins=[replace(config,blocks=(replace(b,projection=replace(q,representation=c.fn.Representation(q.attention.function,2,b'\7'))),)),
           replace(config,blocks=(replace(b,gain1=b.gain2,gain2=b.gain1),)),
           replace(config,blocks=(replace(b,projection=replace(q,rotation=replace(q.rotation,base=c.rope.Q(20000)))),))]
    for twin in twins:
        other_args,other_model,other_records,other=case(twin,data)
        assert other_model==model and other_records==records and other!=raw and other_args[0]!=args[0]
        reject('Identity',lambda:s.encode(args[0],other_args[1],args[2],data))
        reject('BoundSet',lambda:s.validate(*other_args,raw))
        reject('BoundSet',lambda:check(other))
    f=c.fn.Function('exp_q/product',1,bytes([15,7,8,7]))
    changed=replace(config,blocks=(replace(b,projection=replace(q,attention=replace(q.attention,function=f),
                    representation=c.fn.Representation(f,1,b''))),))
    other_args,_,other_records,other=case(changed,data)
    assert other_records==records and other!=raw
    reject('BoundSet',lambda:s.validate(*other_args,raw))
    # Gain values and channel mantissas cannot tighten static records, but changing
    # committed bytes changes the collection's artifact identity even if records match.
    codes=model.embedding.codes; first=(0 if codes[0][0] else 1,)+codes[0][1:]
    for changed in (replace(model,gains=(257,)+model.gains[1:]),
                    replace(model,embedding=replace(model.embedding,codes=(first,)+codes[1:])),
                    replace(model,embedding=replace(model.embedding,mantissas=(1,)*len(model.embedding.mantissas)))):
        cfg,source=fixture(changed); other_args,_,other_records,other=case(cfg,source)
        assert other_args[0]==args[0] and other_args[2]!=args[2] and other_records==records and other!=raw
        reject('ArtifactDigest',lambda:s.encode(args[0],args[1],args[2],source))
        reject('BoundSet',lambda:s.validate(*other_args,raw))
    # Static weight exponents do select scaled-linear records and must come from
    # the validated artifact, not the supplied bound frame.
    changed=replace(model,embedding=replace(model.embedding,exponent=model.embedding.exponent+1))
    cfg,source=fixture(changed); other_args,_,other_records,other=case(cfg,source)
    assert other_args[0]==args[0] and other_records[0]!=records[0] and other_records[1:]==records[1:]
    reject('BoundSet',lambda:s.validate(*other_args,raw))
    huge=replace(config,embedding=replace(config.embedding,shape=(1<<20,config.final_norm.d)),
                 head=replace(config.head,shape=(1<<20,config.final_norm.d)))
    reject('Capacity',lambda:s.encode(c.identity(huge),c.encode(huge),args[2],b''))
    return len(offsets)


def check():
    rng=random.Random(2657); digest=hashlib.sha256(); count=0; largest=0
    for index in range(256):
        model=make(rng,index); blocks=[]
        for b in model.blocks:
            blocks.append(replace(b,norm1=replace(b.norm1,E=5+index%8,G=7+index%5),
                norm2=replace(b.norm2,E=6+index%7,G=7+index%6),
                first=('static',259) if index%5==0 else b.first,
                gated=('static',65535) if index%7==0 else b.gated))
        model=replace(model,blocks=tuple(blocks),final_norm=replace(model.final_norm,E=5+index%8),
                      policy=('static',259) if index%11==0 else model.policy)
        config,data=fixture(model)
        if index%13==0:
            config=replace(config,blocks=tuple(replace(b,projection=replace(b.projection,rotation=None)) for b in config.blocks))
        _,_,records,raw=case(config,data); count+=len(records); largest=max(largest,len(raw)); digest.update(raw)
    # Maximum layer count and every optional block record, with small physical rows.
    model=make(random.Random(2660),1); model=replace(model,blocks=(model.blocks[0],)*128)
    config,data=fixture(model); _,_,records,raw=case(config,data); assert len(records)==3333 and len(raw)<=1<<25
    mutations=controls()
    assert (count,largest,len(raw),mutations)==(14310,96592,3876218,566)
    assert digest.hexdigest()=='cfa53be38034d7da5dcc18ce24eb95bfee21010875303f4367ba0eda4757ef13'
    print(json.dumps(dict(seed=2657,models=256,records=count,largest=largest,sha256=digest.hexdigest(),
                          maximum_layer_records=len(records),maximum_layer_bytes=len(raw),byte_mutations=mutations),sort_keys=True))
