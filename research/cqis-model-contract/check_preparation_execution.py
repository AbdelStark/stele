"""Draft RFC-0025: original-file to execution and complete numerical identity joins."""
from dataclasses import replace
from fractions import Fraction as Q
from hashlib import sha256
import json
from random import Random
from struct import pack

from blake3 import blake3
import safetensors

from check_arithmetic_bounds import rejects
from check_artifact_codec import layout_oracle
from check_model_codec import roles, oracle as model_frame
from check_model_execution import fixture, compare, generation_case
from check_source_architecture import mapped
from check_source_conversion import FORMATS, dyadic, oracle as conversion_oracle
import artifact_codec
import bound_collection
import model_execution
import registry_codec
import scales_codec
import source_architecture
import source_codec
import preparation_execution as c


def configuration(m,kind):
    s=m.shape
    d=dict(architectures=['LlamaForCausalLM' if s.family else 'GPT2LMHeadModel'],model_type='llama' if s.family else 'gpt2',
           bos_token_id=0,eos_token_id=s.vocabulary-1,vocab_size=s.vocabulary)
    if not s.family:
        d.update(n_layer=s.layers,n_embd=s.width,n_head=s.heads,n_positions=s.context,activation_function='gelu_new',layer_norm_epsilon='EPS')
    else:
        r=m.blocks[0].rotation
        d.update(num_hidden_layers=s.layers,hidden_size=s.width,num_attention_heads=s.heads,num_key_value_heads=s.groups,
                 intermediate_size=s.hidden,max_position_embeddings=s.context,hidden_act='silu',rms_norm_eps='EPS',rope_theta=r.rationals[0][0])
        if r.family:
            d['rope_scaling']=dict(rope_type='linear' if r.family==1 else 'llama3',factor=r.rationals[1][0])
            if r.family==2:d['rope_scaling'].update(low_freq_factor=r.rationals[2][0],high_freq_factor=r.rationals[3][0],original_max_position_embeddings=r.original)
    return json.dumps(d,separators=(',',':')).replace('"EPS"','0.00001').encode()


def original(m,mp,arrays):
    slots={}; descriptions={}
    for entry,(name,layer,dims),(_,fraction) in zip(mp.entries,roles(m.shape),m.formats):
        count=entry.shape[0]*(entry.shape[1] if len(entry.shape)==2 else 1)
        values=slots.setdefault(entry.name,[None]*count); descriptions[entry.name]=entry
        if len(dims)==1: physical=[Q(x)*Q(2)**-fraction for x in arrays[name,layer][-1]]
        else:
            _,e,ms,codes=arrays[name,layer]; physical=[Q(x*ms[i//dims[1]])*Q(2)**e for i,x in enumerate(codes)]
        for i,value in enumerate(physical):
            if entry.transform==0: source=i
            elif entry.transform==3: source=entry.part*dims[0]+i
            else:
                row,column=divmod(i,dims[1]); source=column*entry.shape[1]+row+(entry.part*dims[0] if entry.transform==2 else 0)
            assert values[source] is None; values[source]=value
    tensors={}
    for name,values in slots.items():
        e=descriptions[name]; assert all(v is not None for v in values)
        raw=b''.join(dyadic(e.dtype,v.numerator,-(v.denominator.bit_length()-1)) for v in values)
        tensors[name]=dict(dtype=FORMATS[e.dtype][3],shape=list(e.shape),data=raw)
    for name,target in mp.aliases: tensors[name]=dict(tensors[mp.entries[target].name])
    return tensors


def package(m,kind,mp,tensors,groups):
    names=sorted(tensors); files={}; locations={}
    for i in range(groups):
        label=f'model-{i}.safetensors'; selected=names[i::groups]
        files[label]=safetensors.serialize({name:tensors[name] for name in selected}); locations.update((name,label) for name in selected)
    index=None
    if groups>1:
        index='model.index.json'; files[index]=json.dumps(dict(metadata=dict(total_size=sum(len(t['data']) for t in tensors.values())),weight_map=locations),separators=(',',':')).encode()
    source=source_codec.describe_source(files,index)
    auxiliary={'config.json':configuration(m,kind),'tokenizer.json':b'{}'}
    assets=source_codec.describe_assets('config.json',('tokenizer.json',),None,auxiliary)
    return source,assets,{**files,**auxiliary}


def converted_arrays(m,scales,raw):
    layouts,_=layout_oracle(m); ss=iter(scales); result={}
    for (name,layer,dims),(bits,_),(_,offset,_,_) in zip(roles(m.shape),m.formats,layouts):
        count=dims[0]*(dims[1] if len(dims)==2 else 1)
        if bits==4:
            codes=tuple((((raw[offset+i//2]>>(4*(i%2)))&15)+8)%16-8 for i in range(count))
        else:
            size=bits//8; codes=tuple(int.from_bytes(raw[offset+size*i:offset+size*(i+1)],'little',signed=True) for i in range(count))
        if len(dims)==1: result[name,layer]=(dims,codes)
        else:
            scale=next(ss); ms=tuple(int.from_bytes(scale.mantissas[i:i+2],'little') for i in range(0,len(scale.mantissas),2))
            result[name,layer]=(dims,scale.exponent,ms,codes)
    return result


def case(rng,kind,dtype,groups):
    m,_,_,_,a=fixture(rng,int(kind==2),layers=2)
    if kind==2:
        r=replace(m.blocks[0].rotation,layout=1);m=replace(m,blocks=tuple(replace(b,rotation=r) for b in m.blocks))
    mp=mapped(m,kind,rng); mp=replace(mp,entries=tuple(replace(e,dtype=dtype) for e in mp.entries),ignored=())
    ts=original(m,mp,a); src,assets,files=package(m,kind,mp,ts,groups)
    return m,mp,ts,src,assets,files


def check(rng,kind,dtype,groups):
    m,mp,ts,src,assets,files=case(rng,kind,dtype,groups); result=c.prepare(m,mp,kind,src,assets,files)
    scales,expected=conversion_oracle(m,mp,ts); sr=scales_codec.encode(m,scales)
    assert result.conversion.scales==sr and result.execution.raw==expected
    assert result.conversion.digest==blake3(expected).digest() and result.conversion.length==len(expected)
    assert result.conversion.source_identity==source_codec.identity(src)
    assert result.conversion.assets_id==blake3(source_codec.encode_assets(assets)).digest()
    assert result.conversion.quantiser_id==blake3(artifact_codec.encode_preparation(m,mp)).digest()
    auxiliary={f.name:files[f.name] for f in source_codec._asset_files(assets)}
    assert result.source_config==source_architecture.binding(m,mp,kind,assets,auxiliary)
    arrays=converted_arrays(m,scales,expected); prompt=(0,)
    tag,generated=generation_case(result.execution,arrays,prompt,rng)
    if tag!='reject': compare(m,mp,sr,expected,arrays,generated[0])
    return result,(m,mp,ts,src,assets,files),tag


def controls(values,kind):
    m,mp,ts,src,assets,files=values
    changed=dict(files); changed['config.json']=files['config.json']+b' '; rejects(lambda:c.prepare(m,mp,kind,src,assets,changed),'FileLength')
    changed=dict(files); del changed['tokenizer.json']; rejects(lambda:c.prepare(m,mp,kind,src,assets,changed),'FileSet')
    changed=dict(files); name=src.files[0].name; raw=files[name]; changed[name]=raw[:-1]+bytes((raw[-1]^1,))
    rejects(lambda:c.prepare(m,mp,kind,src,assets,changed),'FileDigest')
    changed=dict(files); changed['tokenizer.json']=bytearray(files['tokenizer.json']); rejects(lambda:c.prepare(m,mp,kind,src,assets,changed),'Bytes')
    changed=dict(files); changed['config.json']=files['config.json'].replace(b'0.00001',b'0.00002')
    auxiliary={f.name:changed[f.name] for f in source_codec._asset_files(assets)}
    other=source_codec.describe_assets('config.json',('tokenizer.json',),None,auxiliary)
    rejects(lambda:c.prepare(m,mp,kind,src,other,changed),'Epsilon')
    bad=replace(mp,entries=(replace(mp.entries[0],name='substituted.weight'),)+mp.entries[1:])
    rejects(lambda:c.prepare(m,bad,kind,src,assets,files),'RoleMap')


def identity_case(m,scales):
    registry=registry_codec.encode(m); bounds=bound_collection.encode(m,scales,registry)
    expected=b'stele/v0.1/cqis/identity'+b''.join(blake3(raw).digest() for raw in (model_frame(m),scales,registry,bounds))
    raw=c.identity_frame(m,scales,registry,bounds); assert raw==expected
    assert c.identity(m,scales,registry,bounds)==blake3(expected).digest(); c.verify_identity(m,scales,registry,bounds,expected)
    for at in (0,24,len(raw)-1):
        changed=raw[:at]+bytes((raw[at]^1,))+raw[at+1:]; rejects(lambda:c.verify_identity(m,scales,registry,bounds,changed),'Identity')
    rejects(lambda:c.verify_identity(m,scales,registry,bounds,raw+b'\0'),'Identity')
    rejects(lambda:c.verify_identity(m,scales,registry,bounds,bytearray(raw)),'Identity')
    rejects(lambda:c.identity_frame(m,scales,registry,bounds[:-1]+bytes((bounds[-1]^1,))),'Encoding')
    rejects(lambda:c.identity_frame(m,scales,bytes((registry[0]^1,))+registry[1:],bounds),'Structure')
    rejects(lambda:c.identity_frame(replace(m,logits_fraction=(m.logits_fraction+1)%31),scales,registry,bounds),'ModelIdentity')
    return dict(identity=blake3(raw).hexdigest(),frame_bytes=len(raw),registry_bytes=len(registry),bounds_bytes=len(bounds))


def main():
    rng=Random(2693); corpus=sha256(); outcomes={}; identities=[]; retained={}
    for kind in range(3):
        for dtype in range(1,5):
            for groups in range(1,4):
                result,values,tag=check(rng,kind,dtype,groups); outcomes[tag]=outcomes.get(tag,0)+1
                corpus.update(result.source_config+result.conversion.source_identity+result.conversion.digest+tag.encode())
                retained.setdefault(kind,(result,values)); print(json.dumps(dict(layout=kind,dtype=dtype,shards=groups,outcome=tag)),flush=True)
    for kind,(result,values) in retained.items(): controls(values,kind)
    for kind in (0,2):
        result,values=retained[kind]; identities.append(identity_case(values[0],result.conversion.scales)); print(json.dumps(dict(identity_layout=kind)),flush=True)
    print(json.dumps(dict(seed=2693,packages=36,outcomes=outcomes,identities=identities,corpus_sha256=corpus.hexdigest()),sort_keys=True))


if __name__=='__main__': main()
