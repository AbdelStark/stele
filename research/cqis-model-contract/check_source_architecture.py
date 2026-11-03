"""Draft RFC-0025 source architecture: independent role/configuration bindings."""
from dataclasses import replace
from decimal import Decimal
from fractions import Fraction as Q
from hashlib import sha256
import json
from pathlib import Path
from random import Random
from struct import pack

from blake3 import blake3

import source_architecture as c
import source_codec as source
from check_arithmetic_bounds import rejects
from check_model_codec import make, oracle as model_frame, roles
from check_source_map import encode_oracle as map_frame
from check_source_codec import assets_frame
from source_map import Entry, Shape, SourceMap


def load(raw): return json.loads(raw,parse_float=Decimal)


def dump(value):
    if type(value) is Decimal: return str(value)
    if type(value) is dict: return '{'+','.join(json.dumps(k)+':'+dump(v) for k,v in value.items())+'}'
    if type(value) is list: return '['+','.join(dump(v) for v in value)+']'
    return json.dumps(value)


def mapped(model,kind,rng):
    entries=[]; types={}; prefix='transformer.' if kind==1 else ''
    for name,layer,dims in roles(model.shape):
        tag,part=0,None; shape=dims
        if kind<2:
            if layer<0:
                key={'token':'wte.weight','position':'wpe.weight','final.gain':'ln_f.weight','final.bias':'ln_f.bias'}[name]
            elif name.startswith('norm'):
                norm,field=name.split('.'); key=f'h.{layer}.ln_{norm[-1]}.{ "weight" if field=="gain" else "bias"}'
            else:
                role=name.removesuffix('.bias'); bias=name.endswith('.bias')
                if role in ('Q','K','V'):
                    key=f'h.{layer}.attn.c_attn.{"bias" if bias else "weight"}'; tag=3 if bias else 2; part=('Q','K','V').index(role)
                    shape=(3*model.shape.width,) if bias else (model.shape.width,3*model.shape.width)
                else:
                    stem={'O':'attn.c_proj','up':'mlp.c_fc','down':'mlp.c_proj'}[role]
                    key=f'h.{layer}.{stem}.{"bias" if bias else "weight"}'
                    if not bias: tag,shape=1,dims[::-1]
            key=prefix+key
        elif layer<0: key={'token':'model.embed_tokens.weight','final.gain':'model.norm.weight','head':'lm_head.weight'}[name]
        else:
            stem={'norm1.gain':'input_layernorm','norm2.gain':'post_attention_layernorm','Q':'self_attn.q_proj',
                  'K':'self_attn.k_proj','V':'self_attn.v_proj','O':'self_attn.o_proj','up':'mlp.up_proj','gate':'mlp.gate_proj','down':'mlp.down_proj'}[name]
            key=f'model.layers.{layer}.{stem}.weight'
        entries.append(Entry(key,types.setdefault(key,rng.randint(1,4)),shape,tag,part))
    ignored=tuple(sorted((prefix+f'h.{i}.attn.bias' if kind<2 else f'model.layers.{i}.self_attn.rotary_emb.inv_freq') for i in range(model.shape.layers)))
    return SourceMap(model.shape,tuple(entries),(('lm_head.weight',0),) if kind<2 and rng.randrange(2) else (),ignored)


def fixture(rng,kind,shape=None):
    m=make(rng,int(kind==2),shape); s=m.shape; epsilon=Q(rng.choice((1,3,7,9)),10**rng.randrange(7))
    rotation=replace(m.blocks[0].rotation,width=s.head_width,layout=1) if kind==2 else None
    def norm(n): return replace(n,en=epsilon.numerator,ed=epsilon.denominator)
    m=replace(m,blocks=tuple(replace(b,norm1=norm(b.norm1),norm2=norm(b.norm2),rotation=rotation) for b in m.blocks),final_norm=norm(m.final_norm))
    eos=sorted(rng.sample(range(s.vocabulary),min(3,s.vocabulary))); bos=rng.randrange(s.vocabulary)
    config=dict(architectures=['LlamaForCausalLM' if kind==2 else 'GPT2LMHeadModel'],model_type='llama' if kind==2 else 'gpt2',bos_token_id=bos,eos_token_id=eos)
    if kind<2:
        config.update(n_layer=s.layers,n_embd=s.width,n_head=s.heads,n_positions=s.context,vocab_size=s.vocabulary,activation_function='gelu_new',layer_norm_epsilon='EPS')
    else:
        config.update(num_hidden_layers=s.layers,hidden_size=s.width,num_attention_heads=s.heads,num_key_value_heads=s.groups,
                      intermediate_size=s.hidden,max_position_embeddings=s.context,vocab_size=s.vocabulary,hidden_act='silu',rms_norm_eps='EPS',rope_theta=rotation.rationals[0][0])
        if rotation.family:
            config['rope_scaling']=dict(rope_type='llama3' if rotation.family==2 else 'linear',factor=8)
            if rotation.family==2: config['rope_scaling'].update(low_freq_factor=1,high_freq_factor=4,original_max_position_embeddings=8192)
    exponent=0; denominator=epsilon.denominator
    while denominator>1: denominator//=10; exponent+=1
    # The chosen numerator may cancel a factor of ten; Fraction's denominator is 10^k here.
    raw=json.dumps(config,separators=(',',':')).replace('"EPS"',f'{epsilon.numerator}e-{exponent}').encode()
    return m,mapped(m,kind,rng),raw,epsilon,rotation,bos,tuple(eos)


def assets(raw):
    files={'config.json':raw,'tokenizer.json':b'{}'}
    return source.describe_assets('config.json',('tokenizer.json',),None,files),files


def architecture_frame(kind,m,epsilon,rotation,bos,eos,pad=None):
    s=m.shape; r=b'' if rotation is None else rotation.encode()
    return (b'stele/v0.1/cqis/source-architecture'+bytes((kind,))+pack('<B6H2I',s.family,s.layers,s.width,s.heads,s.groups,s.head_width,s.hidden,s.vocabulary,s.context)+
            pack('<II',epsilon.numerator,epsilon.denominator)+pack('<I',len(r))+r+pack('<I',bos)+bytes((int(pad is not None),))+
            (pack('<I',pad) if pad is not None else b'')+pack('<I',len(eos))+b''.join(pack('<I',i) for i in eos))


def check(kind,m,mp,raw,epsilon,rotation,bos,eos):
    a,files=assets(raw); expected=architecture_frame(kind,m,epsilon,rotation,bos,eos)
    assert c.derive(kind,raw).encode()==expected
    frame=b'stele/v0.1/cqis/source-config'+blake3(model_frame(m)).digest()+blake3(map_frame(mp)).digest()+blake3(assets_frame(a)).digest()+pack('<I',len(expected))+expected
    assert c.binding(m,mp,kind,a,files)==frame; c.verify(m,mp,kind,a,files,frame)
    return frame,a,files


def boundaries():
    rng=Random(26900); m,mp,raw,epsilon,rotation,bos,eos=fixture(rng,0,Shape(0,1,4,1,1,4,16,7,5)); frame,a,files=check(0,m,mp,raw,epsilon,rotation,bos,eos)
    bad=dict(files); bad['config.json']=raw+b' '; rejects(lambda:c.binding(m,mp,0,a,bad),'FileLength')
    bad=dict(files); bad['config.json']=bytes((raw[0]^1,))+raw[1:]; rejects(lambda:c.binding(m,mp,0,a,bad),'FileDigest')
    for key,value,reason in (('n_layer',2,'Shape'),('n_embd',True,'Dimension'),('activation_function','gelu','Activation'),
                             ('scale_attn_weights',False,'Flags'),('tie_word_embeddings',False,'Flags'),('add_cross_attention',True,'Flags'),
                             ('n_inner',17,'Inner'),('n_ctx',6,'Context'),('n_head',0,'Dimension'),('bos_token_id',7,'Token'),
                             ('eos_token_id',[0,0],'EOS'),('unknown_architecture',1,'Fields')):
        d=load(raw); d[key]=value; changed=dump(d).encode(); aa,ff=assets(changed)
        rejects(lambda:c.binding(m,mp,0,aa,ff),reason)
    for changed,reason in ((b'{"a":1,"a":2}','Duplicate'),(b'{"a":NaN}','JSON'),(b'{"a":1e999999}','Number'),
                           (b'{"a":18446744073709551616}','Number'),(b'{"a":"\\ud800"}','Unicode'),(b'['*40+b'0'+b']'*40,'Depth')):
        rejects(lambda:c.derive(0,changed),reason)
    other=replace(m,final_norm=replace(m.final_norm,en=epsilon.numerator+epsilon.denominator))
    rejects(lambda:c.binding(other,mp,0,a,files),'Epsilon')
    entry=mp.entries[0]; wrong=replace(mp,entries=(replace(entry,name='wrong.weight'),)+mp.entries[1:])
    rejects(lambda:c.binding(m,wrong,0,a,files),'RoleMap')
    wrong=replace(mp,ignored=('not.a.buffer',)); rejects(lambda:c.binding(m,wrong,0,a,files),'Ignored')
    for pos in (0,28,60,92,len(frame)-1):
        changed=frame[:pos]+bytes((frame[pos]^1,))+frame[pos+1:]
        rejects(lambda:c.verify(m,mp,0,a,files,changed),'Binding')
    changed=load(raw); changed['transformers_version']='annotation'; aa,ff=assets(dump(changed).encode())
    assert c.derive(0,ff['config.json']).encode()==c.derive(0,raw).encode()
    rejects(lambda:c.verify(m,mp,0,aa,ff,frame),'Binding')
    lm,lmp,lr,le,rot,lb,ls=fixture(rng,2,Shape(1,1,4,1,1,4,8,7,5)); la,lf=assets(lr)
    rejects(lambda:c.binding(replace(lm,blocks=(replace(lm.blocks[0],rotation=replace(rot,layout=0)),)),lmp,2,la,lf),'Rotation')
    for key,value,reason in (('attention_bias',True,'Flags'),('mlp_bias',True,'Flags'),('tie_word_embeddings',True,'Flags'),
                             ('pretraining_tp',2,'Flags'),('hidden_act','relu','Activation'),('head_dim',2,'HeadWidth'),
                             ('num_key_value_heads',2,'Groups'),('rope_scaling',{'rope_type':'dynamic','factor':8},'Rotation')):
        d=load(lr); d[key]=value; aa,ff=assets(dump(d).encode())
        rejects(lambda:c.binding(lm,lmp,2,aa,ff),reason)
    # Exact decimal parsing must distinguish values that a binary64 cast would merge.
    assert c._json(b'{"x":0.10000000000000001}')['x']==Q(10000000000000001,10**17)
    assert c._json(b'{"x":1e-64}')['x']==Q(1,10**64)
    full=b'{"x":0}'+b' '*((1<<20)-7); assert c._json(full)=={'x':0}
    rejects(lambda:c._json(full+b' '),'Capacity')
    value={'x':[None]*65533}; assert c._json(dump(value).encode())==value
    value['x'].append(None); rejects(lambda:c._json(dump(value).encode()),'Capacity')
    value={'x':'a'*65535}; assert c._json(dump(value).encode())==value
    value['x']+='a'; rejects(lambda:c._json(dump(value).encode()),'String')
    em,emp,er,ee,rr,eb,es=fixture(rng,0,Shape(0,1,4,1,1,4,16,2**20,1))
    d=load(er); es=tuple(range(50000)); d['eos_token_id']=list(es)
    large,_,_=check(0,em,emp,dump(d).encode(),ee,rr,eb,es)
    return dict(gpt_fields=12,llama_fields=8,json_controls=6,source_layouts=3,maximum_json_bytes=1<<20,
                maximum_json_nodes=65536,large_eos_count=len(es),large_binding_bytes=len(large))


def full_shapes():
    rng=Random(26901); result=[]
    shapes=(Shape(0,12,768,12,12,64,3072,50257,1024),Shape(1,32,4096,32,8,128,14336,128256,131072),
            Shape(0,128,4096,128,128,32,16384,2**20,2**20),Shape(1,128,16384,128,128,128,16384,2**20,2**20))
    for i,s in enumerate(shapes):
        kind=2 if s.family else 0; m,mp,raw,eps,rot,bos,eos=fixture(rng,kind,s)
        if i<2:
            eps=Q(1,100000)
            if i==0:
                # Exact public config bytes at HF revision607a30d; no checkpoint payload is present.
                raw=(Path(__file__).parent/'fixtures/gpt2-config.json').read_bytes()
                assert sha256(raw).hexdigest()=='0daed7749b4f02b8f76240d5444551d7b08712dab4d0adb8239c56ba823bb7b4'
                bos,eos=50256,(50256,)
            else:
                # Synthetic HF-layout metadata using pinned Meta architecture, not a fetched gated config.
                d=load(raw); d.update(rms_norm_eps=Decimal('0.00001'),rope_theta=500000,bos_token_id=128000,eos_token_id=128001,
                    rope_scaling=dict(rope_type='llama3',factor=8,low_freq_factor=1,high_freq_factor=4,original_max_position_embeddings=8192))
                raw=dump(d).encode(); rot=c.Rotation(128,131072,2,1,8192,((500000,1),(8,1),(1,1),(4,1))); bos,eos=128000,(128001,)
            def norm(n): return replace(n,en=1,ed=100000)
            m=replace(m,blocks=tuple(replace(b,norm1=norm(b.norm1),norm2=norm(b.norm2),rotation=rot) for b in m.blocks),final_norm=norm(m.final_norm))
        frame,_,_=check(kind,m,mp,raw,eps,rot,bos,eos); result.append([len(m.formats),len(mp.encode()),len(frame)])
    return result


def main():
    rng=Random(2690); corpus=sha256(); layouts=[0,0,0]; maximum=0
    for i in range(10000):
        kind=2 if i%2 else (i//2)%2; m,mp,raw,e,r,b,s=fixture(rng,kind)
        frame,_,_=check(kind,m,mp,raw,e,r,b,s); corpus.update(pack('<I',len(frame))+frame); layouts[kind]+=1; maximum=max(maximum,len(frame))
        if (i+1)%2000==0: print(json.dumps(dict(completed=i+1)),flush=True)
    print(json.dumps(dict(seed=2690,configurations=10000,layouts=layouts,maximum_binding_bytes=maximum,corpus_sha256=corpus.hexdigest(),boundaries=boundaries(),metadata_only_full_shapes=full_shapes()),sort_keys=True))


if __name__=='__main__': main()
