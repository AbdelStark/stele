"""RFC-0025 source architecture: bounded independent fixtures, no campaign mains."""
from dataclasses import replace
from decimal import Decimal
from fractions import Fraction
from hashlib import sha256
from math import prod
import json
from pathlib import Path
from random import Random
import sys
from blake3 import blake3
import safetensors

root=Path(__file__).resolve().parents[4]
sys.path.insert(0,str(root/'research/cqis-model-contract'))
import source_architecture as c
import source_codec as source
from check_source_architecture import fixture, load, dump, architecture_frame
from check_model_codec import oracle as model_frame
from check_source_map import encode_oracle as map_frame
from check_source_codec import assets_frame
from source_map import Shape

rng=Random(50460);data=bytearray();cases=[];bindings=[];numbers=[];spans={}
def store(raw):
    if raw not in spans:
        spans[raw]=dict(offset=len(data),length=len(raw));data.extend(raw)
    return spans[raw]
def add(label,kind,raw,error=None):
    if isinstance(raw,dict):raw=dump(raw).encode()
    try:a=c.derive(kind,raw)
    except ValueError as failure:
        assert error is not None,(label,str(failure));expected=b''
    else:
        assert error is None,label
        expected=a.encode()
        # A second framing implementation checks all emitted canonical fields.
        expected2=architecture_frame(kind,type('Model',(),{'shape':a.shape})(),Fraction(*a.epsilon),a.rotation,a.bos,a.eos,a.pad)
        assert expected==expected2
    cases.append(dict(label=label,kind=kind,raw=store(raw),expected=store(expected),error=error))

bases=[]
for i in range(30):
    kind=i%3;m,mp,raw,*_=fixture(rng,kind)
    add('random '+str(i),kind,raw)
    if i<3:bases.append((m,mp,raw))
base=load(bases[0][2]);llama=load(bases[2][2])
def changed(label,key,value,error=None,kind=0):
    d=dict(llama if kind==2 else base);d[key]=value;add(label,kind,d,error)

for kind in (0,2):
    d=dict(llama if kind==2 else base)
    d.update(_name_or_path=None,_commit_hash='é😀',transformers_version='pinned',torch_dtype='bfloat16',
             return_dict=True,output_attentions=False,output_hidden_states=False,use_cache=True,
             initializer_range=Decimal('0.10000000000000001'),task_specific_params={'x':[True,False,None,-(2**64-1),2**64-1,Decimal('1e-64')]})
    if kind==0:d.update(n_ctx=d['n_positions'],n_inner=None,resid_pdrop=0,embd_pdrop=1,attn_pdrop=Decimal('0.5'),summary_first_dropout=0,
                        summary_type=None,summary_activation='tanh',summary_use_proj=False,summary_proj_to_labels=True)
    else:d.update(head_dim=d['hidden_size']//d['num_attention_heads'],attention_dropout=Decimal('0.5'))
    add('recognized annotations '+str(kind),kind,d)
    for key in list(d):
        if key in ('architectures','model_type','bos_token_id','eos_token_id','vocab_size','activation_function','layer_norm_epsilon',
                   'n_layer','n_embd','n_head','n_positions','num_hidden_layers','hidden_size','num_attention_heads','intermediate_size',
                   'max_position_embeddings','hidden_act','rms_norm_eps','rope_theta'):
            missing=dict(d);del missing[key];add('missing '+key,kind,missing,'SourceFields')

for key,value,error in [('unknown',0,'SourceFields'),('n_embd',True,'Shape'),('n_embd',Decimal(str(base['n_embd'])+'.0'),'Shape'),
    ('n_head',0,'Shape'),('n_layer',129,'Shape'),('n_ctx',base['n_positions']+1,'Shape'),('n_inner',4*base['n_embd']+1,'Shape'),
    ('model_type','llama','SourceFamily'),('architectures',['GPT2LMHeadModel','GPT2LMHeadModel'],'SourceFamily'),
    ('activation_function','gelu','Activation'),('layer_norm_epsilon',0,'SourceRational'),('layer_norm_epsilon',True,'SourceRational'),
    ('layer_norm_epsilon',Decimal('0.10000000000000001'),'SourceRational'),('layer_norm_epsilon',Decimal('1e-64'),'SourceRational'),
    ('bos_token_id',base['vocab_size'],'SourceToken'),('eos_token_id',[0,0],'SourceToken'),('eos_token_id',[],'SourceToken'),
    ('eos_token_id',Decimal('0.0'),'SourceToken'),('pad_token_id',True,'SourceToken'),('initializer_range',-1,'SourceMetadata'),
    ('task_specific_params',[],'SourceMetadata'),('torch_dtype',3,'SourceMetadata'),('use_cache',1,'SourceMetadata'),
    ('attn_pdrop',Decimal('1.00000000000000001'),'SourceMetadata')]:changed(key, key,value,error)
for key,expected in [('scale_attn_weights',True),('scale_attn_by_inverse_layer_idx',False),('reorder_and_upcast_attn',False),
                     ('add_cross_attention',False),('is_encoder_decoder',False),('tie_word_embeddings',True)]:
    changed('valid flag '+key,key,expected);changed('wrong flag '+key,key,not expected,'SourceFlags');changed('integer flag '+key,key,int(expected),'SourceFlags')
for key,value in [('attention_bias',True),('mlp_bias',True),('tie_word_embeddings',True),('pretraining_tp',2),('pretraining_tp',True)]:changed('llama '+key,key,value,'SourceFlags',2)
for key,value,error in [('head_dim',0,'Shape'),('num_key_value_heads',0,'Shape'),('hidden_act','relu','Activation'),
                      ('rope_theta',Decimal('0.5'),'Rotation'),('rope_theta',2**32+1,'Rotation')]:changed('llama '+key,key,value,error,2)
for scaling in [None,{'type':'linear','factor':Decimal('1.25')},{'rope_type':'linear','type':'linear','factor':2},
                {'rope_type':'llama3','factor':8,'low_freq_factor':Decimal('0.5'),'high_freq_factor':4,'original_max_position_embeddings':8192}]:changed('rotation '+str(scaling),'rope_scaling',scaling,kind=2)
for scaling in [{},[],{'rope_type':'dynamic','factor':8},{'rope_type':'linear','type':'llama3','factor':8},
                {'rope_type':'linear','factor':8,'unknown':0},{'type':'linear','factor':Decimal('0.5')},
                {'type':'llama3','factor':8,'low_freq_factor':4,'high_freq_factor':4,'original_max_position_embeddings':8192}]:changed('bad rotation '+str(scaling),'rope_scaling',scaling,'Rotation',2)
changed('pad null','pad_token_id',None);changed('pad zero','pad_token_id',0);changed('single eos','eos_token_id',0)
changed('sorted eos','eos_token_id',list(reversed(base['eos_token_id'])))
changed('groups null','num_key_value_heads',None,kind=2)
d=dict(llama);d.pop('num_key_value_heads',None);add('groups absent',2,d)
for theta in [Decimal('1.00000000000000001'),Decimal('4294967295.999999999')]:changed('full u64 rotation ratio '+str(theta),'rope_theta',theta,kind=2)

# Whole JSON limits, including ignored nested annotations. No float parser is used.
raw=dump(base).encode()
add('maximum original bytes',0,raw+b' '*((1<<20)-len(raw)))
add('original bytes overflow',0,raw+b' '*((1<<20)-len(raw)+1),'Capacity')
changed('maximum string','_name_or_path','é'*32767+'a')
changed('string overflow','_name_or_path','é'*32768,'SourceString')
node={'x':None}
for _ in range(29):node={'x':node}
changed('maximum depth','task_specific_params',node)
changed('depth overflow','task_specific_params',{'x':node},'SourceDepth')
def nodes(v):
    if isinstance(v,dict):return 1+sum(1+nodes(x) for x in v.values())
    if isinstance(v,list):return 1+sum(nodes(x) for x in v)
    return 1
d=dict(base);d['task_specific_params']={'x':[]};d['task_specific_params']['x']=[None]*(65536-nodes(d))
assert nodes(d)==65536;add('maximum nodes',0,d)
d['task_specific_params']['x'].append(None);add('node overflow',0,d,'Capacity')
for token in [b'-0',b'-0.0',b'1e-64',b'1e64',b'0.10000000000000001',b'1E+0000000000000000000000000000000000000000000000000000000000000',
              b'0.'+b'0'*59+b'1',b'1'+b'0'*59+b'e-64']:
    add('exact number '+token.decode(),0,raw[:-1]+b',"task_specific_params":{"n":'+token+b'}}')
for token in [b'NaN',b'Infinity',b'01',b'-00',b'1.',b'.1',b'1e',b'+1',b'truex',b'nullx']:
    add('bad token '+token.decode(),0,raw[:-1]+b',"task_specific_params":{"n":'+token+b'}}','SourceJson')
for token in [b'18446744073709551616',b'-18446744073709551616',b'1e65',b'1e-65',b'0.'+b'0'*63,b'9'*63+b'.0',b'9'*60+b'e64',b'0.'+b'0'*59+b'1e-64']:
    add('number domain '+token.decode(),0,raw[:-1]+b',"task_specific_params":{"n":'+token+b'}}','SourceNumber')
for label,suffix,error in [('duplicate',b',"n_layer":1}','SourceDuplicate'),('nested duplicate',b',"task_specific_params":{"x":0,"\\u0078":1}}','SourceDuplicate'),
    ('surrogate',b',"_name_or_path":"\\ud800"}','SourceJson'),('UTF8',b',"_name_or_path":"\xff"}','SourceJson'),('trailing comma',b',}','SourceJson')]:add(label,0,raw[:-1]+suffix,error)
add('invalid layout',3,raw,'SourceLayout');add('not object',0,b'[]','SourceJson');add('trailing data',0,raw+b'0','SourceJson')

tokens=['0','-0','18446744073709551615','-18446744073709551615','-0.0','0.10000000000000001','1e-64','1e64',
        '11579208923731e64','11579208923732e64','1.00000000000000000000000000000000000000000000000000000000000e-64']
for i in range(128):
    coefficient=str(rng.randrange(1,10**rng.randrange(1,55)))
    tokens.append(('-' if i%2 else '')+coefficient+'e'+str(rng.randrange(-64,65)))
for raw_number in tokens:
    integer='.' not in raw_number and 'e' not in raw_number.lower()
    try:q=Fraction(c._int(raw_number) if integer else c._decimal(raw_number))
    except ValueError:numbers.append(dict(raw=raw_number,error='SourceNumber'))
    else:numbers.append(dict(raw=raw_number,integer=integer,negative=q<0,numerator=[(abs(q.numerator)>>(32*i))&0xffffffff for i in range(8)],denominator=[(q.denominator>>(32*i))&0xffffffff for i in range(8)],error=None))

# Complete named/max geometries are config metadata only, not source qualification.
gpt=(root/'research/cqis-model-contract/fixtures/gpt2-config.json').read_bytes()
assert sha256(gpt).hexdigest()=='0daed7749b4f02b8f76240d5444551d7b08712dab4d0adb8239c56ba823bb7b4'
add('original public GPT2 config metadata',0,gpt)
for shape in [Shape(1,32,4096,32,8,128,14336,128256,131072),Shape(0,128,4096,128,128,32,16384,2**20,2**20),Shape(1,128,16384,128,128,128,16384,2**20,2**20)]:
    kind=2 if shape.family else 0;_,_,sr,*_=fixture(rng,kind,shape);add('synthetic full geometry '+str(shape),kind,sr)
d=dict(base);d['vocab_size']=2**20;d['eos_token_id']=list(range(50000));add('50000 EOS ids',0,d)

def bind(label,kind,m,mp,raw,error=None,reason=None):
    aux={'config.json':raw,'tokenizer.json':b'{}','generation.json':b'{}'}
    assets=source.describe_assets('config.json',('tokenizer.json',),'generation.json',aux)
    try:expected=c.binding(m,mp,kind,assets,aux)
    except ValueError as failure:
        assert error is not None and str(failure)==reason,(label,str(failure));expected=b''
    else:
        assert error is None,label
        arch=c.derive(kind,raw).encode()
        assert expected==c.BINDING+blake3(model_frame(m)).digest()+blake3(map_frame(mp)).digest()+blake3(assets_frame(assets)).digest()+len(arch).to_bytes(4,'little')+arch
    tensors={e.name:dict(dtype={1:'float16',2:'bfloat16',3:'float32',4:'float64'}[e.dtype],shape=list(e.shape),data=bytes(prod(e.shape)*{1:2,2:2,3:4,4:8}[e.dtype])) for e in mp.entries}
    for name,target in mp.aliases:tensors[name]=tensors[mp.entries[target].name]
    for name in mp.ignored:tensors[name]=dict(dtype='int64',shape=[],data=bytes(8))
    files={'model.safetensors':safetensors.serialize(tensors)};src=source.describe_source(files);files.update(aux)
    source.verify(mp,src,assets,files)
    bindings.append(dict(label=label,kind=kind,model=store(model_frame(m)),map=store(map_frame(mp)),source=store(source.encode_source(src)),assets=store(assets_frame(assets)),
                         files=[dict(name=n,raw=store(b)) for n,b in sorted(files.items())],expected=store(expected),error=error))

for kind in range(3):
    for i in range(4):
        shape=Shape(int(kind==2),2,8,2,1 if kind==2 else 2,4,13 if kind==2 else 32,17,9)
        m,mp,raw,*_=fixture(rng,kind,shape);bind(f'complete {kind} {i}',kind,m,mp,raw)
        if i:continue
        annotated=load(raw);annotated['transformers_version']='different authenticated annotation'
        assert c.derive(kind,dump(annotated).encode()).encode()==c.derive(kind,raw).encode()
        bind('annotation '+str(kind),kind,m,mp,dump(annotated).encode())
        d=load(raw);d['num_hidden_layers' if kind==2 else 'n_layer']=3;bind('config shape '+str(kind),kind,m,mp,dump(d).encode(),'Shape','Shape')
        for which in ('final','first','second'):
            if which=='final':other=replace(m,final_norm=replace(m.final_norm,en=m.final_norm.en+m.final_norm.ed))
            else:
                b=m.blocks[-1];key='norm1' if which=='first' else 'norm2';n=getattr(b,key)
                other=replace(m,blocks=m.blocks[:-1]+(replace(b,**{key:replace(n,en=n.en+n.ed)}),))
            bind(f'norm {kind} {which}',kind,other,mp,raw,'SourceEpsilon','Epsilon')
        if kind==2:
            b=m.blocks[-1];other=replace(m,blocks=m.blocks[:-1]+(replace(b,rotation=replace(b.rotation,layout=0)),))
            bind('rotation join',kind,other,mp,raw,'Rotation','Rotation')
        for name in dict.fromkeys(e.name for e in mp.entries):
            entries=tuple(replace(e,name=e.name+'.wrong') if e.name==name else e for e in mp.entries)
            bind('role '+name,kind,m,replace(mp,entries=entries),raw,'SourceRole','RoleMap')
        # Square projections admit both Map transforms; only one fits the adapter.
        ordinal=next(j for j,(role,_,_) in enumerate(m.shape.roles()) if role=='O')
        es=list(mp.entries);e=es[ordinal];es[ordinal]=replace(e,transform=1-e.transform,shape=e.shape[::-1])
        bind('role transform '+str(kind),kind,m,replace(mp,entries=tuple(es)),raw,'SourceRole','RoleMap')
        bind('ignored '+str(kind),kind,m,replace(mp,ignored=('not.a.buffer',)),raw,'SourceIgnored','Ignored')
        if kind<2:bind('alias '+str(kind),kind,m,replace(mp,aliases=(('wrong.head',0),)),raw,'SourceAlias','Alias')

m,mp,raw,*_=fixture(rng,0,Shape(0,1,4,1,1,4,16,50000,1))
d=load(raw);d['eos_token_id']=list(reversed(range(50000)))
bind('complete 50000 EOS binding',0,m,mp,dump(d).encode())

out=root/'crates/stele-cqis/tests/fixtures'
(out/'source-architecture.bin').write_bytes(data)
(out/'source-architecture.json').write_text(json.dumps(dict(seed=50460,cases=cases,bindings=bindings,numbers=numbers),separators=(',',':'))+'\n')
print(json.dumps(dict(cases=len(cases),valid=sum(v['error'] is None for v in cases),bindings=len(bindings),valid_bindings=sum(v['error'] is None for v in bindings),numbers=len(numbers),bytes=len(data))))
