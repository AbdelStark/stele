"""Draft RFC-0025 source-architecture appendix; no tokenizer/proof admission."""
from dataclasses import dataclass
from fractions import Fraction as Q
from hashlib import sha256
import json
from math import gcd
import re
from struct import pack

from blake3 import blake3

from model_codec import Rotation, encode as encode_model
from numerics import integer
import source_codec as source
from source_map import Entry, Shape, SourceMap

ARCH=b'stele/v0.1/cqis/source-architecture'
BINDING=b'stele/v0.1/cqis/source-config'
LIMIT=1<<20


def _int(raw):
    if len(raw.lstrip('-'))>20: raise ValueError('Number')
    value=int(raw); integer(value,-(2**64-1),2**64-1,'Number'); return value


def _decimal(raw):
    exponent=re.search(r'[eE]([+-]?\d+)$',raw)
    if len(raw)>64 or (exponent and abs(int(exponent[1]))>64): raise ValueError('Number')
    value=Q(raw)
    if max(abs(value.numerator).bit_length(),value.denominator.bit_length())>256: raise ValueError('Number')
    return value


def _json(raw):
    if type(raw) is not bytes or len(raw)>LIMIT: raise ValueError('Capacity')
    try:
        value=json.loads(raw.decode('utf8'),object_pairs_hook=source.legacy.unique,
                         parse_int=_int,parse_float=_decimal,parse_constant=source.legacy.no_number)
    except (UnicodeError,RecursionError) as error: raise ValueError('JSON') from error
    except json.JSONDecodeError as error: raise ValueError('JSON') from error
    pending=[(value,1)]; count=0
    while pending:
        item,depth=pending.pop(); count+=1
        if depth>32: raise ValueError('Depth')
        if count>65536: raise ValueError('Capacity')
        if type(item) is str:
            if len(source.legacy.utf8(item))>65535: raise ValueError('String')
        elif type(item) is dict:
            if count+len(pending)+2*len(item)>65536: raise ValueError('Capacity')
            pending.extend((x,depth+1) for pair in item.items() for x in pair)
        elif type(item) is list:
            if count+len(pending)+len(item)>65536: raise ValueError('Capacity')
            pending.extend((x,depth+1) for x in item)
    if type(value) is not dict: raise ValueError('JSON')
    return value


def _number(value):
    if type(value) not in (int,Q): raise ValueError('Number')
    return Q(value)


def _ratio(value,maximum):
    value=_number(value)
    integer(value.numerator,1,maximum,'Rational'); integer(value.denominator,1,maximum,'Rational')
    return value.numerator,value.denominator


def _exact(value,expected,reason):
    if type(value) is not type(expected) or value!=expected: raise ValueError(reason)


@dataclass(frozen=True)
class Architecture:
    kind: int
    shape: Shape
    epsilon: tuple[int,int]
    rotation: Rotation | None
    bos: int
    eos: tuple[int,...]
    pad: int | None

    def encode(self):
        integer(self.kind,0,2,'Layout'); s=self.shape
        if type(s) is not Shape or s.family!=int(self.kind==2): raise ValueError('Shape')
        sr=s.encode()
        if type(self.epsilon) is not tuple or len(self.epsilon)!=2: raise ValueError('Rational')
        for x in self.epsilon: integer(x,1,2**32-1,'Rational')
        if gcd(*self.epsilon)!=1: raise ValueError('Rational')
        if self.kind==2:
            if type(self.rotation) is not Rotation or (self.rotation.width,self.rotation.length,self.rotation.layout)!=(s.head_width,s.context,1): raise ValueError('Rotation')
            rotation=self.rotation.encode()
        else:
            if self.rotation is not None: raise ValueError('Rotation')
            rotation=b''
        integer(self.bos,0,s.vocabulary-1,'Token')
        if self.pad is not None: integer(self.pad,0,s.vocabulary-1,'Token')
        if type(self.eos) is not tuple or not 1<=len(self.eos)<=65536: raise ValueError('EOS')
        for token in self.eos: integer(token,0,s.vocabulary-1,'Token')
        if tuple(sorted(set(self.eos)))!=self.eos: raise ValueError('EOS')
        raw=(ARCH+bytes((self.kind,))+sr+pack('<II',*self.epsilon)+pack('<I',len(rotation))+rotation+pack('<I',self.bos)+
             bytes((int(self.pad is not None),))+(pack('<I',self.pad) if self.pad is not None else b'')+
             pack('<I',len(self.eos))+b''.join(pack('<I',x) for x in self.eos))
        if len(raw)>LIMIT: raise ValueError('Capacity')
        return raw


STRINGS={'_name_or_path','_commit_hash','transformers_version','torch_dtype'}
BOOLEANS={'return_dict','output_attentions','output_hidden_states','use_cache'}
COMMON={'architectures','model_type','bos_token_id','eos_token_id','pad_token_id','tie_word_embeddings',
        'add_cross_attention','is_encoder_decoder','initializer_range','task_specific_params'}|STRINGS|BOOLEANS
GPT={'n_layer','n_embd','n_head','n_positions','vocab_size','n_ctx','n_inner','activation_function','layer_norm_epsilon',
     'scale_attn_weights','scale_attn_by_inverse_layer_idx','reorder_and_upcast_attn','resid_pdrop','embd_pdrop','attn_pdrop',
     'summary_first_dropout','summary_type','summary_activation','summary_use_proj','summary_proj_to_labels'}
LLAMA={'num_hidden_layers','hidden_size','num_attention_heads','num_key_value_heads','intermediate_size','max_position_embeddings',
       'vocab_size','head_dim','hidden_act','rms_norm_eps','rope_theta','rope_scaling','attention_bias','mlp_bias','pretraining_tp','attention_dropout'}


def derive(kind,raw):
    integer(kind,0,2,'Layout'); d=_json(raw); llama=kind==2
    if set(d)-COMMON-(LLAMA if llama else GPT): raise ValueError('Fields')
    required={'architectures','model_type','bos_token_id','eos_token_id','vocab_size'}|(
        {'num_hidden_layers','hidden_size','num_attention_heads','intermediate_size','max_position_embeddings','hidden_act','rms_norm_eps','rope_theta'} if llama else
        {'n_layer','n_embd','n_head','n_positions','activation_function','layer_norm_epsilon'})
    if not required<=set(d): raise ValueError('Fields')
    _exact(d['model_type'],'llama' if llama else 'gpt2','Family')
    _exact(d['architectures'],['LlamaForCausalLM' if llama else 'GPT2LMHeadModel'],'Family')
    _exact(d['hidden_act' if llama else 'activation_function'],'silu' if llama else 'gelu_new','Activation')
    for field in STRINGS|({'summary_type','summary_activation'} if not llama else set()):
        if field in d and d[field] is not None and type(d[field]) is not str: raise ValueError('Metadata')
    for field in BOOLEANS|({'summary_use_proj','summary_proj_to_labels'} if not llama else set()):
        if field in d and type(d[field]) is not bool: raise ValueError('Metadata')
    if 'task_specific_params' in d and d['task_specific_params'] is not None and type(d['task_specific_params']) is not dict: raise ValueError('Metadata')
    if 'initializer_range' in d and _number(d['initializer_range'])<0: raise ValueError('Metadata')
    for field in ({'attention_dropout'} if llama else {'resid_pdrop','embd_pdrop','attn_pdrop','summary_first_dropout'}):
        if field in d and not 0<=_number(d[field])<=1: raise ValueError('Metadata')
    flags={'tie_word_embeddings':not llama,'add_cross_attention':False,'is_encoder_decoder':False}
    flags.update({'attention_bias':False,'mlp_bias':False,'pretraining_tp':1} if llama else
                 {'scale_attn_weights':True,'scale_attn_by_inverse_layer_idx':False,'reorder_and_upcast_attn':False})
    for field,expected in flags.items(): _exact(d.get(field,expected),expected,'Flags')
    names=('num_hidden_layers','hidden_size','num_attention_heads','intermediate_size','max_position_embeddings','vocab_size') if llama else ('n_layer','n_embd','n_head','n_positions','vocab_size')
    for field in names: integer(d[field],1,1<<20,'Dimension')
    if llama: layers,width,heads,hidden,context,vocabulary=(d[n] for n in names)
    else:
        layers,width,heads,context,vocabulary=(d[n] for n in names); hidden=4*width
        if 'n_ctx' in d: _exact(d['n_ctx'],context,'Context')
        if d.get('n_inner') is not None: _exact(d['n_inner'],hidden,'Inner')
    if width%heads: raise ValueError('HeadWidth')
    groups=d.get('num_key_value_heads') if llama else heads
    if groups is None: groups=heads
    integer(groups,1,heads,'Groups')
    if heads%groups: raise ValueError('Groups')
    shape=Shape(int(llama),layers,width,heads,groups,width//heads,hidden,vocabulary,context); shape.encode()
    if llama and 'head_dim' in d: _exact(d['head_dim'],shape.head_width,'HeadWidth')
    epsilon=_ratio(d['rms_norm_eps' if llama else 'layer_norm_epsilon'],2**32-1); rotation=None
    if llama:
        theta=_ratio(d['rope_theta'],2**64-1); scaling=d.get('rope_scaling'); mode,original,ratios=0,0,(theta,(1,1),(0,1),(0,1))
        if scaling is not None:
            if type(scaling) is not dict: raise ValueError('Rotation')
            name=scaling.get('rope_type',scaling.get('type'))
            if name not in ('linear','llama3') or ('type' in scaling and scaling['type']!=name): raise ValueError('Rotation')
            keys={'factor'}|({'low_freq_factor','high_freq_factor','original_max_position_embeddings'} if name=='llama3' else set())
            if set(scaling)-{'type','rope_type'}!=keys: raise ValueError('Rotation')
            factor=_ratio(scaling['factor'],2**64-1); mode=1 if name=='linear' else 2
            if mode==1: ratios=(theta,factor,(0,1),(0,1))
            else:
                original=scaling['original_max_position_embeddings']; integer(original,1,1<<20,'Rotation')
                ratios=(theta,factor,_ratio(scaling['low_freq_factor'],2**64-1),_ratio(scaling['high_freq_factor'],2**64-1))
        rotation=Rotation(shape.head_width,context,mode,1,original,ratios)
    eos=d['eos_token_id']; eos=[eos] if type(eos) is int else eos
    if type(eos) is not list or not eos or any(type(x) is not int for x in eos) or len(set(eos))!=len(eos): raise ValueError('EOS')
    value=Architecture(kind,shape,epsilon,rotation,d['bos_token_id'],tuple(sorted(eos)),d.get('pad_token_id')); value.encode(); return value


def _role(kind,shape,role,layer,dims,dtype):
    tag,part,raw_shape=0,None,dims
    if kind<2:
        prefix='transformer.' if kind==1 else ''
        if role in ('token','position'): name={'token':'wte.weight','position':'wpe.weight'}[role]
        elif role.startswith('final.'): name='ln_f.'+('weight' if role.endswith('gain') else 'bias')
        elif role.startswith('norm'): name=f'h.{layer}.ln_{role[4]}.'+('weight' if role.endswith('gain') else 'bias')
        else:
            weight=not role.endswith('.bias'); projection=role.removesuffix('.bias')
            if projection in ('Q','K','V'):
                name=f'h.{layer}.attn.c_attn.'+('weight' if weight else 'bias'); tag=2 if weight else 3; part=('Q','K','V').index(projection)
                raw_shape=(shape.width,3*shape.width) if weight else (3*shape.width,)
            else:
                stem={'O':'attn.c_proj','up':'mlp.c_fc','down':'mlp.c_proj'}[projection]
                name=f'h.{layer}.{stem}.'+('weight' if weight else 'bias')
                if weight: tag,raw_shape=1,dims[::-1]
        name=prefix+name
    elif layer<0: name={'token':'model.embed_tokens.weight','final.gain':'model.norm.weight','head':'lm_head.weight'}[role]
    else:
        stem={'norm1.gain':'input_layernorm','norm2.gain':'post_attention_layernorm','Q':'self_attn.q_proj','K':'self_attn.k_proj',
              'V':'self_attn.v_proj','O':'self_attn.o_proj','up':'mlp.up_proj','gate':'mlp.gate_proj','down':'mlp.down_proj'}[role]
        name=f'model.layers.{layer}.{stem}.weight'
    return Entry(name,dtype,raw_shape,tag,part)


def binding(model,mapping,kind,assets,files):
    mr=encode_model(model)
    if type(mapping) is not SourceMap or mapping.shape!=model.shape: raise ValueError('Shape')
    mp=mapping.encode(); ar=source.encode_assets(assets); snapshot=source._snapshot(files); expected=source._asset_files(assets)
    if set(snapshot)!={f.name for f in expected}: raise ValueError('FileSet')
    for f in expected:
        if len(snapshot[f.name])!=f.length: raise ValueError('FileLength')
        if sha256(snapshot[f.name]).digest()!=f.sha256: raise ValueError('FileDigest')
    architecture=derive(kind,snapshot[assets.config.name])
    if architecture.shape!=model.shape: raise ValueError('Shape')
    for norm in (model.final_norm,)+tuple(n for b in model.blocks for n in (b.norm1,b.norm2)):
        if (norm.en,norm.ed)!=architecture.epsilon: raise ValueError('Epsilon')
    if any(b.rotation!=architecture.rotation for b in model.blocks): raise ValueError('Rotation')
    for entry,(role,layer,dims) in zip(mapping.entries,model.shape.roles()):
        if entry!=_role(kind,model.shape,role,layer,dims,entry.dtype): raise ValueError('RoleMap')
    if mapping.aliases not in (((),(('lm_head.weight',0),)) if kind<2 else ((),)): raise ValueError('Alias')
    prefix='transformer.' if kind==1 else ''
    allowed={prefix+f'h.{i}.attn.{name}' for i in range(model.shape.layers) for name in ('bias','masked_bias')} if kind<2 else {
        f'model.layers.{i}.self_attn.rotary_emb.inv_freq' for i in range(model.shape.layers)}
    if not set(mapping.ignored)<=allowed: raise ValueError('Ignored')
    raw=architecture.encode(); result=BINDING+blake3(mr).digest()+blake3(mp).digest()+blake3(ar).digest()+pack('<I',len(raw))+raw
    if len(result)>LIMIT: raise ValueError('Capacity')
    return result


def verify(model,mapping,kind,assets,files,raw):
    if type(raw) is not bytes or len(raw)>LIMIT: raise ValueError('Capacity')
    if raw!=binding(model,mapping,kind,assets,files): raise ValueError('Binding')
