"""Draft RFC-0025 §§2.2–2.6: Artifact-backed numerical execution, not a proof API."""
from dataclasses import dataclass
from fractions import Fraction as Q
from functools import lru_cache
from pathlib import Path
from struct import unpack_from
import sys
from types import MappingProxyType

from blake3 import blake3

import artifact_codec as artifact
import attention_input_bounds as attention
import decoding_execution as decoding
from flow_bounds import Row as RowSpec
from model_codec import encode as encode_model
from numerics import LayerNorm, affine, checked_output, embedding, grouped_affine, integer, layer_norm, round_ratio, shifted_pair
import request_bounds as request
from rms_bounds import RMSNorm
import scales_codec
import weighted_bounds as weighted
import certified_activations as act
import certified_rmsnorm as rms

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'cqis-checkpoint'))
import rope


class _Stream:
    def __init__(self,raw): self.raw,self.position=raw,0
    def read(self,n):
        result=self.raw[self.position:self.position+n]; self.position+=len(result); return result


@dataclass(frozen=True)
class Data:
    model: object
    raw: bytes
    records: tuple
    scales: object
    ids: object
    scope: tuple[bytes,...]

    def record(self,name,layer=-1): return self.records[self.ids[name,layer]]

    def code(self,record,index):
        integer(index,0,record.elements-1,'Index')
        offset=record.payload_offset
        if record.bits==16: return unpack_from('<h',self.raw,offset+2*index)[0]
        if record.bits==8:
            value=self.raw[offset+index]; return value-256 if value>=128 else value
        value=(self.raw[offset+index//2]>>(4*(index%2)))&15
        return value-16 if value>=8 else value

    def scale(self,record,row):
        integer(row,0,record.dimensions[0]-1,'Index'); scale=self.scales[record.ordinal]
        return unpack_from('<H',scale.mantissas,2*row)[0],scale.exponent

    def vector(self,name,layer=-1):
        record=self.record(name,layer)
        return tuple(self.code(record,j) for j in range(record.elements))


def load(model,mapping,scales_raw,raw,expected):
    model_raw=encode_model(model); scales=scales_codec.decode(model,scales_raw); s=model.shape
    for b in model.blocks:
        f,p=b.fractions,b.policies
        attention.derive(attention.Score(s.heads,s.groups,s.head_width,s.context,f[0],f[1],b.exp.F,*p[1],*p[2],b.score_m,b.score_e))
        weighted._constants(weighted.Weighted(s.heads,s.groups,s.head_width,s.context,f[2],b.exp.E,*p[3],b.accumulation,b.drop))
        if b.activation.E>b.activation.F: raise ValueError('ActivationRange')
    if type(raw) is not bytes: raise ValueError('Artifact')
    artifact.verify(model,mapping,scales_raw,_Stream(raw),expected)
    records,_=artifact.layout(model); matrix_ids=[r.ordinal for r in records if len(r.dimensions)==2]
    ids={(name,layer):i for i,(name,layer,_) in enumerate(s.roles())}
    if not s.family: ids['head',-1]=ids['token',-1]
    return Data(model,raw,records,MappingProxyType(dict(zip(matrix_ids,scales))),MappingProxyType(ids),
                (blake3(model_raw).digest(),blake3(scales_raw).digest(),expected))


@dataclass(frozen=True)
class Row:
    codes: tuple[int,...]
    scale: int | tuple[int,...]  # a tuple of group scales for a grouped row (RFC-0004 A15)
    fraction: int


def convert(values,fraction,policy,gated=False):
    """A grouped row (policy mode 2, RFC-0004 A15) has a tuple of group scales, one per g values."""
    if type(values) is not tuple: raise ValueError('Row')
    RowSpec(len(values),int(gated),fraction,*policy)
    for x in values: integer(x,-(1<<30) if gated else -32768,(1<<30) if gated else 32767,'Input')
    if policy[0]==2:
        g=policy[1]; parts=tuple(convert(values[i:i+g],fraction,(0,0),gated) for i in range(0,len(values),g))
        return Row(tuple(c for part in parts for c in part.codes),tuple(part.scale for part in parts),fraction)
    scale=policy[1] if policy[0] else (max(map(abs,values))+126)//127
    codes=tuple(round_ratio(x,scale) for x in values) if scale else (0,)*len(values)
    if any(abs(x)>127 for x in codes): raise ValueError('RowRange')
    return Row(codes,scale,fraction)


def width(model):
    """Residual-stream bits: 24 when every norm is rmsnorm_q version 2 (RFC-0004 A14), else 16."""
    return 24 if model.shape.family and model.final_norm.version==2 else 16


def linear(data,name,layer,x,fraction):
    record=data.record(name,layer); rows,columns=record.dimensions
    if len(x.codes)!=columns: raise ValueError('Shape')
    bias=None if data.model.shape.family or name=='head' else data.record(name+'.bias',layer)
    fb=0 if bias is None else data.model.formats[bias.ordinal][1]; result=[]
    grouped=type(x.scale) is tuple; g=columns//len(x.scale) if grouped else columns
    for j in range(rows):
        m,e=data.scale(record,j); b=0 if bias is None else data.code(bias,j); bits=width(data.model) if name in ('O','down') else 16
        if grouped:  # RFC-0004 A15: A' = sum_i s_g(i)*q_i*w_i, then the same single rounding
            dot=sum(x.scale[k//g]*code*data.code(record,j*columns+k) for k,code in enumerate(x.codes))
            result.append(grouped_affine(dot,m,e,x.fraction,fraction,b,fb,bits)); continue
        dot=sum(code*data.code(record,j*columns+k) for k,code in enumerate(x.codes))
        result.append(affine(dot,m,x.scale,e,x.fraction,fraction,b,fb,bits))
    return tuple(result)


def normalize(data,n,row,name,layer=-1):
    gains=data.vector(name+'.gain',layer)
    if type(n) is LayerNorm: return tuple(layer_norm(n,list(row),list(gains),list(data.vector(name+'.bias',layer)))['output'])
    p=rms.Parameters(n.d,n.F,n.G,n.E,n.en,n.ed,n.version)
    try: return tuple(rms.evaluate(p,list(row),list(gains))['output'])
    except ValueError as error:
        if str(error)=='Overflow': raise ValueError('Range') from error
        raise


def residual(left,fx,right,fy,fo,bits=16):
    return tuple(checked_output(round_ratio(*shifted_pair(x,fo-fx,y,fo-fy)),bits) for x,y in zip(left,right))


def embed(data,token,position):
    m=data.model; s=m.shape; token_record=data.record('token'); tm,te=data.scale(token_record,token)
    position_record=None if s.family else data.record('position')
    pm,pe=(1,0) if s.family else data.scale(position_record,position)
    return tuple(embedding(data.code(token_record,token*s.width+j),tm,te,
                 0 if s.family else data.code(position_record,position*s.width+j),pm,pe,m.f0) for j in range(s.width))


@lru_cache(maxsize=65536,typed=True)
def _rotation(r,position,j):
    values=tuple(Q(*pair) for pair in r.rationals)
    p=rope.Parameters(r.width,r.length,values[0],('base','linear','llama3')[r.family],('adjacent','split')[r.layout],*values[1:],r.original)
    entry=rope.certify(p,position,j); return entry['cos'],entry['sin']


def rotate(r,values,position,heads,width):
    if r is None: return values
    result=list(values)
    for h in range(heads):
        for j in range(r.width//2):
            cosine,sine=_rotation(r,position,j); left=h*width+(2*j if r.layout==0 else j); right=left+1 if r.layout==0 else left+r.width//2
            result[left]=checked_output(round_ratio(values[left]*cosine-values[right]*sine,16384))
            result[right]=checked_output(round_ratio(values[left]*sine+values[right]*cosine,16384))
    return tuple(result)


@lru_cache(maxsize=65536,typed=True)
def activation(p,value):
    config=act.Parameters('silu' if p.kind==1 else 'gelu_tanh',p.F,p.E)
    try: return act.certify(config,value)['value']
    except ValueError as error:
        if str(error)=='Overflow': raise ValueError('Range') from error
        raise


def project(data,layer,row,position):
    b=data.model.blocks[layer]; s=data.model.shape
    x=convert(normalize(data,b.norm1,row,'norm1',layer),b.norm1.E,b.policies[0])
    q,k,v=(linear(data,name,layer,x,b.fractions[j]) for j,name in enumerate(('Q','K','V')))
    q=rotate(b.rotation,q,position,s.heads,s.head_width); k=rotate(b.rotation,k,position,s.groups,s.head_width)
    return tuple(convert(values,b.fractions[j],b.policies[j+1]) for j,values in enumerate((q,k,v)))


def attend(data,layer,q,position,keys):
    b=data.model.blocks[layer]; s=data.model.shape; out=[]
    integer(position,0,len(keys)-1,'Position')
    shift=b.score_e-b.fractions[0]-b.fractions[1]+b.exp.F
    for head in range(s.heads):
        group=head//(s.heads//s.groups); scores=[]
        for key,_ in keys:
            dot=sum(q.codes[head*s.head_width+j]*key.codes[group*s.head_width+j] for j in range(s.head_width))
            value=dot*q.scale*key.scale*b.score_m
            score=round_ratio(value<<max(shift,0),1<<max(-shift,0)); integer(score,-(1<<31),(1<<31)-1,'Score'); scores.append(score)
        selected=max(range(position+1),key=lambda j:scores[j]); maximum=scores[selected]
        weights=[decoding.exponential(b.exp,x-maximum) if j<=position else 0 for j,x in enumerate(scores)]; z=sum(weights)
        for lane in range(s.head_width):
            total=0; partial=0
            for j,((_,value),weight) in enumerate(zip(keys,weights)):
                partial+=weight*value.scale*value.codes[group*s.head_width+lane]
                if b.accumulation and ((j+1)%1024==0 or j+1==len(keys)):
                    total+=checked_output(round_ratio(partial,1<<b.drop)); partial=0
            if not b.accumulation: total=partial
            exponent=b.attention-b.fractions[2]+b.drop
            out.append(checked_output(round_ratio(total<<max(exponent,0),z<<max(-exponent,0))))
    return tuple(out)


def finish_block(data,layer,row,position,projected,keys):
    m=data.model; b=m.blocks[layer]; incoming=m.f0 if layer==0 else m.blocks[layer-1].out
    values=attend(data,layer,projected[0],position,keys)
    o=linear(data,'O',layer,convert(values,b.attention,b.policies[4]),b.fractions[3])
    mid=residual(row,incoming,o,b.fractions[3],b.mid,width(m))
    x=convert(normalize(data,b.norm2,mid,'norm2',layer),b.norm2.E,b.policies[5])
    up=linear(data,'up',layer,x,b.fractions[4]); gate=linear(data,'gate',layer,x,b.fractions[5]) if m.shape.family else up
    activated=tuple(activation(b.activation,t) for t in gate)
    product=tuple(a*b for a,b in zip(up,activated)) if m.shape.family else activated
    fraction=b.activation.E+(b.fractions[4] if m.shape.family else 0)
    down=linear(data,'down',layer,convert(product,fraction,b.policies[6],bool(m.shape.family)),b.fractions[-1])
    return residual(mid,b.mid,down,b.fractions[-1],b.out,width(m))


def finish(data,row):
    m=data.model; values=normalize(data,m.final_norm,row,'final')
    return linear(data,'head',-1,convert(values,m.final_norm.E,m.final_policy),m.logits_fraction)


@dataclass(frozen=True)
class Cache:
    scope: tuple[bytes,...]
    tokens: tuple[int,...]
    layers: tuple


@dataclass(frozen=True)
class Full:
    cuts: tuple
    logits: tuple
    cache: Cache


@dataclass(frozen=True)
class Step:
    cuts: tuple
    logits: tuple[int,...]


def tokens(data,sequence):
    if type(data) is not Data: raise ValueError('Model')
    if type(sequence) is not tuple or not 1<=len(sequence)<=data.model.shape.context: raise ValueError('Length')
    for token in sequence: integer(token,0,data.model.shape.vocabulary-1,'Token')


def full(data,sequence):
    tokens(data,sequence); rows=tuple(embed(data,t,p) for p,t in enumerate(sequence)); cuts=[rows]; layers=[]
    for layer in range(data.model.shape.layers):
        projected=tuple(project(data,layer,row,p) for p,row in enumerate(rows)); keys=tuple((x[1],x[2]) for x in projected)
        rows=tuple(finish_block(data,layer,row,p,x,keys) for p,(row,x) in enumerate(zip(rows,projected)))
        cuts.append(rows); layers.append(keys)
    logits=tuple(finish(data,row) for row in rows)
    return Full(tuple(cuts),logits,Cache(data.scope,sequence,tuple(layers)))


def _cache(data,cache):
    if type(cache) is not Cache or cache.scope!=data.scope: raise ValueError('CacheScope')
    tokens(data,cache.tokens); s=data.model.shape
    if type(cache.layers) is not tuple or len(cache.layers)!=s.layers: raise ValueError('Cache')
    for b,layer in zip(data.model.blocks,cache.layers):
        if type(layer) is not tuple or len(layer)!=len(cache.tokens): raise ValueError('Cache')
        for pair in layer:
            if type(pair) is not tuple or len(pair)!=2: raise ValueError('Cache')
            for j,row in enumerate(pair):
                mode,scale=b.policies[j+2]
                if type(row) is not Row or type(row.codes) is not tuple or len(row.codes)!=s.groups*s.head_width or row.fraction!=b.fractions[j+1]: raise ValueError('Cache')
                integer(row.fraction,0,30,'Cache'); integer(row.scale,scale if mode else 0,scale if mode else 259,'Cache')
                bound=min(127,(65536+row.scale)//(2*row.scale)) if row.scale else 0
                for code in row.codes: integer(code,-bound,bound,'Cache')


def step(data,token,cache=None):
    if cache is not None: _cache(data,cache)
    sequence=(token,) if cache is None else cache.tokens+(token,); tokens(data,sequence); position=len(sequence)-1
    row=embed(data,token,position); cuts=[row]; layers=[]
    for layer in range(data.model.shape.layers):
        projected=project(data,layer,row,position)
        keys=(() if cache is None else cache.layers[layer])+((projected[1],projected[2]),)
        row=finish_block(data,layer,row,position,projected,keys); cuts.append(row); layers.append(keys)
    logits=finish(data,row)
    # Expose immutable new K/V state only after every layer and the head succeeds.
    return Step(tuple(cuts),logits),Cache(data.scope,sequence,tuple(layers))


def generate(data,boundary,prompt,seed):
    decoding.validate_seed(data.model,boundary,seed); tokens(data,prompt)
    if len(prompt)!=boundary.prompt_length: raise ValueError('Prefix')
    initial=full(data,prompt); cache=initial.cache; logits=initial.logits[-1]; reason=0
    for _ in range(boundary.maximum_new):
        decision=decoding.choose(data.model,boundary,prompt,cache.tokens,logits,seed)
        result,cache=step(data,decision.token,cache); logits=result.logits
        if decision.token in boundary.eos: reason=1; break
    p=request.Spec(data.model.shape.vocabulary,data.model.shape.context,int(data.model.decoding is not None))
    request.check_completion(p,boundary,prompt,cache.tokens,reason)
    return cache.tokens,reason,cache
