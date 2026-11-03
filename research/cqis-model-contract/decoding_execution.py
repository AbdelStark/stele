"""Draft RFC-0025 §§2.6/2.7: numerical decoding composition, no proof admission."""
from dataclasses import dataclass
from fractions import Fraction
from functools import lru_cache
from struct import pack

from blake3 import blake3

import decoding
from function_bounds import Exponential
from model_codec import encode as encode_model
from numerics import integer
import request_bounds as request
from certified_exp import certify

LIMIT=(1<<20)+45+4*(1<<20)+32+8


def policy(model,boundary):
    encode_model(model)
    p=request.Spec(model.shape.vocabulary,model.shape.context,int(model.decoding is not None))
    raw=request.encode_request(p,boundary)
    d=b'\0' if model.decoding is None else model.decoding.encode(p.v)
    return pack('<I',len(d))+d+pack('<I',len(raw))+raw


def verify_policy(model,boundary,raw):
    if type(raw) is not bytes or len(raw)>LIMIT: raise ValueError('Capacity')
    if raw!=policy(model,boundary): raise ValueError('Policy')


def validate_seed(model,boundary,seed):
    policy(model,boundary)
    if model.decoding is None:
        if seed is not None: raise ValueError('Seed')
    else:
        if type(seed) is not bytes or len(seed)!=32: raise ValueError('Seed')
        if blake3(b'stele/v0.1/cqis/sample-seed'+seed).digest()!=boundary.seed_commitment:
            raise ValueError('SeedBinding')


@lru_cache(maxsize=65536,typed=True)
def _point(p,t):
    def nearest(i): return certify(Fraction(i,1<<p.F),p.E)['value']
    if p.mode==0: return nearest(-t)
    high,low=divmod(-t,1<<p.k)
    product=nearest(high*(1<<p.k))*nearest(low)//(1<<p.E)
    if p.mode==1: return product
    correction=nearest(-t)-product
    integer(correction,-1,2,'Correction')
    return product+correction


def exponential(p,t):
    if type(p) is not Exponential: raise ValueError('Function')
    integer(t,-(1<<p.bits),0,'ExpDomain')
    # Only definition-derived points enter the cache; this does not admit Registry data.
    return _point(p,t)


@dataclass(frozen=True)
class Decision:
    position: int
    token: int
    arguments: tuple[int,...]
    weights: tuple[int,...]
    order: tuple[int,...]
    cdf: tuple[int,...]
    draw: int | None


def choose(model,boundary,prompt,prefix,logits,seed):
    validate_seed(model,boundary,seed)
    if type(prompt) is not tuple or len(prompt)!=boundary.prompt_length or type(prefix) is not tuple:
        raise ValueError('Prefix')
    if not len(prompt)<=len(prefix)<len(prompt)+boundary.maximum_new: raise ValueError('Position')
    for token in prefix:
        integer(token,0,model.shape.vocabulary-1,'Token')
    for token in prompt:
        integer(token,0,model.shape.vocabulary-1,'Token')
    if prefix[:len(prompt)]!=prompt: raise ValueError('Prefix')
    terminal=frozenset(boundary.eos)
    if any(t in terminal for t in prefix[len(prompt):]): raise ValueError('Stopped')
    if type(logits) is not tuple or len(logits)!=model.shape.vocabulary: raise ValueError('Logits')
    for value in logits: integer(value,-32768,32767,'Input')
    if model.decoding is None:
        token=logits.index(max(logits))
        return Decision(len(prefix),token,(),(),(),(),None)
    d=model.decoding; e=d.exp
    arguments=decoding.temperature(list(logits),model.logits_fraction,d.tn,d.td,e.F,e.bits)
    weights=[exponential(e,t) for t in arguments]
    raw=blake3(b'stele/v0.1/cqis/sample-draw'+seed+pack('<I',len(prefix))).digest()
    draw=int.from_bytes(raw[:4],'little')
    token,order,cdf=decoding.select(weights,d.pn,d.pd,draw)
    return Decision(len(prefix),token,tuple(arguments),tuple(weights),order,cdf,draw)
