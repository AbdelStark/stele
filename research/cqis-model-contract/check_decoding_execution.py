"""Draft RFC-0025: Model/request/seed/actual-exp decoding composition evidence."""
from dataclasses import replace
from fractions import Fraction as Q
from hashlib import sha256
import json
from random import Random
from struct import pack

from blake3 import blake3
from flint import arb, ctx

from check_arithmetic_bounds import rejects
from check_decoding import oracle as selection_oracle, rounding
from check_model_codec import make, selection
from function_bounds import Exponential
from model_codec import Sampled
from request_bounds import Request
from source_map import Shape
import decoding_execution as c


def seed_hash(seed): return blake3(b'stele/v0.1/cqis/sample-seed'+seed).digest()


def draw(seed, position):
    raw=blake3(b'stele/v0.1/cqis/sample-draw'+seed+pack('<I',position)).digest()
    return int.from_bytes(raw,'little')%(2**32)


def policy_oracle(m,r):
    d=b'\0' if m.decoding is None else b'\1'+pack('<4I',m.decoding.tn,m.decoding.td,m.decoding.pn,m.decoding.pd)+selection(m.decoding.exp)
    boundary=b'stele/v0.1/cqis/request-boundary'+bytes((int(m.decoding is not None),))+pack('<III',r.prompt_length,r.maximum_new,len(r.eos))
    boundary+=b''.join(pack('<I',x) for x in r.eos)+(r.seed_commitment or b'')
    return pack('<I',len(d))+d+pack('<I',len(boundary))+boundary


def exp_oracle(p,t):
    with ctx.workprec(256):
        def nearest(i):
            n=(((-arb(i)/2**p.F).exp()*2**p.E)+arb(1)/2).floor().unique_fmpz()
            assert n is not None,'OraclePrecision'
            return int(n)
        if p.mode!=1: return nearest(-t)
        hi,lo=divmod(-t,2**p.k)
        return nearest(hi*2**p.k)*nearest(lo)//2**p.E


def oracle(m,r,prefix,logits,seed):
    if m.decoding is None:
        token=min(i for i,x in enumerate(logits) if x==max(logits))
        return c.Decision(len(prefix),token,(),(),(),(),None)
    d=m.decoding; e=d.exp
    z=tuple(rounding(Q(x-max(logits),2**m.logits_fraction)*Q(d.td,d.tn)*2**e.F) for x in logits)
    if min(z)<-2**e.bits: raise ValueError('ExpDomain')
    weights=tuple(exp_oracle(e,t) for t in z); u=draw(seed,len(prefix))
    token,order,cdf=selection_oracle(list(weights),d.pn,d.pd,u)
    return c.Decision(len(prefix),token,z,weights,order,cdf,u)


def fixture(rng,family,mode,v=None,n=None):
    v=v or rng.randint(1,16); n=n or rng.randint(2,64)
    shape=Shape(family,rng.randint(1,3),2,1,1,2,8 if not family else rng.randint(1,8),v,n)
    m=make(rng,family,shape); seed=None; decoding=None
    if mode>=0:
        bits=rng.randint(7,31 if mode==1 else 15); k=rng.randint(max(1,bits-15),min(bits,16)) if mode else 0
        tn,td=rng.randint(1,31),rng.randint(1,31); t=Q(tn,td)
        pp=Q(rng.randint(1,31),31)
        e=Exponential(v,bits,rng.randrange(31),rng.randrange(15),mode,k)
        decoding=Sampled(t.numerator,t.denominator,pp.numerator,pp.denominator,e); seed=rng.randbytes(32)
    blocks=m.blocks if decoding is None else tuple(replace(b,exp=replace(decoding.exp,n=n)) for b in m.blocks)
    m=replace(m,blocks=blocks,decoding=decoding,logits_fraction=rng.randrange(31))
    q=rng.randint(1,n-1); a=rng.randint(1,n-q); g=rng.randrange(a) if v>1 else 0
    eos=(v-1,); prompt=tuple(rng.randrange(v) for _ in range(q)); prefix=prompt+tuple(rng.randrange(v-1) for _ in range(g))
    r=Request(q,a,eos,None if seed is None else seed_hash(seed))
    return m,r,prompt,prefix,tuple(rng.randrange(-32768,32768) for _ in range(v)),seed


def boundaries():
    rng=Random(26910); m,r,p,prefix,logits,seed=fixture(rng,0,2,4,8)
    e=Exponential(4,7,0,4,2,4); m=replace(m,decoding=Sampled(1,1,1,1,e),logits_fraction=0)
    p=(3,); prefix=p+(1,); r=Request(1,7,(3,),seed_hash(seed)); logits=(0,0,-128,-1)
    expected=oracle(m,r,prefix,logits,seed); assert c.choose(m,r,p,prefix,logits,seed)==expected
    assert expected.draw==draw(seed,2) and expected.draw!=draw(seed,0)
    raw=c.policy(m,r); assert raw==policy_oracle(m,r); c.verify_policy(m,r,raw)
    for i in (0,4,len(raw)//2,len(raw)-1):
        changed=raw[:i]+bytes((raw[i]^1,))+raw[i+1:]; rejects(lambda:c.verify_policy(m,r,changed),'Policy')
    for changed in (raw[:-1],raw+b'\0'): rejects(lambda:c.verify_policy(m,r,changed),'Policy')
    rejects(lambda:c.verify_policy(m,r,bytearray(raw)),'Capacity')
    rejects(lambda:c.verify_policy(m,r,bytes(c.LIMIT+1)),'Capacity')
    rejects(lambda:c.verify_policy(replace(m,decoding=replace(m.decoding,tn=2)),r,raw),'Policy')
    rejects(lambda:c.verify_policy(m,replace(r,maximum_new=6),raw),'Policy')
    badseed=bytes((seed[0]^1,))+seed[1:]
    rejects(lambda:c.choose(m,r,p,prefix,logits,badseed),'SeedBinding')
    rejects(lambda:c.choose(m,r,p,prefix,logits,None),'Seed')
    rejects(lambda:c.choose(m,r,p,(2,1),logits,seed),'Prefix')
    rejects(lambda:c.choose(m,r,p,p+(3,),logits,seed),'Stopped')
    rejects(lambda:c.choose(m,r,p,p+(0,)*7,logits,seed),'Position')
    rejects(lambda:c.choose(m,r,p,prefix,logits[:-1],seed),'Logits')
    rejects(lambda:c.choose(m,r,p,prefix,(True,0,0,0),seed),'Input')
    rejects(lambda:c.choose(m,r,p,prefix,(0,-129,0,0),seed),'ExpDomain')
    zero=replace(r,maximum_new=0); c.validate_seed(m,zero,seed)
    rejects(lambda:c.validate_seed(m,zero,badseed),'SeedBinding')
    rejects(lambda:c.choose(m,zero,p,p,logits,seed),'Position')
    greedy=replace(m,decoding=None); gr=replace(r,seed_commitment=None)
    assert c.choose(greedy,gr,p,prefix,logits,None).token==0
    rejects(lambda:c.choose(greedy,gr,p,prefix,logits,seed),'Seed')
    # Direct and corrected nearest are equal; product preserves its own rounding.
    differences=0
    for t in range(-128,1):
        values=[c.exponential(Exponential(1,7,4,4,mode,4 if mode else 0),t) for mode in range(3)]
        assert values==[exp_oracle(Exponential(1,7,4,4,mode,4 if mode else 0),t) for mode in range(3)]
        assert values[0]==values[2]; differences+=values[0]!=values[1]
    assert differences>0
    # Full domain endpoint and strict type checks precede point computation/cache lookup.
    endpoint=Exponential(1,31,30,14,1,16)
    assert c.exponential(endpoint,-2**31)==exp_oracle(endpoint,-2**31)
    rejects(lambda:c.exponential(endpoint,-2**31-1),'ExpDomain')
    rejects(lambda:c.exponential(endpoint,True),'ExpDomain')
    return dict(product_nearest_differences=differences,mode_controls=3,zero_limit_seed_checked=True)


def full_domains():
    rng=Random(26911); v=2**20
    m,r,p,prefix,_,seed=fixture(rng,1,1,v,2)
    m=replace(m,decoding=Sampled(1,1,1,1,Exponential(v,31,30,14,1,16)))
    p=(v-1,); r=Request(1,1,(v-1,),seed_hash(seed)); logits=(0,)*v
    result=c.choose(m,r,p,p,logits,seed); u=draw(seed,1)
    assert result.token==u//4096 and result.arguments==(0,)*v and result.weights==(16384,)*v
    assert result.order==tuple(range(v)) and result.cdf==tuple((i+1)*4096 for i in range(v))
    # Full EOS public-policy bytes and last legal absolute position use complete domains.
    all_eos=replace(r,eos=tuple(range(v))); policy=c.policy(m,all_eos); assert policy==policy_oracle(m,all_eos)
    n=2**20; gm,_,_,_,_,_=fixture(rng,0,-1,1,n); p=(0,)*(n-1); gr=Request(n-1,1,(0,),None)
    last=c.choose(gm,gr,p,p,(7,),None); assert last.position==n-1 and last.token==0
    return dict(vocabulary=v,policy_bytes=len(policy),last_position=last.position,uniform_token=result.token)


def main():
    rng=Random(2691); digest=sha256(); counts={str(mode):dict(accept=0,reject=0) for mode in range(-1,3)}
    for i in range(10000):
        mode=i%4-1; m,r,p,prefix,logits,seed=fixture(rng,(i//4)%2,mode)
        raw=c.policy(m,r); assert raw==policy_oracle(m,r); c.verify_policy(m,r,raw); c.validate_seed(m,r,seed)
        try: expected=oracle(m,r,prefix,logits,seed)
        except ValueError as error:
            assert str(error)=='ExpDomain'; rejects(lambda:c.choose(m,r,p,prefix,logits,seed),'ExpDomain'); counts[str(mode)]['reject']+=1; outcome='ExpDomain'
        else:
            actual=c.choose(m,r,p,prefix,logits,seed); assert actual==expected; counts[str(mode)]['accept']+=1
            outcome=[actual.position,actual.token,actual.arguments,actual.weights,actual.order,actual.cdf,actual.draw]
        digest.update(pack('<I',len(raw))+raw+json.dumps([prefix,logits,outcome],separators=(',',':')).encode())
        if (i+1)%2000==0: print(json.dumps(dict(completed=i+1)),flush=True)
    print(json.dumps(dict(seed=2691,configurations=10000,modes=counts,corpus_sha256=digest.hexdigest(),boundaries=boundaries(),full_domains=full_domains()),sort_keys=True))


if __name__=='__main__': main()
