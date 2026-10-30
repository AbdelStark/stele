# /// script
# requires-python = ">=3.12"
# dependencies = ["numpy==2.3.4", "blake3==1.0.11", "python-flint==0.9.0"]
# ///
"""Configured divisor bytes, the same actual exponent, and public final controls."""
import copy
from dataclasses import replace
import hashlib
import json
from math import gcd
import random
import sys
import numpy as np
import norm_divisor as c

r=c.r


def rejects(reason,call):
    try: call()
    except ValueError as error: assert str(error)==reason,(reason,str(error))
    else: raise AssertionError('accepted '+reason)


def spec(count=1,f=0,en=1,ed=3,identity=1150,repetitions=1):
    return c.Spec(c.norm.Spec(count,f,30,14,en,ed),identity,73,79,89,97,repetitions)


def corpus():
    rng=random.Random(2690); digest=hashlib.sha256()
    for a in range(-23,10):
        p=spec(); grid=c.public_grid(p.schema); words=c.witness(p,a)
        assert words==[grid[j*64+a+23] for j in range(16)]
        assert int.from_bytes(bytes(words),'little')==3*4**max(a,0)
    for case in range(10000):
        en,ed=rng.randrange(1,1<<32),rng.randrange(1,1<<32); common=gcd(en,ed)
        p=spec(1+case%16384,rng.randrange(31),en//common,ed//common,case,1+case%2); a=rng.randrange(-23,10); v=c.derive(p,4)
        answer=int(np.prod(np.array([p.schema.ed,p.schema.d,1<<(2*p.schema.F),4**max(a,0)],dtype=object)))
        words=c.witness(p,a); grid=c.public_grid(p.schema)
        assert int.from_bytes(bytes(words),'little')==answer and 0<answer<=v['cert']['D_max']
        assert words==[grid[j*64+a+23] for j in range(16)] and all(grid[j*64+i]==0 for j in range(16) for i in range(33,64))
        digest.update(v['raw']+bytes(words)+bytes(grid))
    p=spec(16384,30,(1<<32)-1,(1<<32)-2,(1<<38)-1,2); v=c.derive(p,8)
    assert v['base']+(1<<24)==(1<<63)+(1<<62) and int.from_bytes(bytes(c.witness(p,9)),'little').bit_length()==124
    for bad in (replace(p,identity=1<<38),replace(p,repetitions=True),replace(p,scaled=p.source),replace(p,output=p.exponent),
                replace(p,source=v['base']),replace(p,schema=replace(p.schema,d=0)),replace(p,schema=replace(p.schema,en=2,ed=2))): rejects('Spec',lambda:c.derive(bad,4))
    for a in (-24,10,False): rejects('Exponent',lambda:c.witness(p,a))
    rejects('Spec',lambda:c.derive(p,True))
    assert digest.hexdigest()=='04185115f4347a30084ce0cee2e441d557b54336bbc52cd5ca28d342b16ea4ac'
    print(json.dumps(dict(seed=2690,cases=10000,exponents=33,sha256=digest.hexdigest()),sort_keys=True),flush=True)


def public(d):
    rng=random.Random(2691+d); digest=hashlib.sha256()
    def basis(point,index):
        value=r.sc.scalar(1,d)
        for bit,x in enumerate(reversed(point)): value=r.sc.mul(value,x if index>>bit&1 else r.sc.add(r.sc.scalar(1,d),r.sc.neg(x)))
        return value
    for case in range(10000):
        p=spec(1+case%16384,rng.randrange(31),1,rng.randrange(1,1<<32),case); grid=c.public_grid(p.schema)
        point=[tuple(rng.randrange(r.sc.P) for _ in range(d)) for _ in range(10)]
        if case%31<2: point=[r.sc.scalar(case%31,d)]*10
        elif case%31==2: point=[r.sc.scalar(rng.randrange(2),d) for _ in range(10)]
        elif case%31==3: point=[r.sc.scalar(-1,d)]*10
        iw=[basis(point[4:],i) for i in range(33)]; jw=[basis(point[:4],j) for j in range(16)]; answer=r.sc.scalar(0,d)
        for i in range(33):
            value=p.schema.ed*p.schema.d*4**(p.schema.F+max(i-23,0)); row=list(value.to_bytes(16,'little'))
            term=tuple(sum(byte*w[k] for byte,w in zip(row,jw))%r.sc.P for k in range(d)); answer=r.sc.add(answer,r.sc.mul(term,iw[i]))
        assert r.zc.folded([r.sc.scalar(x,d) for x in grid],point)==answer
        digest.update(r.sc.encode(answer))
        if case%1000==999: print('public',d,case+1,flush=True)
    print(json.dumps(dict(field=d,public_points=10000,sha256=digest.hexdigest()),sort_keys=True),flush=True)


def account(p,out,d):
    v=c.derive(p,d); sv=c.s.derive(v['scaled'],d); b=sv['layout']['h']; g=sv['layout']['g']; f=lambda m:3*m*(m-1)//2+2*m
    dims=[7,b+2,g+3,g+3]
    assert out['account']==dict(identities=[((1<<m)+255,p.repetitions) for m in dims],
        lookup_reduction_numerator=sum(p.repetitions*(f(m)+f(8)+3*m) for m in dims),range_reduction_numerator=163+9*b+18*g,
        selection_reduction_numerator=6,product_identity_numerator=sv['layout']['k']-1,product_reduction_numerator=4*b,denominator=r.sc.P**d)
    assert out['draws']=={r.zc.WEIGHT:10,r.zc.tr.CHALLENGE:10} and len(out['claims'])==3 and sum(x['numerator'] for x in out['sc'])==30
    lower=out['scaled']; ex=lower['exponent']; prod=lower['product']; src=prod['input']
    draws=[out['draws'],ex['draws'],ex['indicator']['draws'],src['draws'],src['word']['draws'],prod['output']['draws'],prod['carry']['draws'],prod['core']['draws']]
    assert lower['draws']=={} and sum(x.get(r.zc.WEIGHT,0) for x in draws)==63+4*b+8*g
    assert sum(x.get(r.zc.tr.CHALLENGE,0) for x in draws)==70+6*b+8*g


def honest():
    digest=hashlib.sha256(); count=0
    cases=((1,0,1,3,-23,0),(1,0,1,3,0,1),(16384,30,(1<<32)-1,(1<<32)-2,-1,None),(16384,30,(1<<32)-1,(1<<32)-2,9,1))
    for d in (4,8):
        for reps in (1,2):
            for length,f,en,ed,a,n in cases:
                p=spec(length,f,en,ed,1151+count,reps); v=c.derive(p,d); n=v['cert']['N_max'] if n is None else n
                answer=ed*length*4**(f+max(a,0)); proof,state=c.prove(p,n,a,d)
                out=c.verify(p,c.expected_roots(p,n,a,n*4**max(-a,0),answer),proof,d); assert out['state']==state; account(p,out,d)
                if length==16384 and a==9: assert answer.bit_length()==124 and proof['divisor'][15]>0
                digest.update(state); count+=1; print('honest',count,d,reps,length,f,a,flush=True)
    print(json.dumps(dict(proofs=count,sha256=digest.hexdigest()),sort_keys=True),flush=True)


def controls():
    d=4; p=spec(identity=1180); v=c.derive(p,d); pair,words=c.prepare(p,0,-1,d); proof,state=c.assemble(p,pair,words,d); expected=c.roots(p,proof)
    assert c.verify(p,expected,proof,d)['state']==state
    for j in range(16):
        bad=copy.deepcopy(proof); bad['divisor'][j]+=1; rejects('Divisor:CommitmentMismatch',lambda:c.verify(p,expected,bad,d))
    bad=copy.deepcopy(proof); bad['scaled']['exponent']['indicator']['words'][22]=0
    rejects('Scaled:Exponent:Indicator:CommitmentMismatch',lambda:c.verify(p,expected,bad,d))
    bad=copy.deepcopy(proof); bad['scaled']['product']['input']['digits'][0]+=1
    rejects('Scaled:Numerator:CommitmentMismatch',lambda:c.verify(p,expected,bad,d))
    for j in (1,2):
        if j==1: bad=copy.deepcopy(proof)
        bad['zero']['final'][j][0]=r.sc.add(bad['zero']['final'][j][0],r.sc.scalar(1,d))
    rejects('Divisor:ClaimMismatch',lambda:c.verify(p,expected,bad,d))
    for wrong in (0,4,3+r.sc.P,3+(1<<120)):
        false,_=c.assemble(p,pair,list(wrong.to_bytes(16,'little')),d)
        rejects('Divisor:RoundSumMismatch',lambda:c.verify(p,c.roots(p,false),false,d))
    # One altered public cell makes all Boolean equations true for the wrong D.
    false,_=c.assemble(p,pair,[4]+[0]*15,d); i,tables=c.parts(p,false,d); tables[2][22]=r.sc.scalar(4,d)
    t=c.transcript(v,c.roots(p,false),pair[1],d); false['zero']=r.zero_prove(t,i,tables)
    rejects('Divisor:ClaimMismatch',lambda:c.verify(p,c.roots(p,false),false,d))
    other=c.s.prove(v['scaled'],0,-2,d); false,_=c.assemble(p,other,words,d)
    assert c.s.verify(v['scaled'],c.roots(p,false)[:3],other[0],d)['state']==other[1]
    assert c.roots(p,false)[0]==expected[0] and c.roots(p,false)[2:]==expected[2:]
    rejects('Scaled:Exponent:Offset:CommitmentMismatch',lambda:c.verify(p,expected,false,d))
    for mutate,reason in ((lambda q:q['divisor'].__setitem__(0,False),'NoncanonicalField'),(lambda q:q['divisor'].__setitem__(0,r.sc.P),'NoncanonicalField'),
                          (lambda q:q['divisor'].pop(),'OpeningShape'),(lambda q:q['zero']['final'].pop(),'ProofShape'),
                          (lambda q:q['zero']['final'][2].__setitem__(0,(False,0,0,0)),'Divisor:NoncanonicalField')):
        bad=copy.deepcopy(proof); mutate(bad); rejects(reason,lambda:c.verify(p,expected,bad,d))
    for key in ('grid','P'): rejects('ProofShape',lambda:c.verify(p,expected,dict(proof,**{key:0}),d))
    rejects('Root',lambda:c.verify(p,[False]*4,proof,d))
    rejects('Scaled:Exponent:Exponent:RoundSumMismatch',lambda:c.verify(replace(p,schema=replace(p.schema,G=29)),expected,proof,d))
    print('divisor source/public/alias controls and same-result negative-exponent substitution passed',flush=True)


def compose():
    import norm_numerator as num
    p=spec(identity=1183); np=num.Spec(p.schema,1182,67,p.source,1); d=4
    source,state=num.prove(np,0,d); nr=num.expected_roots(np,0,1); assert num.verify(np,nr,source,d)['state']==state
    proof,state=c.prove(p,1,-8,d); roots=c.expected_roots(p,1,-8,65536,3); roots[0]=nr[1]
    assert c.verify(p,roots,proof,d)['state']==state
    false,_=c.prove(p,2,-8,d); roots=c.expected_roots(p,2,-8,131072,3); roots[0]=nr[1]
    rejects('Scaled:Numerator:CommitmentMismatch',lambda:c.verify(p,roots,false,d))
    print('actual numerator-to-paired scaled/divisor source composition passed',flush=True)


if __name__=='__main__':
    modes={'--corpus':corpus,'--public4':lambda:public(4),'--public8':lambda:public(8),'--honest':honest,'--controls':controls,'--compose':compose}
    if sys.argv[1:]:
        assert all(mode in modes for mode in sys.argv[1:])
        for mode in sys.argv[1:]: modes[mode]()
    else:
        for test in modes.values(): test()
