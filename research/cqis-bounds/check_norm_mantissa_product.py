# /// script
# requires-python = ">=3.12"
# dependencies = ["numpy==2.3.4", "blake3==1.0.11", "python-flint==0.9.0"]
# ///
"""Actual mantissa lower bounds, full divisor sources and complete MD products."""
import copy
from dataclasses import replace
import hashlib
import json
from math import gcd
import random
import sys
import numpy as np
import norm_mantissa_product as c

r=c.r


def rejects(reason,call):
    try: call()
    except ValueError as error: assert str(error)==reason,(reason,str(error))
    else: raise AssertionError('accepted '+reason)


def spec(count=1,f=0,en=1,ed=3,identity=1200,repetitions=1):
    return c.Spec(c.norm.Spec(count,f,30,14,en,ed),identity,101,97,103,repetitions)


def corpus():
    rng=random.Random(2694); digest=hashlib.sha256(); cells=0
    for case in range(10000):
        en,ed=rng.randrange(1,1<<32),rng.randrange(1,1<<32); common=gcd(en,ed)
        p=spec(1+case%16384,rng.randrange(31),en//common,ed//common,case,1+case%2); v=c.derive(p,4)
        m=rng.randrange(16384,65536); divisor=0 if case%17==0 else rng.randrange(v['cert']['D_max']+1); w=c.witness(p,m,divisor)
        answer=int(np.prod(np.array([m,divisor],dtype=object))); digits,z,_=c.lp.witness(v['product'],w)
        coeff=np.convolve(np.array(w['left'][0],dtype=np.int64),np.array(w['right'][0],dtype=np.int64))
        for j,value in enumerate(w['result']): assert (int(coeff[j]) if j<len(coeff) else 0)+w['carry'][j]==value+256*w['carry'][j+1]
        words=r.witness(v['mantissa'],[m-16384])[0]
        assert c.mantissa_value(words)==int(np.frombuffer(bytes(words),dtype='<u2')[0])+16384==m
        assert int.from_bytes(bytes(c.divisor_source(v,digits)),'little')==divisor
        assert c.source(v,digits,m)==digits and sum(x<<(8*j) for j,x in enumerate(z))==answer<=v['cert']['MD_max']
        digest.update(v['raw']+m.to_bytes(2,'little')+bytes(digits)+bytes(z)); cells+=len(digits)
    p=spec(16384,30,(1<<32)-1,(1<<32)-2,(1<<44)-1,2); v=c.derive(p,8)
    assert v['base']+(1<<18)==(1<<63)+(1<<62) and v['cert']['MD_max'].bit_length()==140 and v['layout']['s']==32
    c.witness(p,65535,v['cert']['D_max'])
    for bad in (replace(p,identity=1<<44),replace(p,repetitions=True),replace(p,mantissa=p.divisor),replace(p,output=p.divisor),
                replace(p,mantissa=v['base']),replace(p,schema=replace(p.schema,F=True))): rejects('Spec',lambda:c.derive(bad,4))
    rejects('Spec',lambda:c.derive(p,True))
    for m in (False,16383,65536): rejects('Mantissa',lambda:c.witness(p,m,0))
    for divisor in (False,-1,v['cert']['D_max']+1): rejects('Divisor',lambda:c.witness(p,16384,divisor))
    assert cells==305392 and digest.hexdigest()=='be8aa319006f98f8b825a2b886b32df0f4302d13192f9c5c93282ba6ff84ca47'
    print(json.dumps(dict(seed=2694,cases=10000,source_cells=cells,sha256=digest.hexdigest()),sort_keys=True),flush=True)


def account(p,out,d):
    v=c.derive(p,d); b=v['layout']['h']; g=v['layout']['g']; f=lambda m:3*m*(m-1)//2+2*m; dims=[2,b+2,g+3,g+3]
    assert out['account']==dict(identities=[((1<<m)+255,p.repetitions) for m in dims],
        lookup_reduction_numerator=sum(p.repetitions*(f(m)+f(8)+3*m) for m in dims),range_reduction_numerator=9*b+18*g+38,
        product_identity_numerator=v['layout']['k']-1,product_reduction_numerator=4*b,denominator=r.sc.P**d)
    prod=out['product']; src=prod['input']; draws=[out['mantissa']['draws'],src['draws'],src['word']['draws'],prod['output']['draws'],prod['carry']['draws'],prod['core']['draws']]
    assert out['draws']=={} and sum(x.get(r.zc.WEIGHT,0) for x in draws)==16+4*b+8*g
    assert sum(x.get(r.zc.tr.CHALLENGE,0) for x in draws)==17+6*b+8*g
    assert len(prod['core']['original_claims'])==len(prod['core']['public_claims'])==2


def affine():
    assert c.mantissa_value([0,0])==16384 and c.mantissa_value([255,191])==65535
    for words in ([r.sc.P-1,0],[0,r.sc.P-1],[False,0]):
        rejects('NoncanonicalField',lambda:c.mantissa_value(words))
    print('affine source refuses noncanonical output before one-field root encoding',flush=True)


def honest():
    digest=hashlib.sha256(); count=0
    cases=((1,0,1,3,16384,0),(1,0,1,3,65535,1),(1,0,1,3,16384,None),(16384,30,(1<<32)-1,(1<<32)-2,65535,None))
    for d in (4,8):
        for reps in (1,2):
            for length,f,en,ed,m,divisor in cases:
                p=spec(length,f,en,ed,1201+count,reps); v=c.derive(p,d); divisor=v['cert']['D_max'] if divisor is None else divisor
                proof,state=c.prove(p,m,divisor,d); out=c.verify(p,c.expected_roots(p,m,divisor,m*divisor),proof,d)
                assert out['state']==state; account(p,out,d)
                if length==16384: assert (m*divisor).bit_length()==140 and proof['product']['output']['words'][17]>0
                digest.update(state); count+=1; print('honest',count,d,reps,length,f,m,flush=True)
    assert count==16 and digest.hexdigest()=='b509898977efa6706180a20733d691f8f07a324f4787da7f470808c873b73eb5'
    print(json.dumps(dict(proofs=count,sha256=digest.hexdigest()),sort_keys=True),flush=True)


def controls():
    d=4; p=spec(identity=1220); v=c.derive(p,d); pairs=c.prepare(p,16384,0,d); proof,state=c.assemble(p,pairs,d); expected=c.expected_roots(p,16384,0,0)
    assert c.verify(p,expected,proof,d)['state']==state
    bad=copy.deepcopy(proof); bad['mantissa']['words'][0]+=1
    rejects('Mantissa:SourceCopy:ClaimMismatch',lambda:c.verify(p,expected,bad,d))
    for slot,reason in ((0,'Product:SourceJoin'),(1,'Divisor:CommitmentMismatch')):
        bad=copy.deepcopy(proof); bad['product']['input']['digits'][slot]+=1; rejects(reason,lambda:c.verify(p,expected,bad,d))
    for name in ('output','carry'):
        bad=copy.deepcopy(proof); bad['product'][name]['words'][0]+=1
        rejects('Product:'+name.title()+':CommitmentMismatch',lambda:c.verify(p,expected,bad,d))
    # The bare product accepts subminimum/changed M at D=0; the actual M join must not.
    for m in (16383,16385):
        w=c.lp.limbs.witness(v['product'].schema,(m,),(0,)); child=c.lp.prove(v['product'],w,d); ds,z,cs=c.lp.witness(v['product'],w)
        assert c.lp.verify(v['product'],c.lp.roots(v['product'],ds,z,cs)[:2],child[0],d)['state']==child[1]
        false,_=c.assemble(p,dict(pairs,product=child),d); rejects('Product:SourceJoin',lambda:c.verify(p,expected,false,d))
        target=list(expected); target[0]=r.root(p.mantissa,[m]); rejects('Mantissa:CommitmentMismatch',lambda:c.verify(p,target,false,d))
    # Wrapped offset slack satisfies every byte column except the terminal carry.
    child=r.assemble(v['mantissa'],[0,192],[0,192,255,255],[0,1],d)
    false,_=c.assemble(p,dict(pairs,mantissa=child),d)
    rejects('Mantissa:TerminalCarry:FinalEvaluationMismatch',lambda:c.verify(p,expected,false,d))
    high=[0]*15+[1]; target=list(expected); target[1]=r.root(p.divisor,high)
    assert v['layout']['layout']['planes']==4; rejects('Divisor:CommitmentMismatch',lambda:c.verify(p,target,proof,d))
    target=list(expected); target[0]=r.root(p.mantissa,[16384+r.sc.P]); rejects('Mantissa:CommitmentMismatch',lambda:c.verify(p,target,proof,d))
    w=c.witness(p,16384,0); children=c.lp.ranges(v['product'],w,d); words=list(c.lp.limbs.digits(r.sc.P,8,v['layout']['s']))
    children[1]=c.lp.cr.prove(v['layout']['output'],words,d); _,_,carry=c.lp.witness(v['product'],w)
    assert c.lp.target(v['product'],v['layout'],words,carry,r.sc.scalar(256,d),d)==r.sc.scalar(0,d)
    false,_=c.assemble(p,dict(pairs,product=c.lp.assemble(v['product'],children,d)),d)
    rejects('Product:Product:FinalEvaluationMismatch',lambda:c.verify(p,c.expected_roots(p,16384,0,r.sc.P),false,d))
    for mutate,reason in ((lambda q:q['mantissa']['words'].__setitem__(0,False),'Mantissa:NoncanonicalField'),
                          (lambda q:q['product']['input']['digits'].__setitem__(0,False),'Product:NoncanonicalField')):
        bad=copy.deepcopy(proof); mutate(bad); rejects(reason,lambda:c.verify(p,expected,bad,d))
    rejects('ProofShape',lambda:c.verify(p,expected,dict(proof,minimum=0),d)); rejects('Root',lambda:c.verify(p,[False]*3,proof,d))
    print('mantissa lower/upper/source bounds, zero-factor substitutions, full divisor root and MD alias controls passed',flush=True)


def middle():
    digest=hashlib.sha256(); count=0
    for d in (4,8):
        for reps in (1,2):
            p=spec(f=14,identity=1240+count,repetitions=reps); v=c.derive(p,d); divisor=v['cert']['D_max']
            assert v['layout']['layout']['planes']==8 and v['layout']['k']==8 and v['layout']['s']==16
            proof,state=c.prove(p,32768,divisor,d); roots=c.expected_roots(p,32768,divisor,32768*divisor); out=c.verify(p,roots,proof,d)
            assert out['state']==state; account(p,out,d); digest.update(state); count+=1
            high=list(divisor.to_bytes(16,'little')); high[15]=1; roots[1]=r.root(p.divisor,high)
            rejects('Divisor:CommitmentMismatch',lambda:c.verify(p,roots,proof,d)); print('middle',d,reps,flush=True)
    assert count==4 and digest.hexdigest()=='97529418aaddcb487717ddf01794a508ec941fb9794b6ae086a5c00940238547'
    print(json.dumps(dict(middle_proofs=count,sha256=digest.hexdigest()),sort_keys=True),flush=True)


def compose():
    import norm_divisor as div
    p=spec(identity=1223); dp=div.Spec(p.schema,1222,73,79,89,p.divisor,1); d=4
    source,state=div.prove(dp,1,-8,d); dr=div.expected_roots(dp,1,-8,65536,3); assert div.verify(dp,dr,source,d)['state']==state
    proof,state=c.prove(p,21845,3,d); roots=c.expected_roots(p,21845,3,65535); roots[1]=dr[3]
    assert c.verify(p,roots,proof,d)['state']==state
    false,_=c.prove(p,21845,4,d); roots=c.expected_roots(p,21845,4,87380); roots[1]=dr[3]
    rejects('Divisor:CommitmentMismatch',lambda:c.verify(p,roots,false,d))
    print('actual configured-divisor-to-mantissa-product source composition passed',flush=True)


if __name__=='__main__':
    modes={'--corpus':corpus,'--affine':affine,'--honest':honest,'--middle':middle,'--controls':controls,'--compose':compose}
    if sys.argv[1:]:
        assert all(mode in modes for mode in sys.argv[1:])
        for mode in sys.argv[1:]: modes[mode]()
    else:
        for test in modes.values(): test()
