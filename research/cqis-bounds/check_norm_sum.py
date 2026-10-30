# /// script
# requires-python = ">=3.12"
# dependencies = ["numpy==2.3.4", "blake3==1.0.11", "python-flint==0.9.0"]
# ///
"""Actual MD/R/A joins, unit factors and the complete closed norm sum."""
import copy
from dataclasses import replace
import hashlib
import json
from math import gcd
import random
import sys
import numpy as np
import norm_sum as c

r=c.r


def rejects(reason,call):
    try: call()
    except ValueError as error: assert str(error)==reason,(reason,str(error))
    else: raise AssertionError('accepted '+reason)


def spec(count=1,f=0,en=1,ed=3,identity=1300,repetitions=1):
    return c.Spec(c.norm.Spec(count,f,30,14,en,ed),identity,103,107,89,repetitions)


def corpus():
    rng=random.Random(2698); digest=hashlib.sha256(); cells=0; widths=set()
    for case in range(10000):
        en,ed=rng.randrange(1,1<<32),rng.randrange(1,1<<32); common=gcd(en,ed)
        p=spec(1+case%16384,rng.randrange(31),en//common,ed//common,case,1+case%2); v=c.derive(p,4)
        md=rng.randrange(v['cert']['MD_max']+1); rem=rng.randrange(v['remainder_max']+1); w=c.witness(p,md,rem)
        answer=int(np.sum(np.array([md,rem],dtype=object))); digits,z,carry=c.lp.witness(v['sum'],w)
        coeff=sum((np.convolve(np.array(x,dtype=np.int64),np.array(y,dtype=np.int64)) for x,y in zip(w['left'],w['right'])))
        for j,value in enumerate(w['result']): assert (int(coeff[j]) if j<len(coeff) else 0)+carry[j]==value+256*carry[j+1]
        assert c.source(v,digits)==digits
        for index,(value,size) in enumerate(((md,v['md_slots']),(rem,16))):
            assert int.from_bytes(bytes(c.source_view(v,digits,index,size)),'little')==value
        assert int.from_bytes(bytes(c.output_view(v,z)),'little')==answer
        digest.update(v['raw']+bytes(digits)+bytes(z)); cells+=len(digits); widths.add((v['layout']['h'],v['layout']['s'],v['md_slots'],v['a_slots']))
    p=spec(16384,30,(1<<32)-1,(1<<32)-2,(1<<44)-1,2);v=c.derive(p,8)
    assert v['base']+(1<<18)==(1<<63)+(1<<62) and v['cert']['MD_max'].bit_length()==140
    for bad in (replace(p,identity=1<<44),replace(p,repetitions=True),replace(p,product=p.remainder),replace(p,output=p.remainder),
                replace(p,product=v['base']),replace(p,schema=replace(p.schema,F=True))): rejects('Spec',lambda:c.derive(bad,4))
    rejects('Spec',lambda:c.derive(p,True))
    for x in (False,-1,v['cert']['MD_max']+1): rejects('Product',lambda:c.witness(p,x,0))
    for x in (False,-1,v['remainder_max']+1): rejects('Remainder',lambda:c.witness(p,0,x))
    assert cells==727680 and digest.hexdigest()=='366f19a64949544aa45574cc47b53dc3807e4b74bb0bafe072650fb069d9389f'
    print(json.dumps(dict(seed=2698,cases=10000,source_cells=cells,widths=sorted(widths),sha256=digest.hexdigest()),sort_keys=True),flush=True)


def account(p,out,d):
    v=c.derive(p,d);b=v['layout']['h'];g=v['layout']['g'];f=lambda m:3*m*(m-1)//2+2*m;dims=[b+3,g+3,g+3]
    assert out['account']==dict(identities=[((1<<m)+255,p.repetitions) for m in dims],
        lookup_reduction_numerator=sum(p.repetitions*(f(m)+f(8)+3*m) for m in dims),range_reduction_numerator=9*b+18*g+42,
        product_identity_numerator=v['layout']['k']-1,product_reduction_numerator=2+4*b,denominator=r.sc.P**d)
    prod=out['sum'];src=prod['input'];draws=[src['draws'],src['word']['draws'],prod['output']['draws'],prod['carry']['draws'],prod['core']['draws']]
    assert out['draws']=={} and sum(x.get(r.zc.WEIGHT,0) for x in draws)==18+4*b+8*g
    assert sum(x.get(r.zc.tr.CHALLENGE,0) for x in draws)==20+6*b+8*g
    assert len(prod['core']['original_claims'])==len(prod['core']['public_claims'])==2


def honest():
    digest=hashlib.sha256();count=0;widths=set()
    cases=((1,0,1,3,False),(1,0,1,3,True),(1,15,1,3,True),(16384,30,(1<<32)-1,(1<<32)-2,True))
    for d in (4,8):
        for reps in (1,2):
            for length,f,en,ed,maximum in cases:
                p=spec(length,f,en,ed,1301+count,reps);v=c.derive(p,d)
                md,rem=(v['cert']['MD_max'],v['cert']['D_max']-1) if maximum else (0,0)
                proof,state=c.prove(p,md,rem,d);out=c.verify(p,c.expected_roots(p,md,rem,md+rem),proof,d)
                assert out['state']==state;account(p,out,d);widths.add((v['layout']['h'],v['layout']['s'],v['md_slots'],v['a_slots']))
                if length==16384: assert (md+rem).bit_length()==140 and proof['sum']['output']['words'][17]>0
                digest.update(state);count+=1;print('honest',count,d,reps,length,f,maximum,flush=True)
    assert {x[0] for x in widths}=={3,4,5} and {x[1] for x in widths}=={8,16,32}
    print(json.dumps(dict(proofs=count,widths=sorted(widths),sha256=digest.hexdigest()),sort_keys=True),flush=True)


def controls():
    d=4;p=spec(identity=1320);v=c.derive(p,d);child=c.prepare(p,0,0,d);proof,state=c.assemble(p,child,d);expected=c.expected_roots(p,0,0,0)
    assert c.verify(p,expected,proof,d)['state']==state
    for slot,reason in ((0,'Product:CommitmentMismatch'),(1,'Remainder:CommitmentMismatch'),(2,'Sum:SourceJoin')):
        bad=copy.deepcopy(proof);bad['sum']['input']['digits'][slot]+=1;rejects(reason,lambda:c.verify(p,expected,bad,d))
    for side in (0,1):
        values=[0,0];values[side]=1;changed,_=c.prove(p,*values,d)
        target=c.expected_roots(p,*values,1);target[side]=expected[side]
        rejects(('Product' if side==0 else 'Remainder')+':CommitmentMismatch',lambda:c.verify(p,target,changed,d))
    # Bare sum-of-products accepts dropped unit factors; the actual role join must reject.
    w=c.lp.limbs.witness(v['sum'].schema,(3,2),(0,1));pair=c.lp.prove(v['sum'],w,d);digits,z,carry=c.lp.witness(v['sum'],w)
    assert c.lp.verify(v['sum'],c.lp.roots(v['sum'],digits,z,carry)[:2],pair[0],d)['state']==pair[1]
    false,_=c.assemble(p,pair,d);rejects('Sum:SourceJoin',lambda:c.verify(p,c.expected_roots(p,3,2,2),false,d))
    for index,size,reason in ((1,16,'Remainder'),(2,v['a_slots'],'Scaled')):
        target=list(expected);target[index]=r.root((p.remainder,p.output)[index-1],[0]*(size-1)+[1])
        rejects(reason+':CommitmentMismatch',lambda:c.verify(p,target,proof,d))
    w=c.witness(p,0,0);children=c.lp.ranges(v['sum'],w,d);words=list(c.lp.limbs.digits(r.sc.P,8,v['layout']['s']))
    children[1]=c.lp.cr.prove(v['layout']['output'],words,d);_,_,carry=c.lp.witness(v['sum'],w)
    assert c.lp.target(v['sum'],v['layout'],words,carry,r.sc.scalar(256,d),d)==r.sc.scalar(0,d)
    false,_=c.assemble(p,c.lp.assemble(v['sum'],children,d),d)
    rejects('Sum:Product:RoundSumMismatch',lambda:c.verify(p,c.expected_roots(p,0,0,r.sc.P),false,d))
    bad=copy.deepcopy(proof);bad['sum']['input']['digits'][0]=False;rejects('Product:NoncanonicalField',lambda:c.verify(p,expected,bad,d))
    bad=copy.deepcopy(proof);bad['sum']['output']['words'].append(0);rejects('Scaled:OpeningShape',lambda:c.verify(p,expected,bad,d))
    rejects('ProofShape',lambda:c.verify(p,expected,dict(proof,strict=True),d));rejects('Root',lambda:c.verify(p,[False]*3,proof,d))
    # Equality deliberately cannot establish strictness: R=D is valid here.
    divisor=v['cert']['P'];equal,state=c.prove(p,0,divisor,d);assert c.verify(p,c.expected_roots(p,0,divisor,divisor),equal,d)['state']==state
    print('sum source/unit/high-slot/alias controls passed; R=D remains an explicit separate obligation',flush=True)


def padding():
    digest=hashlib.sha256();count=0;widths=set();d=4
    cases=((1,10,1,3),(1,11,1,3),(1,21,(1<<32)-1,(1<<32)-2),
           (1,27,1,(1<<32)-1),(1,27,(1<<32)-1,(1<<32)-2),
           (1,28,1,(1<<32)-1),(1,28,(1<<32)-1,(1<<32)-2),(16384,30,(1<<32)-1,(1<<32)-2))
    for length,f,en,ed in cases:
        p=spec(length,f,en,ed,1340+count);v=c.derive(p,d);md,rem=v['cert']['MD_max'],v['cert']['D_max']-1
        proof,state=c.prove(p,md,rem,d);roots=c.expected_roots(p,md,rem,md+rem);out=c.verify(p,roots,proof,d)
        assert out['state']==state;account(p,out,d);widths.add((v['layout']['h'],v['layout']['s'],v['md_slots'],v['a_slots']))
        if v['md_slots']>v['layout']['layout']['planes']:
            high=list(c.lp.limbs.digits(md,8,v['md_slots']));high[-1]=1;target=list(roots);target[0]=r.root(p.product,high)
            rejects('Product:CommitmentMismatch',lambda:c.verify(p,target,proof,d))
        if v['layout']['s']>v['a_slots']:
            bad=copy.deepcopy(proof);bad['sum']['output']['words'][v['a_slots']]=1
            rejects('Scaled:SourcePadding',lambda:c.verify(p,roots,bad,d))
        if v['layout']['layout']['planes']>16:
            bad=copy.deepcopy(proof);bad['sum']['input']['digits'][4*16+1]=1
            rejects('Remainder:SourcePadding',lambda:c.verify(p,roots,bad,d))
        digest.update(state);count+=1;print('padding',count,length,f,en,ed,flush=True)
    assert count==8 and digest.hexdigest()=='ec01b18abd84f118573b253429bd305b1e6eb25b002abaae9b4a1b8537dbdce8'
    print(json.dumps(dict(padding_proofs=count,widths=sorted(widths),sha256=digest.hexdigest()),sort_keys=True),flush=True)


def compose():
    import norm_divisor as div
    import norm_mantissa_product as mp
    d=4;p=spec(identity=1323);dp=div.Spec(p.schema,1321,73,79,p.output,97,1);pp=mp.Spec(p.schema,1322,101,dp.output,p.product,1)
    upstream,state=div.prove(dp,1,-8,d);dr=div.expected_roots(dp,1,-8,65536,3);assert div.verify(dp,dr,upstream,d)['state']==state
    product,state=mp.prove(pp,21845,3,d);pr=mp.expected_roots(pp,21845,3,65535);pr[1]=dr[3];assert mp.verify(pp,pr,product,d)['state']==state
    proof,state=c.prove(p,65535,1,d);roots=c.expected_roots(p,65535,1,65536);roots[0]=pr[2];roots[2]=dr[2]
    assert c.verify(p,roots,proof,d)['state']==state
    false,_=c.prove(p,65534,2,d);roots[1]=r.root(p.remainder,[2]+[0]*15)
    rejects('Product:CommitmentMismatch',lambda:c.verify(p,roots,false,d))
    print('actual paired scaled A and MD proof roots compose with the decomposition; same-sum substitution rejects',flush=True)


if __name__=='__main__':
    modes={'--corpus':corpus,'--honest':honest,'--padding':padding,'--controls':controls,'--compose':compose}
    if sys.argv[1:]:
        assert all(mode in modes for mode in sys.argv[1:])
        for mode in sys.argv[1:]:modes[mode]()
    else:
        for test in modes.values():test()
