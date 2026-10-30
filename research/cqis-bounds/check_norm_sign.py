# /// script
# requires-python = ">=3.12"
# dependencies = ["numpy==2.3.4", "blake3==1.0.11", "python-flint==0.9.0"]
# ///
"""RFC-0022 norm sign: exact zero predicates, same-source signs and padding."""
import copy
from dataclasses import replace
import hashlib
import json
from math import gcd
import random
import sys
import numpy as np
import norm_sign as c

r=c.r


def rejects(reason,call):
    try:call()
    except ValueError as error:assert str(error)==reason,(reason,str(error))
    else:raise AssertionError('accepted '+reason)


def spec(count=5,identity=2000,repetitions=1):
    return c.Spec(c.norm.Spec(count,30,30,14,1,3),identity,197,199,211,223,repetitions)


def signs(xs,ys):
    return [int(bool(x and y) and (x<0)!=(y<0)) for x,y in zip(xs,ys)]


def expected(p,xs,ys,ss=None):
    return c.expected_roots(p,xs,ys,[abs(x*y) for x,y in zip(xs,ys)],signs(xs,ys) if ss is None else ss)


def corpus():
    rng=random.Random(2716);digest=hashlib.sha256();cells=0
    for case in range(10000):
        count=1+case%127;en,ed=rng.randrange(1,1<<32),rng.randrange(1,1<<32);common=gcd(en,ed)
        p=replace(spec(count,case,1+case%2),schema=c.norm.Spec(count,rng.randrange(31),rng.randrange(31),rng.randrange(15),en//common,ed//common))
        xs=np.array([rng.randrange(-32768,32768) for _ in range(count)],dtype=np.int64);ys=np.array([rng.randrange(-32768,32768) for _ in range(count)],dtype=np.int64)
        xs[0],ys[0]=((0,-32768),(-32768,0),(0,0),(-32768,-32768),(-1,1),(1,-1),(32767,32767))[case%7]
        v=c.derive(p,4);w=c.witness(p,xs.tolist(),ys.tolist());n=v['n'];mx=np.pad(np.abs(xs),(0,n-count));my=np.pad(np.abs(ys),(0,n-count));nx=(mx>0).astype(np.int64);ny=(my>0).astype(np.int64)
        sx=np.pad(xs<0,(0,n-count)).astype(np.int64);sy=np.pad(ys<0,(0,n-count)).astype(np.int64);ss=((sx!=sy)&(nx!=0)&(ny!=0)).astype(np.int64)
        flags=np.concatenate((nx,ny,ss));pred=np.concatenate((np.maximum(mx-1,0),np.maximum(my-1,0)));mag=np.concatenate((mx,my));nz=np.concatenate((nx,ny))
        assert w==dict(flags=flags.tolist(),predecessor=pred.tolist())
        assert np.array_equal(mag,pred+nz) and np.all(mag*(1-nz)==0) and np.array_equal(ss,sx*ny+sy*nx-2*sx*sy)
        assert all(0<=x<=cap for name in w for x,cap in zip(w[name],v[name].caps))
        digest.update(v['raw']+bytes(w['flags'])+b''.join(x.to_bytes(2,'little') for x in w['predecessor']));cells+=5*n
    p=spec(16384,(1<<42)-1,2);v=c.derive(p,8);assert v['base']+(1<<20)==(1<<63)+(1<<62)
    assert r.derive(v['flags'],8)[2:4]==(65536,1) and r.derive(v['predecessor'],8)[2:4]==(32768,2)
    for bad in (replace(p,identity=1<<42),replace(p,repetitions=True),replace(p,left=p.output),replace(p,product=v['base']),replace(p,schema=replace(p.schema,G=True))):rejects('Spec',lambda:c.derive(bad,4))
    rejects('Spec',lambda:c.derive(spec(16385),4));rejects('Spec',lambda:c.derive(p,True))
    for xs,ys in (([False]*5,[0]*5),([32768]*5,[0]*5),([0],[0]*5)):rejects('Input',lambda:c.witness(spec(),xs,ys))
    assert digest.hexdigest()=='1c00d0c60f7029c8c6ecec8e28e08c19ffb2dcef550f53d884a31220d68a9913'
    print(json.dumps(dict(seed=2716,cases=10000,word_cells=cells,sha256=digest.hexdigest()),sort_keys=True),flush=True)


def account(p,out,d):
    a=c.derive(p,d)['a'];dims=[a+2]*6+[a+3]*4;f=lambda m:3*m*(m-1)//2+2*m
    assert out['account']==dict(identities=[((1<<m)+255,p.repetitions) for m in dims],lookup_reduction_numerator=sum(p.repetitions*(f(m)+f(8)+3*m) for m in dims),range_reduction_numerator=131*a+148,denominator=r.sc.P**d)
    assert len(out['claims'])==9 and out['draws']=={r.zc.WEIGHT:2*a+2,r.zc.tr.CHALLENGE:2*a+2}
    xy=out['xy'];draws=[out['draws'],xy['draws']]+[child['draws'] for child in xy['children']]+[child['draws'] for child in out['ranges']]
    draws += [child['draws'] for source in xy['children'][:2] for child in source['ranges']]
    assert all(sum(row.get(label,0) for row in draws)==55*a+61 for label in (r.zc.WEIGHT,r.zc.tr.CHALLENGE))


def honest(maximum=False):
    digest=hashlib.sha256();count=0
    for d,reps in (((4,1),) if maximum else ((4,1),(4,2),(8,1),(8,2))):
        for size in ((16384,) if maximum else (1,5,16,65)):
            p=spec(size,2010+count,reps);xs=([-32768,0,32767,-1,255,0,1]*((size+6)//7))[:size];ys=([-32768,-32768,1,0,-255,0,-1]*((size+6)//7))[:size]
            print('honest start',count+1,d,reps,size,flush=True);proof,state=c.prove(p,xs,ys,d);out=c.verify(p,expected(p,xs,ys),proof,d)
            assert out['state']==state;account(p,out,d);digest.update(state);count+=1;print('honest passed',count,d,reps,size,flush=True)
    print(json.dumps(dict(maximum=maximum,proofs=count,sha256=digest.hexdigest()),sort_keys=True),flush=True)


def controls():
    p=spec();d=4;xs=[0,7,-7,-1,0];ys=[-7,-1,-1,1,0];v=c.derive(p,d);n=v['n'];w=c.witness(p,xs,ys);pairs=c.prepare(p,xs,ys,d);proof,state=c.assemble(p,pairs,d);roots=expected(p,xs,ys)
    assert c.verify(p,roots,proof,d)['state']==state
    for name in ('flags','predecessor'):
        bad=copy.deepcopy(proof);bad[name]['words'][0]^=1;rejects(name.title()+':CommitmentMismatch',lambda:c.verify(p,roots,bad,d))
    bad=copy.deepcopy(proof);bad['xy']['left']['ranges'][0]['words'][0]^=1;rejects('XY:Left:Raw:CommitmentMismatch',lambda:c.verify(p,roots,bad,d))
    for index in range(5):
        flags=w['flags'].copy();flags[2*n+index]^=1;bad,_=c.assemble(p,dict(pairs,flags=r.prove(v['flags'],flags,d)),d);wrong=signs(xs,ys);wrong[index]^=1
        rejects('Sign:RoundSumMismatch',lambda:c.verify(p,expected(p,xs,ys,wrong),bad,d))
        rejects('Sign:CommitmentMismatch',lambda:c.verify(p,roots,bad,d))
    flags=w['flags'].copy();flags[0]=1;bad,_=c.assemble(p,dict(pairs,flags=r.prove(v['flags'],flags,d)),d)
    rejects('Predicates:RoundSumMismatch',lambda:c.verify(p,roots,bad,d))
    flags=w['flags'].copy();flags[1]=0;pred=w['predecessor'].copy();pred[1]=7
    bad,_=c.assemble(p,dict(pairs,flags=r.prove(v['flags'],flags,d),predecessor=r.prove(v['predecessor'],pred,d)),d)
    rejects('Predicates:RoundSumMismatch',lambda:c.verify(p,roots,bad,d))
    pred=w['predecessor'].copy();pred[1]-=1;bad,_=c.assemble(p,dict(pairs,predecessor=r.prove(v['predecessor'],pred,d)),d)
    rejects('Predicates:RoundSumMismatch',lambda:c.verify(p,roots,bad,d))
    bad=copy.deepcopy(proof);final=bad['zero'][1]['final'];delta=r.sc.sub(final[3][0],r.sc.mul(r.sc.scalar(2,d),final[1][0]));final[0][0]=r.sc.add(final[0][0],r.sc.scalar(1,d));final[4][0]=r.sc.add(final[4][0],delta)
    rejects('Sign:ClaimMismatch',lambda:c.verify(p,roots,bad,d))
    zero=spec(1,2030);bad,_=c.prove(zero,[0],[-7],d);bad['zero'][1]['final'][3][0]=r.sc.scalar(2,d)
    rejects('Sign:ClaimMismatch',lambda:c.verify(zero,expected(zero,[0],[-7]),bad,d))
    rejects('ProofShape',lambda:c.verify(p,roots,dict(proof,certificate={}),d));rejects('Root',lambda:c.verify(p,[False]*4,proof,d))
    print('false signs, both predicate directions, predecessor, source and original-final controls passed',flush=True)


def boundaries():
    p=spec(3,2040);d=4;xs=[-32768,0,-1];ys=[1,-1,1];v=c.derive(p,d);n=v['n'];pairs=c.prepare(p,xs,ys,d);roots=expected(p,xs,ys);w=c.witness(p,xs,ys)
    for name,index in (('flags',3*n),('flags',n-1),('flags',2*n),('predecessor',n-1),('predecessor',0)):
        child=v[name];caps=list(child.caps);values=w[name].copy()
        if index==len(caps):caps.extend([0]*n);values.extend([0]*n)
        caps[index]+=1;values[index]=caps[index];loose=replace(child,caps=tuple(caps));false=r.assemble(child,*r.witness(loose,values),d);changed=dict(pairs);changed[name]=false;bad,_=c.assemble(p,changed,d)
        rejects(name.title()+':CapRelation:RoundSumMismatch',lambda:c.verify(p,roots,bad,d))
    print('nonboolean sign, padded flags/predecessor and predecessor overflow reject at cap consumers',flush=True)


def composition():
    import norm_product as product
    p=spec(3,2050);d=4;xs=[-7,0,255];ys=[0,-32768,-255];proof,state=c.prove(p,xs,ys,d);roots=expected(p,xs,ys)
    assert c.verify(p,roots,proof,d)['state']==state
    pp=product.Spec(p.schema,2051,p.product,227,229,1);values=[abs(x*y) for x,y in zip(xs,ys)];child,st=product.prove(pp,values,16384,d);other=product.expected_roots(pp,values,16384,[x*16384 for x in values]);other[0]=roots[2]
    assert product.verify(pp,other,child,d)['state']==st
    bad,_=c.prove(p,[7,0,255],ys,d);rejects('XY:Left:Raw:CommitmentMismatch',lambda:c.verify(p,roots,bad,d))
    print('actual product and sign share the xy root; same-result raw-source substitution rejects',flush=True)


if __name__=='__main__':
    modes={'--corpus':corpus,'--honest':honest,'--maximum':lambda:honest(True),'--controls':controls,'--boundaries':boundaries,'--composition':composition}
    if sys.argv[1:]:
        assert all(mode in modes for mode in sys.argv[1:])
        for mode in sys.argv[1:]:modes[mode]()
    else:
        for test in modes.values():test()
