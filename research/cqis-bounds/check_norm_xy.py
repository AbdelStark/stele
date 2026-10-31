# /// script
# requires-python = ">=3.12"
# dependencies = ["numpy==2.3.4", "blake3==1.0.11", "python-flint==0.9.0"]
# ///
"""RFC-0022 xy: independent byte products, actual originals and exact bounds."""
import copy
from dataclasses import replace
import hashlib
import json
from math import gcd
import random
import sys
import numpy as np
import norm_xy as c

r=c.r


def rejects(reason,call):
    try:call()
    except ValueError as error:assert str(error)==reason,(reason,str(error))
    else:raise AssertionError('accepted '+reason)


def spec(count=3,identity=1700,repetitions=1):
    return c.Spec(c.norm.Spec(count,30,30,14,1,3),identity,71,73,79,repetitions)


def corpus():
    rng=random.Random(2714);digest=hashlib.sha256();cells=0
    for case in range(10000):
        count=1+case%127;en,ed=rng.randrange(1,1<<32),rng.randrange(1,1<<32);common=gcd(en,ed)
        p=replace(spec(count,case,1+case%2),schema=c.norm.Spec(count,rng.randrange(31),rng.randrange(31),rng.randrange(15),en//common,ed//common))
        xs=np.array([rng.randrange(-32768,32768) for _ in range(count)],dtype=np.int64);ys=np.array([rng.randrange(-32768,32768) for _ in range(count)],dtype=np.int64)
        if case%7==0:xs[0],ys[0]=-32768,-32768
        v=c.derive(p,4);w=c.witness(p,xs.tolist(),ys.tolist());n=v['n'];z=np.abs(xs*ys)
        assert w['output']==z.tolist();left=np.pad(np.abs(xs),(0,n-count));right=np.pad(np.abs(ys),(0,n-count))
        xb=np.stack([(left>>(8*j))&255 for j in range(2)]);yb=np.stack([(right>>(8*j))&255 for j in range(2)])
        raw=np.stack([sum((xb[j]*yb[k-j] for j in range(2) if 0<=k-j<2),np.zeros(n,dtype=np.int64)) for k in range(4)])
        incoming=np.zeros(n,dtype=np.int64);carry=[];out=[]
        for row in raw:out.extend(((row+incoming)%256).tolist());incoming=(row+incoming)//256;carry.extend(incoming.tolist())
        assert carry==w['carry'] and np.all(incoming==0)
        assert all(0<=x<=cap for x,cap in zip(carry,v['carry'].caps));assert r.witness(v['output'],w['output'])[0]==out
        assert v['cert']['carry_caps']==(0,254,255,64,0) and max(v['cert']['lhs']+v['cert']['rhs'])==65535
        digest.update(v['raw']+bytes(out)+bytes(carry));cells+=4*n
    p=spec(1024,(1<<44)-1,2);v=c.derive(p,8);assert v['base']+(1<<18)==(1<<63)+(1<<62)
    for bad in (replace(p,identity=1<<44),replace(p,repetitions=True),replace(p,left=p.output),replace(p,output=v['base']),replace(p,schema=replace(p.schema,G=True))):rejects('Spec',lambda:c.derive(bad,4))
    rejects('Capacity',lambda:c.derive(spec(1025),4));rejects('Spec',lambda:c.derive(p,True))
    for xs,ys in (([False]*3,[0]*3),([32768]*3,[0]*3),([0],[0]*3)):rejects('Input',lambda:c.witness(spec(),xs,ys))
    assert digest.hexdigest()=='f873271b7a0ecfacad1ccbef6c15966414806db0e4958a99aaa44a2039df17a4'
    print(json.dumps(dict(seed=2714,cases=10000,column_cells=cells,sha256=digest.hexdigest()),sort_keys=True),flush=True)


def account(p,out,d):
    a=c.derive(p,d)['a'];dims=[a+2]*6+[a+3]*2;f=lambda m:3*m*(m-1)//2+2*m
    assert out['account']==dict(identities=[((1<<m)+255,p.repetitions) for m in dims],
        lookup_reduction_numerator=sum(p.repetitions*(f(m)+f(8)+3*m) for m in dims),range_reduction_numerator=107*a+108,denominator=r.sc.P**d)
    assert len(out['claims'])==7 and out['draws']=={r.zc.WEIGHT:a+2,r.zc.tr.CHALLENGE:a+2}
    draws=[out['draws']]+[x['draws'] for x in out['children']]
    draws += [part['draws'] for child in out['children'][:2] for part in child['ranges']]
    assert all(sum(row.get(label,0) for row in draws)==45*a+44 for label in (r.zc.WEIGHT,r.zc.tr.CHALLENGE))


def honest(maximum=False):
    digest=hashlib.sha256();count=0
    for d,reps in (((4,1),) if maximum else ((4,1),(4,2),(8,1),(8,2))):
        for size in ((1024,) if maximum else (1,3,16,65)):
            p=spec(size,1710+count,reps);xs=([-32768,0,32767,-1,255]*((size+4)//5))[:size];ys=([-32768,-32768,1,0,-255]*((size+4)//5))[:size]
            proof,state=c.prove(p,xs,ys,d);out=c.verify(p,c.expected_roots(p,xs,ys,[abs(x*y) for x,y in zip(xs,ys)]),proof,d)
            assert out['state']==state;account(p,out,d);digest.update(state);count+=1;print('honest',count,d,reps,size,flush=True)
    if maximum:assert digest.hexdigest()=='3ebe58ec21e52b8c5446f982ad9e9ae9be0250e357a3328eaafc8f6d22968f41'
    else:assert digest.hexdigest()=='4c3206c708d544df3e02f6b6a38e20680ad829263a6b5ff75eb0131ed7b46048'
    print(json.dumps(dict(maximum=maximum,proofs=count,sha256=digest.hexdigest()),sort_keys=True),flush=True)


def controls():
    p=spec();d=4;xs=[-32768,255,0];ys=[-1,-255,-32768];v=c.derive(p,d);pairs=c.prepare(p,xs,ys,d);proof,state=c.assemble(p,pairs,d);values=[abs(x*y) for x,y in zip(xs,ys)];expected=c.expected_roots(p,xs,ys,values)
    assert c.verify(p,expected,proof,d)['state']==state
    for name,reason,path in (('left','Left:Raw:CommitmentMismatch',('ranges',0)),('right','Right:Raw:CommitmentMismatch',('ranges',0)),('left','Left:Magnitude:CommitmentMismatch',('ranges',1)),('output','Output:CommitmentMismatch',()),('carry','Carry:CommitmentMismatch',())):
        bad=copy.deepcopy(proof);part=bad[name]
        for index in path:part=part[index]
        part['words'][0]^=1;rejects(reason,lambda:c.verify(p,expected,bad,d))
    wrong=values.copy();wrong[0]+=1;changed=dict(pairs,output=r.prove(v['output'],wrong,d));bad,_=c.assemble(p,changed,d)
    rejects('ProductColumns:RoundSumMismatch',lambda:c.verify(p,c.expected_roots(p,xs,ys,wrong),bad,d))
    carry=c.witness(p,xs,ys)['carry'];carry[0]^=1;changed=dict(pairs,carry=r.prove(v['carry'],carry,d));bad,_=c.assemble(p,changed,d)
    rejects('ProductColumns:RoundSumMismatch',lambda:c.verify(p,expected,bad,d))
    loose=replace(v['carry'],caps=v['carry'].caps[:-1]+(1,));carry=c.witness(p,xs,ys)['carry'];carry[-1]=1;changed=dict(pairs,carry=r.assemble(v['carry'],*r.witness(loose,carry),d));bad,_=c.assemble(p,changed,d)
    rejects('Carry:CapRelation:RoundSumMismatch',lambda:c.verify(p,expected,bad,d))
    loose=replace(v['output'],caps=((1<<32)-1,)*3);wrong=values.copy();wrong[0]+=r.sc.P;changed=dict(pairs,output=r.assemble(v['output'],*r.witness(loose,wrong),d));bad,_=c.assemble(p,changed,d)
    rejects('Output:CapRelation:RoundSumMismatch',lambda:c.verify(p,c.expected_roots(p,xs,ys,wrong),bad,d))
    bad=copy.deepcopy(proof);bad['zero']['final'][5][0]=r.sc.add(bad['zero']['final'][5][0],r.sc.scalar(256,d));bad['zero']['final'][6][0]=r.sc.add(bad['zero']['final'][6][0],r.sc.scalar(-1,d))
    rejects('ProductColumns:ClaimMismatch',lambda:c.verify(p,expected,bad,d))
    zero=spec(1,1730);bad,_=c.prove(zero,[0],[7],d);roots=c.expected_roots(zero,[0],[7],[0]);bad['zero']['final'][1][0]=r.sc.add(bad['zero']['final'][1][0],r.sc.scalar(1,d))
    rejects('ProductColumns:ClaimMismatch',lambda:c.verify(zero,roots,bad,d))
    bad=copy.deepcopy(proof);bad['output']['words'][0]=False;rejects('Output:NoncanonicalField',lambda:c.verify(p,expected,bad,d))
    rejects('ProofShape',lambda:c.verify(p,expected,dict(proof,certificate={}),d));rejects('Root',lambda:c.verify(p,[False]*3,proof,d))
    print('source/magnitude/product/carry/alias, terminal/padding cap and original-final controls passed',flush=True)


def composition():
    import norm_statistic as s
    p=spec(3,1740);xs=[-7,0,255];ys=[0,-32768,-255];proof,state=c.prove(p,xs,ys,4);expected=c.expected_roots(p,xs,ys,[abs(x*y) for x,y in zip(xs,ys)])
    assert c.verify(p,expected,proof,4)['state']==state
    sp=s.Spec(p.schema,1741,p.left,83,1);stat,st=s.prove(sp,xs,4);roots=s.expected_roots(sp,xs,sum(x*x for x in xs));roots[0]=expected[0]
    assert s.verify(sp,roots,stat,4)['state']==st
    changed=[7,0,255];bad,_=c.prove(p,changed,ys,4)
    rejects('Left:Raw:CommitmentMismatch',lambda:c.verify(p,expected,bad,4))
    print('actual statistic X root composes; same-magnitude signed-source substitution rejects',flush=True)


def boundaries():
    p=spec(3,1745);d=4;xs=[1,0,-1];ys=[1,2,-3];v=c.derive(p,d);pairs=c.prepare(p,xs,ys,d);expected=c.expected_roots(p,xs,ys,[1,0,3])
    for index in (3*v['n'],v['n']-1):
        caps=list(v['carry'].caps);caps[index]=1;loose=replace(v['carry'],caps=tuple(caps));values=c.witness(p,xs,ys)['carry'];values[index]=1
        child=r.assemble(v['carry'],*r.witness(loose,values),d);bad,_=c.assemble(p,dict(pairs,carry=child),d)
        rejects('Carry:CapRelation:RoundSumMismatch',lambda:c.verify(p,expected,bad,d))
    loose=replace(v['output'],caps=v['output'].caps+(1,));child=r.assemble(v['output'],*r.witness(loose,[1,0,3,1]),d)
    bad,_=c.assemble(p,dict(pairs,output=child),d);target=expected.copy();target[2]=r.source_root(v['output'],child[0]['words'])
    rejects('Output:CapRelation:RoundSumMismatch',lambda:c.verify(p,target,bad,d))
    print('real terminal carry, padded carry and padded output separately reject at their cap consumers',flush=True)


if __name__=='__main__':
    modes={'--corpus':corpus,'--honest':honest,'--maximum':lambda:honest(True),'--controls':controls,'--composition':composition,'--boundaries':boundaries}
    if sys.argv[1:]:
        assert all(mode in modes for mode in sys.argv[1:])
        for mode in sys.argv[1:]:modes[mode]()
    else:
        for test in modes.values():test()
