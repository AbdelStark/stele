# /// script
# requires-python = ">=3.12"
# dependencies = ["numpy==2.3.4", "blake3==1.0.11", "python-flint==0.9.0"]
# ///
"""RFC-0022 product: exact full-row geometry, columns and actual source joins."""
import copy
from dataclasses import replace
import hashlib
import json
from math import gcd
import random
import sys
import numpy as np
import norm_product as c

r=c.r


def rejects(reason,call):
    try:call()
    except ValueError as error:assert str(error)==reason,(reason,str(error))
    else:raise AssertionError('accepted '+reason)


def spec(count=3,identity=1900,repetitions=1):
    return c.Spec(c.norm.Spec(count,30,30,14,1,3),identity,163,167,173,repetitions)


def corpus():
    rng=random.Random(2715);digest=hashlib.sha256();cells=0
    for case in range(10000):
        count=1+case%127;en,ed=rng.randrange(1,1<<32),rng.randrange(1,1<<32);common=gcd(en,ed)
        p=replace(spec(count,case,1+case%2),schema=c.norm.Spec(count,rng.randrange(31),rng.randrange(31),rng.randrange(15),en//common,ed//common))
        xs=np.array([rng.randrange((1<<30)+1) for _ in range(count)],dtype=np.int64);j=rng.randrange(8192,16385)
        if case%7==0:xs[0],j=1<<30,16384
        v=c.derive(p,4);w=c.witness(p,xs.tolist(),j);n=v['n'];padded=np.pad(xs,(0,n-count))
        assert w['output']==(xs*j).tolist();xb=np.stack([(padded>>(8*k))&255 for k in range(4)])
        raw=np.stack([sum((xb[k]*((j>>(8*(column-k)))&255) for k in range(4) if 0<=column-k<2),np.zeros(n,dtype=np.int64)) for column in range(8)])
        incoming=np.zeros(n,dtype=np.int64);carry=[];out=[]
        for row in raw:out.extend(((row+incoming)%256).tolist());incoming=(row+incoming)//256;carry.extend(incoming.tolist())
        assert carry[:3*n]==w['carry_wide'] and carry[3*n:5*n]==w['carry_byte'] and not any(carry[5*n:])
        for name in ('carry_wide','carry_byte'):assert all(0<=x<=cap for x,cap in zip(w[name],v[name].caps))
        assert r.witness(v['output'],w['output'])[0]==out
        assert v['cert']['carry_caps']==(0,254,318,318,128,16,0) and max(v['cert']['lhs']+v['cert']['rhs'])==81663
        digest.update(v['raw']+bytes(out)+b''.join(x.to_bytes(2,'little') for x in carry));cells+=8*n
    p=spec(16384,(1<<44)-1,2);v=c.derive(p,8)
    assert [r.derive(v[name],8)[2:4] for name in c.NAMES]==[(16384,4),(1,2),(16384,8),(65536,2),(32768,1)]
    for bad in (replace(p,identity=1<<44),replace(p,repetitions=True),replace(p,xy=p.output),replace(p,reciprocal=v['base']),replace(p,schema=replace(p.schema,G=True))):rejects('Spec',lambda:c.derive(bad,4))
    rejects('Spec',lambda:c.derive(spec(16385),4));rejects('Spec',lambda:c.derive(p,True))
    for xs,j in (([False]*3,8192),([1<<31]*3,8192),([0],8192),([0]*3,8191),([0]*3,16385),([0]*3,True)):rejects('Input',lambda:c.witness(spec(),xs,j))
    assert digest.hexdigest()=='8edffed9ff302d9c132750ec6b5a201e6c8a610ba2063285299648586baa214f'
    print(json.dumps(dict(seed=2715,cases=10000,column_cells=cells,sha256=digest.hexdigest()),sort_keys=True),flush=True)


def account(p,out,d):
    a=c.derive(p,d)['a'];dims=[a+3,2,a+4,a+4,a+2];f=lambda m:3*m*(m-1)//2+2*m
    assert out['account']==dict(identities=[((1<<m)+255,p.repetitions) for m in dims],
        lookup_reduction_numerator=sum(p.repetitions*(f(m)+f(8)+3*m) for m in dims),range_reduction_numerator=39*a+85,denominator=r.sc.P**d)
    assert len(out['claims'])==7 and out['draws']=={r.zc.WEIGHT:a+3,r.zc.tr.CHALLENGE:a+3}
    draws=[out['draws']]+[x['draws'] for x in out['children']]
    assert all(sum(row.get(label,0) for row in draws)==17*a+36 for label in (r.zc.WEIGHT,r.zc.tr.CHALLENGE))


def honest(maximum=False):
    digest=hashlib.sha256();count=0
    for d,reps in (((4,1),) if maximum else ((4,1),(4,2),(8,1),(8,2))):
        for size in ((16384,) if maximum else (1,3,16,65)):
            p=spec(size,1910+count,reps);xs=([1<<30,0,255,(1<<30)-1,1]*((size+4)//5))[:size];j=(8192,16384,10000,16383)[count%4]
            print('honest start',count+1,d,reps,size,flush=True);proof,state=c.prove(p,xs,j,d);out=c.verify(p,c.expected_roots(p,xs,j,[x*j for x in xs]),proof,d)
            assert out['state']==state;account(p,out,d);digest.update(state);count+=1;print('honest passed',count,d,reps,size,flush=True)
    if not maximum:assert digest.hexdigest()=='3ef9e1b99949c3ff074517e0ea1806d31acfc620b58ea688e2ac8c840867e5ff'
    print(json.dumps(dict(maximum=maximum,proofs=count,sha256=digest.hexdigest()),sort_keys=True),flush=True)


def controls():
    p=spec();d=4;xs=[1<<30,255,0];j=16384;v=c.derive(p,d);pairs=c.prepare(p,xs,j,d);proof,state=c.assemble(p,pairs,d);values=[x*j for x in xs];expected=c.expected_roots(p,xs,j,values)
    assert c.verify(p,expected,proof,d)['state']==state
    for name in c.NAMES:
        bad=copy.deepcopy(proof);bad[name]['words'][0]^=1
        rejects(name.title()+':CommitmentMismatch',lambda:c.verify(p,expected,bad,d))
    for delta in (1,r.sc.P):
        wrong=values.copy();wrong[1]+=delta;changed=dict(pairs,output=r.prove(v['output'],wrong,d));bad,_=c.assemble(p,changed,d)
        rejects('ProductColumns:RoundSumMismatch',lambda:c.verify(p,c.expected_roots(p,xs,j,wrong),bad,d))
    for name in ('carry_wide','carry_byte'):
        carry=c.witness(p,xs,j)[name];carry[0]^=1;changed=dict(pairs);changed[name]=r.prove(v[name],carry,d);bad,_=c.assemble(p,changed,d)
        rejects('ProductColumns:RoundSumMismatch',lambda:c.verify(p,expected,bad,d))
    bad=copy.deepcopy(proof);bad['zero']['final'][5][0]=r.sc.add(bad['zero']['final'][5][0],r.sc.scalar(256,d));bad['zero']['final'][6][0]=r.sc.add(bad['zero']['final'][6][0],r.sc.scalar(-1,d))
    rejects('ProductColumns:ClaimMismatch',lambda:c.verify(p,expected,bad,d))
    zero=spec(1,1930);bad,_=c.prove(zero,[0],j,d);roots=c.expected_roots(zero,[0],j,[0]);bad['zero']['final'][1][0]=r.sc.add(bad['zero']['final'][1][0],r.sc.scalar(1,d))
    rejects('ProductColumns:ClaimMismatch',lambda:c.verify(zero,roots,bad,d))
    bad,_=c.prove(zero,[0],j-1,d);rejects('Reciprocal:CommitmentMismatch',lambda:c.verify(zero,roots,bad,d))
    bad=copy.deepcopy(proof);bad['output']['words'][0]=False;rejects('Output:NoncanonicalField',lambda:c.verify(p,expected,bad,d))
    rejects('ProofShape',lambda:c.verify(p,expected,dict(proof,certificate={}),d));rejects('Root',lambda:c.verify(p,[False]*3,proof,d))
    print('actual source, product, carry, p-alias and zero-hidden original controls passed',flush=True)


def boundaries():
    p=spec(3,1940);d=4;xs=[1,0,3];j=16384;v=c.derive(p,d);pairs=c.prepare(p,xs,j,d);expected=c.expected_roots(p,xs,j,[x*j for x in xs])
    for name,index in (('carry_wide',3*v['n']),('carry_wide',v['n']-1),('carry_byte',v['n'])):
        child=v[name];values=c.witness(p,xs,j)[name];caps=list(child.caps)
        if index==len(caps):caps.extend([0]*v['n']);values.extend([0]*v['n'])
        caps[index]+=1;values[index]=caps[index];loose=replace(child,caps=tuple(caps))
        changed=dict(pairs);changed[name]=r.assemble(child,*r.witness(loose,values),d);bad,_=c.assemble(p,changed,d)
        rejects(name.title()+':CapRelation:RoundSumMismatch',lambda:c.verify(p,expected,bad,d))
    for loose,values in ((replace(v['output'],caps=v['output'].caps+(1,)),[x*j for x in xs]+[1]),(replace(v['output'],caps=((1<<64)-1,)*3),[(1<<48)+j,0,3*j])):
        child=r.assemble(v['output'],*r.witness(loose,values),d);bad,_=c.assemble(p,dict(pairs,output=child),d);target=expected.copy();target[2]=r.source_root(v['output'],child[0]['words'])
        rejects('Output:CapRelation:RoundSumMismatch',lambda:c.verify(p,target,bad,d))
    print('carry caps, carry padding, output padding and high output planes reject',flush=True)


def composition():
    import norm_xy as xy
    import norm_rsqrt as rs
    p=spec(3,1950);d=4;xs=[-32768,0,255];ys=[-32768,-1,-255];values=[abs(x*y) for x,y in zip(xs,ys)]
    xp=xy.Spec(p.schema,1951,179,181,p.xy,1);proof,state=xy.prove(xp,xs,ys,d);roots=xy.expected_roots(xp,xs,ys,values)
    assert xy.verify(xp,roots,proof,d)['state']==state
    rp=rs.Spec(p.schema,1952,191,p.reciprocal,1);j=rs.witness(rp,16384);reciprocal,st=rs.prove(rp,16384,d);rsroots=rs.expected_roots(rp,16384,j)
    assert rs.verify(rp,rsroots,reciprocal,d)['state']==st
    product,state=c.prove(p,values,j,d);expected=c.expected_roots(p,values,j,[x*j for x in values]);expected[:2]=[roots[2],rsroots[1]]
    assert c.verify(p,expected,product,d)['state']==state
    bad,_=c.prove(p,values,j-1,d);rejects('Reciprocal:CommitmentMismatch',lambda:c.verify(p,expected,bad,d))
    print('actual xy and complete rsqrt roots compose; reciprocal substitution rejects',flush=True)


def offset_bound():
    p=spec(1,1955);d=4;v=c.derive(p,d);pairs=c.prepare(p,[1],16384,d)
    child=v['offset'];loose=replace(child,caps=(8193,))
    false=r.assemble(child,*r.witness(loose,[8193]),d);bad,_=c.assemble(p,dict(pairs,offset=false),d)
    rejects('Offset:CapRelation:RoundSumMismatch',lambda:c.verify(p,c.expected_roots(p,[1],16384,[16384]),bad,d))
    print('reciprocal offset one above8192 rejects at the actual cap relation',flush=True)


if __name__=='__main__':
    modes={'--corpus':corpus,'--honest':honest,'--maximum':lambda:honest(True),'--controls':controls,'--boundaries':boundaries,'--composition':composition,'--offset-bound':offset_bound}
    if sys.argv[1:]:
        assert all(mode in modes for mode in sys.argv[1:])
        for mode in sys.argv[1:]:modes[mode]()
    else:
        for test in modes.values():test()
