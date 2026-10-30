# /// script
# requires-python = ">=3.12"
# dependencies = ["numpy==2.3.4", "blake3==1.0.11", "python-flint==0.9.0"]
# ///
"""RFC-0022 bias: wide sums, real-row scalar mask and actual source roots."""
import copy
from dataclasses import replace
import hashlib
import json
from math import gcd
import random
import sys
import numpy as np
import norm_bias as c

r=c.r
MASK=(1<<64)-1


def rejects(reason,call):
    try:call()
    except ValueError as error:assert str(error)==reason,(reason,str(error))
    else:raise AssertionError('accepted '+reason)


def spec(count=3,identity=2300,repetitions=1):
    return c.Spec(c.norm.Spec(count,30,30,0,1,3),identity,307,311,313,repetitions)


def corpus():
    rng=random.Random(2719);digest=hashlib.sha256();cells=0
    for case in range(10000):
        count=1+case%63;en,ed=rng.randrange(1,1<<32),rng.randrange(1,1<<32);common=gcd(en,ed)
        p=replace(spec(count,case,1+case%2),schema=c.norm.Spec(count,rng.randrange(31),rng.randrange(31),rng.randrange(15),en//common,ed//common))
        v=c.derive(p,4);ts=np.array([rng.randrange((1<<44)+1) for _ in range(count)],dtype=np.int64);ts[0]=(0,1<<44,255,(1<<44)-1)[case%4]
        h=rng.randrange(v['limit']+1) if case%3 else (v['limit'] if case%2 else 0);w=c.witness(p,ts.tolist(),h);n=v['n'];padded=np.pad(ts,(0,n-count));mask=(np.arange(n)<count).astype(np.int64)
        sums=ts.astype(object)+h;assert w['product']==ts.tolist() and w['bias']==[h] and w['low']==[int(x)&MASK for x in sums]
        if 'high' in v['ranges']:assert w['high']==[int(x)>>64 for x in sums]
        carry=np.zeros(n,dtype=np.int64);all_carry=[];out=[]
        for k in range(16):
            total=((padded>>(8*k))&255 if k<8 else np.zeros(n,dtype=np.int64))+mask*((h>>(8*k))&255)+carry
            out.extend((total%256).tolist());carry=total//256;all_carry.extend(carry.tolist())
        assert not carry.any()
        for g in range(4):
            name='carry_'+str(g);values=all_carry[4*g*n:4*(g+1)*n]
            if name in v['ranges']:assert w[name]==values
            else:assert not any(values)
        assert out==[int(x)>>(8*k)&255 for k in range(16) for x in np.pad(sums,(0,n-count))]
        assert all(0<=x<=cap for name in w for x,cap in zip(w[name],v['ranges'][name].caps))
        digest.update(v['raw']+h.to_bytes(16,'little')+bytes(out)+bytes(all_carry));cells+=16*n
    p=spec(16384,(1<<44)-1,2);v=c.derive(p,8)
    assert v['columns']==16 and v['cert']['carry_caps']==(0,)+(1,)*11+(0,) and len(v['ranges'])==7
    assert max(v['cert']['lhs']+v['cert']['rhs'])==511
    assert all(r.derive(child,8)[2]*r.derive(child,8)[3]<=131072 and r.lookup_plan(child,8)['m']<=18 for child in v['ranges'].values())
    for shift in range(16,91):
        f,g,e=(0,0,30-shift) if shift<30 else (min(30,shift-30),max(0,shift-60),0)
        p=replace(spec(),schema=c.norm.Spec(3,f,g,e,1,3));v=c.derive(p,4);assert v['limit']==1<<(shift-1) and v['columns'] in (8,16)
    p=spec();v=c.derive(p,4)
    for bad in (replace(p,identity=1<<44),replace(p,repetitions=True),replace(p,product=p.output),replace(p,bias=v['base']),replace(p,schema=replace(p.schema,E=True))):rejects('Spec',lambda:c.derive(bad,4))
    rejects('Spec',lambda:c.derive(spec(16385),4));rejects('Spec',lambda:c.derive(p,True))
    for ts,h in (([False]*3,0),([(1<<44)+1]*3,0),([0],0),([0]*3,-1),([0]*3,(1<<89)+1),([0]*3,True)):rejects('Input',lambda:c.witness(p,ts,h))
    print(json.dumps(dict(seed=2719,cases=10000,column_cells=cells,sha256=digest.hexdigest()),sort_keys=True),flush=True)


def account(p,out,d):
    v=c.derive(p,d);a=v['a'];bs={name:r.derive(child,d)[1] for name,child in v['ranges'].items()};h=int('high' in bs);g=sum(name.startswith('carry_') for name in bs);x=3+bs['bias']+bs['low']+bs.get('high',0);cc=(v['columns']-1).bit_length()
    dims=[a+4,bs['bias']+1,a+bs['low']+1]+([a+bs['high']+1] if h else [])+[a+3]*g;f=lambda m:3*m*(m-1)//2+2*m
    assert out['account']==dict(identities=[((1<<m)+255,p.repetitions) for m in dims],lookup_reduction_numerator=sum(p.repetitions*(f(m)+f(8)+3*m) for m in dims),range_reduction_numerator=(20+9*h+9*g)*a+7*x+18*g+2*cc,denominator=r.sc.P**d)
    assert len(out['claims'])==5 and out['draws']=={r.zc.WEIGHT:a+cc,r.zc.tr.CHALLENGE:a+cc}
    assert all(sum(row.get(label,0) for row in [out['draws']]+[child['draws'] for child in out['children']])==(9+4*h+4*g)*a+3*x+8*g+cc for label in (r.zc.WEIGHT,r.zc.tr.CHALLENGE))


def honest(maximum=False):
    digest=hashlib.sha256();count=0;cases=((1,0,0,14,0),(3,30,4,0,1<<63),(16,30,3,0,(1<<62)-1),(65,30,30,0,1<<89))
    for d,reps in (((4,1),) if maximum else ((4,1),(4,2),(8,1),(8,2))):
        for size,f,g,e,h in (((16384,30,30,0,1<<89),) if maximum else cases):
            p=replace(spec(size,2310+count,reps),schema=c.norm.Spec(size,f,g,e,1,3));ts=([1<<44,0,255,1,(1<<44)-1]*((size+4)//5))[:size]
            print('honest start',count+1,d,reps,size,flush=True);proof,state=c.prove(p,ts,h,d);out=c.verify(p,c.expected_roots(p,ts,h,[t+h for t in ts]),proof,d)
            assert out['state']==state;account(p,out,d);digest.update(state);count+=1;print('honest passed',count,d,reps,size,flush=True)
    print(json.dumps(dict(maximum=maximum,proofs=count,sha256=digest.hexdigest()),sort_keys=True),flush=True)


def controls():
    p=spec();d=4;ts=[1<<44,255,0];h=1<<89;v=c.derive(p,d);pairs=c.prepare(p,ts,h,d);proof,state=c.assemble(p,pairs,d);roots=c.expected_roots(p,ts,h,[t+h for t in ts]);w=c.witness(p,ts,h)
    assert c.verify(p,roots,proof,d)['state']==state
    for name in v['ranges']:
        bad=copy.deepcopy(proof);bad[name]['words'][0]^=1;rejects(name.title()+':CommitmentMismatch',lambda:c.verify(p,roots,bad,d))
    for name,index,delta in (('low',0,1),('low',2,r.sc.P),('high',1,1)):
        values=w[name].copy();values[index]+=delta;changed=dict(pairs);changed[name]=r.prove(v['ranges'][name],values,d);bad,_=c.assemble(p,changed,d)
        rejects('SumColumns:RoundSumMismatch',lambda:c.verify(p,c.roots(p,bad),bad,d))
    for name in (key for key in v['ranges'] if key.startswith('carry_')):
        values=w[name].copy();values[0]^=1;changed=dict(pairs);changed[name]=r.prove(v['ranges'][name],values,d);bad,_=c.assemble(p,changed,d)
        rejects('SumColumns:RoundSumMismatch',lambda:c.verify(p,roots,bad,d))
    bad=copy.deepcopy(proof);bad['zero']['final'][0][0]=r.sc.add(bad['zero']['final'][0][0],r.sc.scalar(1,d));bad['zero']['final'][1][0]=r.sc.add(bad['zero']['final'][1][0],r.sc.scalar(-1,d))
    rejects('SumColumns:ClaimMismatch',lambda:c.verify(p,roots,bad,d))
    zeros=c.prepare(p,[0]*3,0,d);zeros['low']=r.prove(v['ranges']['low'],[1,0,0],d);zeros['high']=r.prove(v['ranges']['high'],[v['cert']['result_max']>>64,0,0],d);bad,_=c.assemble(p,zeros,d)
    rejects('SumColumns:RoundSumMismatch',lambda:c.verify(p,c.roots(p,bad),bad,d))
    bad=copy.deepcopy(proof);bad['zero']['rounds'][0][0]=(False,0,0,0);rejects('NoncanonicalField',lambda:c.verify(p,roots,bad,d))
    for key in ('certificate','mask','carry_3'):rejects('ProofShape',lambda:c.verify(p,roots,dict(proof,**{key:{}}),d))
    rejects('Root',lambda:c.verify(p,[False]*3,proof,d))
    print('false sums/carries, p-alias, split-bound forgery and preserving original finals reject',flush=True)


def boundaries():
    p=spec(3,2340);d=4;ts=[1<<44,0,1];h=1<<89;v=c.derive(p,d);pairs=c.prepare(p,ts,h,d);proof,_=c.assemble(p,pairs,d);roots=c.roots(p,proof);w=c.witness(p,ts,h);n=v['n']
    for name,index in (('carry_0',n-1),('carry_2',3*n)):
        child=v['ranges'][name];caps=list(child.caps);values=w[name].copy();caps[index]=values[index]=1;badpair=r.assemble(child,*r.witness(replace(child,caps=tuple(caps)),values),d);changed=dict(pairs);changed[name]=badpair;bad,_=c.assemble(p,changed,d)
        rejects(name.title()+':CapRelation:RoundSumMismatch',lambda:c.verify(p,roots,bad,d))
    for name in ('product','low','high'):
        bad=copy.deepcopy(proof);bad[name]['words'][n-1]=1;rejects(name.title()+':CommitmentMismatch',lambda:c.verify(p,roots,bad,d))
    child=v['ranges']['bias'];badpair=r.assemble(child,*r.witness(replace(child,caps=(h+1,)),[h+1]),d);bad,_=c.assemble(p,dict(pairs,bias=badpair),d)
    rejects('Bias:CapRelation:RoundSumMismatch',lambda:c.verify(p,c.roots(p,bad),bad,d))
    output=[t+h for t in ts];output[0]+=1<<120;rejects('Output:CommitmentMismatch',lambda:c.verify(p,c.expected_roots(p,ts,h,output),proof,d))
    small=replace(spec(1,2341),schema=c.norm.Spec(1,0,0,14,1,3));bad,_=c.prove(small,[0],0,d);expect=c.expected_roots(small,[0],0,[0]);expect[1]=r.root(small.bias,[0]*15+[1])
    rejects('Bias:CommitmentMismatch',lambda:c.verify(small,expect,bad,d))
    print('ragged nonzero-bias rows, terminal/padded carries, bias overflow and high extensions checked',flush=True)


def composition():
    import norm_product as product
    import norm_output_factors as factors
    p=spec(3,2350);d=4;xy=[0,255,1<<30];j=16384;ts=[x*j for x in xy];h=1<<89;proof,state=c.prove(p,ts,h,d);roots=c.expected_roots(p,ts,h,[t+h for t in ts])
    pp=product.Spec(p.schema,2351,317,331,p.product,1);child,st=product.prove(pp,xy,j,d);pr=product.expected_roots(pp,xy,j,ts);assert pr[2]==roots[0] and product.verify(pp,pr,child,d)['state']==st
    fp=factors.Spec(p.schema,2352,337,347,349,353,359,1);child,st=factors.prove(fp,0,9,d);fc=c.norm.constants(p.schema);fr=factors.expected_roots(fp,0,9,0,fc['P']<<18,child['factors'])
    assert factors.verify(fp,fr,child,d)['state']==st;roots[1]=r.root(p.bias,child['factors'][18:34]);assert c.verify(p,roots,proof,d)['state']==state
    bad,_=c.prove(p,ts,h-1,d);rejects('Bias:CommitmentMismatch',lambda:c.verify(p,roots,bad,d))
    print('actual product and verified factor bias compose; substituted bias rejects',flush=True)


if __name__=='__main__':
    modes={'--corpus':corpus,'--honest':honest,'--maximum':lambda:honest(True),'--controls':controls,'--boundaries':boundaries,'--composition':composition}
    if sys.argv[1:]:
        assert all(mode in modes for mode in sys.argv[1:])
        for mode in sys.argv[1:]:modes[mode]()
    else:
        for test in modes.values():test()
