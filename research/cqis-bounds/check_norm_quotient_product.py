# /// script
# requires-python = ">=3.12"
# dependencies = ["numpy==2.3.4", "blake3==1.0.11", "python-flint==0.9.0"]
# ///
"""RFC-0022 quotient product: wide result halves, carries and actual roots."""
import copy
from dataclasses import replace
import hashlib
import json
from math import gcd
import random
import sys
import numpy as np
import norm_quotient_product as c

r=c.r
MASK=(1<<64)-1


def rejects(reason,call):
    try:call()
    except ValueError as error:assert str(error)==reason,(reason,str(error))
    else:raise AssertionError('accepted '+reason)


def spec(count=3,identity=2200,repetitions=1):
    return c.Spec(c.norm.Spec(count,30,30,0,1,3),identity,251,257,263,repetitions)


def corpus():
    rng=random.Random(2718);digest=hashlib.sha256();cells=0
    for case in range(10000):
        count=1+case%63;en,ed=rng.randrange(1,1<<32),rng.randrange(1,1<<32);common=gcd(en,ed)
        p=replace(spec(count,case,1+case%2),schema=c.norm.Spec(count,rng.randrange(31),rng.randrange(31),rng.randrange(15),en//common,ed//common))
        v=c.derive(p,4);qs=np.array([rng.randrange(32769) for _ in range(count)],dtype=np.int64);qs[0]=(0,32768,32767,255)[case%4]
        b=rng.randrange(1,v['limit']+1) if case%3 else v['limit'];w=c.witness(p,qs.tolist(),b);n=v['n'];padded=np.pad(qs,(0,n-count))
        products=qs.astype(object)*b;assert w['quotient']==qs.tolist() and w['offset']==[b-1] and w['low']==[int(x)&MASK for x in products]
        if 'high' in v['ranges']:assert w['high']==[int(x)>>64 for x in products]
        carry=np.zeros(n,dtype=np.int64);all_carry=[];out=[]
        for k in range(16):
            column=(padded&255)*((b>>(8*k))&255)
            if k:column+=(padded>>8)*((b>>(8*(k-1)))&255)
            total=column+carry;out.extend((total%256).tolist());carry=total//256;all_carry.extend(carry.tolist())
        assert not carry.any()
        for g in range(4):
            name='carry_'+str(g);values=all_carry[4*g*n:4*(g+1)*n]
            if name in v['ranges']:assert w[name]==values
            else:assert not any(values)
        assert out==[int(x)>>(8*k)&255 for k in range(16) for x in np.pad(products,(0,n-count))]
        assert all(0<=x<=cap for name in w for x,cap in zip(w[name],v['ranges'][name].caps))
        digest.update(v['raw']+b.to_bytes(16,'little')+bytes(out)+b''.join(x.to_bytes(2,'little') for x in all_carry));cells+=16*n
    p=spec(16384,(1<<44)-1,2);v=c.derive(p,8)
    assert v['columns']==16 and v['cert']['carry_caps']==(0,254,382,382,382,382,382,382,382,382,382,382,132,2,0)
    assert max(v['cert']['lhs']+v['cert']['rhs'])==98047 and len(v['ranges'])==8
    assert all(r.derive(child,8)[2]*r.derive(child,8)[3]<=131072 and r.lookup_plan(child,8)['m']<=18 for child in v['ranges'].values())
    for f in range(31):
        for g in range(31):
            p=replace(spec(),schema=c.norm.Spec(3,f,g,(f+g)%15,1,3));v=c.derive(p,4);assert v['columns'] in (4,8,16)
    p=spec();v=c.derive(p,4)
    for bad in (replace(p,identity=1<<44),replace(p,repetitions=True),replace(p,quotient=p.output),replace(p,divisor=v['base']),replace(p,schema=replace(p.schema,E=True))):rejects('Spec',lambda:c.derive(bad,4))
    rejects('Spec',lambda:c.derive(spec(16385),4));rejects('Spec',lambda:c.derive(p,True))
    for qs,b in (([False]*3,1),([32769]*3,1),([0],1),([0]*3,0),([0]*3,(1<<90)+1),([0]*3,True)):rejects('Input',lambda:c.witness(p,qs,b))
    assert digest.hexdigest()=='9070ddcc675628bc070b46e26f5c548aa7a2b9c554682066ab9c04557bb2197b'
    print(json.dumps(dict(seed=2718,cases=10000,column_cells=cells,sha256=digest.hexdigest()),sort_keys=True),flush=True)


def account(p,out,d):
    v=c.derive(p,d);a=v['a'];bs={name:r.derive(child,d)[1] for name,child in v['ranges'].items()};h=int('high' in bs);g=sum(name.startswith('carry_') for name in bs);x=1+bs['offset']+bs['low']+bs.get('high',0)+sum(b for name,b in bs.items() if name.startswith('carry_'));cc=(v['columns']-1).bit_length()
    dims=[a+2,bs['offset']+1,a+bs['low']+1]+([a+bs['high']+1] if h else [])+[a+b+3 for name,b in bs.items() if name.startswith('carry_')];f=lambda m:3*m*(m-1)//2+2*m
    assert out['account']==dict(identities=[((1<<m)+255,p.repetitions) for m in dims],lookup_reduction_numerator=sum(p.repetitions*(f(m)+f(8)+3*m) for m in dims),range_reduction_numerator=(21+9*h+9*g)*a+7*x+18*g+3*cc,denominator=r.sc.P**d)
    assert len(out['claims'])==7 and out['draws']=={r.zc.WEIGHT:a+cc,r.zc.tr.CHALLENGE:a+cc}
    assert all(sum(row.get(label,0) for row in [out['draws']]+[child['draws'] for child in out['children']])==(9+4*h+4*g)*a+3*x+8*g+cc for label in (r.zc.WEIGHT,r.zc.tr.CHALLENGE))


def honest(maximum=False):
    digest=hashlib.sha256();count=0;cases=((1,0,0,14,1),(3,17,17,14,1<<40),(16,30,30,0,(1<<90)-1),(65,30,30,0,1<<90))
    for d,reps in (((4,1),) if maximum else ((4,1),(4,2),(8,1),(8,2))):
        for size,f,g,e,b in (((16384,30,30,0,1<<90),) if maximum else cases):
            p=replace(spec(size,2210+count,reps),schema=c.norm.Spec(size,f,g,e,1,3));qs=([32768,0,32767,1,255]*((size+4)//5))[:size]
            print('honest start',count+1,d,reps,size,flush=True);proof,state=c.prove(p,qs,b,d);out=c.verify(p,c.expected_roots(p,qs,b,[q*b for q in qs]),proof,d)
            assert out['state']==state;account(p,out,d);digest.update(state);count+=1;print('honest passed',count,d,reps,size,flush=True)
    print(json.dumps(dict(maximum=maximum,proofs=count,sha256=digest.hexdigest()),sort_keys=True),flush=True)


def controls():
    p=spec();d=4;qs=[32768,0,255];b=(1<<80)+3;v=c.derive(p,d);pairs=c.prepare(p,qs,b,d);proof,state=c.assemble(p,pairs,d);roots=c.expected_roots(p,qs,b,[q*b for q in qs]);w=c.witness(p,qs,b)
    assert c.verify(p,roots,proof,d)['state']==state
    for name in v['ranges']:
        bad=copy.deepcopy(proof);bad[name]['words'][0]^=1;rejects(name.title()+':CommitmentMismatch',lambda:c.verify(p,roots,bad,d))
    for name,index,delta in (('low',0,1),('low',1,r.sc.P),('high',1,1)):
        values=w[name].copy();values[index]+=delta;changed=dict(pairs);changed[name]=r.prove(v['ranges'][name],values,d);bad,_=c.assemble(p,changed,d)
        rejects('ProductColumns:RoundSumMismatch',lambda:c.verify(p,c.roots(p,bad),bad,d))
    for name in (key for key in v['ranges'] if key.startswith('carry_')):
        values=w[name].copy();values[0]^=1;changed=dict(pairs);changed[name]=r.prove(v['ranges'][name],values,d);bad,_=c.assemble(p,changed,d)
        rejects('ProductColumns:RoundSumMismatch',lambda:c.verify(p,roots,bad,d))
    bad=copy.deepcopy(proof);bad['zero']['final'][4][0]=r.sc.add(bad['zero']['final'][4][0],r.sc.scalar(256,d));bad['zero']['final'][6][0]=r.sc.add(bad['zero']['final'][6][0],r.sc.scalar(1,d))
    rejects('ProductColumns:ClaimMismatch',lambda:c.verify(p,roots,bad,d))
    zero=spec(1,2230);bad,_=c.prove(zero,[0],1,d);bad['zero']['final'][2][0]=r.sc.add(bad['zero']['final'][2][0],r.sc.scalar(1,d))
    rejects('ProductColumns:ClaimMismatch',lambda:c.verify(zero,c.expected_roots(zero,[0],1,[0]),bad,d))
    bad,_=c.prove(zero,[0],2,d);rejects('Divisor:CommitmentMismatch',lambda:c.verify(zero,c.expected_roots(zero,[0],1,[0]),bad,d))
    zeros=c.prepare(p,[0]*3,1,d);zeros['low']=r.prove(v['ranges']['low'],[1,0,0],d);zeros['high']=r.prove(v['ranges']['high'],[v['cert']['result_max']>>64,0,0],d);bad,_=c.assemble(p,zeros,d)
    rejects('ProductColumns:RoundSumMismatch',lambda:c.verify(p,c.roots(p,bad),bad,d))
    rejects('ProofShape',lambda:c.verify(p,roots,dict(proof,certificate={}),d));rejects('Root',lambda:c.verify(p,[False]*3,proof,d))
    print('false products/carries, p-alias, split-bound forgery and zero-hidden originals reject',flush=True)


def boundaries():
    p=spec(3,2240);d=4;qs=[32768,0,1];b=1<<90;v=c.derive(p,d);pairs=c.prepare(p,qs,b,d);proof,_=c.assemble(p,pairs,d);roots=c.roots(p,proof);w=c.witness(p,qs,b);n=v['n']
    for name,index in (('carry_0',n-1),('carry_3',n),('carry_3',2*n)):
        child=v['ranges'][name];caps=list(child.caps);values=w[name].copy();caps[index]=values[index]=1;badpair=r.assemble(child,*r.witness(replace(child,caps=tuple(caps)),values),d);changed=dict(pairs);changed[name]=badpair;bad,_=c.assemble(p,changed,d)
        rejects(name.title()+':CapRelation:RoundSumMismatch',lambda:c.verify(p,roots,bad,d))
    for name in ('quotient','low','high'):
        bad=copy.deepcopy(proof);bad[name]['words'][n-1]=1;rejects(name.title()+':CommitmentMismatch',lambda:c.verify(p,roots,bad,d))
    child=v['ranges']['offset'];badpair=r.assemble(child,*r.witness(replace(child,caps=(b,)),[b]),d);bad,_=c.assemble(p,dict(pairs,offset=badpair),d)
    rejects('Offset:CapRelation:RoundSumMismatch',lambda:c.verify(p,c.roots(p,bad),bad,d))
    small=replace(spec(1,2241),schema=c.norm.Spec(1,0,0,14,1,3));bad,_=c.prove(small,[0],1,d);rejects('ProofShape',lambda:c.verify(small,c.expected_roots(small,[0],1,[0]),dict(bad,high={}),d))
    print('padded sources/carries, zero endpoints, offset overflow and unexpected families reject',flush=True)


def composition():
    import signed_source as signed
    import norm_output_factors as factors
    p=spec(3,2250);d=4;ys=[-32768,0,255];qs=list(map(abs,ys));b=1<<90;proof,state=c.prove(p,qs,b,d);roots=c.expected_roots(p,qs,b,[q*b for q in qs])
    sp=signed.Spec(2251,269,p.quotient,16,3,1);source,st=signed.prove(sp,ys,d);sv=signed.derive(sp,d);raw=r.source_root(sv['ranges'][0],source['ranges'][0]['words'])
    assert signed.verify(sp,[raw,roots[0]],source,d)['state']==st
    fp=factors.Spec(p.schema,2252,271,277,281,283,293,1);child,st=factors.prove(fp,0,9,d);fc=c.norm.constants(p.schema);fr=factors.expected_roots(fp,0,9,0,fc['P']<<18,child['factors'])
    assert factors.verify(fp,fr,child,d)['state']==st;roots[1]=r.root(p.divisor,child['factors'][2:18]);assert c.verify(p,roots,proof,d)['state']==state
    bad,_=c.prove(p,qs,b//2,d);rejects('Divisor:CommitmentMismatch',lambda:c.verify(p,roots,bad,d))
    print('actual signed-Y magnitude and verified factor bytes compose; substituted divisor rejects',flush=True)


def middle():
    digest=hashlib.sha256()
    for index,(d,reps) in enumerate(((4,1),(4,2),(8,1),(8,2))):
        p=replace(spec(5,2260+index,reps),schema=c.norm.Spec(5,10,0,14,1,3));qs=[32768,0,255,1,32767];b=(1<<26)-1
        assert c.derive(p,d)['columns']==8
        proof,state=c.prove(p,qs,b,d);out=c.verify(p,c.expected_roots(p,qs,b,[q*b for q in qs]),proof,d)
        assert out['state']==state;account(p,out,d);digest.update(state);print('middle passed',d,reps,flush=True)
    print(json.dumps(dict(middle_proofs=4,sha256=digest.hexdigest()),sort_keys=True),flush=True)


if __name__=='__main__':
    modes={'--corpus':corpus,'--honest':honest,'--maximum':lambda:honest(True),'--controls':controls,'--boundaries':boundaries,'--composition':composition,'--middle':middle}
    if sys.argv[1:]:
        assert all(mode in modes for mode in sys.argv[1:])
        for mode in sys.argv[1:]:modes[mode]()
    else:
        for test in modes.values():test()
