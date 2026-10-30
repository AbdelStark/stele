# /// script
# requires-python = ">=3.12"
# dependencies = ["numpy==2.3.4", "blake3==1.0.11", "python-flint==0.9.0"]
# ///
"""RFC-0022 output division: complete children and independent strict remainder."""
import copy
from dataclasses import replace
import hashlib
import json
import random
import sys
import numpy as np
import norm_division as c
from check_norm_quotient_product import account as quotient_account
from check_norm_bias import account as bias_account

r=c.r
MASK=(1<<64)-1


def rejects(reason,call):
    try:call()
    except ValueError as error:assert str(error)==reason,(reason,str(error))
    else:raise AssertionError('accepted '+reason)


def spec(count=3,identity=2400,repetitions=1):
    return c.Spec(c.norm.Spec(count,30,30,0,1,3),identity,367,373,379,383,389,397,401,repetitions)


def corpus():
    rng=random.Random(2720);digest=hashlib.sha256();cells=0
    for case in range(10000):
        count=1+case%63;p=replace(spec(count,case,1+case%2),schema=c.norm.Spec(count,rng.randrange(31),rng.randrange(31),rng.randrange(15),1,3));v=c.derive(p,4)
        b=1<<rng.randrange(v['limit'].bit_length());h=b//2;maximum=min(1<<44,32768*b-h)
        ts=[rng.randrange(maximum+1) for _ in range(count)];ts[0]=(0,maximum)[case%2];qs=[(t+h)//b for t in ts];rs=[(t+h)%b for t in ts];w=c.witness(p,ts,h,qs,b,rs);n=v['n']
        for prefix,xs in (('remainder',rs),('gap',[b-1-x for x in rs])):
            assert w[prefix+'_low']==[x&MASK for x in xs]
            if prefix+'_high' in w:assert w[prefix+'_high']==[x>>64 for x in xs]
        for prefix,left,right,first,expected in (('equal',[q*b for q in qs],rs,0,[t+h for t in ts]),('strict',rs,[b-1-x for x in rs],1,[b]*count)):
            carry=np.array([first]*count+[0]*(n-count),dtype=np.int64);all_carry=[];out=[]
            for k in range(16):
                low=np.array([x>>(8*k)&255 for x in left]+[0]*(n-count),dtype=np.int64);high=np.array([x>>(8*k)&255 for x in right]+[0]*(n-count),dtype=np.int64)
                total=low+high+carry;out.extend((total%256).tolist());carry=total//256;all_carry.extend(carry.tolist())
            assert not carry.any() and out==[x>>(8*k)&255 for k in range(16) for x in expected+[0]*(n-count)]
            for g in range(4):
                name=prefix+'_'+str(g);values=all_carry[4*g*n:4*(g+1)*n]
                if name in w:assert w[name]==values
                else:assert not any(values)
            digest.update(bytes(out)+bytes(all_carry));cells+=16*n
        assert all(0<=x<=cap for name in w for x,cap in zip(w[name],v['ranges'][name].caps));digest.update(v['raw'])
    v=c.derive(spec(16384,(1<<40)-1,2),8);assert len(v['ranges'])==11 and v['equal_caps'][14:]==[0,0,0] and v['strict_caps'][12:]==[0]*5
    assert all(r.derive(child,8)[2]*r.derive(child,8)[3]<=131072 and r.lookup_plan(child,8)['m']<=18 for child in v['ranges'].values())
    p=spec();v=c.derive(p,4)
    for bad in (replace(p,identity=1<<40),replace(p,repetitions=True),replace(p,divisor=p.bias),replace(p,remainder=v['base']),replace(p,schema=replace(p.schema,E=True))):rejects('Spec',lambda:c.derive(bad,4))
    rejects('Spec',lambda:c.derive(spec(16385),4));rejects('Spec',lambda:c.derive(p,True))
    for ts,h,qs,b,rs in (([0]*3,0,[0]*3,1,[1]*3),([0]*3,0,[False]*3,1,[0]*3),([0]*3,0,[0]*3,0,[0]*3),([1]*3,0,[0]*3,1,[0]*3)):
        rejects('Input',lambda:c.witness(p,ts,h,qs,b,rs))
    assert cells==13534880 and digest.hexdigest()=='3edca88f2b7d996e38f91dddb1bcfc89ea62883d549c23c3ec41795e68e1f291'
    print(json.dumps(dict(seed=2720,cases=10000,column_cells=cells,sha256=digest.hexdigest()),sort_keys=True),flush=True)


def account(p,out,d):
    v=c.derive(p,d);quotient_account(v['quotient_product'],out['children'][0],d);bias_account(v['bias'],out['children'][1],d)
    a=v['a'];bs={name:r.derive(child,d)[1] for name,child in v['ranges'].items()};h=int('remainder_high' in bs);bl=bs['remainder_low'];bh=bs.get('remainder_high',0);g=len(bs)-2*(1+h);f=lambda m:3*m*(m-1)//2+2*m
    dims=([a+bl+1]+([a+bh+1] if h else []))*2+[a+3]*g;children=[item['account'] for item in out['children']]
    assert out['account']==dict(identities=sum((item['identities'] for item in children),[])+[((1<<m)+255,p.repetitions) for m in dims],lookup_reduction_numerator=sum(item['lookup_reduction_numerator'] for item in children)+sum(p.repetitions*(f(m)+f(8)+3*m) for m in dims),range_reduction_numerator=sum(item['range_reduction_numerator'] for item in children)+(22+18*h+9*g)*a+14*(bl+h*bh)+18*g+16,denominator=r.sc.P**d)
    assert len(out['claims'])==10 and out['draws']=={r.zc.WEIGHT:2*(a+4),r.zc.tr.CHALLENGE:2*(a+4)}
    for label in (r.zc.WEIGHT,r.zc.tr.CHALLENGE):assert sum(row.get(label,0) for row in [out['draws']]+[part['draws'] for part in out['ranges']])==(10+8*h+4*g)*a+6*(bl+h*bh)+8*g+8


def honest(maximum=False):
    digest=hashlib.sha256();count=0;cases=((1,0,0,14,1),(3,30,4,0,257),(16,30,3,0,1<<32),(65,30,30,0,1<<90))
    for d,reps in (((4,1),) if maximum else ((4,1),(4,2),(8,1),(8,2))):
        for size,f,g,e,b in (((16384,30,30,0,1<<90),) if maximum else cases):
            p=replace(spec(size,2410+count,reps),schema=c.norm.Spec(size,f,g,e,1,3));h=b//2;limit=min(1<<44,32768*b-h);ts=([limit,0,min(limit,255),min(limit,b-h),min(limit,b-h-1)]*((size+4)//5))[:size];qs=[(t+h)//b for t in ts];rs=[(t+h)%b for t in ts]
            print('honest start',count+1,d,reps,size,flush=True);proof,state=c.prove(p,ts,h,qs,b,rs,d);out=c.verify(p,c.expected_roots(p,ts,h,qs,b,rs),proof,d)
            assert out['state']==state;account(p,out,d);digest.update(state);count+=1;print('honest passed',count,d,reps,size,flush=True)
    if not maximum:assert digest.hexdigest()=='73f9d46b9eab59475258efa04699038da74df1738539f94ea3ef4131b515bfb8'
    print(json.dumps(dict(maximum=maximum,proofs=count,sha256=digest.hexdigest()),sort_keys=True),flush=True)


def controls():
    p=spec();d=4;ts=[128,129,1000];h=128;b=257;qs=[0,1,4];rs=[256,0,100];v=c.derive(p,d);w=c.witness(p,ts,h,qs,b,rs);pairs=c.prepare(p,ts,h,qs,b,rs,d);proof,state=c.assemble(p,pairs,d);roots=c.expected_roots(p,ts,h,qs,b,rs)
    assert c.verify(p,roots,proof,d)['state']==state
    for name in v['ranges']:
        bad=copy.deepcopy(proof);bad[name]['words'][0]^=1;rejects(name.title()+':CommitmentMismatch',lambda:c.verify(p,roots,bad,d))
    for name in (name for name in v['ranges'] if name.startswith(('equal_','strict_'))):
        values=w[name].copy();values[0]^=1;changed=dict(pairs);changed[name]=r.prove(v['ranges'][name],values,d);bad,_=c.assemble(p,changed,d)
        rejects(('Equality' if name.startswith('equal_') else 'StrictRemainder')+':RoundSumMismatch',lambda:c.verify(p,roots,bad,d))
    changed=dict(pairs)
    for name,delta in (('remainder_low',1),('gap_low',-1)):
        values=w[name].copy();values[1]+=delta;changed[name]=r.prove(v['ranges'][name],values,d)
    bad,_=c.assemble(p,changed,d);rejects('Equality:RoundSumMismatch',lambda:c.verify(p,c.roots(p,bad),bad,d))
    changed=dict(pairs);changed['bias']=c.bias.prove(v['bias'],[129,129,1000],h,d);values=w['remainder_low'].copy();values[0]+=1;changed['remainder_low']=r.prove(v['ranges']['remainder_low'],values,d);bad,_=c.assemble(p,changed,d)
    rejects('StrictRemainder:RoundSumMismatch',lambda:c.verify(p,c.roots(p,bad),bad,d))
    for index,left,right in ((0,0,3),(1,0,1)):
        bad=copy.deepcopy(proof);bad['zero'][index]['final'][left][0]=r.sc.add(bad['zero'][index]['final'][left][0],r.sc.scalar(1,d));delta=1 if index==0 else -1;bad['zero'][index]['final'][right][0]=r.sc.add(bad['zero'][index]['final'][right][0],r.sc.scalar(delta,d))
        rejects(('Equality' if index==0 else 'StrictRemainder')+':ClaimMismatch',lambda:c.verify(p,roots,bad,d))
    bad=copy.deepcopy(proof);bad['quotient_product']['quotient']['words'][0]=1;rejects('QuotientProduct:Quotient:CommitmentMismatch',lambda:c.verify(p,roots,bad,d))
    bad=copy.deepcopy(proof);bad['bias']['product']['words'][0]^=1;rejects('Bias:Product:CommitmentMismatch',lambda:c.verify(p,roots,bad,d))
    child=v['quotient_product'];qparts=c.qp.prepare(child,qs,b,d);values=[q*b for q in qs];values[0]=1;qv=c.qp.derive(child,d);qparts['low']=r.prove(qv['ranges']['low'],values,d);bad,_=c.assemble(p,dict(pairs,quotient_product=c.qp.assemble(child,qparts,d)),d)
    rejects('QuotientProduct:ProductColumns:RoundSumMismatch',lambda:c.verify(p,c.roots(p,bad),bad,d))
    for key in ('mask','certificate','receipt'):rejects('ProofShape',lambda:c.verify(p,roots,dict(proof,**{key:{}}),d))
    bad=copy.deepcopy(proof);bad['zero'][1]['rounds'][0][0]=(False,0,0,0);rejects('NoncanonicalField',lambda:c.verify(p,roots,bad,d))
    print('false equality, equality-preserving r=B, carry/original/source and nested-child controls reject',flush=True)


def boundaries():
    p=spec(3,2440);d=4;ts=[0,1,255];h=1<<89;b=1<<90;qs=[0]*3;rs=[t+h for t in ts];v=c.derive(p,d);w=c.witness(p,ts,h,qs,b,rs);pairs=c.prepare(p,ts,h,qs,b,rs,d);proof,_=c.assemble(p,pairs,d);roots=c.roots(p,proof);n=v['n']
    for name,index in (('equal_0',n-1),('strict_0',n-1),('equal_3',n),('strict_2',3*n)):
        child=v['ranges'][name];caps=list(child.caps);values=w[name].copy();caps[index]=values[index]=1;changed=dict(pairs);changed[name]=r.assemble(child,*r.witness(replace(child,caps=tuple(caps)),values),d);bad,_=c.assemble(p,changed,d)
        rejects(name.title()+':CapRelation:RoundSumMismatch',lambda:c.verify(p,roots,bad,d))
    for name in ('remainder_low','remainder_high','gap_low','gap_high'):
        bad=copy.deepcopy(proof);bad[name]['words'][n-1]=1;rejects(name.title()+':CommitmentMismatch',lambda:c.verify(p,roots,bad,d))
    expected=roots.copy();words=c.wide_words(v,proof,'remainder');words[15*n]=1;expected[6]=r.root(p.remainder,words);rejects('Remainder:CommitmentMismatch',lambda:c.verify(p,expected,proof,d))
    print('ragged wide remainder, masked scalar/one, padded and terminal carries, and high roots checked',flush=True)


def aliases():
    for shift in range(16,91):
        f,g,e=(0,0,30-shift) if shift<30 else (min(30,shift-30),max(0,shift-60),0)
        p=replace(spec(),schema=c.norm.Spec(3,f,g,e,1,3));v=c.derive(p,4)
        for prefix in ('remainder','gap'):
            low=v['ranges'][prefix+'_low'].caps[0];high=v['ranges'][prefix+'_high'].caps[0] if prefix+'_high' in v['ranges'] else 0
            assert low+(high<<64)==(1<<shift)-1 and bool(high)==(shift>64)
        assert v['equal_caps'][-1]==v['strict_caps'][-1]==0
    p=spec(3,2445);d=4;ts=[0,1,255];h=1<<89;b=1<<90;qs=[0]*3;rs=[t+h for t in ts];v=c.derive(p,d);w=c.witness(p,ts,h,qs,b,rs);pairs=c.prepare(p,ts,h,qs,b,rs,d)
    for name,delta in (('remainder_low',r.sc.P),('gap_low',-r.sc.P)):
        values=w[name].copy();values[0]+=delta;pairs[name]=r.prove(v['ranges'][name],values,d)
    bad,_=c.assemble(p,pairs,d);rejects('Equality:RoundSumMismatch',lambda:c.verify(p,c.roots(p,bad),bad,d))
    print('all75 split-bound transitions and strict-preserving remainder+p forgery checked',flush=True)


def composition():
    import norm_output_factors as factors
    p=spec(3,2450);d=4;ts=[0,255,1<<44];h=1<<89;b=1<<90;qs=[0]*3;rs=[t+h for t in ts];proof,state=c.prove(p,ts,h,qs,b,rs,d);roots=c.expected_roots(p,ts,h,qs,b,rs)
    fp=factors.Spec(p.schema,2451,409,419,421,431,433,1);child,st=factors.prove(fp,0,9,d);fc=c.norm.constants(p.schema);fr=factors.expected_roots(fp,0,9,0,fc['P']<<18,child['factors']);assert factors.verify(fp,fr,child,d)['state']==st
    roots[1]=r.root(p.divisor,child['factors'][2:18]);roots[4]=r.root(p.bias,child['factors'][18:34]);assert c.verify(p,roots,proof,d)['state']==state
    bad,_=c.prove(p,ts,h,qs,b-1,rs,d);rejects('QuotientProduct:Divisor:CommitmentMismatch',lambda:c.verify(p,roots,bad,d))
    print('one verified factor source supplies actual B/h; zero-quotient divisor substitution rejects',flush=True)


if __name__=='__main__':
    modes={'--corpus':corpus,'--honest':honest,'--maximum':lambda:honest(True),'--controls':controls,'--boundaries':boundaries,'--composition':composition,'--aliases':aliases}
    if sys.argv[1:]:
        assert all(mode in modes for mode in sys.argv[1:])
        for mode in sys.argv[1:]:modes[mode]()
    else:
        for test in modes.values():test()
