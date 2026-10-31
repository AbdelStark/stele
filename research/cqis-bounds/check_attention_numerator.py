# /// script
# requires-python = ">=3.12"
# dependencies = ["numpy==2.3.4", "blake3==1.0.11", "python-flint==0.9.0"]
# ///
"""Draft RFC-0004 A3/A6: full-width scaled attention magnitudes and controls."""
import copy
from dataclasses import replace
import hashlib
import json
import random
import sys
import numpy as np
import attention_numerator as c

r=c.r


def rejects(reason,call):
    try:call()
    except ValueError as error:assert str(error)==reason,(reason,str(error))
    else:raise AssertionError('accepted '+reason)


def spec(width=3,identity=6600,repetitions=1):
    return c.Spec(c.bounds.Spec(65,width,3,8,8,'static',1,'exact',0),identity,9301,9307,repetitions)


def oracle(p,ms):
    n=1<<(p.schema.width-1).bit_length();shift=max(p.schema.output_fraction-p.schema.fraction+p.schema.drop,0);us=(np.array(ms,dtype=object)*(1<<shift)).tolist()
    def planes(xs,wide):
        low=np.array([x&((1<<64)-1) for x in xs]+[0]*(n-len(xs)),dtype='<u8');rows=np.frombuffer(low.tobytes(),dtype=np.uint8).reshape(n,8).T
        if wide:
            high=np.array([x>>64 for x in xs]+[0]*(n-len(xs)),dtype='<u8');rows=np.concatenate((rows,np.frombuffer(high.tobytes(),dtype=np.uint8).reshape(n,8).T))
        return rows.reshape(-1).tolist()
    return us,[r.root(p.source,planes(ms,False)),r.root(p.output,planes(us,True))]


def corpus():
    rng=random.Random(2743);digest=hashlib.sha256();cells=zeros=0;shifts=set();widths=set();groups=set()
    def check(p,ms):
        nonlocal cells,zeros
        v=c.derive(p,4);w=c.witness(p,ms);us,roots=oracle(p,ms);n=v['n'];q,rem=divmod(v['shift'],8);assert c.expected_roots(p,ms)==roots and w['source']==ms
        assert [x for j in range(v['groups']) for x in w['output_'+str(j)]]==us
        m=ms+[0]*(n-len(ms));u=us+[0]*(n-len(us));carry=np.array([0]*n,dtype=np.int64);cs=[]
        for k in range(16):
            source=np.array([x>>(8*(k-q))&255 if 0<=k-q<8 else 0 for x in m],dtype=np.int64);total=(1<<rem)*source+carry;byte=total%256;carry=total//256
            assert byte.tolist()==[x>>(8*k)&255 for x in u];cs.extend(carry.tolist())
        assert cs==sum((w['carry_'+str(j)] for j in range(4)),[]) and cs[-n:]==[0]*n
        assert all(0<=x<=cap for name,child in v['ranges'].items() for x,cap in zip(w[name],child.caps))
        assert all(r.derive(child,4)[2]*r.derive(child,4)[3]<=131072 for child in v['ranges'].values())
        shaped={name:{'words':r.witness(child,w[name])[0]} for name,child in v['ranges'].items()};assert c.roots(p,shaped)==roots
        digest.update(v['raw']+b''.join(roots)+bytes(cs));cells+=len(ms);zeros+=not v['constants']['total_max'];shifts.add(v['shift']);widths.add((v['bm'],v['bu']));groups.add(v['groups'])
    for case in range(10000):
        width=1+case%65;length=rng.choice((1,3,1024,1025,1<<20));E=case%15;mode='block1024' if case%2 else 'exact';policy='dynamic' if case%4<2 else 'static';scale=0 if policy=='dynamic' else rng.choice((1,2,259,65535));fv=case%31;fo=(case//31)%31
        S=127*259 if policy=='dynamic' else scale*min(127,(65536+scale)//(2*scale));H=1024*(1<<E)*S;minimum=next(k for k in range(63) if (H+(1<<k)//2)//(1<<k)<=32767);drop=0 if mode=='exact' else minimum+case%(63-minimum)
        if case<93:mode='block1024';policy='static';scale=1;E=0;drop=max(2,case-30);fv=max(drop-case,0);fo=max(case-drop,0)
        p=replace(spec(width,case,1+case%2),schema=c.bounds.Spec(length,width,fv,fo,E,policy,scale,mode,drop));v=c.derive(p,4);cap=v['constants']['total_max'];ms=[rng.randrange(cap+1) for _ in range(width)]
        for j,x in enumerate((0,cap,max(0,cap-1))[:width]):ms[j]=x
        check(p,ms)
    for width in (8193,16384):
        p=replace(spec(width,(1<<48)-1,2),schema=c.bounds.Spec(1<<20,width,0,30,14,'static',65535,'exact',0));v=c.derive(p,8);assert v['groups']==2 and v['bu']==4;check(p,[v['constants']['total_max']*(i%2) for i in range(width)])
        spans=sorted((r.derive(child,8)[4],64) for child in v['ranges'].values());assert all(v['base']+19<lo and lo+size<=v['base']+(1<<14) for lo,size in spans) and all(lo+size<=nxt for (lo,size),(nxt,_) in zip(spans,spans[1:]))
    p=spec();v=c.derive(p,4)
    for bad in (replace(p,identity=1<<48),replace(p,repetitions=True),replace(p,source=p.output),replace(p,output=v['base']),replace(p,schema=replace(p.schema,width=16385)),replace(p,schema=replace(p.schema,drop=1))):rejects('Spec',lambda:c.derive(bad,4))
    rejects('Spec',lambda:c.derive(p,True))
    for ms in ([False]*3,[-1]*3,[v['constants']['total_max']+1]*3,[0]):rejects('Input',lambda:c.witness(p,ms))
    assert shifts==set(range(93)) and groups=={1,2} and zeros>1000 and any(bu==4 for _,bu in widths)
    print(json.dumps(dict(seed=2743,cases=10000,capacity_cases=2,cells=cells,zero_bound_cases=zeros,widths=sorted(widths),sha256=digest.hexdigest()),sort_keys=True),flush=True)


def account(p,out,d):
    v=c.derive(p,d);a,bm,bu,G=v['a'],v['bm'],v['bu'],v['groups'];dims=[a+bm+1]+[a-(G-1)+bu+1]*G+[a+3]*4;f=lambda m:3*m*(m-1)//2+2*m
    total=56*a+7*(bm+bu)+80 if G==1 else 65*a+7*bm+14*bu+62;draws=25*a+36+3*(bm+bu) if G==1 else 29*a+28+3*bm+6*bu
    assert out['account']==dict(identities=[((1<<m)+255,p.repetitions) for m in dims],lookup_reduction_numerator=sum(p.repetitions*(f(m)+f(8)+3*m) for m in dims),range_reduction_numerator=total,denominator=r.sc.P**d)
    assert out['draws']=={r.zc.WEIGHT:a+4,r.zc.tr.CHALLENGE:a+4} and [claim[0] for claim in out['claims']]==[v['base']+j for j in range(16,20)] and [x['numerator'] for x in out['sc']]==[a+4,0,a+4]
    for label in (r.zc.WEIGHT,r.zc.tr.CHALLENGE):assert sum(child['draws'].get(label,0) for child in [out]+out['children'])==draws


def honest(mode='matrix'):
    digest=hashlib.sha256();done=0;cases=((1,1,0,30,0,'block1024',62,1),(3,65,3,8,8,'exact',0,1),(16,1025,30,0,0,'block1024',2,1),(65,1<<20,0,30,14,'exact',0,65535))
    if mode=='maximum':cases=((16384,1<<20,0,30,14,'exact',0,65535),)
    if mode=='full-identity':cases=((16384,1<<20,30,0,14,'exact',0,1),)
    for d,reps in (((4,1),) if mode!='matrix' else ((4,1),(4,2),(8,1),(8,2))):
        for width,length,fv,fo,E,acc,drop,scale in cases:
            p=replace(spec(width,6610+done,reps),schema=c.bounds.Spec(length,width,fv,fo,E,'static',scale,acc,drop));v=c.derive(p,d);cap=v['constants']['total_max'];ms=[(0,cap,max(0,cap-1),1 if cap else 0)[(i+i//v['group_n'])%4] for i in range(width)]
            print('honest start',done+1,d,reps,width,v['groups'],v['shift'],flush=True);proof,state=c.prove(p,ms,d);roots=oracle(p,ms)[1];out=c.verify(p,roots,proof,d);assert out['state']==state;account(p,out,d);digest.update(state);done+=1;print('honest passed',done,d,reps,width,v['groups'],v['shift'],flush=True)
            if mode=='maximum':
                assert v['groups']==2;words=c.output_words(v,proof);wrong=[x for g in range(2) for k in range(16) for x in words[k*v['n']+g*v['group_n']:k*v['n']+(g+1)*v['group_n']]];assert wrong!=words;rejects('Numerator:CommitmentMismatch',lambda:c.verify(p,[roots[0],r.root(p.output,wrong)],proof,d));print('full group-major output substitution rejects the plane-major external root',flush=True)
    print(json.dumps(dict(mode=mode,proofs=done,sha256=digest.hexdigest()),sort_keys=True),flush=True)


def controls():
    p=spec();d=4;v=c.derive(p,d);ms=[0,17,257];w=c.witness(p,ms);pairs=c.prepare(p,ms,d);proof,state=c.assemble(p,pairs,d);roots=oracle(p,ms)[1];out=c.verify(p,roots,proof,d);assert out['state']==state;account(p,out,d)
    for index,name in enumerate(('Magnitude','Numerator')):
        bad=roots.copy();bad[index]=bytes(32);rejects(name+':CommitmentMismatch',lambda:c.verify(p,bad,proof,d))
    for name in v['ranges']:
        bad=copy.deepcopy(proof);bad[name]['words'][0]^=1;rejects(name.title()+':CommitmentMismatch',lambda:c.verify(p,roots,bad,d));bad=copy.deepcopy(proof);bad['roots'][name]=bytes(32);rejects(name.title()+':CommitmentMismatch',lambda:c.verify(p,roots,bad,d))
    for name in ('source','output_0','carry_0'):
        values=w[name].copy();values[0]+=1;bad,_=c.assemble(p,dict(pairs,**{name:r.prove(v['ranges'][name],values,d)}),d);rejects('Shift:RoundSumMismatch',lambda:c.verify(p,c.roots(p,bad),bad,d))
    zp,zs=c.prove(p,[0]*3,d);zr=c.roots(p,zp);assert c.verify(p,zr,zp,d)['state']==zs
    for changes in (((0,1),(2,v['c'])),((1,1),(2,1)),((2,256),(3,-1)),((3,1),(1,256))):
        bad=copy.deepcopy(zp)
        for column,delta in changes:bad['zero'][0]['final'][column][0]=r.sc.add(bad['zero'][0]['final'][column][0],r.sc.scalar(delta,d))
        rejects('Shift:ClaimMismatch',lambda:c.verify(p,zr,bad,d))
    other=replace(p,schema=replace(p.schema,fraction=4,output_fraction=9));rejects('Shift:RoundSumMismatch',lambda:c.verify(other,roots,proof,d))
    for key in ('receipt','certificate','shift','group'):rejects('ProofShape',lambda:c.verify(p,roots,dict(proof,**{key:{}}),d))
    bad=copy.deepcopy(proof);bad['zero'][0]['rounds'][0][0]=(False,0,0,0);rejects('NoncanonicalField',lambda:c.verify(p,roots,bad,d));rejects('Root',lambda:c.verify(p,roots[:-1],proof,d))
    print('external/internal roots, complete children, false source/output/carry, metadata replay and all four compensated original views reject',flush=True)


def boundaries():
    p=spec(identity=6640);d=4;v=c.derive(p,d);w=c.witness(p,[0]*3);pairs=c.prepare(p,[0]*3,d)
    for name,child in v['ranges'].items():
        for index in (0,p.schema.width,len(child.caps)-1):
            caps=list(child.caps);values=w[name].copy()
            if index==len(caps):caps.append(0);values.append(0)
            caps[index]+=1;values[index]=caps[index];pair=r.assemble(child,*r.witness(replace(child,caps=tuple(caps)),values),d);bad,_=c.assemble(p,dict(pairs,**{name:pair}),d);rejects(name.title()+':CapRelation:RoundSumMismatch',lambda:c.verify(p,c.roots(p,bad),bad,d))
    p=replace(spec(1,6641),schema=c.bounds.Spec(1<<20,1,0,30,14,'static',65535,'exact',0));v=c.derive(p,d);ms=[v['constants']['total_max']];pairs=c.prepare(p,ms,d);values=c.witness(p,ms)['output_0'];values[0]-=r.sc.P;assert values[0]>=0;bad,_=c.assemble(p,dict(pairs,output_0=r.prove(v['ranges']['output_0'],values,d)),d);rejects('Shift:RoundSumMismatch',lambda:c.verify(p,c.roots(p,bad),bad,d))
    p=replace(spec(1,6642),schema=c.bounds.Spec(1,1,0,30,0,'static',1,'block1024',62));v=c.derive(p,d);assert v['shift']==92 and v['constants']['total_max']==0;pairs=c.prepare(p,[0],d);proof,state=c.assemble(p,pairs,d);roots=oracle(p,[0])[1];out=c.verify(p,roots,proof,d);assert out['state']==state;account(p,out,d)
    for index,identity,width in ((0,p.source,8),(1,p.output,16)):
        words=[0]*width;words[-1]=1;bad=roots.copy();bad[index]=r.root(identity,words);rejects(('Magnitude','Numerator')[index]+':CommitmentMismatch',lambda:c.verify(p,bad,proof,d))
    child=v['ranges']['source'];pair=r.assemble(child,*r.witness(replace(child,caps=(1,)),[1]),d);bad,_=c.assemble(p,dict(pairs,source=pair),d);rejects('Source:CapRelation:FinalEvaluationMismatch',lambda:c.verify(p,c.roots(p,bad),bad,d))
    print('whole caps, dense padding, all carry endpoints, genuinely ranged U-p, full external high planes and zero-bound shift92 source reject',flush=True)


def composition():
    import attention_sign as raw
    import attention_block_total_sign as block
    for mode in ('exact','block1024'):
        p=replace(spec(identity=6650+(mode=='exact')),schema=c.bounds.Spec(65,3,3,8,0,'static',1,mode,0 if mode=='exact' else 2));d=4;cap=c.derive(p,d)['constants']['total_max'];offsets=[cap,cap-1,cap+2];ms=[0,1,2]
        if mode=='exact':
            schema=raw.bounds.Spec(65,3,3,0,'static',1,'exact');sp=raw.Spec(schema,6750,9401,9407,p.source,9413,1);prove=lambda values:raw.prove(sp,values,cap,d);expected=lambda values:raw.expected_roots(sp,values,cap,[abs(x-cap) for x in values],[int(x<cap) for x in values]);module=raw;index=2
        else:
            schema=block.bounds.Spec(65,3,3,0,'static',1,2);sp=block.Spec(schema,(0,),6751,9401,p.source,9413,1);prove=lambda values:block.prove(sp,values,d);expected=lambda values:block.expected_roots(sp,values);module=block;index=1
        child,st=prove(offsets);sr=expected(offsets);assert module.verify(sp,sr,child,d)['state']==st;proof,state=c.prove(p,ms,d);roots=oracle(p,ms)[1];assert roots[0]==sr[index] and c.verify(p,roots,proof,d)['state']==state
        changed=offsets.copy();changed[2]+=1;other,st=prove(changed);rr=expected(changed);assert module.verify(sp,rr,other,d)['state']==st;rejects('Magnitude:CommitmentMismatch',lambda:c.verify(p,[rr[index],roots[1]],proof,d));print('complete canonical magnitude source composes; valid changed magnitude rejects',mode,flush=True)


if __name__=='__main__':
    modes={'--corpus':corpus,'--controls':controls,'--boundaries':boundaries,'--composition':composition,'--honest':honest,'--maximum':lambda:honest('maximum'),'--full-identity':lambda:honest('full-identity')}
    if sys.argv[1:]:
        assert all(mode in modes for mode in sys.argv[1:])
        for mode in sys.argv[1:]:modes[mode]()
    else:
        for test in list(modes.values())[:-2]:test()
