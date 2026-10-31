# /// script
# requires-python = ">=3.12"
# dependencies = ["numpy==2.3.4", "blake3==1.0.11", "python-flint==0.9.0"]
# ///
"""Draft RFC-0004 A3/A6: canonical signs of actual accumulated block totals."""
import copy
from dataclasses import replace
import hashlib
import json
import random
import sys
import numpy as np
import attention_block_total_sign as c

r=c.r


def rejects(reason,call):
    try:call()
    except ValueError as error:assert str(error)==reason,(reason,str(error))
    else:raise AssertionError('accepted '+reason)


def spec(width=3,identity=5600,repetitions=1):
    return c.Spec(c.bounds.Spec(1<<20,width,7,14,'static',65535,26),(0,2),identity,6001,6007,6011,repetitions)


def oracle(p,offsets):
    s=p.schema;S=127*259 if s.value_mode=='dynamic' else s.scale*min(127,(65536+s.scale)//(2*s.scale));qmax=(1024*(1<<s.exponent)*S+(1<<s.drop)//2)//(1<<s.drop);G=((s.length+1023)//1024)*qmax;n=1<<(s.width-1).bit_length()
    totals=np.array(offsets,dtype=np.int64)-G;magnitudes=np.abs(totals).tolist();signs=(totals<0).astype(np.uint8).tolist();predecessors=(np.abs(totals)-(totals<0)).tolist()
    def planes(xs,dtype):return np.frombuffer(np.array(xs+[0]*(n-len(xs)),dtype=dtype).tobytes(),dtype=np.uint8).reshape(n,-1).T.reshape(-1).tolist()
    roots=[r.root(identity,planes(xs,dtype)) for identity,xs,dtype in ((p.offset,offsets,'<u8'),(p.magnitude,magnitudes,'<u8'),(p.sign,signs,'<u1'))]
    return dict(offset=offsets,magnitude=magnitudes,sign=signs,predecessor=predecessors),roots


def corpus():
    rng=random.Random(2740);digest=hashlib.sha256();cells=zeros=0;shifts=set();widths=set()
    for case in range(10000):
        length=rng.choice((1,1024,1025,2049,1<<20));bmax=(length+1023)//1024;ids=tuple(sorted(rng.sample(range(bmax),min(1+case%5,bmax))));width=1+case%65;mode='dynamic' if case%2 else 'static';scale=0 if mode=='dynamic' else rng.choice((1,2,259,65535));E=case%15
        if case<61:mode='static';scale=1;E=0
        S=127*259 if mode=='dynamic' else scale*min(127,(65536+scale)//(2*scale));H=1024*(1<<E)*S;minimum=next(drop for drop in range(63) if (H+(1<<drop)//2)//(1<<drop)<=32767);drop=2+case if case<61 else minimum+case%(63-minimum)
        p=replace(spec(width,case,1+case%2),schema=c.bounds.Spec(length,width,case%31,E,mode,scale,drop),blocks=ids);v=c.derive(p,4);G=v['G'];offsets=[rng.randrange(2*G+1) for _ in range(width)]
        for j,x in enumerate((0,G,2*G,max(0,G-1),min(2*G,G+1))[:width]):offsets[j]=x
        w,roots=oracle(p,offsets);assert c.witness(p,offsets)==w and c.expected_roots(p,offsets)==roots
        assert 2*max(4*G,G+1)<r.sc.P and G<1<<25 and all(0<=x<=cap for name in w for x,cap in zip(w[name],v['ranges'][name].caps))
        digest.update(v['raw']+b''.join(roots));cells+=width;zeros+=not G;shifts.add(drop);widths.add(tuple(r.derive(v['ranges'][name],4)[3] for name in ('offset','magnitude')))
    p=replace(spec(16384,(1<<48)-1,2),blocks=tuple(range(1024)));v=c.derive(p,8);assert v['n']==16384 and v['base']+(1<<14)==(1<<63)+(1<<62)
    spans=sorted((r.derive(child,8)[4],64) for child in v['ranges'].values());assert all(v['base']+20<lo and lo+size<=v['base']+(1<<14) for lo,size in spans) and all(lo+size<=nxt for (lo,size),(nxt,_) in zip(spans,spans[1:]))
    p=spec();v=c.derive(p,4)
    for bad in (replace(p,identity=1<<48),replace(p,repetitions=True),replace(p,blocks=()),replace(p,blocks=(2,0)),replace(p,blocks=(0,0)),replace(p,blocks=(0,1024)),replace(p,magnitude=p.offset),replace(p,sign=v['base']),replace(p,schema=replace(p.schema,drop=True))):rejects('Spec',lambda:c.derive(bad,4))
    rejects('Spec',lambda:c.derive(p,True))
    for values in ([False]*3,[-1]*3,[2*v['G']+1]*3,[0]):rejects('Input',lambda:c.witness(p,values))
    assert zeros>1000 and shifts==set(range(2,63)) and {(1,1),(2,1),(2,2),(4,2),(4,4)}<=widths
    assert (cells,zeros,digest.hexdigest())==(329725,6660,'14c2f3733de98a71593e189c89e72d4d7facd86e07c38f8a64faf9d29f40e2f2')
    print(json.dumps(dict(seed=2740,cases=10000,cells=cells,zero_bound_cases=zeros,widths=sorted(widths),sha256=digest.hexdigest()),sort_keys=True),flush=True)


def account(p,out,d):
    v=c.derive(p,d);a=v['a'];bo=r.derive(v['ranges']['offset'],d)[1];bm=r.derive(v['ranges']['magnitude'],d)[1];dims=[a+bo+1,a+bm+1,a+1,a+bm+1];f=lambda m:3*m*(m-1)//2+2*m
    assert out['account']==dict(identities=[((1<<m)+255,p.repetitions) for m in dims],lookup_reduction_numerator=sum(p.repetitions*(f(m)+f(8)+3*m) for m in dims),range_reduction_numerator=41*a+7*(bo+2*bm),denominator=r.sc.P**d)
    assert len(out['claims'])==7 and out['draws']==({r.zc.WEIGHT:2*a,r.zc.tr.CHALLENGE:2*a} if a else {})
    assert [row['numerator'] for row in out['sc']]==[a,0,2*a,a,0,a]
    assert [claim[0] for claim in out['claims']]==[v['base']+j for j in (16,17,18,19,18,20,17)]
    for label in (r.zc.WEIGHT,r.zc.tr.CHALLENGE):assert sum(x['draws'].get(label,0) for x in [out]+out['children'])==18*a+3*(bo+2*bm)


def honest(maximum=False):
    digest=hashlib.sha256();done=0;cases=((1,1,0,'static',1,62),(3,1,0,'static',1,9),(16,1025,0,'static',1,2),(65,1<<20,14,'dynamic',0,25))
    if maximum:cases=((16384,1<<20,0,'static',1,2),)
    for d,reps in (((4,1),) if maximum else ((4,1),(4,2),(8,1),(8,2))):
        for width,length,E,mode,scale,drop in cases:
            blocks=tuple(range((length+1023)//1024)) if maximum else (0,);p=replace(spec(width,5610+done,reps),schema=c.bounds.Spec(length,width,7,E,mode,scale,drop),blocks=blocks);G=c.derive(p,d)['G'];offsets=[(0,G,2*G,max(0,G-1),min(2*G,G+1))[j%5] for j in range(width)]
            print('honest start',done+1,d,reps,width,length,drop,flush=True);proof,state=c.prove(p,offsets,d);out=c.verify(p,oracle(p,offsets)[1],proof,d);assert out['state']==state;account(p,out,d);digest.update(state);done+=1;print('honest passed',done,d,reps,width,length,drop,flush=True)
    if not maximum:assert (done,digest.hexdigest())==(16,'6ad91d56e515a63ac2ccab994cd9f5b5c6cca5ef517f6a70d0c328392b4ac595')
    print(json.dumps(dict(maximum=maximum,proofs=done,sha256=digest.hexdigest()),sort_keys=True),flush=True)


def controls():
    p=spec();d=4;v=c.derive(p,d);G=v['G'];offsets=[G,G+1,G-1];w=c.witness(p,offsets);pairs=c.prepare(p,offsets,d);proof,state=c.assemble(p,pairs,d);roots=oracle(p,offsets)[1];out=c.verify(p,roots,proof,d);assert out['state']==state;account(p,out,d)
    for index,name in enumerate(('Offset','Magnitude','Sign')):
        bad=roots.copy();bad[index]=bytes(32);rejects(name+':CommitmentMismatch',lambda:c.verify(p,bad,proof,d))
    for name in c.NAMES:
        bad=copy.deepcopy(proof);bad[name]['words'][0]^=1;rejects(name.title()+':CommitmentMismatch',lambda:c.verify(p,roots,bad,d))
    values=w['magnitude'].copy();values[1]+=1;bad,_=c.assemble(p,dict(pairs,magnitude=r.prove(v['ranges']['magnitude'],values,d)),d);rejects('SignRelation:RoundSumMismatch',lambda:c.verify(p,c.roots(p,bad),bad,d))
    values=w['sign'].copy();values[0]=1;bad,_=c.assemble(p,dict(pairs,sign=r.prove(v['ranges']['sign'],values,d)),d);rejects('CanonicalZero:RoundSumMismatch',lambda:c.verify(p,c.roots(p,bad),bad,d))
    for name in ('offset','magnitude','predecessor'):
        child=v['ranges'][name];values=w[name].copy();caps=list(child.caps);values[0]+=r.sc.P;caps[0]=values[0];pair=r.assemble(child,*r.witness(replace(child,caps=tuple(caps)),values),d);bad,_=c.assemble(p,dict(pairs,**{name:pair}),d);rejects(name.title()+':CapRelation:RoundSumMismatch',lambda:c.verify(p,c.roots(p,bad),bad,d))
    for other in (replace(p,schema=replace(p.schema,fraction=8)),replace(p,blocks=(0,3))):rejects('SignRelation:RoundSumMismatch',lambda:c.verify(other,roots,proof,d))
    zp,zs=c.prove(p,[G]*3,d);zr=c.roots(p,zp);assert c.verify(p,zr,zp,d)['state']==zs
    attacks=((0,((0,1),(3,1))),(0,((1,1),)),(0,((2,1),(0,1))),(0,((3,-1),(2,1))),(1,((0,1),(1,1))),(1,((1,1),(2,-1))))
    for index,changes in attacks:
        bad=copy.deepcopy(zp)
        for column,delta in changes:bad['zero'][index]['final'][column][0]=r.sc.add(bad['zero'][index]['final'][column][0],r.sc.scalar(delta,d))
        rejects(('SignRelation','CanonicalZero')[index]+':ClaimMismatch',lambda:c.verify(p,zr,bad,d))
    bad=copy.deepcopy(proof);bad['zero'][0]['rounds'][0][0]=(False,0,0,0);rejects('NoncanonicalField',lambda:c.verify(p,roots,bad,d))
    for key in ('receipt','certificate','mask','point'):rejects('ProofShape',lambda:c.verify(p,roots,dict(proof,**{key:{}}),d))
    rejects('Root',lambda:c.verify(p,roots[:-1],proof,d));bad=copy.deepcopy(proof);bad['zero'][1]['final'].pop();rejects('ProofShape',lambda:c.verify(p,roots,bad,d))
    print('all roots/ranges, false magnitude, negative zero, relaxed-cap modulus aliases, metadata replay and all seven original views reject',flush=True)


def boundaries():
    p=spec(identity=5640);d=4;v=c.derive(p,d);offsets=[v['G']]*3;w=c.witness(p,offsets);pairs=c.prepare(p,offsets,d)
    for name in c.NAMES:
        for index,value in ((0,v['ranges'][name].caps[0]+1),(p.schema.width,1)):
            child=v['ranges'][name];caps=list(child.caps);values=w[name].copy()
            if index==len(caps):caps.append(0);values.append(0)
            caps[index]=values[index]=value;pair=r.assemble(child,*r.witness(replace(child,caps=tuple(caps)),values),d);bad,_=c.assemble(p,dict(pairs,**{name:pair}),d);rejects(name.title()+':CapRelation:RoundSumMismatch',lambda:c.verify(p,c.roots(p,bad),bad,d))
    p=replace(spec(1,5641),schema=c.bounds.Spec(1,1,0,0,'static',1,62),blocks=(0,));v=c.derive(p,d);assert v['G']==0;pairs=c.prepare(p,[0],d);proof,state=c.assemble(p,pairs,d);roots=oracle(p,[0])[1];out=c.verify(p,roots,proof,d);assert out['state']==state;account(p,out,d)
    for index,identity in ((0,p.offset),(1,p.magnitude)):
        words=[0]*8;words[-1]=1;bad=roots.copy();bad[index]=r.root(identity,words);rejects(('Offset','Magnitude')[index]+':CommitmentMismatch',lambda:c.verify(p,bad,proof,d))
    bad,_=c.assemble(p,dict(pairs,sign=r.prove(v['ranges']['sign'],[1],d)),d);rejects('CanonicalZero:FinalEvaluationMismatch',lambda:c.verify(p,c.roots(p,bad),bad,d))
    print('whole caps, Boolean signs, all dense padding, full external planes and dimension-zero negative zero reject',flush=True)


def composition():
    import attention_block_sum as upstream
    for drop in (26,62):
        p=replace(spec(identity=5650+drop),schema=replace(spec().schema,drop=drop));d=4;sp=upstream.Spec(p.schema,p.blocks,5740+drop,(6101,6107),6113,p.offset,1);flags=[0,1,0,1,0,1];qs=[1,2,3,4,5,6] if drop==26 else [0]*6
        child,st=upstream.prove(sp,flags,qs,d);sr=upstream.expected_roots(sp,flags,qs);assert upstream.verify(sp,sr,child,d)['state']==st;offsets=upstream.witness(sp,flags,qs)['output'];proof,state=c.prove(p,offsets,d);roots=oracle(p,offsets)[1];assert roots[0]==sr[-1] and c.verify(p,roots,proof,d)['state']==state
        if drop==26:
            changed=qs.copy();changed[0]+=1;other,st=upstream.prove(sp,flags,changed,d);rr=upstream.expected_roots(sp,flags,changed);assert upstream.verify(sp,rr,other,d)['state']==st;bad=roots.copy();bad[0]=rr[-1];rejects('Offset:CommitmentMismatch',lambda:c.verify(p,bad,proof,d))
        else:
            assert c.witness(p,offsets)['sign']==[0]*3;changed=flags.copy();changed[0]=1;other,st=upstream.prove(sp,changed,qs,d);rr=upstream.expected_roots(sp,changed,qs);assert upstream.verify(sp,rr,other,d)['state']==st and rr[-1]==roots[0];bad=sr.copy();bad[0]=rr[0];rejects('Sign:0:CommitmentMismatch',lambda:upstream.verify(sp,bad,child,d));assert c.verify(p,roots,proof,d)['state']==state
        print('complete block totals compose; changed aggregate or pinned upstream sign rejects; total zero is canonical',drop,flush=True)


if __name__=='__main__':
    modes={'--corpus':corpus,'--controls':controls,'--boundaries':boundaries,'--composition':composition,'--honest':honest,'--maximum':lambda:honest(True)}
    if sys.argv[1:]:
        assert all(mode in modes for mode in sys.argv[1:])
        for mode in sys.argv[1:]:modes[mode]()
    else:
        for test in modes.values():test()
