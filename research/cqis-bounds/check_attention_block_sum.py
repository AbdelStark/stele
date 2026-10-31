# /// script
# requires-python = ">=3.12"
# dependencies = ["numpy==2.3.4", "blake3==1.0.11", "python-flint==0.9.0"]
# ///
"""Draft RFC-0004 A3/A6: signed block totals with complete original sources."""
import copy
from dataclasses import replace
import hashlib
import json
import random
import sys
import numpy as np
import attention_block_sum as c

r=c.r


def rejects(reason,call):
    try:call()
    except ValueError as error:assert str(error)==reason,(reason,str(error))
    else:raise AssertionError('accepted '+reason)


def spec(blocks=2,width=3,identity=5300,repetitions=1):
    ids=tuple(range(blocks)) if blocks==1024 else tuple(2*j for j in range(blocks))
    return c.Spec(c.bounds.Spec(1<<20,width,7,14,'static',65535,26),ids,identity,tuple(2101+j for j in range(blocks)),5003,5009,repetitions)


def oracle(p,flags,qs):
    width=p.schema.width;blocks=len(p.blocks);n=1<<(len(qs)-1).bit_length();nc=1<<(width-1).bit_length();s=p.schema;S=127*259 if s.value_mode=='dynamic' else s.scale*min(127,(65536+s.scale)//(2*s.scale));qmax=(1024*(1<<s.exponent)*S+(1<<s.drop)//2)//(1<<s.drop);G=((s.length+1023)//1024)*qmax
    totals=(((1-2*np.array(flags,dtype=np.int64))*np.array(qs,dtype=np.int64)).reshape(blocks,width).sum(axis=0)).tolist();outputs=[x+G for x in totals]
    def planes(xs,size,dtype):return np.frombuffer(np.array(xs+[0]*(size-len(xs)),dtype=dtype).tobytes(),dtype=np.uint8).reshape(size,-1).T.reshape(-1).tolist()
    roots=[r.root(identity,planes(flags[j*width:(j+1)*width],nc,'<u1')) for j,identity in enumerate(p.sign_sources)];roots.extend((r.root(p.quotient,planes(qs,n,'<u2')),r.root(p.output,planes(outputs,nc,'<u8'))));return outputs,roots


def corpus():
    rng=random.Random(2739);digest=hashlib.sha256();cells=zeros=negative_raw_zero=0;shifts=set();qwidths=set();owidths=set()
    for case in range(10000):
        length=rng.choice((1,1024,1025,2049,1<<20));bmax=(length+1023)//1024;blocks=min(1+case%5,bmax);width=1+case%17;ids=tuple(sorted(rng.sample(range(bmax),blocks)));mode='dynamic' if case%2 else 'static';scale=0 if mode=='dynamic' else rng.choice((1,2,259,65535));E=case%15
        if case<61:mode='static';scale=1;E=0
        S=127*259 if mode=='dynamic' else scale*min(127,(65536+scale)//(2*scale));H=1024*(1<<E)*S;minimum=next(drop for drop in range(63) if (H+(1<<drop)//2)//(1<<drop)<=32767);drop=2+case if case<61 else minimum+case%(63-minimum)
        p=replace(spec(blocks,width,case,1+case%2),schema=c.bounds.Spec(length,width,case%31,E,mode,scale,drop),blocks=ids);v=c.derive(p,4);flags=[rng.randrange(2) for _ in range(v['count'])];qs=[rng.randrange(v['constants']['rounded_max']+1) for _ in flags];qs[0]=0;flags[0]=1
        outputs,roots=oracle(p,flags,qs);w=c.witness(p,flags,qs);assert w==dict(sign=flags,quotient=qs,output=outputs) and c.expected_roots(p,flags,qs)==roots
        assert 8*v['G']<r.sc.P and v['G']<1<<25 and all(0<=x<=cap for name in w for x,cap in zip(w[name],v['ranges'][name].caps))
        digest.update(v['raw']+b''.join(roots));cells+=len(flags);zeros+=not any(qs);negative_raw_zero+=sum(b and not q for b,q in zip(flags,qs));shifts.add(drop);qwidths.add(r.derive(v['ranges']['quotient'],4)[3]);owidths.add(r.derive(v['ranges']['output'],4)[3])
    for blocks,width in ((128,128),(1024,16),(1,16384)):
        p=spec(blocks,width,(1<<48)-1,2);v=c.derive(p,8);assert v['base']+(1<<14)==(1<<63)+(1<<62)
        spans=sorted((r.derive(child,8)[4],64) for child in v['ranges'].values());assert all(v['base']+17<lo and lo+size<=v['base']+(1<<14) for lo,size in spans) and all(lo+size<=nxt for (lo,size),(nxt,_) in zip(spans,spans[1:]))
    p=spec();v=c.derive(p,4)
    for bad in (replace(p,identity=1<<48),replace(p,repetitions=True),replace(p,blocks=()),replace(p,blocks=(2,0)),replace(p,blocks=(0,0)),replace(p,blocks=(0,1024)),replace(p,sign_sources=(p.quotient,2102)),replace(p,sign_sources=(v['base'],2102)),replace(p,sign_sources=(2101,)),replace(p,schema=replace(p.schema,drop=True))):rejects('Spec',lambda:c.derive(bad,4))
    rejects('Capacity',lambda:c.derive(spec(2,16384),4));rejects('Spec',lambda:c.derive(p,True))
    for flags,qs in (([False]*6,[0]*6),([2]*6,[0]*6),([0]*6,[-1]*6),([0]*6,[v['constants']['rounded_max']+1]*6),([0],[0]*6)):rejects('Input',lambda:c.witness(p,flags,qs))
    assert zeros>1000 and negative_raw_zero>=10000 and shifts==set(range(2,63)) and qwidths=={1,2} and owidths=={1,2,4}
    assert (cells,zeros,negative_raw_zero,digest.hexdigest())==(165678,6835,64010,'aa02e228b2512898004c4f1261746a7fab48f7513408c81bb542d58bd101fa00')
    print(json.dumps(dict(seed=2739,cases=10000,cells=cells,zero_quotient_cases=zeros,negative_raw_sign_zero_quotient_entries=negative_raw_zero,sha256=digest.hexdigest()),sort_keys=True),flush=True)


def account(p,out,d):
    v=c.derive(p,d);a,ac=v['a'],v['ac'];bq=r.derive(v['ranges']['quotient'],d)[1];bo=r.derive(v['ranges']['output'],d)[1];dims=[a+1,a+bq+1,ac+bo+1];f=lambda m:3*m*(m-1)//2+2*m
    assert out['account']==dict(identities=[((1<<m)+255,p.repetitions) for m in dims],lookup_reduction_numerator=sum(p.repetitions*(f(m)+f(8)+3*m) for m in dims),range_reduction_numerator=18*a+9*ac+7*(bq+bo),channel_identity_numerator=ac,sum_reduction_numerator=2*a,denominator=r.sc.P**d)
    assert len(out['claims'])==2 and out['draws']==({r.zc.tr.CHALLENGE:ac+a} if ac+a else {})
    for label,expected in ((r.zc.WEIGHT,8*a+4*ac+3*(bq+bo)),(r.zc.tr.CHALLENGE,9*a+5*ac+3*(bq+bo))):assert sum(x['draws'].get(label,0) for x in [out]+out['children'])==expected


def honest(mode=None):
    digest=hashlib.sha256();done=0;cases=((1,1,0,'static',1,2),(2,3,14,'dynamic',0,25),(3,16,8,'static',259,20),(5,13,14,'static',65535,62))
    if mode:cases=(({'maximum':128,'blocks':1024,'wide':1}[mode],{'maximum':128,'blocks':16,'wide':16384}[mode],14,'static',65535,26),)
    for d,reps in (((4,1),) if mode else ((4,1),(4,2),(8,1),(8,2))):
        for blocks,width,E,policy,scale,drop in cases:
            p=replace(spec(blocks,width,5310+done,reps),schema=c.bounds.Spec(1<<20,width,7,E,policy,scale,drop));v=c.derive(p,d);qmax=v['constants']['rounded_max'];flags=[j%2 for j in range(v['count'])];qs=[(0,qmax,qmax//2)[j%3] for j in range(v['count'])]
            print('honest start',done+1,d,reps,blocks,width,drop,flush=True);proof,state=c.prove(p,flags,qs,d);out=c.verify(p,oracle(p,flags,qs)[1],proof,d);assert out['state']==state;account(p,out,d);digest.update(state);done+=1;print('honest passed',done,d,reps,blocks,width,drop,flush=True)
    if mode is None:assert (done,digest.hexdigest())==(16,'701f68e006fa0f2b22c62703ecfadb4ce7c23a649d91406dc2ab5f98718aa14d')
    print(json.dumps(dict(mode=mode,proofs=done,sha256=digest.hexdigest()),sort_keys=True),flush=True)


def controls():
    p=spec();d=4;v=c.derive(p,d);flags=[0,1,0,1,0,1];qs=[1,2,3,4,5,6];w=c.witness(p,flags,qs);pairs=c.prepare(p,flags,qs,d);proof,state=c.assemble(p,pairs,d);roots=oracle(p,flags,qs)[1];out=c.verify(p,roots,proof,d);assert out['state']==state;account(p,out,d)
    for index,name in enumerate(['Sign:'+str(block) for block in p.blocks]+['Quotient','Output']):
        bad=roots.copy();bad[index]=bytes(32);rejects(name+':CommitmentMismatch',lambda:c.verify(p,bad,proof,d))
    for name in v['ranges']:
        bad=copy.deepcopy(proof);bad[name]['words'][0]^=1;rejects(name.title()+':CommitmentMismatch',lambda:c.verify(p,roots,bad,d))
    for changes in ((1,0,0),(1,-1,0)):
        outputs=[x+y for x,y in zip(w['output'],changes)];bad,_=c.assemble(p,dict(pairs,output=r.prove(v['ranges']['output'],outputs,d)),d);rejects('BlockSum:RoundSumMismatch',lambda:c.verify(p,c.roots(p,bad),bad,d))
    child=v['ranges']['output'];values=w['output'].copy();values[0]+=r.sc.P;caps=list(child.caps);caps[0]=values[0];pair=r.assemble(child,*r.witness(replace(child,caps=tuple(caps)),values),d);bad,_=c.assemble(p,dict(pairs,output=pair),d);rejects('Output:CapRelation:RoundSumMismatch',lambda:c.verify(p,c.roots(p,bad),bad,d))
    for bs,qvalues,name in ((flags[3:]+flags[:3],qs,'Sign:0'),(flags,qs[3:]+qs[:3],'Quotient')):
        other,st=c.prove(p,bs,qvalues,d);assert c.verify(p,oracle(p,bs,qvalues)[1],other,d)['state']==st;rejects(name+':CommitmentMismatch',lambda:c.verify(p,roots,other,d))
    for changed in (replace(p,blocks=(1,2)),replace(p,schema=replace(p.schema,fraction=8))):rejects('BlockSum:RoundSumMismatch',lambda:c.verify(changed,roots,proof,d))
    zp,zs=c.prove(p,[0]*6,[0]*6,d);zr=oracle(p,[0]*6,[0]*6)[1];assert c.verify(p,zr,zp,d)['state']==zs
    for changes in (((1,r.sc.scalar(1,d)),),((0,r.sc.scalar(1,d)),(1,r.sc.scalar(pow(2,-1,r.sc.P),d)))):
        bad=copy.deepcopy(zp)
        for index,value in changes:bad['sum']['final'][index]=value
        rejects('BlockSum:ClaimMismatch',lambda:c.verify(p,zr,bad,d))
    bad=copy.deepcopy(proof);bad['sum']['final'][0]=(r.sc.P,)+(0,)*(d-1);rejects('NoncanonicalField',lambda:c.verify(p,roots,bad,d))
    for key in ('receipt','certificate','mask','projected','target'):rejects('ProofShape',lambda:c.verify(p,roots,dict(proof,**{key:{}}),d))
    rejects('Root',lambda:c.verify(p,roots[:-1],proof,d))
    print('all roots/ranges, false totals, compensating channels, output+p, valid sources, metadata replay and both original consumers reject',flush=True)


def boundaries():
    p=spec(identity=5340);d=4;v=c.derive(p,d);flags=[0]*v['count'];qs=[0]*v['count'];w=c.witness(p,flags,qs);pairs=c.prepare(p,flags,qs,d)
    attacks=[('sign',0,2),('quotient',0,v['constants']['rounded_max']+1),('output',0,2*v['G']+1),('sign',v['count'],1),('quotient',v['count'],1),('output',p.schema.width,1)]
    for name,index,value in attacks:
        child=v['ranges'][name];caps=list(child.caps);values=w[name].copy()
        if index==len(caps):caps.append(0);values.append(0)
        caps[index]=values[index]=value;pair=r.assemble(child,*r.witness(replace(child,caps=tuple(caps)),values),d);bad,_=c.assemble(p,dict(pairs,**{name:pair}),d);rejects(name.title()+':CapRelation:RoundSumMismatch',lambda:c.verify(p,c.roots(p,bad),bad,d))
    proof,state=c.assemble(p,pairs,d);roots=oracle(p,flags,qs)[1];assert c.verify(p,roots,proof,d)['state']==state
    words=[0]*v['nc'];words[p.schema.width]=1;bad=roots.copy();bad[0]=r.root(p.sign_sources[0],words);rejects('Sign:0:CommitmentMismatch',lambda:c.verify(p,bad,proof,d))
    p=replace(spec(1,1,5341),schema=c.bounds.Spec(1,1,0,0,'static',1,62));proof,state=c.prove(p,[1],[0],d);roots=oracle(p,[1],[0])[1];out=c.verify(p,roots,proof,d);assert out['state']==state;account(p,out,d)
    for index,identity,width in ((1,p.quotient,2),(2,p.output,8)):
        words=[0]*width;words[-1]=1;bad=roots.copy();bad[index]=r.root(identity,words);rejects(('Quotient' if index==1 else 'Output')+':CommitmentMismatch',lambda:c.verify(p,bad,proof,d))
    bad=copy.deepcopy(proof);bad['sum']['final'][1]=r.sc.scalar(0,d);rejects('BlockSum:ClaimMismatch',lambda:c.verify(p,roots,bad,d))
    print('Boolean/whole bounds, dense and per-block padding, zero-cap full planes and negative raw sign at q=0 retain consumers',flush=True)


def composition():
    import attention_sign as sign
    import attention_block_rounding as rounding
    for drop in (26,62):
        p=replace(spec(identity=5350+drop),schema=replace(spec().schema,drop=drop));d=4;schema=sign.bounds.Spec(p.schema.length,p.schema.width,p.schema.fraction,p.schema.exponent,p.schema.value_mode,p.schema.scale,'block1024');H=sign.bounds.constants(schema)['base_max']//1024;ms=[];flags=[];sr=[];mr=[];sources=[]
        for j,O in enumerate(([0,H,H+H//2],[2*H,H,H-1])):
            sp=sign.Spec(schema,5440+j+drop,5501+10*j,5503+10*j,5507+10*j,p.sign_sources[j],1);child,st=sign.prove(sp,O,H,d);roots=sign.roots(sp,child);assert sign.verify(sp,roots,child,d)['state']==st;sw=sign.witness(sp,O,H);ms.extend(sw['magnitude']);flags.extend(sw['sign']);sr.append(roots[3]);mr.append(roots[2]);sources.append((sp,O))
        rp=rounding.Spec(p.schema,p.blocks,5460+drop,tuple(sp.magnitude for sp,_ in sources),p.quotient,5021,1);child,st=rounding.prove(rp,ms,d);rr=rounding.roots(rp,child);assert rr[:2]==mr and rounding.verify(rp,rr,child,d)['state']==st;qs=rounding.witness(rp,ms)['quotient'];assert any(b and not q for b,q in zip(flags,qs))
        proof,state=c.prove(p,flags,qs,d);roots=oracle(p,flags,qs)[1];assert roots[:3]==sr+[rr[2]] and c.verify(p,roots,proof,d)['state']==state
        sp,O=sources[0];O[0]=2*H;other,st=sign.prove(sp,O,H,d);ar=sign.roots(sp,other);assert sign.verify(sp,ar,other,d)['state']==st and ar[2]==mr[0];bad=roots.copy();bad[0]=ar[3];rejects('Sign:0:CommitmentMismatch',lambda:c.verify(p,bad,proof,d))
        if drop==26:
            O[2]+=1<<drop;other,st=sign.prove(sp,O,H,d);ar=sign.roots(sp,other);assert sign.verify(sp,ar,other,d)['state']==st;changed=ms.copy();changed[2]+=1<<drop;other,st=rounding.prove(rp,changed,d);br=rounding.roots(rp,other);assert br[0]==ar[2] and rounding.verify(rp,br,other,d)['state']==st;bad=roots.copy();bad[2]=br[2];rejects('Quotient:CommitmentMismatch',lambda:c.verify(p,bad,proof,d))
        print('complete sign/rounding block sources compose; pinned alternatives reject, including negative raw sign at rounded zero',drop,flush=True)


if __name__=='__main__':
    modes={'--corpus':corpus,'--controls':controls,'--boundaries':boundaries,'--composition':composition,'--honest':honest,'--maximum':lambda:honest('maximum'),'--full-blocks':lambda:honest('blocks'),'--full-wide':lambda:honest('wide')}
    if sys.argv[1:]:
        assert all(mode in modes for mode in sys.argv[1:])
        for mode in sys.argv[1:]:modes[mode]()
    else:
        for test in modes.values():test()
