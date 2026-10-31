# /// script
# requires-python = ">=3.12"
# dependencies = ["numpy==2.3.4", "blake3==1.0.11", "python-flint==0.9.0"]
# ///
"""Draft RFC-0004 A3/A6: signed attention output and actual source joins."""
import copy
from dataclasses import replace
import hashlib
import json
import random
import sys
import numpy as np
import attention_signed_output as c

r=c.r


def rejects(reason,call):
    try:call()
    except ValueError as error:assert str(error)==reason,(reason,str(error))
    else:raise AssertionError('accepted '+reason)


def spec(width=3,identity=8000,repetitions=1):
    return c.Spec(c.bounds.Spec(65,width,7,7,8,'static',1,'exact',0),identity,10401,10407,10411,repetitions)


def oracle(p,bs,ys):
    n=1<<(p.schema.width-1).bit_length();values=np.array(ys,dtype=np.int64);qs=np.abs(values).tolist()
    def planes(xs,dtype):return np.frombuffer(np.array(xs+[0]*(n-len(xs)),dtype=dtype).tobytes(),dtype=np.uint8).reshape(n,-1).T.reshape(-1).tolist()
    return qs,[r.root(p.sign,bs+[0]*(n-len(bs))),r.root(p.quotient,planes(qs,'<u2')),r.root(p.output,planes(ys,'<i2'))]


def corpus():
    rng=random.Random(2748);digest=hashlib.sha256();cells=zeros=minimum=0;policies=set()
    def check(p,bs,ys):
        nonlocal cells,zeros,minimum
        v=c.derive(p,4);qs,roots=oracle(p,bs,ys);c.inputs(p,bs,ys);assert c.expected_roots(p,bs,ys)==roots;n=v['n'];raw,mag,flags,carry=c.signed.witness(v['output'],ys);assert raw==[x%65536 for x in ys] and mag==qs and flags[:n]==[int(x<0) for x in ys]+[0]*(n-len(ys))
        incoming=np.zeros(n,dtype=np.int64);sign=np.array(flags[:n],dtype=np.int64);cs=[];us=raw+[0]*(n-len(raw));ms=mag+[0]*(n-len(mag))
        for k in range(2):incoming=sign*((np.array([x>>(8*k)&255 for x in us])+np.array([x>>(8*k)&255 for x in ms])+incoming)//256);cs.extend(incoming.tolist())
        assert cs==carry and all(q*b==q*int(y<0) for q,b,y in zip(qs,bs,ys));digest.update(v['raw']+b''.join(roots)+bytes(carry));cells+=len(ys);zeros+=sum(b==1 and y==0 for b,y in zip(bs,ys));minimum+=ys.count(-32768);policies.add((p.schema.value_mode,p.schema.accumulation))
    for case in range(10000):
        width=1+case%65;length=rng.choice((1,65,1024,1025,1<<20));E=case%15;policy='dynamic' if case%2 else 'static';scale=0 if policy=='dynamic' else rng.choice((1,2,259,65535));mode='block1024' if case%3 else 'exact';S=127*259 if policy=='dynamic' else scale*min(127,(65536+scale)//(2*scale));H=1024*(1<<E)*S;low=next(k for k in range(63) if (H+(1<<k)//2)//(1<<k)<=32767);drop=0 if mode=='exact' else low+case%(63-low)
        p=replace(spec(width,case,1+case%2),schema=c.bounds.Spec(length,width,case%31,(case//31)%31,E,policy,scale,mode,drop));qs=[rng.randrange(32769) for _ in range(width)];bs=[1 if q==32768 else rng.randrange(2) for q in qs];endpoints=((0,1),(32768,1),(32767,0),(1,1))
        for j in range(min(4,width)):qs[j],bs[j]=endpoints[(case+j)%4]
        ys=((1-2*np.array(bs,dtype=np.int64))*np.array(qs,dtype=np.int64)).tolist();check(p,bs,ys)
    for width in (8193,16384):
        p=spec(width,(1<<48)-1,2);v=c.derive(p,8);ys=([-32768,32767,0,-1]*((width+3)//4))[:width];bs=[1 if y<=0 else 0 for y in ys];check(p,bs,ys);sv=c.signed.derive(v['output'],8);spans=[(r.derive(v['sign'],8)[4],64),(sv['base'],512)];assert v['base']+18<spans[0][0] and spans[0][0]+64<=spans[1][0] and spans[1][0]+512<=v['base']+(1<<14)
    p=spec();v=c.derive(p,4)
    for bad in (replace(p,identity=1<<48),replace(p,repetitions=True),replace(p,output=p.sign),replace(p,quotient=v['base']),replace(p,schema=replace(p.schema,width=16385))):rejects('Spec',lambda:c.derive(bad,4))
    rejects('Spec',lambda:c.derive(p,True))
    for bs,ys in (([False]*3,[0]*3),([2]*3,[0]*3),([0],[0]*3),([0]*3,[False]*3),([0]*3,[32768]*3),([1]*3,[-32769]*3)):rejects('Input',lambda:c.inputs(p,bs,ys))
    assert zeros>0 and minimum>0 and policies=={('dynamic','exact'),('dynamic','block1024'),('static','exact'),('static','block1024')}
    print(json.dumps(dict(seed=2748,cases=10000,capacity_cases=2,cells=cells,negative_input_zeros=zeros,int16_minima=minimum,sha256=digest.hexdigest()),sort_keys=True),flush=True)


def account(p,out,d):
    v=c.derive(p,d);a=v['a'];dims=[a+1]+[a+2]*3;f=lambda m:3*m*(m-1)//2+2*m
    assert out['account']==dict(identities=[((1<<m)+255,p.repetitions) for m in dims],lookup_reduction_numerator=sum(p.repetitions*(f(m)+f(8)+3*m) for m in dims),range_reduction_numerator=55*a+35,denominator=r.sc.P**d)
    assert out['draws']==({r.zc.WEIGHT:a,r.zc.tr.CHALLENGE:a} if a else {}) and [claim[0] for claim in out['claims']]==[v['base']+j for j in range(16,19)] and [x['numerator'] for x in out['sc']]==[a,0,2*a]
    sign,output=out['children'];assert len(output['claims'])==16 and sum(x['numerator'] for x in output['sc'])==16*a+12
    for label in (r.zc.WEIGHT,r.zc.tr.CHALLENGE):assert sum(child['draws'].get(label,0) for child in [out,sign,output]+output['ranges'])==23*a+14


def honest(maximum=False):
    digest=hashlib.sha256();done=0;cases=((1,1,0,0,'exact',0),(3,65,7,8,'exact',0),(16,1025,30,0,'block1024',2),(65,1<<20,0,14,'exact',0))
    if maximum:cases=((16384,1<<20,30,14,'exact',0),)
    for d,reps in (((4,1),) if maximum else ((4,1),(4,2),(8,1),(8,2))):
        for width,length,fv,E,acc,drop in cases:
            p=replace(spec(width,8010+done,reps),schema=c.bounds.Spec(length,width,fv,0,E,'static',1,acc,drop));ys=([-32768,32767,0,-1,1]*((width+4)//5))[:width];bs=[int(y<=0) for y in ys];roots=oracle(p,bs,ys)[1];print('honest start',done+1,d,reps,width,flush=True);proof,state=c.prove(p,bs,ys,d);out=c.verify(p,roots,proof,d);assert out['state']==state;account(p,out,d);digest.update(state);done+=1;print('honest passed',done,d,reps,width,flush=True)
    print(json.dumps(dict(maximum=maximum,proofs=done,sha256=digest.hexdigest()),sort_keys=True),flush=True)


def controls():
    p=spec();d=4;v=c.derive(p,d);bs=[0,1,1];ys=[1,-2,0];pairs=c.prepare(p,bs,ys,d);proof,state=c.assemble(p,pairs,d);roots=oracle(p,bs,ys)[1];out=c.verify(p,roots,proof,d);assert out['state']==state;account(p,out,d)
    for index,label in enumerate(('Sign','Output:Magnitude','Output:Raw')):
        bad=roots.copy();bad[index]=bytes(32);rejects(label+':CommitmentMismatch',lambda:c.verify(p,bad,proof,d))
    for key in ('words','byte_root','carry_root'):
        bad=copy.deepcopy(proof)
        if key=='words':bad['sign'][key][0]^=1
        else:bad['sign'][key]=bytes(32)
        rejects('Sign:CommitmentMismatch',lambda:c.verify(p,roots,bad,d))
    for index,label in enumerate(('Raw','Magnitude','Sign')):
        bad=copy.deepcopy(proof);bad['output']['ranges'][index]['words'][0]^=1;rejects('Output:'+label+':CommitmentMismatch',lambda:c.verify(p,roots,bad,d))
    for key,label in (('sign_root','Sign'),('carry_root','Carry')):
        bad=copy.deepcopy(proof);bad['output'][key]=bytes(32);rejects('Output:'+label+':CommitmentMismatch',lambda:c.verify(p,roots,bad,d))
    for name,pair in (('sign',r.prove(v['sign'],[1,1,1],d)),('output',c.signed.prove(v['output'],[1,2,0],d))):
        bad,_=c.assemble(p,dict(pairs,**{name:pair}),d);rejects('SignedOutput:RoundSumMismatch',lambda:c.verify(p,c.roots(p,bad),bad,d))
    changed,st=c.prove(p,bs,[2,-2,0],d);rr=c.roots(p,changed);assert c.verify(p,rr,changed,d)['state']==st;rr[1]=roots[1];rejects('Output:Magnitude:CommitmentMismatch',lambda:c.verify(p,rr,changed,d))
    zero,state=c.prove(p,[0]*3,[0]*3,d);zr=c.roots(p,zero);assert c.verify(p,zr,zero,d)['state']==state
    for index in range(3):
        bad=copy.deepcopy(zero);bad['zero']['final'][index][0]=r.sc.add(bad['zero']['final'][index][0],r.sc.scalar(1,d));rejects('SignedOutput:ClaimMismatch',lambda:c.verify(p,zr,bad,d))
    bad=copy.deepcopy(proof)
    for index in (1,2):bad['zero']['final'][index][0]=r.sc.add(bad['zero']['final'][index][0],r.sc.scalar(1,d))
    rejects('SignedOutput:ClaimMismatch',lambda:c.verify(p,roots,bad,d));other=replace(p,schema=replace(p.schema,fraction=8,output_fraction=8));rejects('SignedOutput:RoundSumMismatch',lambda:c.verify(other,roots,proof,d))
    bad=copy.deepcopy(proof);bad['zero']['rounds'][0][0]=(False,0,0,0);rejects('NoncanonicalField',lambda:c.verify(p,roots,bad,d))
    for key in ('receipt','certificate','point','branch'):rejects('ProofShape',lambda:c.verify(p,roots,dict(proof,**{key:{}}),d))
    print('all roots, fresh wrong signs, actual quotient pinning, metadata and all three zero-hidden or compensated originals reject',flush=True)


def boundaries():
    p=spec(identity=8040);d=4;v=c.derive(p,d);bs=[1]*3;ys=[-32768,0,-1];pairs=c.prepare(p,bs,ys,d);proof,state=c.assemble(p,pairs,d);roots=oracle(p,bs,ys)[1];assert c.verify(p,roots,proof,d)['state']==state
    # Valid int16 -32768 is the only signed source with this magnitude; an
    # input sign of zero cannot relabel it as positive 32768.
    bad,_=c.assemble(p,dict(pairs,sign=r.prove(v['sign'],[0,1,1],d)),d);rejects('SignedOutput:RoundSumMismatch',lambda:c.verify(p,c.roots(p,bad),bad,d))
    for index,value in ((0,2),(3,1)):
        child=v['sign'];caps=list(child.caps);values=bs.copy()
        if index==len(caps):caps.append(0);values.append(0)
        caps[index]=value;values[index]=value;pair=r.assemble(child,*r.witness(replace(child,caps=tuple(caps)),values),d);bad,_=c.assemble(p,dict(pairs,sign=pair),d);rejects('Sign:CapRelation:RoundSumMismatch',lambda:c.verify(p,c.roots(p,bad),bad,d))
    sv=c.signed.derive(v['output'],d);sp,carry=c.signed.ranges(v['output'],ys,d);child=sv['ranges'][1];caps=list(child.caps);caps[0]=32769;sp[1]=r.assemble(child,*r.witness(replace(child,caps=tuple(caps)),[32769,0,1]),d);bad,_=c.assemble(p,dict(pairs,output=c.signed.assemble(v['output'],sp,carry,d)),d);rejects('Output:Magnitude:CapRelation:RoundSumMismatch',lambda:c.verify(p,c.roots(p,bad),bad,d))
    for index,identity,words,label in ((1,p.quotient,proof['output']['ranges'][1]['words'].copy(),'Output:Magnitude'),(2,p.output,proof['output']['ranges'][0]['words'].copy(),'Output:Raw')):
        words[-1]=1;bad=roots.copy();bad[index]=r.root(identity,words);rejects(label+':CommitmentMismatch',lambda:c.verify(p,bad,proof,d))
    print('negative int16 minimum and negative-input zero accept; positive 32768, q32769, nonboolean signs, padding and full byte planes reject',flush=True)


def composition():
    import attention_sign as raw
    import attention_block_total_sign as block
    import attention_numerator as numerator
    import attention_denominator as denominator
    import attention_division as division
    for mode in ('exact','block1024'):
        p=replace(spec(identity=8050+(mode=='exact')),schema=c.bounds.Spec(2049,3,0 if mode=='exact' else 2,0,0,'static',1,mode,0 if mode=='exact' else 2));d=4;sc=p.schema;mid=10601;uid=10603;did=10607;totals=[-1,-4,5];bs=[1,1,0];ms=[1,4,5];z=3
        if mode=='exact':sp=raw.Spec(raw.bounds.Spec(sc.length,sc.width,sc.fraction,sc.exponent,sc.value_mode,sc.scale,mode),8150,10621,10623,mid,p.sign,1);H=381
        else:sp=block.Spec(block.bounds.Spec(sc.length,sc.width,sc.fraction,sc.exponent,sc.value_mode,sc.scale,sc.drop),(0,1,2),8150,10621,mid,p.sign,1);H=block.derive(sp,d)['G']
        def source(ts):
            offsets=[H+t for t in ts]
            if mode=='exact':proof,state=raw.prove(sp,offsets,H,d);roots=raw.expected_roots(sp,offsets,H,[abs(t) for t in ts],[int(t<0) for t in ts]);out=raw.verify(sp,roots,proof,d)
            else:proof,state=block.prove(sp,offsets,d);roots=block.expected_roots(sp,offsets);out=block.verify(sp,roots,proof,d)
            assert out['state']==state;return roots
        sr=source(totals);np_spec=numerator.Spec(sc,8151,mid,uid,1);up,st=numerator.prove(np_spec,ms,d);ur=numerator.expected_roots(np_spec,ms);assert numerator.verify(np_spec,ur,up,d)['state']==st and ur[0]==sr[-2];dp=denominator.Spec(sc,8152,10631,did,1);down,st=denominator.prove(dp,z,d);dr=denominator.expected_roots(dp,z);assert denominator.verify(dp,dr,down,d)['state']==st
        vp=division.Spec(sc,8153,uid,did,p.quotient,10637,10639,10643,10649,1);constants=c.bounds.constants(sc);us=[m*constants['left_factor'] for m in ms];D=z*constants['right_factor'];qr=[divmod(2*u+D,2*D) for u in us];qs,rs=map(list,zip(*qr));div,st=division.prove(vp,us,D,qs,rs,d);vr=division.expected_roots(vp,us,D,qs,rs);assert division.verify(vp,vr,div,d)['state']==st and vr[:2]==[ur[1],dr[1]]
        ys=[(1-2*b)*q for b,q in zip(bs,qs)];proof,state=c.prove(p,bs,ys,d);roots=oracle(p,bs,ys)[1];assert ys==[0,-1,2] and roots[:2]==[sr[-1],vr[2]] and c.verify(p,roots,proof,d)['state']==state
        changed=source([1,-4,5]);assert changed[-2]==sr[-2];rejects('Sign:CommitmentMismatch',lambda:c.verify(p,[changed[-1],*roots[1:]],proof,d))
        us[1]=7*constants['left_factor'];qr=[divmod(2*u+D,2*D) for u in us];qs,rs=map(list,zip(*qr));changed,st=division.prove(vp,us,D,qs,rs,d);rr=division.expected_roots(vp,us,D,qs,rs);assert division.verify(vp,rr,changed,d)['state']==st;rejects('Output:Magnitude:CommitmentMismatch',lambda:c.verify(p,[roots[0],rr[2],roots[2]],proof,d));print('actual canonical sign, scaled magnitude, positive denominator and strict division compose; valid replacements reject',mode,flush=True)


if __name__=='__main__':
    modes={'--corpus':corpus,'--controls':controls,'--boundaries':boundaries,'--composition':composition,'--honest':honest,'--maximum':lambda:honest(True)}
    if sys.argv[1:]:
        assert all(mode in modes for mode in sys.argv[1:])
        for mode in sys.argv[1:]:modes[mode]()
    else:
        for test in list(modes.values())[:-1]:test()
