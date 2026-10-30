# /// script
# requires-python = ">=3.12"
# dependencies = ["numpy==2.3.4", "blake3==1.0.11", "python-flint==0.9.0"]
# ///
"""Draft RFC-0004 A3/A8: exact residual quotient, bias and strict remainder."""
import copy
from dataclasses import replace
from fractions import Fraction
import hashlib
import json
import random
import sys
import numpy as np
import residual_rounding as c

r=c.r


def rejects(reason,call):
    try:call()
    except ValueError as error:assert str(error)==reason,(reason,str(error))
    else:raise AssertionError('accepted '+reason)


def spec(count=3,identity=3100,repetitions=1):
    return c.Spec(c.residual.Spec(count,0,30,0),identity,853,857,859,repetitions)


def planes(xs,width,n):
    return [x>>(8*k)&255 for k in range(width) for x in xs+[0]*(n-len(xs))]


def corpus():
    rng=random.Random(2727);digest=hashlib.sha256();cells=accepted=overflow=0;shifts=set();widths=set();seen_carries=set()
    for case in range(10000):
        count=1+case%31;fracs=tuple(rng.randrange(31) for _ in range(3)) if case>=31 else (0,case,0);p=replace(spec(count,case,1+case%2),schema=c.residual.Spec(count,*fracs));v=c.derive(p,4);f=max(fracs);shift=f-fracs[2];B=2**shift;h=B//2;H=32768*(2**(f-fracs[0])+2**(f-fracs[1]));limit=H if case%4==0 else min(H,32769*B-h-1)
        ms=[rng.randrange(limit+1) for _ in range(count)];ms[0]=min(limit,(0,h,B-1,B,32768*B-h,H)[case%6]);M=np.array(ms,dtype=np.int64);qs=(M+h)//B;rs=M+h-qs*B
        for m,q in zip(ms,qs):
            z=Fraction(m,B);assert int(q)==(2*z.numerator+z.denominator)//(2*z.denominator)
        digest.update(v['raw']+json.dumps([ms,qs.tolist(),rs.tolist()],separators=(',',':')).encode());shifts.add(shift)
        if np.any(qs>32768):rejects('QuotientRange',lambda:c.witness(p,ms));overflow+=1;continue
        accepted+=1;w=c.witness(p,ms);assert w['magnitude']==ms and w['quotient']==qs.tolist() and w['remainder']==rs.tolist();widths.add((v['widths']['magnitude'],v['widths']['remainder']));n=v['n'];mask=(np.arange(n)<count).astype(np.int64)
        M=np.pad(M,(0,n-count));Q=np.pad(qs,(0,n-count));R=np.pad(rs,(0,n-count));carry=np.zeros(n,dtype=np.int64);cs=[]
        for k in range(8):
            qb=((Q>>(8*(k-shift//8)))&255)*2**(shift%8) if shift//8<=k<shift//8+2 else np.zeros(n,dtype=np.int64)
            diff=((M>>(8*k))&255)+mask*((h>>(8*k))&255)-qb-((R>>(8*k))&255)+carry;assert not np.any(diff%256);carry=diff//256
            assert np.all((-129<=carry)&(carry<=2));seen_carries.update(carry[:count].tolist());cs.extend(((carry+129)*mask).tolist())
        assert not carry.any()
        for g in range(2):assert w['carry_'+str(g)]==cs[4*g*n:4*(g+1)*n]
        assert all(0<=x<=cap for name in w for x,cap in zip(w[name],v['ranges'][name].caps));roots=c.expected_roots(p,ms,qs.tolist(),rs.tolist());assert roots==[r.root(p.magnitude,planes(ms,8,n)),r.root(p.quotient,planes(qs.tolist(),2,n)),r.root(p.remainder,planes(rs.tolist(),4,n))]
        digest.update(b''.join(roots)+bytes(cs));cells+=8*n
    p=spec(16384,(1<<48)-1,2);v=c.derive(p,8);assert v['base']+(1<<14)==(1<<63)+(1<<62)
    spans=sorted((r.derive(child,8)[4],64) for child in v['ranges'].values());assert all(v['base']+23<lo and lo+size<=v['base']+(1<<14) for lo,size in spans) and all(lo+size<=nxt for (lo,size),(nxt,_) in zip(spans,spans[1:]))
    for bad in (replace(p,identity=1<<48),replace(p,repetitions=True),replace(p,magnitude=p.quotient),replace(p,remainder=v['base']),replace(p,schema=replace(p.schema,output_fraction=True))):rejects('Spec',lambda:c.derive(bad,4))
    rejects('Capacity',lambda:c.derive(spec(16385),4));rejects('Spec',lambda:c.derive(p,True))
    for values in ([False]*3,[-1]*3,[v['constants']['numerator_max']+1]*3,[0]):rejects('Input',lambda:c.witness(spec(),values))
    assert accepted+overflow==10000 and accepted>0 and overflow>0 and shifts==set(range(31)) and widths=={(4,1),(4,2),(4,4),(8,1),(8,2),(8,4)} and min(seen_carries)<0<max(seen_carries)
    assert (accepted,overflow,cells,min(seen_carries),max(seen_carries))==(8418,1582,1406072,-127,1)
    assert digest.hexdigest()=='5cb49625c6585357714ea2fc67564e95b255a8ba590c2594ac9ff67ede992482'
    print(json.dumps(dict(seed=2727,cases=10000,accepted=accepted,overflow=overflow,column_cells=cells,carry_min=min(seen_carries),carry_max=max(seen_carries),sha256=digest.hexdigest()),sort_keys=True),flush=True)


def account(p,out,d):
    v=c.derive(p,d);a=v['a'];bm=(v['widths']['magnitude']-1).bit_length();br=(v['widths']['remainder']-1).bit_length();dims=[a+bm+1,a+2,a+br+1,a+3,a+3];f=lambda m:3*m*(m-1)//2+2*m
    assert out['account']==dict(identities=[((1<<m)+255,p.repetitions) for m in dims],lookup_reduction_numerator=sum(p.repetitions*(f(m)+f(8)+3*m) for m in dims),range_reduction_numerator=49*a+7*(bm+br)+49,denominator=r.sc.P**d)
    assert len(out['claims'])==8 and out['draws']=={r.zc.WEIGHT:2*a+3,r.zc.tr.CHALLENGE:2*a+3} and sum(x['numerator'] for x in out['sc'])==4*a+6
    assert all(sum(x['draws'].get(label,0) for x in [out]+out['children'])==22*a+22+3*(bm+br) for label in (r.zc.WEIGHT,r.zc.tr.CHALLENGE))


def honest(maximum=False):
    digest=hashlib.sha256();count=0;cases=((1,0,0,0),(3,0,9,0),(16,0,16,0),(65,0,30,0))
    for d,reps in (((4,1),) if maximum else ((4,1),(4,2),(8,1),(8,2))):
        for size,fl,fr,fo in (((16384,0,30,0),) if maximum else cases):
            p=replace(spec(size,3110+count,reps),schema=c.residual.Spec(size,fl,fr,fo));v=c.derive(p,d);B=v['divisor'];h=v['bias'];limit=min(v['constants']['numerator_max'],32769*B-h-1);pattern=[min(x,limit) for x in (0,h,B-1,B,limit)];ms=(pattern*((size+4)//5))[:size];w=c.witness(p,ms)
            print('honest start',count+1,d,reps,size,flush=True);proof,state=c.prove(p,ms,d);out=c.verify(p,c.expected_roots(p,ms,w['quotient'],w['remainder']),proof,d);assert out['state']==state;account(p,out,d);digest.update(state);count+=1;print('honest passed',count,d,reps,size,flush=True)
    print(json.dumps(dict(maximum=maximum,proofs=count,sha256=digest.hexdigest()),sort_keys=True),flush=True)


def controls():
    p=spec();d=4;v=c.derive(p,d);B=v['divisor'];h=v['bias'];ms=[0,h,B];w=c.witness(p,ms);pairs=c.prepare(p,ms,d);proof,state=c.assemble(p,pairs,d);roots=c.expected_roots(p,ms,w['quotient'],w['remainder']);out=c.verify(p,roots,proof,d);assert out['state']==state;account(p,out,d)
    for index,name in enumerate(('Magnitude','Quotient','Remainder')):
        bad=roots.copy();bad[index]=bytes([bad[index][0]^1])+bad[index][1:];rejects(name+':CommitmentMismatch',lambda:c.verify(p,bad,proof,d))
    for name in v['ranges']:
        bad=copy.deepcopy(proof);bad[name]['words'][0]^=1;rejects(name.title()+':CommitmentMismatch',lambda:c.verify(p,roots,bad,d))
    for name,index,delta in (('magnitude',0,1),('magnitude',0,r.sc.P),('quotient',0,1),('remainder',0,1)):
        values=w[name].copy();values[index]+=delta;bad,_=c.assemble(p,dict(pairs,**{name:r.prove(v['ranges'][name],values,d)}),d);rejects('RoundColumns:RoundSumMismatch',lambda:c.verify(p,c.roots(p,bad),bad,d))
    qs=w['quotient'].copy();rs=w['remainder'].copy();qs[1]=0;rs[1]=B;assert all(m+h==q*B+rem for m,q,rem in zip(ms,qs,rs));changed=dict(pairs,quotient=r.prove(v['ranges']['quotient'],qs,d));child=v['ranges']['remainder'];caps=list(child.caps);caps[1]=B;changed['remainder']=r.assemble(child,*r.witness(replace(child,caps=tuple(caps)),rs),d);cs=c.carries(p,ms,qs,rs)
    for g in range(2):changed['carry_'+str(g)]=r.prove(v['ranges']['carry_'+str(g)],cs[4*g*v['n']:4*(g+1)*v['n']],d)
    bad,_=c.assemble(p,changed,d);rejects('Remainder:CapRelation:RoundSumMismatch',lambda:c.verify(p,c.roots(p,bad),bad,d))
    changed=dict(pairs,quotient=r.prove(v['ranges']['quotient'],[m//B for m in ms],d),remainder=r.prove(child,[m%B for m in ms],d));bad,_=c.assemble(p,changed,d);rejects('RoundColumns:RoundSumMismatch',lambda:c.verify(p,c.roots(p,bad),bad,d))
    for name,index,reason in (('carry_0',0,'RoundColumns:RoundSumMismatch'),('carry_1',3*v['n'],'TerminalCarry:RoundSumMismatch')):
        values=w[name].copy();values[index]+=1;bad,_=c.assemble(p,dict(pairs,**{name:r.prove(v['ranges'][name],values,d)}),d);rejects(reason,lambda:c.verify(p,roots,bad,d))
    for index,changes in ((0,((0,1),(1,1))),(1,((0,1),(3,1))),(1,((1,1),(4,1))),(1,((2,256),(5,1)))):
        bad=copy.deepcopy(proof)
        for column,delta in changes:bad['zero'][index]['final'][column][0]=r.sc.add(bad['zero'][index]['final'][column][0],r.sc.scalar(delta,d))
        rejects(('TerminalCarry','RoundColumns')[index]+':ClaimMismatch',lambda:c.verify(p,roots,bad,d))
    bad=copy.deepcopy(proof);bad['zero'][1]['rounds'][0][0]=(False,0,0,0);rejects('NoncanonicalField',lambda:c.verify(p,roots,bad,d))
    for key in ('receipt','certificate','bias','mask'):rejects('ProofShape',lambda:c.verify(p,roots,dict(proof,**{key:{}}),d))
    print('roots, range-valid p-alias, coherent r=B, omitted bias, carries and all eight originals reject',flush=True)


def boundaries():
    p=spec(3,3140);d=4;v=c.derive(p,d);ms=[0]*3;w=c.witness(p,ms);pairs=c.prepare(p,ms,d)
    for name,index,value in (('magnitude',0,v['constants']['numerator_max']+1),('quotient',0,32769),('carry_0',v['n']-1,1),('carry_1',v['n']-1,1)):
        child=v['ranges'][name];caps=list(child.caps);values=w[name].copy();values[index]=caps[index]=value;changed=r.assemble(child,*r.witness(replace(child,caps=tuple(caps)),values),d);bad,_=c.assemble(p,dict(pairs,**{name:changed}),d);rejects(name.title()+':CapRelation:RoundSumMismatch',lambda:c.verify(p,c.roots(p,bad),bad,d))
    small=replace(spec(1,3141),schema=c.residual.Spec(1,0,0,0));proof,state=c.prove(small,[32768],d);sr=c.expected_roots(small,[32768],[32768],[0]);assert c.verify(small,sr,proof,d)['state']==state;rejects('QuotientRange',lambda:c.witness(small,[32769]))
    for index,width in ((0,8),(2,4)):
        words=planes([32768] if index==0 else [0],width,1);words[-1]=1;br=sr.copy();br[index]=r.root((small.magnitude,small.quotient,small.remainder)[index],words);rejects(('Magnitude','Quotient','Remainder')[index]+':CommitmentMismatch',lambda:c.verify(small,br,proof,d))
    print('whole M/q bounds, exact division, overflow, padded carries and high planes reject',flush=True)


def composition():
    import residual_sign as sign
    p=spec(3,3150);v=c.derive(p,4);H=v['constants']['numerator_max'];sp=sign.Spec(p.schema,3151,863,p.magnitude,877,1);O=[H,H+v['bias'],H-v['divisor']];source,st=sign.prove(sp,O,4);sw=sign.witness(sp,O);sr=sign.expected_roots(sp,O,sw['magnitude'],sw['sign']);assert sign.verify(sp,sr,source,4)['state']==st
    proof,state=c.prove(p,sw['magnitude'],4);w=c.witness(p,sw['magnitude']);roots=c.expected_roots(p,sw['magnitude'],w['quotient'],w['remainder']);assert roots[0]==sr[1] and c.verify(p,roots,proof,4)['state']==state
    O[1]+=1;alt,ast=sign.prove(sp,O,4);ar=sign.roots(sp,alt);assert sign.verify(sp,ar,alt,4)['state']==ast;roots[0]=ar[1];rejects('Magnitude:CommitmentMismatch',lambda:c.verify(p,roots,proof,4))
    print('actual canonical numerator magnitude composes; valid substituted source rejects',flush=True)


if __name__=='__main__':
    modes={'--corpus':corpus,'--controls':controls,'--boundaries':boundaries,'--composition':composition,'--honest':honest,'--maximum':lambda:honest(True)}
    if sys.argv[1:]:
        assert all(mode in modes for mode in sys.argv[1:])
        for mode in sys.argv[1:]:modes[mode]()
    else:
        for test in modes.values():test()
