# /// script
# requires-python = ">=3.12"
# dependencies = ["numpy==2.3.4", "blake3==1.0.11", "python-flint==0.9.0"]
# ///
"""Draft RFC-0004 A3/A6: canonical signed attention sums and actual sources."""
import copy
from dataclasses import replace
import hashlib
import json
import random
import sys
import numpy as np
import attention_sign as c

r=c.r


def rejects(reason,call):
    try:call()
    except ValueError as error:assert str(error)==reason,(reason,str(error))
    else:raise AssertionError('accepted '+reason)


def spec(count=3,identity=4900,repetitions=1):
    return c.Spec(c.bounds.Spec(1<<20,count,7,14,'dynamic',0,'exact'),identity,1601,1607,1609,1613,repetitions)


def oracle(p,offsets,H):
    count=p.schema.width;n=1<<(count-1).bit_length();delta=np.array(offsets,dtype=np.int64)-H;M=np.abs(delta).tolist();S=(delta<0).astype(np.int64).tolist()
    def planes(xs,size):return np.frombuffer(np.array(xs+[0]*(size-len(xs)),dtype='<u8').tobytes(),dtype=np.uint8).reshape(size,8).T.reshape(-1).tolist()
    return M,S,[r.root(p.offset,planes(offsets,n)),r.root(p.base_source,planes([H],1)),r.root(p.magnitude,planes(M,n)),r.root(p.sign,S+[0]*(n-count))]


def corpus():
    rng=random.Random(2737);digest=hashlib.sha256();cells=0;overflows=0;widths=set();policies=set()
    for case in range(10000):
        count=1+case%65;mode='dynamic' if case%2 else 'static';scale=0 if mode=='dynamic' else rng.choice((1,2,259,65535));acc='exact' if case%3 else 'block1024';length=rng.choice((1,3,1024,1<<20))
        p=replace(spec(count,case,1+case%2),schema=c.bounds.Spec(length,count,case%31,case%15,mode,scale,acc));v=c.derive(p,4)
        S=127*259 if mode=='dynamic' else scale*min(127,(65536+scale)//(2*scale));cap=(length if acc=='exact' else min(1024,length))*(1<<p.schema.exponent)*S
        assert v['constants']['base_max']==cap;H=(0,cap,rng.randrange(cap+1))[case%3];offsets=[rng.randrange(max(0,H-cap),min(2*cap,H+cap)+1) for _ in range(count)]
        offsets[0]=(H,max(0,H-cap),min(2*cap,H+cap),H,H)[case%5]
        if case%7==0:H=0;offsets[0]=2*cap
        M,S,roots=oracle(p,offsets,H)
        if max(M)>cap:rejects('Magnitude',lambda:c.witness(p,offsets,H));overflows+=1;digest.update(b'overflow'+b''.join(roots));continue
        w=c.witness(p,offsets,H);assert w['offset']==offsets and w['base']==[H] and w['magnitude']==M and w['sign']==S
        assert w['predecessor']==[sum(m>>(8*k)&255 for k in range(8))-s for m,s in zip(M,S)]
        cs=[];n=v['n']
        # Each prefix derives its own carry, independently of the producer recurrence.
        for k in range(1,9):
            modulus=1<<(8*k);diff=[o%modulus+(2*s-1)*(m%modulus)-H%modulus for o,m,s in zip(offsets,M,S)]
            assert all(x%modulus==0 and -2<=x//modulus<=2 for x in diff)
            cs.extend([x//modulus+2 for x in diff]+[0]*(n-count))
        assert cs[-n:]==[2]*count+[0]*(n-count)
        assert w['carry_0']+w['carry_1']==cs and c.expected_roots(p,offsets,H,M,S)==roots
        assert all(0<=x<=cap for name in w for x,cap in zip(w[name],v['ranges'][name].caps));digest.update(v['raw']+b''.join(roots)+bytes(cs));cells+=count;policies.add((mode,acc));widths.update(v['widths'][name] for name in ('offset','base','magnitude'))
    p=spec(16384,(1<<48)-1,2);v=c.derive(p,8);assert v['base']+(1<<14)==(1<<63)+(1<<62)
    spans=sorted((r.derive(child,8)[4],64) for child in v['ranges'].values());assert all(v['base']+26<lo and lo+size<=v['base']+(1<<14) for lo,size in spans) and all(lo+size<=nxt for (lo,size),(nxt,_) in zip(spans,spans[1:]))
    for bad in (replace(p,identity=1<<48),replace(p,repetitions=True),replace(p,offset=p.sign),replace(p,base_source=v['base']),replace(p,schema=replace(p.schema,exponent=True))):rejects('Spec',lambda:c.derive(bad,4))
    rejects('Spec',lambda:c.derive(spec(16385),4));rejects('Spec',lambda:c.derive(p,True))
    p=spec();v=c.derive(p,4)
    for values,H in (([False]*3,0),([-1]*3,0),([v['constants']['offset_sum_max']+1]*3,0),([0],0),([0]*3,True),([0]*3,-1),([0]*3,v['constants']['base_max']+1)):rejects('Input',lambda:c.witness(p,values,H))
    assert overflows>1000 and policies=={('dynamic','exact'),('static','exact'),('dynamic','block1024'),('static','block1024')} and widths=={1,2,4,8}
    assert (cells,overflows,digest.hexdigest())==(282594,1429,'6fb9b680c7173c88644474378ab806c1a8afa938e865dcaef4c53bd5afe9169b')
    print(json.dumps(dict(seed=2737,cases=10000,cells=cells,overflows=overflows,sha256=digest.hexdigest()),sort_keys=True),flush=True)


def account(p,out,d):
    v=c.derive(p,d);a=v['a'];bo,bh,bm=((v['widths'][name]-1).bit_length() for name in ('offset','base','magnitude'));dims=[a+bo+1,bh+1,a+bm+1,a+1,a+2,a+3,a+3];f=lambda m:3*m*(m-1)//2+2*m
    assert out['account']==dict(identities=[((1<<m)+255,p.repetitions) for m in dims],lookup_reduction_numerator=sum(p.repetitions*(f(m)+f(8)+3*m) for m in dims),range_reduction_numerator=61*a+7*(bo+bh+bm)+52,denominator=r.sc.P**d)
    assert len(out['claims'])==12 and out['draws']=={r.zc.WEIGHT:3*a+3,r.zc.tr.CHALLENGE:3*a+3} and sum(x['numerator'] for x in out['sc'])==7*a+9
    assert all(sum(x['draws'].get(label,0) for x in [out]+out['children'])==27*a+22+3*(bo+bh+bm) for label in (r.zc.WEIGHT,r.zc.tr.CHALLENGE))


def honest(maximum=False):
    digest=hashlib.sha256();count=0;cases=((1,1,0,'static',1),(3,3,8,'static',2),(16,1<<20,14,'dynamic',0),(65,1<<20,14,'static',65535))
    for d,reps in (((4,1),) if maximum else ((4,1),(4,2),(8,1),(8,2))):
        for size,length,E,policy,scale in (((16384,1<<20,14,'static',65535),) if maximum else cases):
            p=replace(spec(size,4910+count,reps),schema=c.bounds.Spec(length,size,7,E,policy,scale,'exact'));v=c.derive(p,d);H=0 if size==1 else v['constants']['base_max'];offsets=([0,H,2*H,max(0,H-1),H+int(H>0)]*((size+4)//5))[:size]
            print('honest start',count+1,d,reps,size,flush=True);proof,state=c.prove(p,offsets,H,d);out=c.verify(p,oracle(p,offsets,H)[2],proof,d);assert out['state']==state;account(p,out,d);digest.update(state);count+=1;print('honest passed',count,d,reps,size,flush=True)
    if not maximum:assert (count,digest.hexdigest())==(16,'23a04a1bdd5f29015ef7651056b8edc232735b154f44013e22b1f459b7c980b5')
    print(json.dumps(dict(maximum=maximum,proofs=count,sha256=digest.hexdigest()),sort_keys=True),flush=True)


def controls():
    p=spec();d=4;v=c.derive(p,d);H=v['constants']['base_max']//2;offsets=[H,H+1,H-1];w=c.witness(p,offsets,H);pairs=c.prepare(p,offsets,H,d);proof,state=c.assemble(p,pairs,d);roots=oracle(p,offsets,H)[2];out=c.verify(p,roots,proof,d);assert out['state']==state;account(p,out,d)
    for index,name in enumerate(('Offset','Base','Magnitude','Sign')):
        bad=roots.copy();bad[index]=bytes(32);rejects(name+':CommitmentMismatch',lambda:c.verify(p,bad,proof,d))
    for name in v['ranges']:
        bad=copy.deepcopy(proof);bad[name]['words'][0]^=1;rejects(name.title()+':CommitmentMismatch',lambda:c.verify(p,roots,bad,d))
    for delta in (1,r.sc.P):
        values=w['magnitude'].copy();values[1]+=delta;bad,_=c.assemble(p,dict(pairs,magnitude=r.prove(v['ranges']['magnitude'],values,d)),d);rejects('SignColumns:RoundSumMismatch',lambda:c.verify(p,c.roots(p,bad),bad,d))
    values=w['sign'].copy();values[0]=1;bad,_=c.assemble(p,dict(pairs,sign=r.prove(v['ranges']['sign'],values,d)),d);rejects('CanonicalZero:RoundSumMismatch',lambda:c.verify(p,c.roots(p,bad),bad,d))
    for name,index,reason in (('carry_0',0,'SignColumns:RoundSumMismatch'),('carry_1',3*v['n'],'TerminalCarry:RoundSumMismatch')):
        values=w[name].copy();values[index]+=1;bad,_=c.assemble(p,dict(pairs,**{name:r.prove(v['ranges'][name],values,d)}),d);rejects(reason,lambda:c.verify(p,roots,bad,d))
    other,st=c.prove(p,[x+1 for x in offsets],H+1,d);other_roots=oracle(p,[x+1 for x in offsets],H+1)[2];assert other_roots[2:]==roots[2:] and c.verify(p,other_roots,other,d)['state']==st
    for index,name in ((0,'Offset'),(1,'Base')):
        pinned=other_roots.copy();pinned[index]=roots[index];rejects(name+':CommitmentMismatch',lambda:c.verify(p,pinned,other,d))
    print('all roots/ranges, bounded M+p, negative zero, carry endpoints and compensated O/H sources reject',flush=True)
    zp,zs=c.prove(p,[H]*3,H,d);zr=c.roots(p,zp);assert c.verify(p,zr,zp,d)['state']==zs
    attacks=((0,((0,1),(1,1))),(1,((0,1),(5,1))),(1,((3,1),(4,-1))),(1,((0,256),(6,1))),(1,((0,1),(2,1))),(1,((1,1),)),(2,((0,1),(1,1))),(2,((1,1),(2,-1))))
    for index,changes in attacks:
        bad=copy.deepcopy(zp)
        for column,delta in changes:bad['zero'][index]['final'][column][0]=r.sc.add(bad['zero'][index]['final'][column][0],r.sc.scalar(delta,d))
        rejects(('TerminalCarry','SignColumns','CanonicalZero')[index]+':ClaimMismatch',lambda:c.verify(p,zr,bad,d))
    bad=copy.deepcopy(proof);bad['zero'][1]['rounds'][0][0]=(False,0,0,0);rejects('NoncanonicalField',lambda:c.verify(p,roots,bad,d))
    for key in ('receipt','certificate','mask','point'):rejects('ProofShape',lambda:c.verify(p,roots,dict(proof,**{key:{}}),d))
    print('all twelve originals, including actual H broadcast and zero-hidden sign, retain consumers',flush=True)


def boundaries():
    p=spec(3,4940);d=4;v=c.derive(p,d);H=v['constants']['base_max']//2;offsets=[H]*3;w=c.witness(p,offsets,H);pairs=c.prepare(p,offsets,H,d)
    for name,index,value in (('offset',0,v['constants']['offset_sum_max']+1),('base',0,v['constants']['base_max']+1),('magnitude',0,v['constants']['base_max']+1),('sign',0,2),('predecessor',0,2041),('carry_0',v['n']-1,1),('carry_1',v['n']-1,1)):
        child=v['ranges'][name];values=w[name].copy();caps=list(child.caps);values[index]=caps[index]=value;badpair=r.assemble(child,*r.witness(replace(child,caps=tuple(caps)),values),d);bad,_=c.assemble(p,dict(pairs,**{name:badpair}),d);rejects(name.title()+':CapRelation:RoundSumMismatch',lambda:c.verify(p,c.roots(p,bad),bad,d))
    small=replace(spec(1,4941),schema=c.bounds.Spec(1,1,0,0,'static',1,'exact'));proof,_=c.prove(small,[1],1,d)
    for index,identity in enumerate((small.offset,small.base_source,small.magnitude)):
        br=oracle(small,[1],1)[2];words=[int(index<2)]+[0]*7;words[-1]=1;br[index]=r.root(identity,words);rejects(('Offset','Base','Magnitude')[index]+':CommitmentMismatch',lambda:c.verify(small,br,proof,d))
    print('whole bounds, scalar base cap, nonboolean sign, predecessor overflow, padded carries and external high planes reject',flush=True)


def composition():
    import attention_offset_sum as weighted
    import attention_probability_sum as probability
    import attention_base as base
    p=spec(3,4950);d=4;positions=(0,31,62);wp=weighted.Spec(p.schema,positions,(True,)*3,0,4951,1619,1621,p.offset,1)
    row=probability.attained.Spec(probability.attained.maximum.Spec(p.schema.length,127,7,6),62,positions,0,0,p.schema.length,4952,1627,1637,1657,1663,1);pp=probability.Spec(row,p.schema.exponent,4953,wp.probability,1667);bp=base.Spec(p.schema,3,4954,pp.output,p.base_source,1)
    S=c.bounds.constants(p.schema)['restored_max'];Q=1<<p.schema.exponent;ws=[Q,Q,0];us=[0,S,2*S,S,S,S,2*S,0,S]
    child,st=weighted.prove(wp,ws,us,d);wr=weighted.expected_roots(wp,ws,us);assert weighted.verify(wp,wr,child,d)['state']==st
    child,st=probability.prove(pp,ws,d);pr=probability.expected_roots(pp,ws);assert probability.verify(pp,pr,child,d)['state']==st and pr[0]==wr[0] and probability.derive(pp,d)['allowed']==wp.allowed
    H=2*Q*S;child,st=base.prove(bp,2*Q,d);br=base.expected_roots(bp,2*Q,H);assert base.verify(bp,br,child,d)['state']==st and br[0]==pr[1]
    offsets=[Q*S,2*Q*S,3*Q*S];proof,st=c.prove(p,offsets,H,d);roots=oracle(p,offsets,H)[2];assert roots[:2]==[wr[2],br[1]] and c.verify(p,roots,proof,d)['state']==st
    changed=us.copy();changed[0]+=1;other,st=weighted.prove(wp,ws,changed,d);rr=weighted.expected_roots(wp,ws,changed);assert weighted.verify(wp,rr,other,d)['state']==st;bad=roots.copy();bad[0]=rr[2];rejects('Offset:CommitmentMismatch',lambda:c.verify(p,bad,proof,d))
    other,st=probability.prove(pp,[Q,0,0],d);rr=probability.expected_roots(pp,[Q,0,0]);assert probability.verify(pp,rr,other,d)['state']==st
    other,st=base.prove(bp,Q,d);rrb=base.expected_roots(bp,Q,Q*S);assert base.verify(bp,rrb,other,d)['state']==st and rrb[0]==rr[1];bad=roots.copy();bad[1]=rrb[1];rejects('Base:CommitmentMismatch',lambda:c.verify(p,bad,proof,d))
    print('actual weighted offsets and probability/base sources compose; valid alternative children reject pinned joins',flush=True)


if __name__=='__main__':
    modes={'--corpus':corpus,'--controls':controls,'--boundaries':boundaries,'--composition':composition,'--honest':honest,'--maximum':lambda:honest(True)}
    if sys.argv[1:]:
        assert all(mode in modes for mode in sys.argv[1:])
        for mode in sys.argv[1:]:modes[mode]()
    else:
        for test in modes.values():test()
