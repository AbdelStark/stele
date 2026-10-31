# /// script
# requires-python = ">=3.12"
# dependencies = ["numpy==2.3.4", "blake3==1.0.11"]
# ///
"""RFC-0021 §2.1 / Draft RFC-0004 A3: actual full-domain exp index split."""
import copy
from dataclasses import replace
import hashlib
import json
import random
import sys
import numpy as np
import attention_exp_index as c

r=c.r


def rejects(reason,call):
    try:call()
    except ValueError as error:assert str(error)==reason,(reason,str(error))
    else:raise AssertionError('accepted '+reason)


def spec(count=3,B=31,k=16,E=14,nearest=False,S=(1<<31)-1,identity=3500,repetitions=1):
    schema=c.attained.maximum.Spec(1<<20,S,B,12);ids=tuple(31*j for j in range(count));row=c.attained.Spec(schema,ids[max(0,count-2)],ids,0,0,1<<20,3600,1201,1213,1217,1223,repetitions)
    fn=c.fn.Function('exp_q/nearest' if nearest else 'exp_q/product',1,bytes([B,12,E])+(b'' if nearest else bytes([k])));rep=c.fn.Representation(fn,2 if nearest else 1,bytes([k]) if nearest else b'')
    return c.Spec(row,rep,identity,1231,1237)


def oracle(p,us):
    k=p.representation.params[0] if p.representation.mode==2 else p.representation.function.params[3];n=1<<(len(us)-1).bit_length();U=np.array(us+[0]*(n-len(us)),dtype=np.int64);H,L=np.divmod(U,1<<k)
    hb=np.array([(H>>(8*j))&255 for j in range(2)],dtype=np.int64);lb=np.array([(L>>(8*j))&255 for j in range(4)],dtype=np.int64);shift=np.array([hb[j-k//8] if 0<=j-k//8<2 else np.zeros(n,dtype=np.int64) for j in range(4)])
    powers=np.array([1<<(8*j) for j in range(4)],dtype=np.int64)[:,None];terms=(shift*(1<<(k%8))+lb)*powers;carry=np.cumsum(terms,axis=0)//(256*powers)
    incoming=np.concatenate((np.zeros((1,n),dtype=np.int64),carry[:3]),axis=0);ub=np.array([(U>>(8*j))&255 for j in range(4)],dtype=np.int64)
    assert np.array_equal(shift*(1<<(k%8))+lb+incoming,ub+256*carry) and not carry[-1].any()
    return dict(difference=us.copy(),high=H[:len(us)].tolist(),low=L[:len(us)].tolist(),carry=carry.reshape(-1).tolist())


def corpus():
    rng=random.Random(2731);digest=hashlib.sha256();pairs=[(B,k) for B in range(7,32) for k in range(1,17) if 0<=B-k<=15];covered=set();families=set();widths=set();cmax=0
    for case in range(10000):
        B,k=pairs[case%len(pairs)];count=(1,3,5,16,17,65)[case%6];S=(0,127,128,32767,32768,(1<<31)-1)[(case//6)%6];nearest=B<=15 and case%2==1;p=spec(count,B,k,case%15,nearest,S,case,1+case%2)
        row=replace(p.row,position=p.row.positions[(case//7)%count],window=(0,31,63,1<<20)[case%4]);p=replace(p,row=row);v=c.derive(p,4);us=[rng.randint(0,v['cap']) if bit else 0 for bit in v['allowed']]
        if case%13==0:us[v['allowed'].index(True)]=v['cap']
        w=oracle(p,us);assert c.witness(p,us)==w;covered.add((B,k));families.add(p.representation.mode);widths.add(tuple(v[name] for name in ('bu','bh','bl')));cmax=max(cmax,max(w['carry']))
        manual=[r.source_root(v['ranges'][name],r.witness(v['ranges'][name],w[name])[0]) for name in c.ROLES];assert c.expected_roots(p,us)==manual
        digest.update(v['raw']+json.dumps([us,w],sort_keys=True,separators=(',',':')).encode()+b''.join(manual))
    assert covered==set(pairs) and families=={1,2} and {x[0] for x in widths}=={0,1,2} and cmax>=127,(len(covered),families,widths,cmax)
    p=replace(spec(16384),identity=(1<<50)-1);v=c.derive(p,8);assert v['base']+4096==(1<<63)+(1<<62);assert [r.derive(child,8)[3] for child in v['ranges'].values()]==[4,2,2,1]
    spans=sorted((r.derive(child,8)[4],64) for child in v['ranges'].values());assert all(v['base']+20<lo and lo+size<=v['base']+4096 for lo,size in spans) and all(lo+size<=nxt for (lo,size),(nxt,_) in zip(spans,spans[1:]))
    for bad in (replace(p,identity=1<<50),replace(p,high=p.low),replace(p,high=p.row.source),replace(p,low=v['base']),replace(p,identity=4*p.row.identity),replace(p,row=replace(p.row,repetitions=True))):rejects('Spec',lambda:c.derive(bad,4))
    rejects('Capacity',lambda:c.derive(spec(16385),4));rejects('Spec',lambda:c.derive(p,True))
    direct=c.fn.Representation(c.fn.Function('exp_q/nearest',1,bytes([7,12,14])),0,b'');rejects('Representation',lambda:c.derive(replace(spec(B=7,k=7),representation=direct),4))
    rejects('FunctionScope',lambda:c.derive(replace(spec(),row=replace(spec().row,schema=replace(spec().row.schema,fraction=13))),4))
    for us in ([False]*3,[-1,0,0],[0,0,1],[0,(1<<31)+1,0],[0],(0,0,0)):rejects('Input',lambda:c.witness(spec(),us))
    assert (len(pairs),cmax)==(235,127)
    assert digest.hexdigest()=='7c266b61aa41fc8bec8bc14e99b6653b506426a217e6c936703e5979da3b68ca'
    print(json.dumps(dict(seed=2731,cases=10000,parameter_pairs=len(pairs),carry_max=cmax,sha256=digest.hexdigest()),sort_keys=True),flush=True)


def account(p,out,d):
    v=c.derive(p,d);a=v['a'];bs=v['bu']+v['bh']+v['bl'];dims=[a+v[name]+1 for name in ('bu','bh','bl')]+[a+3];f=lambda m:3*m*(m-1)//2+2*m
    assert out['account']==dict(identities=[((1<<m)+255,p.row.repetitions) for m in dims],lookup_reduction_numerator=sum(p.row.repetitions*(f(m)+f(8)+3*m) for m in dims),range_reduction_numerator=38*a+22+7*bs,denominator=r.sc.P**d)
    assert len(out['claims'])==5 and len(out['children'])==4 and sum(x['numerator'] for x in out['sc'])==2*a+4 and out['draws']=={r.zc.WEIGHT:a+2,r.zc.tr.CHALLENGE:a+2}
    for label in (r.zc.WEIGHT,r.zc.tr.CHALLENGE):assert sum(x['draws'].get(label,0) for x in [out]+out['children'])==17*a+10+3*bs


def honest(maximum=False):
    digest=hashlib.sha256();done=0
    for d,reps in (((4,1),) if maximum else ((4,1),(4,2),(8,1),(8,2))):
        for size,B,k,E,nearest,S in (((16384,31,16,14,False,(1<<31)-1),) if maximum else ((1,7,1,0,False,0),(3,7,7,14,True,127),(16,30,15,0,False,(1<<31)-1),(65,31,16,14,False,(1<<31)-1))):
            p=spec(size,B,k,E,nearest,S,3510+done,reps);v=c.derive(p,d);vals=(0,v['cap'],max(0,v['cap']-1),min(v['cap'],255));us=[vals[j%4] if bit else 0 for j,bit in enumerate(v['allowed'])]
            print('honest start',done+1,d,reps,size,B,k,flush=True);proof,state=c.prove(p,us,d);out=c.verify(p,c.expected_roots(p,us),proof,d);assert out['state']==state;account(p,out,d);digest.update(state);done+=1;print('honest passed',done,d,reps,size,B,k,flush=True)
    if not maximum:assert digest.hexdigest()=='68d8f1ede07f5bf975f9e76573593c66d5c3b11a77192dde4e198d0ab900220d'
    print(json.dumps(dict(maximum=maximum,proofs=done,sha256=digest.hexdigest()),sort_keys=True),flush=True)


def controls():
    p=spec();d=4;v=c.derive(p,d);us=[0,1<<31,0];pairs=c.prepare(p,us,d);proof,state=c.assemble(p,pairs,d);roots=c.expected_roots(p,us);out=c.verify(p,roots,proof,d);assert out['state']==state;account(p,out,d)
    for index,name in enumerate(('Difference','High','Low')):
        changed=roots.copy();changed[index]=bytes([changed[index][0]^1])+changed[index][1:];rejects(name+':CommitmentMismatch',lambda:c.verify(p,changed,proof,d))
    bad=dict(proof,carry_root=bytes([proof['carry_root'][0]^1])+proof['carry_root'][1:]);rejects('Carry:CommitmentMismatch',lambda:c.verify(p,roots,bad,d))
    w=c.witness(p,us)
    for name in c.CHILDREN:
        values=w[name].copy();values[0]+=1;bad,_=c.assemble(p,dict(pairs,**{name:r.prove(v['ranges'][name],values,d)}),d);rejects('Index:RoundSumMismatch',lambda:c.verify(p,c.roots(p,bad),bad,d))
    changed=r.prove(v['ranges']['difference'],[0,1,0],d);assert ((1<<31)-1)%r.sc.P==0;bad,_=c.assemble(p,dict(pairs,difference=changed),d);rejects('Index:RoundSumMismatch',lambda:c.verify(p,c.roots(p,bad),bad,d))
    for key in ('receipt','certificate','mask','split','representation'):rejects('ProofShape',lambda:c.verify(p,roots,dict(proof,**{key:{}}),d))
    bad=copy.deepcopy(proof);bad['zero']['rounds'][0][0]=(False,0,0,0);rejects('NoncanonicalField',lambda:c.verify(p,roots,bad,d))
    print('three external/one carry roots, all arithmetic substitutions and actual u=M31+1 versus1 reject',flush=True)


def originals():
    p=spec(B=22,k=7,identity=3540);d=4;v=c.derive(p,d);pairs=c.prepare(p,[1,17,0],d);proof,state=c.assemble(p,pairs,d);roots=c.expected_roots(p,[1,17,0]);assert c.verify(p,roots,proof,d)['state']==state
    for index,coefficient in ((0,v['coefficient']),(1,1),(2,1),(4,-256)):
        bad=copy.deepcopy(proof);bad['zero']['final'][index][0]=r.sc.add(bad['zero']['final'][index][0],r.sc.scalar(1,d));bad['zero']['final'][3][0]=r.sc.add(bad['zero']['final'][3][0],r.sc.scalar(coefficient,d));rejects('Index:ClaimMismatch',lambda:c.verify(p,roots,bad,d))
    for changed in (replace(p,row=replace(p.row,window=32)),replace(p,row=replace(p.row,position=32)),replace(p,representation=replace(p.representation,function=replace(p.representation.function,params=bytes([22,12,13,7]))))):rejects('Index:ClaimMismatch',lambda:c.verify(changed,roots,proof,d))
    changed=replace(p,representation=replace(p.representation,function=replace(p.representation.function,params=bytes([22,12,14,8]))));rejects('High:CapRelation:ClaimMismatch',lambda:c.verify(changed,roots,proof,d))
    i,tables=c.part(p,proof,d);tables[0][-1]=r.sc.scalar(1,d);tables[3][-1]=r.sc.scalar(v['coefficient'],d);t=c.transcript(v,roots+[proof['carry_root']],[pairs[name][1] for name in c.CHILDREN],d);bad=dict(proof,zero=r.zero_prove(t,i,tables));rejects('Index:ClaimMismatch',lambda:c.verify(p,roots,bad,d))
    print('all five originals, shifted public zeros and expected mask/position/function/split replays reject',flush=True)


def boundaries():
    p=spec(identity=3550);d=4;v=c.derive(p,d);us=[0,1<<31,0];w=c.witness(p,us);pairs=c.prepare(p,us,d)
    for name,index,value in (('difference',1,(1<<31)+1),('high',1,32769),('high',2,1),('low',2,1),('carry',0,2),('carry',3*v['n'],1)):
        child=v['ranges'][name];values=w[name].copy();values[index]=value;caps=list(child.caps);caps[index]=value
        changed=r.assemble(child,*r.witness(replace(child,caps=tuple(caps)),values),d);reason=name.title()+':CapRelation:RoundSumMismatch'
        bad,_=c.assemble(p,dict(pairs,**{name:changed}),d);rejects(reason,lambda:c.verify(p,c.roots(p,bad),bad,d))
    child=v['ranges']['difference'];changed=r.assemble(child,*r.witness(replace(child,caps=child.caps+(1,)),us+[1]),d);bad,_=c.assemble(p,dict(pairs,difference=changed),d);rejects('Difference:CapRelation:RoundSumMismatch',lambda:c.verify(p,c.roots(p,bad),bad,d))
    proof,_=c.assemble(p,pairs,d);bad=copy.deepcopy(proof);bad['low']['words']+=[1]*v['n'];rejects('Low:OpeningShape',lambda:c.verify(p,c.roots(p,proof),bad,d))
    p=spec(B=15,k=15,nearest=True,identity=3551);v=c.derive(p,d);pairs=c.prepare(p,[0,1<<15,0],d);bad,_=c.assemble(p,dict(pairs,low=r.prove(v['ranges']['low'],[0,1,0],d)),d);rejects('Index:RoundSumMismatch',lambda:c.verify(p,c.roots(p,bad),bad,d))
    child=v['ranges']['low'];caps=list(child.caps);caps[0]=32768;changed=r.assemble(child,*r.witness(replace(child,caps=tuple(caps)),[32768,0,0]),d);bad,_=c.assemble(p,dict(pairs,low=changed),d);rejects('Low:CapRelation:RoundSumMismatch',lambda:c.verify(p,c.roots(p,bad),bad,d))
    print('whole bounds, masked/padded indices, nonzero last carry and inclusive endpoint with low1 reject',flush=True)


def composition():
    p=spec(identity=3560);d=4;S=p.row.schema.score_max;xs=[S,-1,S];source,state=c.attained.prove(p.row,xs,d);expected=c.attained.expected_roots(p.row,xs);assert c.attained.verify(p.row,expected,source,d)['state']==state
    us=c.attained.witness(p.row,xs)['difference'];assert us==[0,1<<31,0];proof,state=c.prove(p,us,d);roots=c.roots(p,proof);assert roots[0]==expected[3];assert c.verify(p,[expected[3],roots[1],roots[2]],proof,d)['state']==state
    other,other_state=c.attained.prove(p.row,[S,0,S],d);alternate=c.attained.expected_roots(p.row,[S,0,S]);assert c.attained.verify(p.row,alternate,other,d)['state']==other_state and alternate[3]!=expected[3]
    rejects('Difference:CommitmentMismatch',lambda:c.verify(p,[alternate[3],roots[1],roots[2]],proof,d))
    print('complete attained maximum composes at u=2^31; another valid maximum difference cannot substitute',flush=True)


if __name__=='__main__':
    modes={'--corpus':corpus,'--controls':controls,'--originals':originals,'--boundaries':boundaries,'--composition':composition,'--honest':honest,'--maximum':lambda:honest(True)}
    if sys.argv[1:]:
        assert all(mode in modes for mode in sys.argv[1:])
        for mode in sys.argv[1:]:modes[mode]()
    else:
        for test in modes.values():test()
