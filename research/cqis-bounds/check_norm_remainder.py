# /// script
# requires-python = ">=3.12"
# dependencies = ["numpy==2.3.4", "blake3==1.0.11", "python-flint==0.9.0"]
# ///
"""Strict integer remainder with actual byte ranges and carry consumers."""
import copy
from dataclasses import replace
import hashlib
import json
from math import gcd
import random
import sys
import numpy as np
import norm_remainder as c

r=c.r


def rejects(reason,call):
    try:call()
    except ValueError as error:assert str(error)==reason,(reason,str(error))
    else:raise AssertionError('accepted '+reason)


def spec(count=1,f=0,en=1,ed=3,identity=1400,repetitions=1):
    return c.Spec(c.norm.Spec(count,f,30,14,en,ed),identity,97,107,repetitions)


def corpus():
    rng=random.Random(2702);digest=hashlib.sha256();widths=set()
    for case in range(10000):
        en,ed=rng.randrange(1,1<<32),rng.randrange(1,1<<32);common=gcd(en,ed)
        p=spec(1+case%16384,rng.randrange(31),en//common,ed//common,case,1+case%2);v=c.derive(p,4)
        divisor=rng.randrange(1,v['cert']['D_max']+1);rem=rng.randrange(divisor);gap=divisor-rem-1
        assert int(np.sum(np.array([rem,gap,1],dtype=object)))==divisor
        cs=c.carries(rem,gap);bs=[np.frombuffer(x.to_bytes(16,'little'),dtype=np.uint8).astype(np.int64) for x in (divisor,rem,gap)]
        assert np.array_equal(bs[1]+bs[2]+np.array([1]+cs[:-1],dtype=np.int64),bs[0]+256*np.array(cs,dtype=np.int64))
        assert cs[-1]==0 and all(x in (0,1) for x in cs)
        for name,value in zip(c.NAMES,(divisor,rem,gap)):
            words=r.witness(v['ranges'][name],[value])[0];assert c.external(words)==list(value.to_bytes(16,'little'))
        widths.add(tuple(r.derive(v['ranges'][name],4)[1] for name in c.NAMES));digest.update(v['raw']+divisor.to_bytes(16,'little')+rem.to_bytes(16,'little')+bytes(cs))
    p=spec(16384,30,(1<<32)-1,(1<<32)-2,(1<<50)-1,2);v=c.derive(p,8)
    assert v['base']+4096==(1<<63)+(1<<62) and v['cert']['D_max'].bit_length()==124
    for bad in (replace(p,identity=1<<50),replace(p,repetitions=True),replace(p,divisor=p.remainder),replace(p,divisor=v['base']),replace(p,schema=replace(p.schema,F=True))):
        rejects('Spec',lambda:c.derive(bad,4))
    rejects('Spec',lambda:c.derive(p,True))
    assert digest.hexdigest()=='198097e6694b80c34214660bcde4f0d29607dabc3842c980610eb151155df1d2'
    print(json.dumps(dict(seed=2702,cases=10000,widths=sorted(widths),sha256=digest.hexdigest()),sort_keys=True),flush=True)


def account(p,out,d):
    v=c.derive(p,d);bd,br,_=[r.derive(v['ranges'][name],d)[1] for name in c.NAMES];dims=[bd+1,br+1,br+1];f=lambda m:3*m*(m-1)//2+2*m
    assert out['account']==dict(identities=[((1<<m)+255,p.repetitions) for m in dims],
        lookup_reduction_numerator=sum(p.repetitions*(f(m)+f(8)+3*m) for m in dims),range_reduction_numerator=7*bd+14*br+20,denominator=r.sc.P**d)
    assert out['draws']=={r.zc.WEIGHT:8,r.zc.tr.CHALLENGE:8}
    for label in (r.zc.WEIGHT,r.zc.tr.CHALLENGE):assert out['draws'][label]+sum(x['draws'].get(label,0) for x in out['ranges'])==3*bd+6*br+8
    assert len(out['claims'])==7


def honest():
    digest=hashlib.sha256();count=0;unequal=0
    cases=((1,0,1,3,1,0),(1,7,1,1,None,0),(1,7,1,1,None,None),
           (1,23,1,1,None,None),(16384,30,(1<<32)-1,(1<<32)-2,None,None))
    for d in (4,8):
        for reps in (1,2):
            for length,f,en,ed,divisor,rem in cases:
                p=spec(length,f,en,ed,1401+count,reps);v=c.derive(p,d);divisor=v['cert']['D_max'] if divisor is None else divisor;rem=divisor-1 if rem is None else rem
                proof,state=c.prove(p,divisor,rem,d);out=c.verify(p,c.expected_roots(p,divisor,rem),proof,d)
                assert out['state']==state;account(p,out,d)
                if f in (7,23):assert r.derive(v['ranges']['divisor'],d)[3]>r.derive(v['ranges']['remainder'],d)[3];unequal+=1
                if length==16384:assert divisor.bit_length()==124 and proof['divisor']['words'][15]>0
                digest.update(state);count+=1;print('honest',count,d,reps,length,f,flush=True)
    assert count==20 and unequal==12 and digest.hexdigest()=='a949dd85b7745908ed56a42a83f0a48e3e7a2da887a3f3757f0a2795d0c1ea51'
    print(json.dumps(dict(proofs=count,unequal_width_proofs=unequal,sha256=digest.hexdigest()),sort_keys=True),flush=True)


def pairs(p,divisor,rem,gap,d):
    v=c.derive(p,d);return {name:r.prove(v['ranges'][name],[value],d) for name,value in zip(c.NAMES,(divisor,rem,gap))}


def controls():
    d=4;p=spec(identity=1430);v=c.derive(p,d);children=pairs(p,3,1,1,d);cs=c.carries(1,1);proof,state=c.assemble(p,children,cs,d);expected=c.expected_roots(p,3,1)
    assert c.verify(p,expected,proof,d)['state']==state
    for divisor,rem,gap in ((3,3,0),(0,0,0),(3,4,0)):
        false,_=c.assemble(p,pairs(p,divisor,rem,gap,d),c.carries(rem,gap),d)
        rejects('StrictColumns:RoundSumMismatch',lambda:c.verify(p,c.expected_roots(p,divisor,rem),false,d))
    for index,value,reason in ((0,2,'CarryBoolean:RoundSumMismatch'),(15,1,'TerminalCarry:FinalEvaluationMismatch')):
        altered=list(cs);altered[index]=value;false,_=c.assemble(p,children,altered,d);rejects(reason,lambda:c.verify(p,expected,false,d))
    bad=copy.deepcopy(proof);bad['zero'][2]['final'][0][0]=r.sc.add(bad['zero'][2]['final'][0][0],r.sc.scalar(1,d))
    bad['zero'][2]['final'][1][0]=r.sc.add(bad['zero'][2]['final'][1][0],r.sc.scalar(-1,d))
    rejects('StrictColumns:ClaimMismatch',lambda:c.verify(p,expected,bad,d))
    bad=copy.deepcopy(proof);bad['divisor']['words'][0]+=1;rejects('Divisor:CommitmentMismatch',lambda:c.verify(p,expected,bad,d))
    bad=copy.deepcopy(proof);bad['gap']['words'][0]+=1;rejects('Gap:SourceCopy:ClaimMismatch',lambda:c.verify(p,expected,bad,d))
    for index,identity in enumerate((p.divisor,p.remainder)):
        target=list(expected);words=list((3 if index==0 else 1).to_bytes(16,'little'));words[15]=1;target[index]=r.root(identity,words)
        rejects(('Divisor' if index==0 else 'Remainder')+':CommitmentMismatch',lambda:c.verify(p,target,proof,d))
    bad=copy.deepcopy(proof);bad['carry'][0]=False;rejects('NoncanonicalField',lambda:c.verify(p,expected,bad,d))
    bad=copy.deepcopy(proof);bad['carry'].append(0);rejects('OpeningShape',lambda:c.verify(p,expected,bad,d))
    rejects('ProofShape',lambda:c.verify(p,expected,dict(proof,cap=0),d));rejects('Root',lambda:c.verify(p,[False]*2,proof,d))
    p=spec(f=6,identity=1431);false,_=c.assemble(p,pairs(p,1,r.sc.P,0,d),c.carries(r.sc.P,0),d)
    assert (r.sc.P+1-1)%r.sc.P==0
    rejects('StrictColumns:RoundSumMismatch',lambda:c.verify(p,c.expected_roots(p,1,r.sc.P),false,d))
    print('strict equality/zero/field-alias, carry/terminal, source/final/high-slot controls passed',flush=True)


def compose():
    import norm_divisor as div
    import norm_mantissa_product as mp
    import norm_sum as add
    d=4;p=spec(identity=1443);dp=div.Spec(p.schema,1440,73,79,89,p.divisor,1);pp=mp.Spec(p.schema,1441,101,p.divisor,103,1);sp=add.Spec(p.schema,1442,103,p.remainder,89,1)
    proof,state=div.prove(dp,1,-8,d);dr=div.expected_roots(dp,1,-8,65536,3);assert div.verify(dp,dr,proof,d)['state']==state
    proof,state=mp.prove(pp,21845,3,d);pr=mp.expected_roots(pp,21845,3,65535);pr[1]=dr[3];assert mp.verify(pp,pr,proof,d)['state']==state
    proof,state=add.prove(sp,65535,1,d);sr=add.expected_roots(sp,65535,1,65536);sr[0]=pr[2];sr[2]=dr[2];assert add.verify(sp,sr,proof,d)['state']==state
    proof,state=c.prove(p,3,1,d);roots=[dr[3],sr[1]];assert c.verify(p,roots,proof,d)['state']==state
    false,_=c.prove(p,3,2,d);rejects('Remainder:CommitmentMismatch',lambda:c.verify(p,roots,false,d))
    false,_=c.prove(p,4,1,d);rejects('Divisor:CommitmentMismatch',lambda:c.verify(p,roots,false,d))
    print('actual paired A/D, bounded M/MD, decomposition and strict remainder share the same roots',flush=True)


if __name__=='__main__':
    modes={'--corpus':corpus,'--honest':honest,'--controls':controls,'--compose':compose}
    if sys.argv[1:]:
        assert all(mode in modes for mode in sys.argv[1:])
        for mode in sys.argv[1:]:modes[mode]()
    else:
        for test in modes.values():test()
