# /// script
# requires-python = ">=3.12"
# dependencies = ["numpy==2.3.4", "blake3==1.0.11", "python-flint==0.9.0"]
# ///
"""Actual exponent/factor sources, one-hot bounds and public-table consumers."""
import copy
from collections import Counter
from dataclasses import replace
import hashlib
import json
import random
import sys
import numpy as np
import norm_exponent as c

r=c.r


def rejects(reason,call):
    try: call()
    except ValueError as error: assert str(error)==reason,(reason,str(error))
    else: raise AssertionError('accepted '+reason)


def spec(identity=1050,repetitions=1):
    return c.Spec(c.norm.Spec(16384,30,30,14,(1<<32)-1,(1<<32)-2),identity,79,83,repetitions)


def corpus():
    rng=random.Random(2686); digest=hashlib.sha256(); indices,grid=c.public_tables()
    assert indices==list(range(33))+[0]*31 and len(grid)==1024
    for a in range(-23,10):
        offset,factors,indicator=c.witness(spec(),a)
        assert offset==[a+23] and sum(indicator)==1 and indicator[a+23]==1
        assert [grid[j*64+a+23] for j in range(16)]==factors
        assert int.from_bytes(bytes(factors[:8]),'little')==4**max(-a,0)
        assert int.from_bytes(bytes(factors[8:]),'little')==4**max(a,0)
    assert all(grid[j*64+i]==0 for j in range(16) for i in range(33,64))
    for case in range(10000):
        p=spec(case,1+case%2); a=rng.randrange(-23,10); offset,factors,indicator=c.witness(p,a)
        values=np.left_shift(np.int64(1),2*np.maximum(np.array([-a,a],dtype=np.int64),0))
        expected=np.array(values,dtype='<u8').tobytes(); assert bytes(factors)==expected
        digest.update(c.derive(p,(4,8)[case%2])['raw']+bytes(offset+factors+indicator))
    p=spec((1<<50)-1,2); v=c.derive(p,8); assert v['base']+4096==(1<<63)+(1<<62)
    for bad in (replace(p,identity=1<<50),replace(p,source=p.output),replace(p,source=v['base']),replace(p,repetitions=True),
                replace(p,schema=replace(p.schema,d=16385)),replace(p,schema=replace(p.schema,en=2,ed=2))): rejects('Spec',lambda:c.derive(bad,4))
    for a in (-24,10,True): rejects('Exponent',lambda:c.witness(p,a))
    rejects('Spec',lambda:c.derive(p,True))
    assert digest.hexdigest()=='cb0a9948a89b6da7522709e62144c297f404742067906c41dab2ee42363aed20'
    print(json.dumps(dict(seed=2686,cases=10000,exponents=33,sha256=digest.hexdigest()),sort_keys=True),flush=True)


def public(d):
    rng=random.Random(2687+d); digest=hashlib.sha256(); indices,grid=c.public_tables()
    fields=[[r.sc.scalar(x,d) for x in xs] for xs in (indices,grid)]
    def basis(point,index):
        value=r.sc.scalar(1,d)
        for bit,x in enumerate(reversed(point)):
            value=r.sc.mul(value,x if index>>bit&1 else r.sc.add(r.sc.scalar(1,d),r.sc.neg(x)))
        return value
    for case in range(10000):
        point=[tuple(rng.randrange(r.sc.P) for _ in range(d)) for _ in range(10)]
        if case%31<2: point=[r.sc.scalar(case%31,d)]*10
        elif case%31==2: point=[r.sc.scalar(rng.randrange(2),d) for _ in range(10)]
        elif case%31==3: point=[r.sc.scalar(-1,d)]*10
        iw=[basis(point[4:],i) for i in range(33)]; jw=[basis(point[:4],j) for j in range(16)]
        index=r.zc.total((tuple(i*x%r.sc.P for x in w) for i,w in enumerate(iw)),d)
        value=r.sc.scalar(0,d)
        for i in range(33):
            a=i-23
            for side,power in enumerate((2*max(-a,0),2*max(a,0))):
                term=r.sc.mul(jw[8*side+power//8],iw[i]); value=r.sc.add(value,tuple((1<<(power%8))*x%r.sc.P for x in term))
        assert r.zc.folded(fields[0],point[4:])==index and r.zc.folded(fields[1],point)==value
        digest.update(r.sc.encode(index)+r.sc.encode(value))
        if case%1000==999: print('public',d,case+1,flush=True)
    print(json.dumps(dict(field=d,public_points=10000,sha256=digest.hexdigest()),sort_keys=True),flush=True)


def account(p,out,d):
    reps=p.repetitions
    assert out['account']==dict(identities=[(383,reps)],lookup_reduction_numerator=198*reps,
        range_reduction_numerator=102,selection_reduction_numerator=6,denominator=r.sc.P**d)
    assert out['draws']=={r.zc.WEIGHT:16,r.zc.tr.CHALLENGE:22}
    child=out['indicator']; assert child['draws']=={r.zc.WEIGHT:24,r.zc.tr.CHALLENGE:24}
    assert len(out['claims'])==6 and len(out['one']['claims'])==1 and sum(x['numerator'] for x in out['sc'])==48
    assert child['lookup_draws']==Counter({r.lu.BETA:reps,r.lu.ALPHA:reps,r.lu.ft.GAMMA:15*reps,r.lu.ft.FOLD:15*reps,r.lu.ft.tr.CHALLENGE:56*reps})


def honest():
    digest=hashlib.sha256(); count=0
    for d in (4,8):
        for reps in (1,2):
            for a in (-23,-1,0,9):
                p=spec(1051+count,reps); proof,state=c.prove(p,a,d); out=c.verify(p,c.expected_roots(p,a),proof,d)
                assert out['state']==state; account(p,out,d); digest.update(state); count+=1
                print('honest',count,d,reps,a,flush=True)
    assert count==16 and digest.hexdigest()=='9f539bcceead4396722ec3e4e295af53d5a910de423d9ed37f84aad9a8faf650'
    print(json.dumps(dict(proofs=count,sha256=digest.hexdigest()),sort_keys=True),flush=True)


def controls():
    d=4; p=spec(1080); v=c.derive(p,d); pair,offset,factors=c.prepare(p,0,d); proof,state=c.assemble(p,pair,offset,factors,d)
    expected=c.expected_roots(p,0); assert c.verify(p,expected,proof,d)['state']==state
    for key,size in (('offset',1),('factors',16)):
        for j in range(size):
            bad=copy.deepcopy(proof); bad[key][j]+=1; rejects(key.title()+':CommitmentMismatch',lambda:c.verify(p,expected,bad,d))
    bad=copy.deepcopy(proof); bad['indicator']['words'][23]=0
    rejects('Indicator:CommitmentMismatch',lambda:c.verify(p,expected,bad,d))
    for slot,label in ((0,'Exponent'),(1,'Factors')):
        bad=copy.deepcopy(proof)
        for j in (1,2): bad['zero'][slot]['final'][j][0]=r.sc.add(bad['zero'][slot]['final'][j][0],r.sc.scalar(1,d))
        rejects(label+':ClaimMismatch',lambda:c.verify(p,expected,bad,d))
    for j in (0,7,8,15):
        altered=list(factors); altered[j]+=1; false,_=c.assemble(p,pair,offset,altered,d)
        rejects('Factors:RoundSumMismatch',lambda:c.verify(p,c.roots(p,offset,altered),false,d))
    false,_=c.assemble(p,pair,[32],factors,d)
    rejects('Exponent:RoundSumMismatch',lambda:c.verify(p,c.roots(p,[32],factors),false,d))
    for active,reason in (([], 'OneHot:RoundSumMismatch'),([23,24], 'Exponent:RoundSumMismatch')):
        words=[int(i in active) for i in range(64)]; child=r.prove(v['indicator'],words,d); false,_=c.assemble(p,child,offset,factors,d)
        rejects(reason,lambda:c.verify(p,expected,false,d))
    # Padded selection satisfies both parent relations and sum1, but not its cap.
    words,bs,cs=r.witness(v['indicator'],[0]*64); words[63]=bs[63]=cs[63]=1; bs[127]=255
    child=r.assemble(v['indicator'],words,bs,cs,d); false,_=c.assemble(p,child,[0],[0]*16,d)
    for _,i,tables in c.parts(p,false,d): assert all(r.sc.compose(i['terms'],row,d)==r.sc.scalar(0,d) for row in zip(*tables))
    rejects('Indicator:TerminalCarry:RoundSumMismatch',lambda:c.verify(p,c.roots(p,[0],[0]*16),false,d))
    words,bs,cs=r.witness(v['indicator'],[0]*64); words[23]=bs[23]=2; bs[87]=255; cs[23]=1
    child=r.assemble(v['indicator'],words,bs,cs,d); false,_=c.assemble(p,child,offset,factors,d)
    rejects('Indicator:TerminalCarry:RoundSumMismatch',lambda:c.verify(p,expected,false,d))
    for mutate,reason in ((lambda q:q['factors'].__setitem__(0,True),'NoncanonicalField'),(lambda q:q['offset'].__setitem__(0,r.sc.P),'NoncanonicalField'),
                          (lambda q:q['factors'].pop(),'OpeningShape'),(lambda q:q['zero'].pop(),'ProofShape'),
                          (lambda q:q['one']['final'].__setitem__(0,(False,0,0,0)),'OneHot:NoncanonicalField')):
        bad=copy.deepcopy(proof); mutate(bad); rejects(reason,lambda:c.verify(p,expected,bad,d))
    rejects('Root',lambda:c.verify(p,[False,expected[1]],proof,d))
    rejects('ProofShape',lambda:c.verify(p,expected,dict(proof,grid=[]),d))
    rejects('Exponent:RoundSumMismatch',lambda:c.verify(replace(p,schema=replace(p.schema,F=29)),expected,proof,d))
    print('exponent roots, factor originals, public finals, empty/nonbit/padded selection controls passed',flush=True)


if __name__=='__main__':
    modes={'--corpus':corpus,'--public4':lambda:public(4),'--public8':lambda:public(8),'--honest':honest,'--controls':controls}
    if sys.argv[1:]:
        assert all(mode in modes for mode in sys.argv[1:])
        for mode in sys.argv[1:]: modes[mode]()
    else:
        for test in modes.values(): test()
