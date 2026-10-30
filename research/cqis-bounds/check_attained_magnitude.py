# /// script
# requires-python = ">=3.12"
# dependencies = ["blake3==1.0.11", "python-flint==0.9.0"]
# ///
"""Q26/Q31 attained magnitude: exact byte columns and complete false-proof controls."""
import copy
from dataclasses import replace
import hashlib
import json
import random
import sys
import attained_magnitude as m

r=m.r


def rejects(reason,call):
    try: call()
    except ValueError as error: assert str(error)==reason,(reason,str(error))
    else: raise AssertionError('accepted '+reason)


def schema(kind,count):
    return m.row.Spec(kind,count,0,'dynamic',0)


def corpus():
    rng=random.Random(2673); digest=hashlib.sha256(); cells=0
    for case in range(10000):
        kind=('wide','gated')[case%2]; count=1+case%9; h=32768 if kind=='wide' else 1<<30
        high=h-1 if kind=='wide' else h
        p=m.Spec(replace(schema(kind,count),fraction=case%(31 if kind=='wide' else 45)),case,61,67,1+case%2); v=m.derive(p,4)
        xs=[rng.randrange(-h,high+1) for _ in range(count)]
        if case%17==0: xs=[0]*count
        elif case%7==0: xs[0]=-h
        maximum,gaps,indicator,cs=m.witness(p,xs); expected=sorted(abs(x) for x in xs)[-1]
        assert maximum==[expected] and sum(indicator)==1 and indicator.index(1)==next(i for i,x in enumerate(xs) if abs(x)==expected)
        assert gaps==[expected-abs(x) for x in xs] and all(0<=g<=h for g in gaps)
        n,b=v['n'],v['width']; mags=[abs(x) for x in xs]+[0]*(n-count); padded=gaps+[0]*(n-count)
        for i in range(n):
            target=expected if i<count else 0
            for j in range(b):
                incoming=cs[(j-1)*n+i] if j else 0
                assert mags[i].to_bytes(b,'little')[j]+padded[i].to_bytes(b,'little')[j]+incoming==target.to_bytes(b,'little')[j]+256*cs[j*n+i]
            assert cs[(b-1)*n+i]==0
        assert all(c in (0,1) for c in cs)
        digest.update(v['raw']+b''.join(x.to_bytes(b,'little',signed=True) for x in xs)+bytes(indicator)+bytes(cs)); cells+=n*b
    assert cells==196636 and digest.hexdigest()=='ba9c1d2840b9ade277b5f64a3844b25b7c567946f79c023feafa34698039fbc8'
    print(json.dumps(dict(seed=2673,cases=10000,byte_cells=cells,sha256=digest.hexdigest()),sort_keys=True),flush=True)


def honest():
    digest=hashlib.sha256(); total=0
    for d in (4,8):
        for repetitions in (1,2):
            for kind in ('wide','gated'):
                h=32768 if kind=='wide' else 1<<30; high=h-1 if kind=='wide' else h
                for xs in ([0],[-h,high,-h]):
                    p=m.Spec(schema(kind,len(xs)),801+(kind=='gated'),61,67,repetitions); v=m.derive(p,d)
                    proof,state=m.prove(p,xs,d); out=m.verify(p,m.roots(p,proof),proof,d)
                    assert out['state']==state; a,b=v['a'],v['b']; dims=[a+b+1,a+b+1,a+2,b+1,a+b+1,a+1]
                    f=lambda x:3*x*(x-1)//2+2*x
                    assert out['account']==dict(identities=[((1<<k)+255,repetitions) for k in dims],
                        lookup_reduction_numerator=sum(repetitions*(f(k)+f(8)+3*k) for k in dims),
                        range_reduction_numerator=71*a+48*b+9,selection_reduction_numerator=a,denominator=r.sc.P**d)
                    assert out['draws'].get(r.zc.WEIGHT,0)==4*a+3*b and out['draws'].get(r.zc.tr.CHALLENGE,0)==5*a+3*b
                    signed=out['children'][0]; draws=[out['draws'],signed['draws']]+[x['draws'] for x in signed['ranges']+out['children'][1:]]
                    assert sum(x.get(r.zc.WEIGHT,0) for x in draws)==30*a+19*b+4
                    assert sum(x.get(r.zc.tr.CHALLENGE,0) for x in draws)==31*a+19*b+4
                    for child,k in zip(signed['ranges']+out['children'][1:],dims):
                        account=child['account']
                        assert (account['identity_numerator'],account['identity_power'])==((1<<k)+255,repetitions)
                        assert account['lookup_reduction_numerator']==repetitions*(f(k)+f(8)+3*k)
                    assert len(out['claims'])==9 and len(out['one']['claims'])==1
                    assert sum(x['numerator'] for x in out['sc'])==10*a+8*b
                    i=m.one_descriptor(p,v,d); assert out['one']['sc']==dict(id=i['id'],m=a,degree=1,field_degree=d,numerator=a)
                    digest.update(state); total+=1; print('proof',d,repetitions,kind,len(xs),flush=True)
    assert total==16 and digest.hexdigest()=='3e44bd103f327780f275727aa5f3601dc87718c21975c189881340b5207ccc74'
    print(json.dumps(dict(proofs=total,sha256=digest.hexdigest()),sort_keys=True),flush=True)


def supplied(p,xs,maximum,gaps,indicator,d):
    v=m.derive(p,d); n,b=v['n'],v['width']; mags=[abs(x) for x in xs]+[0]*(n-len(xs)); gs=gaps+[0]*(n-len(xs))
    cs=[]; incoming=[0]*n
    for j in range(b):
        incoming=[((mags[i]>>(8*j)&255)+(gs[i]>>(8*j)&255)+incoming[i])//256 for i in range(n)]; cs.extend(incoming)
    pairs=dict(input=m.ss.prove(v['input'],xs,d),maximum=r.prove(v['maximum'],[maximum],d),
               gap=r.prove(v['gap'],gaps,d),indicator=r.prove(v['indicator'],indicator,d))
    return pairs,cs


def controls():
    d=4; p=m.Spec(schema('wide',3),897,61,67,1); v=m.derive(p,d)
    pairs,cs=supplied(p,[1,2,3],3,[2,1,0],[0,0,1],d); proof,_=m.assemble(p,pairs,cs,d); expected=m.roots(p,proof)
    for name,index,reason in (('input',0,'Input:Raw:CommitmentMismatch'),('input',1,'Input:Magnitude:CommitmentMismatch'),
                              ('maximum',None,'Maximum:CommitmentMismatch'),('gap',None,'Gap:CommitmentMismatch'),
                              ('indicator',None,'Indicator:CommitmentMismatch')):
        bad=copy.deepcopy(proof); part=bad[name]['ranges'][index] if index is not None else bad[name]; part['words'][0]+=1
        rejects(reason,lambda:m.verify(p,expected,bad,d))
    bad=copy.deepcopy(proof); bad['carry'][0]^=1
    rejects('Carry:CommitmentMismatch',lambda:m.verify(p,expected,bad,d))
    bad=copy.deepcopy(proof); bad['zero'][0]['final'][0][0]=r.sc.add(bad['zero'][0]['final'][0][0],r.sc.scalar(1,d))
    rejects('MagnitudeGap:FinalEvaluationMismatch',lambda:m.verify(p,expected,bad,d))
    bad['zero'][0]['final'][1][0]=r.sc.add(bad['zero'][0]['final'][1][0],r.sc.scalar(-1,d))
    rejects('MagnitudeGap:ClaimMismatch',lambda:m.verify(p,expected,bad,d))
    for xs,maximum,gaps,indicator,reason in (([1,2,3],2,[1,0,0],[0,1,0],'MagnitudeGap:RoundSumMismatch'),
            ([1,2,3],4,[3,2,1],[1,0,0],'Attainment:RoundSumMismatch'),
            ([1,2,3],4,[3,2,1],[0,0,0],'OneHot:RoundSumMismatch'),
            ([3,3,1],3,[0,0,2],[1,1,0],'OneHot:RoundSumMismatch')):
        ps,carry=supplied(p,xs,maximum,gaps,indicator,d); false,_=m.assemble(p,ps,carry,d)
        rejects(reason,lambda:m.verify(p,m.roots(p,false),false,d))
    # Select padded zero: every parent equation holds for an above-maximum claim.
    ps,carry=supplied(p,[1,2,3],4,[3,2,1],[0,0,0],d)
    words,bs,cs0=r.witness(v['indicator'],[0,0,0]); words[3]=bs[3]=1; bs[7]=255; cs0[3]=1
    ps['indicator']=r.assemble(v['indicator'],words,bs,cs0,d); false,_=m.assemble(p,ps,carry,d)
    assert sum(words)==1
    for _,i,tables in m.parts(p,false,d): assert all(r.sc.compose(i['terms'],row,d)==r.sc.scalar(0,d) for row in zip(*tables))
    rejects('Indicator:TerminalCarry:RoundSumMismatch',lambda:m.verify(p,m.roots(p,false),false,d))
    # A whole-word difference of p passes all field columns with nonbit carries.
    h=1<<30; alias=m.Spec(schema('gated',2),898,61,67,1); av=m.derive(alias,d)
    ps,_=supplied(alias,[h,1],1,[h,0],[0,1],d); inv=pow(256,-1,r.sc.P); cs=[]; incoming=[0,0]
    assert h+h-1==r.sc.P
    for j in range(4):
        incoming=[(((mag>>(8*j)&255)+(gap>>(8*j)&255)+incoming[i]-(1>>(8*j)&255))*inv)%r.sc.P
                  for i,(mag,gap) in enumerate(((h,h),(1,0)))]; cs.extend(incoming)
    assert incoming==[0,0] and any(c not in (0,1) for c in cs)
    false,_=m.assemble(alias,ps,cs,d)
    for name,i,tables in m.parts(alias,false,d):
        if name!='CarryBoolean': assert all(r.sc.compose(i['terms'],row,d)==r.sc.scalar(0,d) for row in zip(*tables))
    rejects('CarryBoolean:RoundSumMismatch',lambda:m.verify(alias,m.roots(alias,false),false,d))
    for mutate,reason in ((lambda q:q['zero'].pop(),'ProofShape'),(lambda q:q['one']['final'].pop(),'ProofShape'),
                          (lambda q:q['carry'].__setitem__(0,True),'NoncanonicalField'),
                          (lambda q:q['one']['final'].__setitem__(0,(False,0,0,0)),'OneHot:NoncanonicalField')):
        bad=copy.deepcopy(proof); mutate(bad); rejects(reason,lambda:m.verify(p,expected,bad,d))
    for bad in (replace(p,identity=1<<46),replace(p,source=v['base']),replace(p,maximum=p.source),replace(p,repetitions=True),
                replace(p,schema=replace(p.schema,mode='static',scale=1))): rejects('Spec',lambda:m.derive(bad,d))
    rejects('Capacity',lambda:m.witness(replace(p,schema=schema('wide',2049)),None))
    print('attained-magnitude controls passed',flush=True)


def sources():
    d=4; p=m.Spec(schema('wide',3),899,61,67,1); v=m.derive(p,d)
    pairs,cs=supplied(p,[3,3,3],3,[0,0,0],[1,0,0],d); proof,_=m.assemble(p,pairs,cs,d); expected=m.roots(p,proof)
    # Preserve each equation while changing an original/view claim independently.
    coefficients=[1,1,1,-1,-256]
    for slot in range(5):
        bad=copy.deepcopy(proof); other=1 if slot==0 else 0; finals=bad['zero'][0]['final']
        finals[slot][0]=r.sc.add(finals[slot][0],r.sc.scalar(1,d))
        finals[other][0]=r.sc.add(finals[other][0],r.sc.scalar(-coefficients[slot],d))
        rejects('MagnitudeGap:ClaimMismatch',lambda:m.verify(p,expected,bad,d))
    bad=copy.deepcopy(proof); bad['zero'][1]['final'][0][0]=r.sc.scalar(1,d)
    rejects('CarryBoolean:ClaimMismatch',lambda:m.verify(p,expected,bad,d))
    bad=copy.deepcopy(proof); bad['zero'][3]['final'][0][0]=r.sc.add(bad['zero'][3]['final'][0][0],r.sc.scalar(1,d))
    rejects('Attainment:ClaimMismatch',lambda:m.verify(p,expected,bad,d))
    # A different genuine onehot has sum1; only actual original consumption rejects.
    bound=[expected[0],proof['mag_root'],expected[1],proof['gap_root'],proof['indicator_root'],proof['carry_root']]
    t=m.transcript(p,bound,[pairs[name][1] for name in m.NAMES],d)
    for (_,i,tables),part in zip(m.parts(p,proof,d),proof['zero']):
        oracle=copy.deepcopy(t); naive=r.zc.prove(oracle,i,tables)
        fast=r.zero_prove(t,i,tables); assert fast==part==naive and t.state==oracle.state
    bad=copy.deepcopy(proof); bad['one'],_=r.sc.prove(t,m.one_descriptor(p,v,d),[[r.sc.scalar(x,d) for x in (0,1,0,0)]])
    rejects('OneHot:ClaimMismatch',lambda:m.verify(p,expected,bad,d))
    bad=copy.deepcopy(proof); bad['one']['final'][0]=r.sc.add(bad['one']['final'][0],r.sc.scalar(1,d))
    rejects('OneHot:FinalEvaluationMismatch',lambda:m.verify(p,expected,bad,d))
    # Valid signed32 input H+1 and every parent equation hold; cap H must dominate.
    h=1<<30; p=m.Spec(schema('gated',1),900,61,67,1); v=m.derive(p,d)
    words=[(h+1)>>(8*j)&255 for j in range(4)]; bs=words+[255]*4; carry=[1]*4
    pairs=dict(input=m.ss.prove(v['input'],[h+1],d),maximum=r.assemble(v['maximum'],words,bs,carry,d),
               gap=r.prove(v['gap'],[0],d),indicator=r.prove(v['indicator'],[1],d))
    false,_=m.assemble(p,pairs,[0]*4,d)
    for _,i,tables in m.parts(p,false,d): assert all(r.sc.compose(i['terms'],x,d)==r.sc.scalar(0,d) for x in zip(*tables))
    rejects('Maximum:TerminalCarry:FinalEvaluationMismatch',lambda:m.verify(p,m.roots(p,false),false,d))
    # Maximum namespace and row capacity are derivable without proving large data.
    p=m.Spec(schema('gated',2048),(1<<46)-1,61,67,2); v=m.derive(p,8)
    assert v['base']+65536==(1<<63)+(1<<62) and v['n']==2048
    assert max(x['id'] for _,x,_ in m.parts(p,dict(input={'ranges':[None,{'words':[0]*8192}]},
        maximum={'words':[0]*4},gap={'words':[0]*8192},indicator={'words':[0]*2048},carry=[0]*8192),8))<1<<64
    print('attained-magnitude source controls passed',flush=True)


if __name__=='__main__':
    modes={'--corpus':corpus,'--honest':honest,'--controls':controls,'--sources':sources}
    if sys.argv[1:]:
        assert all(x in modes for x in sys.argv[1:])
        for mode in sys.argv[1:]: modes[mode]()
    else:
        for test in modes.values(): test()
