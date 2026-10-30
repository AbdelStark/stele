# /// script
# requires-python = ">=3.12"
# dependencies = ["blake3==1.0.11", "python-flint==0.9.0"]
# ///
"""Q26/Q31 capped range proofs with real lookup and original consumers."""
import copy
from dataclasses import replace
import hashlib
import json
import random
import sys
import capped_range as r
import limbs


def rejects(reason,call):
    try: call()
    except ValueError as error: assert str(error)==reason,(reason,str(error))
    else: raise AssertionError('accepted '+reason)


def corpus():
    rng=random.Random(2667); digest=hashlib.sha256(); cells=0
    for case in range(10000):
        caps=tuple(rng.randrange(r.sc.P) for _ in range(1+case%17))
        if case%7==0: caps=(0,)+caps[1:]
        if case%11==0: caps=(r.sc.P-1,)+caps[1:]
        p=r.Spec(case,23,caps,1+case%2); xs=[rng.randrange(cap+1) for cap in caps]
        words,bs,cs=r.witness(p,xs); a,n,base,raw=r.derive(p,4)
        assert n==1<<a and words==xs+[0]*(n-len(xs)) and len(bs)==8*n and len(cs)==4*n
        assert all(0<=x<=255 for x in bs) and all(x in (0,1) for x in cs)
        for row in range(n):
            cap=caps[row] if row<len(caps) else 0
            x=sum(bs[j*n+row] << (8*j) for j in range(4))
            slack=sum(bs[(4+j)*n+row] << (8*j) for j in range(4))
            assert x==words[row] and x+slack==cap
            for j in range(4):
                incoming=cs[(j-1)*n+row] if j else 0
                assert bs[j*n+row]+bs[(4+j)*n+row]+incoming==(cap >> (8*j) & 255)+256*cs[j*n+row]
            assert cs[3*n+row]==0
        digest.update(raw+bytes(bs)+bytes(cs)); cells+=n
    assert cells==119375 and digest.hexdigest()=='67692ccccdf631b46af21c1f1725e659fb8dc2b68bad2a4dbdc26f5911a3876a'
    maximum=r.Spec(10001,23,(r.sc.P-1,)+(0,)*4095,2)
    words,bs,cs=r.witness(maximum,[r.sc.P-1]+[0]*4095)
    assert r.derive(maximum,8)[:2]==(12,4096) and len(bs)==32768 and len(cs)==16384
    print(json.dumps(dict(seed=2667,cases=10000,padded_rows=cells,sha256=digest.hexdigest()),sort_keys=True),flush=True)


def honest():
    total=0; digest=hashlib.sha256()
    for d in (4,8):
        for repetitions in (1,2):
            for case,caps in enumerate(((0,),(r.sc.P-1,),(15,255,256),(0,1,65535,65536,16777216))):
                p=r.Spec(77+case,19,caps,repetitions); xs=[cap if j%2==0 else cap//2 for j,cap in enumerate(caps)]
                proof,state=r.prove(p,xs,d); words,bs,cs=r.witness(p,xs)
                out=r.verify(p,r.source_root(p,words),proof,d); assert out['state']==state
                a,n,base,_=r.derive(p,d); m=a+3; f=lambda x:3*x*(x-1)//2+2*x
                assert out['account']==dict(identity_numerator=8*n+255,identity_power=repetitions,
                    lookup_reduction_numerator=repetitions*(f(m)+f(8)+3*m),
                    range_reduction_numerator=9*a+10,denominator=r.sc.P**d)
                assert sum(v['numerator'] for v in out['sc'])==9*a+10
                records=[]; claims=[]
                for _,i,_ in r.parts(p,words,bs,cs,d):
                    dimension,degree=i['m'],r.sc.degree(i)
                    for phase,dim,deg,num in ((0,dimension,1,dimension),(1,0,0,0),(2,dimension,degree,dimension*degree)):
                        records.append(dict(id=i['id'],phase=phase,m=dim,degree=deg,field_degree=d,numerator=num))
                    claims.extend((identity,dimension) for identity in i['ids'])
                assert out['sc']==records and [(i,len(point)) for i,point,_ in out['claims']]==claims
                assert out['draws']=={r.zc.WEIGHT:4*a+4,r.zc.tr.CHALLENGE:4*a+4}
                assert len(out['claims'])==12
                assert len(out['lookup_claims'])==2*repetitions
                assert out['lookup_draws'].get(r.lu.UNIT,0)==0
                assert out['lookup_draws'][r.lu.BETA]==out['lookup_draws'][r.lu.ALPHA]==repetitions
                assert out['lookup_draws'][r.lu.ft.GAMMA]==out['lookup_draws'][r.lu.ft.FOLD]==repetitions*(m+8)
                assert out['lookup_draws'][r.lu.ft.tr.CHALLENGE]==repetitions*(m*(m-1)//2+28+m)
                assert proof['lookup']['sources']==[bs]
                assert r.lookup_plan(p,d)['table']==tuple((x,) for x in range(256))
                assert r.lookup_plan(p,d)['sigma']==(1,)*(8*n)
                assert r.lookup_plan(p,d)['b']==m and 8*n<r.sc.P
                if case==0:
                    fast=r.transcript(p,r.source_root(p,words),proof,d,out['lookup_state'])
                    naive=r.transcript(p,r.source_root(p,words),proof,d,out['lookup_state'])
                    for _,i,tables in r.parts(p,words,bs,cs,d):
                        assert r.zero_prove(fast,i,tables)==r.zc.prove(naive,i,tables)
                    assert fast.state==naive.state
                digest.update(state); total+=1
                print('proof',d,repetitions,case,flush=True)
    assert total==16
    assert digest.hexdigest()=='823a52e835b9c7bbf2aad50a590a422b6d1950723886d91a963a83e0c3a9a4a3'
    print(json.dumps(dict(proofs=total,sha256=digest.hexdigest()),sort_keys=True),flush=True)


def controls():
    p=r.Spec(97,21,(255,),1); d=4
    proof,_=r.prove(p,[0],d); root=r.source_root(p,[0])
    changed=copy.deepcopy(proof); changed['zero'][0]['final'][0][0]=r.sc.scalar(1,d)
    rejects('Reconstruction:FinalEvaluationMismatch',lambda:r.verify(p,root,changed,d))
    # Preserve the scalar reconstruction equation with two coordinated finals;
    # conditional reduction success is insufficient without original consumption.
    changed['zero'][0]['final'][1][0]=r.sc.scalar(1,d)
    rejects('Reconstruction:ClaimMismatch',lambda:r.verify(p,root,changed,d))
    rejects('CapRelation:ClaimMismatch',lambda:r.verify(replace(p,caps=(254,)),root,proof,d))
    rejects('CommitmentMismatch',lambda:r.verify(replace(p,source=22),root,proof,d))
    changed=copy.deepcopy(proof); changed['zero'][0]['final'].pop()
    rejects('ProofShape',lambda:r.verify(p,root,changed,d))
    for key in ('words','carry'):
        changed=copy.deepcopy(proof); changed[key][0]+=1
        rejects('CommitmentMismatch',lambda:r.verify(p,root,changed,d))
    changed=copy.deepcopy(proof); changed['lookup']['sources'][0][0]+=1
    rejects('CommitmentMismatch',lambda:r.verify(p,root,changed,d))
    changed=copy.deepcopy(proof); changed['zero'].pop()
    rejects('ProofShape',lambda:r.verify(p,root,changed,d))
    changed=copy.deepcopy(proof); changed['words'][0]=True
    rejects('NoncanonicalField',lambda:r.verify(p,root,changed,d))
    changed=copy.deepcopy(proof); changed['carry'].append(0)
    rejects('OpeningShape',lambda:r.verify(p,root,changed,d))
    # Honest range bytes cannot discharge a different original scalar.
    bs=[0]*4+[255,0,0,0]; cs=[0]*4
    false,_=r.assemble(p,[256],bs,cs,d)
    rejects('Reconstruction:FinalEvaluationMismatch',lambda:r.verify(p,r.source_root(p,[256]),false,d))
    # x+p reconstruction and a wrapped complement satisfy every column and bit
    # relation; the nonzero terminal carry must remain an actual consumer.
    p=replace(p,caps=(r.sc.P-1,)); word=r.sc.P; slack=(1<<32)-1
    bs=[word >> (8*j) & 255 for j in range(4)]+[slack >> (8*j) & 255 for j in range(4)]
    carry=0; cs=[]
    for j in range(4): carry=(bs[j]+bs[4+j]+carry)//256; cs.append(carry)
    assert cs[-1]==1
    false,_=r.assemble(p,[0],bs,cs,d)
    rejects('TerminalCarry:FinalEvaluationMismatch',lambda:r.verify(p,r.source_root(p,[0]),false,d))
    # Field-valued carries can hide p even with a zero terminal carry.
    p=replace(p,caps=(0,)); word=r.sc.P-1; slack=1
    bs=[word >> (8*j) & 255 for j in range(4)]+[slack >> (8*j) & 255 for j in range(4)]
    carry=0; cs=[]
    for j in range(4): carry=(bs[j]+bs[4+j]+carry)*pow(256,-1,r.sc.P)%r.sc.P; cs.append(carry)
    assert cs[-1]==0 and any(x not in (0,1) for x in cs)
    false,_=r.assemble(p,[word],bs,cs,d)
    rejects('CarryBoolean:RoundSumMismatch',lambda:r.verify(p,r.source_root(p,[word]),false,d))
    padded=replace(p,caps=(2,3,4)); words,bs,cs=r.witness(padded,[0,0,0]); words[-1]=1
    false,_=r.assemble(padded,words,bs,cs,d)
    rejects('Reconstruction:RoundSumMismatch',lambda:r.verify(padded,r.source_root(padded,words),false,d))
    # Root-bound but out-of-table bytes: construct the real lookup arithmetic,
    # not a membership-scan failure in the honest witness generator.
    p=replace(p,caps=(0,)); plan=r.lookup_plan(p,d); bs=[1,0,0,0,r.sc.P-1,0,0,0]
    roots=r.lu.source_roots(plan,[bs]); t,theta=r.lu.begin(plan,roots,d)
    mus=[[r.sc.scalar(0,d)]*256]; mr=[r.lu.mu_root(plan,0,mus[0],d)]
    pairs=r.lu.pairs(t,plan,mr); part,_=r.lu.prove_round(t,plan,[bs],mus[0],theta[0],pairs[0],0)
    changed=copy.deepcopy(proof); changed.update(words=[1],carry=[0]*4,byte_root=roots[0])
    changed['lookup']=dict(mu_roots=mr,rounds=[part],sources=[bs],mus=mus)
    rejects('RootMismatch',lambda:r.verify(p,r.source_root(p,[1]),changed,d))
    for bad in (replace(p,caps=(True,)),replace(p,caps=(r.sc.P,)),replace(p,repetitions=0),replace(p,identity=-1)):
        rejects('Spec',lambda:r.derive(bad,d))
    rejects('Capacity',lambda:r.derive(replace(p,caps=(0,)*4097),d))
    _,_,base,_=r.derive(p,d)
    rejects('Spec',lambda:r.derive(replace(p,source=base),d))
    rejects('Root',lambda:r.verify(p,bytes(31),proof,d))
    rejects('Range',lambda:r.prove(p,[1],d))
    print('capped-range controls passed',flush=True)


def columns():
    for d,spec,left,right in [(4,limbs.Spec(1,(1<<159)-1,1,8),((1<<158)+5,),(1,)),
                              (8,limbs.Spec(2,257,31,4),(200,1),(17,31))]:
        w=limbs.witness(spec,left,right); cert=limbs.derive(spec)
        p,values,roles=r.columns(spec,w,201+d,29,1)
        caps=[]; expected=[]; labels=[]
        for side in ('left','right'):
            for i,ds in enumerate(w[side]):
                for j,value in enumerate(ds):
                    caps.append(cert[side+'_caps'][j]); expected.append(value); labels.append((side,i,j))
        for side in ('result','carry'):
            for j,value in enumerate(w[side]):
                caps.append(cert[side+'_caps'][j]); expected.append(value); labels.append((side,0,j))
        assert p.caps==tuple(caps) and values==expected and roles==tuple(labels) and len(set(roles))==len(roles)
        zero=limbs.witness(spec,(0,)*spec.count,(0,)*spec.count)
        assert r.columns(spec,zero,201+d,29,1)[0]==p
        proof,state=r.prove(p,values,d); words,_,_=r.witness(p,values)
        assert r.verify(p,r.source_root(p,words),proof,d)['state']==state
        malformed=copy.deepcopy(w); malformed['left']=malformed['left'][:-1]
        rejects('Witness',lambda:r.columns(spec,malformed,201+d,29,1))
    rejects('Capacity',lambda:r.columns(limbs.Spec(3000,255,255,8),None,201,29,1))
    print('actual limb-column caps: both-field proofs passed',flush=True)


if __name__=='__main__':
    modes={'--corpus':corpus,'--honest':honest,'--controls':controls,'--columns':columns}
    if len(sys.argv)==2: modes[sys.argv[1]]()
    else:
        assert len(sys.argv)==1
        corpus(); honest(); controls(); columns()
