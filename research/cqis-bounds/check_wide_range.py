# /// script
# requires-python = ">=3.12"
# dependencies = ["blake3==1.0.11", "python-flint==0.9.0"]
# ///
"""Q26/Q31 exact unsigned byte-word proofs; actual lookup and source consumers."""
import copy
from dataclasses import replace
import hashlib
import json
import random
import sys
import wide_range as r


def rejects(reason,call):
    try: call()
    except ValueError as error: assert str(error)==reason,(reason,str(error))
    else: raise AssertionError('accepted '+reason)


def weights():
    rng=random.Random(2680); points=0
    for d in (4,8):
        for m in range(9):
            for point in ([r.sc.scalar(0,d)]*m,[r.sc.scalar(1,d)]*m,
                          [tuple(rng.randrange(r.sc.P) for _ in range(d)) for _ in range(m)]):
                expected=[r.zc.eq(point,z,d) for z in r.zc.boolean(m,d)]
                assert r.scalar.eq_weights(point,d)==expected
                assert r.zc.total(expected,d)==r.sc.scalar(1,d); points+=len(expected)
    assert points==3066
    print('equality weights: 3066 exact reference values passed',flush=True)


def corpus():
    rng=random.Random(2668); digest=hashlib.sha256(); cells=0
    for case in range(10000):
        bits=case%161; caps=tuple(rng.getrandbits(bits) for _ in range(1+case%9))
        p=r.Spec(case,23,caps,1+case%2); xs=[rng.randrange(cap+1) for cap in caps]
        words,bs,cs=r.witness(p,xs); a,b,n,width,base,raw=r.derive(p,4)
        assert n==1<<a and width==1<<b and width<=32 and len(words)==width*n
        assert bs[:width*n]==words and len(bs)==2*width*n and len(cs)==width*n
        assert all(0<=x<=255 for x in bs) and all(x in (0,1) for x in cs)
        for i in range(n):
            cap=caps[i] if i<len(caps) else 0
            word=sum(words[j*n+i] << (8*j) for j in range(width))
            slack=sum(bs[(width+j)*n+i] << (8*j) for j in range(width))
            assert word==(xs[i] if i<len(xs) else 0) and word+slack==cap
            for j in range(width):
                incoming=cs[(j-1)*n+i] if j else 0
                assert words[j*n+i]+bs[(width+j)*n+i]+incoming==(cap>>(8*j)&255)+256*cs[j*n+i]
            assert cs[(width-1)*n+i]==0
        digest.update(raw+bytes(words)+bytes(bs)+bytes(cs)); cells+=n*width
    assert cells==971914 and digest.hexdigest()=='c3b0e63ec3fd2ae6d773636f7f60d4afa225e3a6ecb0d75ba1fa39c2ed3c205d'
    maximum=r.Spec(10001,23,((1<<160)-1,)+(0,)*4095,2)
    words,bs,cs=r.witness(maximum,[(1<<160)-1]+[0]*4095)
    assert r.derive(maximum,8)[:4]==(12,5,4096,32) and len(bs)==262144
    assert r.lookup_plan(maximum,8)['m']==18 and len(cs)==131072
    print(json.dumps(dict(seed=2668,cases=10000,byte_cells=cells,sha256=digest.hexdigest()),sort_keys=True),flush=True)


def honest():
    digest=hashlib.sha256(); total=0
    for d in (4,8):
        for repetitions in (1,2):
            for case,caps in enumerate(((0,),(255,),(257,),(0,1,65536),((1<<159)+257,))):
                p=r.Spec(301+case,29,caps,repetitions); xs=[cap if i%2==0 else cap//2 for i,cap in enumerate(caps)]
                words,bs,cs=r.witness(p,xs); proof,state=r.prove(p,xs,d)
                out=r.verify(p,r.source_root(p,words),proof,d); assert out['state']==state
                a,b,n,width,base,_=r.derive(p,d); m=a+b+1; f=lambda x:3*x*(x-1)//2+2*x
                assert out['account']==dict(identity_numerator=2*width*n+255,identity_power=repetitions,
                    lookup_reduction_numerator=repetitions*(f(m)+f(8)+3*m),
                    range_reduction_numerator=9*a+7*b,denominator=r.sc.P**d)
                records=[]; claims=[]
                for _,i,_ in r.parts(p,words,bs,cs,d):
                    dim,degree=i['m'],r.sc.degree(i)
                    for phase,dimension,deg,num in ((0,dim,1,dim),(1,0,0,0),(2,dim,degree,dim*degree)):
                        records.append(dict(id=i['id'],phase=phase,m=dimension,degree=deg,field_degree=d,numerator=num))
                    claims.extend((identity,dim) for identity in i['ids'])
                assert out['sc']==records and [(i,len(point)) for i,point,_ in out['claims']]==claims
                assert len(out['claims'])==9 and len(out['lookup_claims'])==2*repetitions
                assert out['draws'].get(r.zc.WEIGHT,0)==out['draws'].get(r.zc.tr.CHALLENGE,0)==4*a+3*b
                assert set(out['draws'])<={r.zc.WEIGHT,r.zc.tr.CHALLENGE}
                assert out['lookup_draws'].get(r.lu.UNIT,0)==0
                assert out['lookup_draws'][r.lu.BETA]==out['lookup_draws'][r.lu.ALPHA]==repetitions
                assert out['lookup_draws'][r.lu.ft.GAMMA]==out['lookup_draws'][r.lu.ft.FOLD]==repetitions*(m+8)
                assert out['lookup_draws'][r.lu.ft.tr.CHALLENGE]==repetitions*(m*(m-1)//2+28+m)
                assert proof['lookup']['sources']==[bs] and r.lookup_plan(p,d)['sigma']==(1,)*(2*width*n)
                assert r.lookup_plan(p,d)['table']==tuple((x,) for x in range(256))
                assert r.lookup_plan(p,d)['b']==m and 2*width*n<r.sc.P
                if case in (0,2):
                    fast=r.transcript(p,r.source_root(p,words),proof,d,out['lookup_state'])
                    naive=r.transcript(p,r.source_root(p,words),proof,d,out['lookup_state'])
                    for _,i,tables in r.parts(p,words,bs,cs,d):
                        assert r.zero_prove(fast,i,tables)==r.zc.prove(naive,i,tables)
                    assert fast.state==naive.state
                digest.update(state); total+=1; print('proof',d,repetitions,case,flush=True)
    assert total==20
    assert digest.hexdigest()=='5899ef889669e2af476aaf025b21f8fa46fbda65121a5b8ab45b665f2b9c3eba'
    print(json.dumps(dict(proofs=total,sha256=digest.hexdigest()),sort_keys=True),flush=True)


def controls():
    p=r.Spec(397,31,(1,),1); d=4
    proof,_=r.prove(p,[0],d); root=r.source_root(p,[0])
    changed=copy.deepcopy(proof); changed['zero'][0]['final'][0][0]=r.sc.scalar(1,d)
    rejects('SourceCopy:FinalEvaluationMismatch',lambda:r.verify(p,root,changed,d))
    changed['zero'][0]['final'][1][0]=r.sc.scalar(1,d)
    rejects('SourceCopy:ClaimMismatch',lambda:r.verify(p,root,changed,d))
    # The old cap final still satisfies its conditional equation; the actual
    # public cap consumer must reject it against the changed expected cap.
    rejects('CapRelation:ClaimMismatch',lambda:r.verify(replace(p,caps=(0,)),root,proof,d))
    rejects('CommitmentMismatch',lambda:r.verify(replace(p,source=32),root,proof,d))
    for key in ('words','carry'):
        changed=copy.deepcopy(proof); changed[key][0]+=1
        rejects('CommitmentMismatch',lambda:r.verify(p,root,changed,d))
    changed=copy.deepcopy(proof); changed['lookup']['sources'][0][0]+=1
    rejects('CommitmentMismatch',lambda:r.verify(p,root,changed,d))
    false,_=r.assemble(p,[1],[0,1],[0],d)
    rejects('SourceCopy:FinalEvaluationMismatch',lambda:r.verify(p,r.source_root(p,[1]),false,d))
    # The original coordinate caps permit 511 under cap 257. A wrapped
    # complement satisfies every column with Boolean carries, but not the endpoint.
    for cap,word in ((257,511),((1<<159)-1,1<<160)):
        p=replace(p,caps=(cap,)); a,b,n,width,_,_=r.derive(p,d)
        slack=(1<<(8*width))+cap-word
        words=[word>>(8*j)&255 for j in range(width)]
        bs=words+[slack>>(8*j)&255 for j in range(width)]; carry=0; cs=[]
        for j in range(width): carry=(bs[j]+bs[width+j]+carry)//256; cs.append(carry)
        assert cs[-1]==1 and all(x in (0,1) for x in cs)
        false,_=r.assemble(p,words,bs,cs,d)
        rejects('TerminalCarry:FinalEvaluationMismatch',lambda:r.verify(p,r.source_root(p,words),false,d))
    # Nonbit carries can hide a multiple of p, even with zero terminal carry.
    p=replace(p,caps=(0,65536)); words,bs,cs=r.witness(p,[0,0]); n=2; width=4
    word=r.sc.P-1; slack=1; carry=0
    for j in range(width):
        words[j*n]=bs[j*n]=word>>(8*j)&255; bs[(width+j)*n]=slack>>(8*j)&255
        carry=(bs[j*n]+bs[(width+j)*n]+carry)*pow(256,-1,r.sc.P)%r.sc.P; cs[j*n]=carry
    assert cs[6]==0 and any(x not in (0,1) for x in cs)
    false,_=r.assemble(p,words,bs,cs,d)
    rejects('CarryBoolean:RoundSumMismatch',lambda:r.verify(p,r.source_root(p,words),false,d))
    p=replace(p,caps=(0,1,2)); words,bs,cs=r.witness(p,[0,0,0])
    words[3]=bs[3]=1; bs[7]=255; cs[3]=1
    false,_=r.assemble(p,words,bs,cs,d)
    rejects('TerminalCarry:RoundSumMismatch',lambda:r.verify(p,r.source_root(p,words),false,d))
    # Actual fraction arithmetic with invalid selected bytes must fail lookup.
    p=replace(p,caps=(0,)); plan=r.lookup_plan(p,d); bs=[1,r.sc.P-1]
    roots=r.lu.source_roots(plan,[bs]); t,theta=r.lu.begin(plan,roots,d)
    mus=[[r.sc.scalar(0,d)]*256]; mr=[r.lu.mu_root(plan,0,mus[0],d)]
    pairs=r.lu.pairs(t,plan,mr); part,_=r.lu.prove_round(t,plan,[bs],mus[0],theta[0],pairs[0],0)
    changed=copy.deepcopy(proof); changed.update(words=[1],carry=[0],byte_root=roots[0])
    changed['lookup']=dict(mu_roots=mr,rounds=[part],sources=[bs],mus=mus)
    rejects('RootMismatch',lambda:r.verify(p,r.source_root(p,[1]),changed,d))
    for bad in (replace(p,caps=(True,)),replace(p,caps=(-1,)),replace(p,caps=(1<<160,)),
                replace(p,repetitions=0),replace(p,identity=1<<56),replace(p,source=True)):
        rejects('Spec',lambda:r.derive(bad,d))
    rejects('Capacity',lambda:r.derive(replace(p,caps=(0,)*65537),d))
    rejects('Capacity',lambda:r.derive(replace(p,caps=((1<<160)-1,)*4097),d))
    rejects('Spec',lambda:r.derive(replace(p,source=r.derive(p,d)[4]),d))
    rejects('Root',lambda:r.verify(p,bytes(31),proof,d))
    rejects('Range',lambda:r.prove(p,[1],d))
    for mutate,reason in ((lambda q:q['zero'].pop(),'ProofShape'),
                          (lambda q:q['zero'][0]['final'].pop(),'ProofShape'),
                          (lambda q:q['carry'].append(0),'OpeningShape'),
                          (lambda q:q['words'].__setitem__(0,True),'NoncanonicalField')):
        changed=copy.deepcopy(proof); mutate(changed)
        rejects(reason,lambda:r.verify(p,root,changed,d))
    print('wide-range controls passed',flush=True)


if __name__=='__main__':
    modes={'--weights':weights,'--corpus':corpus,'--honest':honest,'--controls':controls}
    selected=sys.argv[1:]
    if selected:
        assert all(x in modes for x in selected)
        for mode in selected: modes[mode]()
    else:
        for test in modes.values(): test()
