# /// script
# requires-python = ">=3.12"
# dependencies = ["blake3==1.0.11", "python-flint==0.9.0"]
# ///
"""Q26/Q31 dynamic row codes: exact rounding, source and zero-semantics controls."""
import copy
from dataclasses import replace
import hashlib
import json
import random
import sys
import row_code as c

r=c.r


def rejects(reason,call):
    try: call()
    except ValueError as error: assert str(error)==reason,(reason,str(error))
    else: raise AssertionError('accepted '+reason)


def spec(kind,count,identity=910,repetitions=1):
    return c.Spec(c.ds.am.row.Spec(kind,count,0,'dynamic',0),identity,61,67,71,repetitions)


def corpus():
    rng=random.Random(2675); digest=hashlib.sha256(); cells=negative=0
    for case in range(10000):
        kind=('wide','gated')[case%2]; h=32768 if kind=='wide' else 1<<30; high=h-1 if kind=='wide' else h
        count=1+case%9; p=spec(kind,count,case,1+case%2); v=c.derive(p,4)
        xs=[rng.randrange(-h,high+1) for _ in range(count)]
        if case<4: xs=[[0],[-1,254,3],[-1,381,0],[-h,high,-h]][case]; p=replace(p,schema=replace(p.schema,dimension=len(xs))); v=c.derive(p,4)
        elif case%17==0: xs=[0]*count
        w=c.witness(p,xs); maximum=sorted(abs(x) for x in xs)[-1]; scale=(maximum+126)//127; expected=[]
        for x in xs:
            q,rem=divmod(abs(x),scale) if scale else (0,0); q+=int(scale>0 and 2*rem>=scale)
            expected.append(-q if x<0 else q)
        assert w['scale']==scale and w['codes']==expected and all(-127<=x<=127 for x in expected)
        assert w['nonzero']==[int(scale>0)] and w['predecessor']==[scale-1 if scale else 0]
        n,planes=v['n'],v['planes']; negative+=sum(t<3 for t in w['carry']); cells+=n*planes
        assert all(0<=t<=258 for t in w['carry']) and w['carry'][-n:]==[3]*n
        for i in range(n):
            mag=abs(xs[i]) if i<len(xs) else 0; si=scale if i<len(xs) else 0
            q=w['quotient'][i] if i<len(xs) else 0; rem=w['remainder'][i] if i<len(xs) else 0
            for j in range(planes):
                incoming=w['carry'][(j-1)*n+i] if j else 3; sb=si.to_bytes(planes,'little')[j]
                assert 2*sb*q+rem.to_bytes(planes,'little')[j]+incoming+765==2*mag.to_bytes(planes,'little')[j]+sb+256*w['carry'][j*n+i]
            if i<len(xs):
                assert rem+w['remainder_gap'][i]+int(scale>0)==2*scale
                assert q+w['zero_gap'][i]==127*int(scale>0)
        digest.update(v['raw']+bytes(x%256 for x in expected)+b''.join(t.to_bytes(2,'little') for t in w['carry']))
    assert cells==262208 and negative==895 and digest.hexdigest()=='356f092d29da7996c8ef0d7af2a94681cb736fd604bdd4a0bf19d917ef941ca4'
    print(json.dumps(dict(seed=2675,cases=10000,byte_cells=cells,negative_carry_cells=negative,sha256=digest.hexdigest()),sort_keys=True),flush=True)


def honest():
    digest=hashlib.sha256(); total=0
    for d in (4,8):
        for repetitions in (1,2):
            for kind in ('wide','gated'):
                h=32768 if kind=='wide' else 1<<30; high=h-1 if kind=='wide' else h
                for xs in ([0],[-h,high,-h]):
                    p=spec(kind,len(xs),911,repetitions); v=c.derive(p,d); a,b,k=v['a'],v['b'],v['c']
                    proof,state=c.prove(p,xs,d); out=c.verify(p,c.roots(p,proof),proof,d); assert out['state']==state
                    dims=[a+b+1,a+b+1,a+2,b+1,a+b+1,a+1,b+1,1,b+1,a+1,a+1,a+2,
                          a+1,a+b+1,a+b+1,a+1,1,b+1,a+k+2]; f=lambda m:3*m*(m-1)//2+2*m
                    assert out['account']==dict(identities=[((1<<m)+255,repetitions) for m in dims],
                        lookup_reduction_numerator=sum(repetitions*(f(m)+f(8)+3*m) for m in dims),
                        range_reduction_numerator=171*a+87*b+12*k+25,selection_reduction_numerator=a,denominator=r.sc.P**d)
                    assert out['draws'].get(r.zc.WEIGHT,0)==5*a+k and out['draws'].get(r.zc.tr.CHALLENGE,0)==5*a+k
                    assert len(out['claims'])==22 and sum(x['numerator'] for x in out['sc'])==12*a+3*k
                    scale,output=out['children'][:2]; maximum=scale['children'][0]; signed=maximum['children'][0]
                    ranges=signed['ranges']+maximum['children'][1:]+scale['children'][1:]+output['ranges']+out['children'][2:]
                    draws=[out['draws'],scale['draws'],maximum['draws'],signed['draws'],output['draws']]+[x['draws'] for x in ranges]
                    assert sum(x.get(r.zc.WEIGHT,0) for x in draws)==73*a+36*b+5*k+11
                    assert sum(x.get(r.zc.tr.CHALLENGE,0) for x in draws)==74*a+36*b+5*k+11
                    for child,m in zip(ranges,dims):
                        account=child['account']; assert (account['identity_numerator'],account['identity_power'])==((1<<m)+255,repetitions)
                        assert account['lookup_reduction_numerator']==repetitions*(f(m)+f(8)+3*m)
                    digest.update(state); total+=1; print('proof',d,repetitions,kind,len(xs),flush=True)
    assert total==16 and digest.hexdigest()=='55e6d84e8afe30aaf333b6d415f2c2b3cd7d3afd46f34fd38b3b21e47614f3aa'
    print(json.dumps(dict(proofs=total,sha256=digest.hexdigest()),sort_keys=True),flush=True)


def supplied(p,xs,w,d):
    v=c.derive(p,d)
    return dict(scale=c.ds.prove(v['scale'],xs,d),output=c.ss.prove(v['output'],w['codes'],d),
                **{name:r.prove(v[name],w[name],d) for name in c.RANGES})


def controls():
    d=4; p=spec('wide',3,912); xs=[-1,254,3]; w=c.witness(p,xs); assert w['codes']==[-1,127,2]
    pairs=supplied(p,xs,w,d); proof,_=c.assemble(p,pairs,d); expected=c.roots(p,proof)
    for name,reason in (('raw','Scale:Maximum:Input:Raw:CommitmentMismatch'),('scale','Scale:Scale:CommitmentMismatch'),
            ('output','Output:Raw:CommitmentMismatch'),('magnitude','Output:Magnitude:CommitmentMismatch')):
        bad=copy.deepcopy(proof)
        words=(bad['scale']['maximum']['input']['ranges'][0]['words'] if name=='raw' else bad['scale']['scale']['words'] if name=='scale'
               else bad['output']['ranges'][int(name=='magnitude')]['words']); words[0]+=1
        rejects(reason,lambda:c.verify(p,expected,bad,d))
    for name in c.RANGES:
        bad=copy.deepcopy(proof); bad[name]['words'][0]+=1
        rejects(name.title().replace('_','')+':CommitmentMismatch',lambda:c.verify(p,expected,bad,d))
    # At the negative half tie q0,r=2S satisfies the division/sign/zero-code relations.
    false_w=copy.deepcopy(w); false_w['codes'][0]=false_w['quotient'][0]=0; false_w['remainder'][0]=4
    false_w['remainder_gap'][0]=0; false_w['zero_gap'][0]=127
    false_w['carry']=c.carry_words(p,xs,w['scale'],false_w['quotient'],false_w['remainder'])
    false,_=c.assemble(p,supplied(p,xs,false_w,d),d)
    for name,i,tables in c.parts(p,false,d):
        if name!='RemainderBound': assert all(r.sc.compose(i['terms'],x,d)==r.sc.scalar(0,d) for x in zip(*tables))
    rejects('RemainderBound:RoundSumMismatch',lambda:c.verify(p,c.roots(p,false),false,d))
    # Wrong sign leaves the unsigned division exact.
    false_w=copy.deepcopy(w); false_w['codes'][0]=1; false,_=c.assemble(p,supplied(p,xs,false_w,d),d)
    rejects('SignTransfer:RoundSumMismatch',lambda:c.verify(p,c.roots(p,false),false,d))
    zero=spec('wide',1,913); zw=c.witness(zero,[0]); zp=supplied(zero,[0],zw,d); zproof,zstate=c.assemble(zero,zp,d); zroots=c.roots(zero,zproof)
    false_w=copy.deepcopy(zw); false_w['codes']=false_w['quotient']=[1]; false,_=c.assemble(zero,supplied(zero,[0],false_w,d),d)
    for name,i,tables in c.parts(zero,false,d):
        if name!='ZeroCode': assert all(r.sc.compose(i['terms'],x,d)==r.sc.scalar(0,d) for x in zip(*tables))
    rejects('ZeroCode:FinalEvaluationMismatch',lambda:c.verify(zero,c.roots(zero,false),false,d))
    # Zero factors do not erase actual claims in the scalar flags or final sign.
    for index,slot,name in ((0,2,'ScaleNonzero'),(1,0,'PredecessorCanonical'),(4,1,'RoundedDivision'),
                            (6,0,'SignTransfer'),(6,1,'SignTransfer'),(6,2,'SignTransfer')):
        bad=copy.deepcopy(zproof); fs=bad['zero'][index]['final']; fs[slot][0]=r.sc.add(fs[slot][0],r.sc.scalar(1,d))
        rejects(name+':ClaimMismatch',lambda:c.verify(zero,zroots,bad,d))
    # Each division original/view final is consumed after preserving its equation.
    coefficients=[r.sc.scalar(-1,d),r.sc.scalar(0,d),r.sc.scalar(1,d),r.sc.scalar(-2,d),r.sc.scalar(1,d),r.sc.scalar(-256,d)]
    for slot in range(6):
        bad=copy.deepcopy(zproof); final=bad['zero'][4]['final']; other=4 if slot==2 else 2
        final[slot][0]=r.sc.add(final[slot][0],r.sc.scalar(1,d)); final[other][0]=r.sc.add(final[other][0],r.sc.neg(coefficients[slot]))
        rejects('RoundedDivision:ClaimMismatch',lambda:c.verify(zero,zroots,bad,d))
    t=c.transcript(zero,c.bound(zroots,zproof),[zp[name][1] for name in c.NAMES],d)
    assert [r.zc.prove(t,i,tables) for _,i,tables in c.parts(zero,zproof,d)]==zproof['zero'] and t.state==zstate
    for mutate,reason in ((lambda q:q['zero'].pop(),'ProofShape'),(lambda q:q['zero'][0]['final'].pop(),'ProofShape'),
            (lambda q:q['roots'].__setitem__('magnitude',b''),'Root')):
        bad=copy.deepcopy(zproof); mutate(bad); rejects(reason,lambda:c.verify(zero,zroots,bad,d))
    bad=copy.deepcopy(zproof); bad['zero'][0]['final'][0][0]=(False,0,0,0)
    rejects('ScaleNonzero:NoncanonicalField',lambda:c.verify(zero,zroots,bad,d))
    for bad in (replace(p,identity=1<<36),replace(p,source=c.derive(p,d)['base']),replace(p,scale=p.output),replace(p,repetitions=True)):
        rejects('Spec',lambda:c.derive(bad,d))
    rejects('Capacity',lambda:c.witness(spec('gated',1025),None))
    edge=c.derive(spec('gated',1024,(1<<36)-1,2),8); assert edge['base']+(1<<26)==(1<<63)+(1<<62) and edge['planes']==4
    print('row-code controls passed',flush=True)


def boundaries():
    d=4
    for xs,codes in (([-1,254,3],[-1,127,2]),([-1,381,0],[0,127,0])):
        p=spec('wide',3,914); proof,state=c.prove(p,xs,d)
        assert c.witness(p,xs)['codes']==codes and c.verify(p,c.roots(p,proof),proof,d)['state']==state
    p=spec('wide',1,915); v=c.derive(p,d); w=c.witness(p,[0]); pairs=supplied(p,[0],w,d)
    proof,_=c.assemble(p,pairs,d); expected=c.roots(p,proof)
    # Genuine range proofs for inconsistent nonzero/predecessor/Q sources.
    for name,value,reason in (('nonzero',1,'ScaleNonzero:FinalEvaluationMismatch'),
            ('predecessor',1,'PredecessorCanonical:FinalEvaluationMismatch'),('quotient',1,'Quotient:CommitmentMismatch')):
        ps=dict(pairs); ps[name]=r.prove(v[name],[value],d); false,_=c.assemble(p,ps,d)
        rejects(reason,lambda:c.verify(p,c.roots(p,false),false,d))
    for index,coefficients,name in ((2,[1,1,1,-2],'RemainderBound'),(3,[1,1,-127],'ZeroCode')):
        for slot in range(len(coefficients)):
            bad=copy.deepcopy(proof); fs=bad['zero'][index]['final']; other=1 if slot==0 else 0
            fs[slot][0]=r.sc.add(fs[slot][0],r.sc.scalar(1,d)); fs[other][0]=r.sc.add(fs[other][0],r.sc.scalar(-coefficients[slot],d))
            rejects(name+':ClaimMismatch',lambda:c.verify(p,expected,bad,d))
    bad=copy.deepcopy(proof); fs=bad['zero'][0]['final']; fs[0][0]=fs[1][0]=r.sc.scalar(1,d)
    rejects('ScaleNonzero:ClaimMismatch',lambda:c.verify(p,expected,bad,d))
    bad=copy.deepcopy(proof); fs=bad['zero'][1]['final']; fs[0][0]=fs[1][0]=r.sc.scalar(1,d)
    rejects('PredecessorCanonical:ClaimMismatch',lambda:c.verify(p,expected,bad,d))
    bad=copy.deepcopy(proof); bad['zero'][5]['final'][0][0]=r.sc.scalar(4,d)
    rejects('TerminalCarry:FinalEvaluationMismatch',lambda:c.verify(p,expected,bad,d))
    print('row-code boundary and remaining-claim controls passed',flush=True)


def asymmetric():
    d=4; p=spec('wide',1,916); v=c.derive(p,d); pairs=c.prepare(p,[0],d)
    pairs['output']=c.ss.prove(v['output'],[-128],d)
    # Canonical signed int8 permits -128, but symmetric CQIS codes do not.
    pairs['quotient']=r.assemble(v['quotient'],[128],[128,255],[1],d)
    proof,_=c.assemble(p,pairs,d)
    rejects('Quotient:TerminalCarry:FinalEvaluationMismatch',lambda:c.verify(p,c.roots(p,proof),proof,d))
    print('row-code symmetric-output bound control passed',flush=True)


if __name__=='__main__':
    modes={'--corpus':corpus,'--honest':honest,'--controls':controls,'--boundaries':boundaries,'--asymmetric':asymmetric}
    if sys.argv[1:]:
        assert all(x in modes for x in sys.argv[1:])
        for mode in sys.argv[1:]: modes[mode]()
    else:
        for test in modes.values(): test()
