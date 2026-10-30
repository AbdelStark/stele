# /// script
# requires-python = ">=3.12"
# dependencies = ["blake3==1.0.11", "python-flint==0.9.0"]
# ///
"""Q26/Q31 static codes: integer rounding, actual consumers and public scale."""
import copy
from dataclasses import replace
import hashlib
import json
import random
import sys
import static_row_code as c

r=c.r


def rejects(reason,call):
    try: call()
    except ValueError as error: assert str(error)==reason,(reason,str(error))
    else: raise AssertionError('accepted '+reason)


def spec(kind,count,scale,identity=920,repetitions=1):
    return c.Spec(c.row.Spec(kind,count,0,'static',scale),identity,61,67,71,repetitions)


def lemma():
    digest=hashlib.sha256()
    for scale in range(1,65536):
        limit=(255*scale-1)//2
        assert 2*limit+scale<=256*scale-1<2*(limit+1)+scale
        assert min(1<<31,limit)<1<<30 and min(1<<15,limit)<=32768
        digest.update(limit.to_bytes(4,'little'))
    assert limit==8355712 and digest.hexdigest()=='5900b09f8bc81f5a8af723e124b90d88892a0a7807a5878f7c3af433bac5a2bc'
    print('static domain lemma: 65535 scales passed',flush=True)


def corpus():
    rng=random.Random(2676); digest=hashlib.sha256(); accepted=overflow=cells=negative=0
    for case in range(10000):
        kind=('wide','gated')[case%2]; h=32768 if kind=='wide' else 1<<30; high=h-1 if kind=='wide' else h
        scale=(1,2,257,32768,32769,65535)[case%6] if case%7 else rng.randrange(1,65536)
        count=1+case%9; p=spec(kind,count,scale,case,1+case%2)
        p=replace(p,schema=replace(p.schema,fraction=case%(45 if kind=='gated' else 31))); v=c.derive(p,4)
        limit=min(h,(255*scale-1)//2) if (case//2)%4 else h; upper=min(high,limit)
        xs=[rng.randrange(-limit,upper+1) for _ in range(count)]; expected=[]
        if case%17==0: xs=[0]*count
        for x in xs:
            q,rem=divmod(abs(x),scale); q+=int(2*rem>=scale); expected.append(-q if x<0 else q)
        if any(abs(x)>127 for x in expected):
            rejects('OutputRange',lambda:c.witness(p,xs)); overflow+=1; digest.update(v['raw']+b'overflow'); continue
        w=c.witness(p,xs); assert w['codes']==expected; accepted+=1; n,planes=v['n'],v['planes']
        negative+=sum(t<3 for t in w['carry']); cells+=n*planes
        assert all(0<=t<=258 for t in w['carry']) and w['carry'][-n:]==[3]*n
        for i in range(n):
            mag=abs(xs[i]) if i<count else 0; si=scale if i<count else 0
            q=w['quotient'][i] if i<count else 0; rem=w['remainder'][i] if i<count else 0
            assert 0<=rem<2*scale
            for j in range(planes):
                incoming=w['carry'][(j-1)*n+i] if j else 3; sb=si.to_bytes(planes,'little')[j]
                assert 2*sb*q+rem.to_bytes(planes,'little')[j]+incoming+765==2*mag.to_bytes(planes,'little')[j]+sb+256*w['carry'][j*n+i]
        digest.update(v['raw']+bytes(x%256 for x in expected)+b''.join(t.to_bytes(2,'little') for t in w['carry']))
    assert (accepted,overflow,cells,negative)==(8487,1513,184694,9983)
    assert digest.hexdigest()=='bbb252e817d51066c21c0020b0ea0fc567445967d33004d36969d347528742d1'
    print(json.dumps(dict(seed=2676,cases=10000,accepted=accepted,overflow=overflow,byte_cells=cells,negative_carry_cells=negative,sha256=digest.hexdigest()),sort_keys=True),flush=True)


def public():
    rng=random.Random(2677); digest=hashlib.sha256()
    for case in range(10000):
        d=(4,8)[case%2]; p=spec(('wide','gated')[case%2],1+case%9,rng.randrange(1,65536)); v=c.derive(p,d)
        point=[tuple(rng.randrange(r.sc.P) for _ in range(d)) for _ in range(v['a']+v['c'])]
        bs=[r.sc.scalar(p.schema.scale>>(8*j)&255,d) for j in range(v['planes'])]
        mask=[r.sc.scalar(int(i<p.schema.dimension),d) for i in range(v['n'])]
        table=[r.sc.scalar(x,d) for x in c.scale_bytes(p,v)]
        assert table==[r.sc.mul(b,m) for b in bs for m in mask]
        direct=r.zc.evaluated(table,point,d)
        factor=r.sc.mul(r.zc.folded(bs,point[:v['c']]),r.zc.folded(mask,point[v['c']:]))
        assert direct==factor==r.zc.folded(table,point)
        digest.update(b''.join(x.to_bytes(4,'little') for x in direct))
    assert digest.hexdigest()=='3a2bbba246d3628bbaca79b9d07755728578d7cdd9cfc02071ce534dd450ea56'
    print(json.dumps(dict(seed=2677,public_mle_points=10000,sha256=digest.hexdigest()),sort_keys=True),flush=True)


def honest():
    digest=hashlib.sha256(); total=0
    for d in (4,8):
        for repetitions in (1,2):
            for kind in ('wide','gated'):
                for scale in (1,65535):
                    xs=[0] if scale==1 else [-32768,32767,-1] if kind=='wide' else [-127*scale,127*scale,-1]
                    p=spec(kind,len(xs),scale,921,repetitions); v=c.derive(p,d); a,b,br,k=v['a'],v['b'],v['br'],v['c']
                    proof,state=c.prove(p,xs,d); out=c.verify(p,c.roots(p,proof),proof,d); assert out['state']==state
                    dims=[a+b+1,a+b+1,a+2,a+1,a+1,a+2,a+1,a+br+1,a+k+2]; f=lambda m:3*m*(m-1)//2+2*m
                    assert out['account']==dict(identities=[((1<<m)+255,repetitions) for m in dims],
                        lookup_reduction_numerator=sum(repetitions*(f(m)+f(8)+3*m) for m in dims),
                        range_reduction_numerator=121*a+26*b+7*br+12*k+25,denominator=r.sc.P**d)
                    assert out['draws'].get(r.zc.WEIGHT,0)==3*a+k and out['draws'].get(r.zc.tr.CHALLENGE,0)==3*a+k
                    assert len(out['claims'])==10 and sum(x['numerator'] for x in out['sc'])==8*a+3*k
                    source,output=out['children'][:2]; ranges=source['ranges']+output['ranges']+out['children'][2:]
                    draws=[out['draws'],source['draws'],output['draws']]+[x['draws'] for x in ranges]
                    for label in (r.zc.WEIGHT,r.zc.tr.CHALLENGE): assert sum(x.get(label,0) for x in draws)==51*a+10*b+3*br+5*k+11
                    for child,m in zip(ranges,dims):
                        account=child['account']; assert (account['identity_numerator'],account['identity_power'])==((1<<m)+255,repetitions)
                        assert account['lookup_reduction_numerator']==repetitions*(f(m)+f(8)+3*m)
                    digest.update(state); total+=1; print('proof',d,repetitions,kind,scale,flush=True)
    assert total==16 and digest.hexdigest()=='535ff1769b4281d624688a29732c7a16f3540522747107ea9576e01dc3963344'
    print(json.dumps(dict(proofs=total,sha256=digest.hexdigest()),sort_keys=True),flush=True)


def supplied(p,xs,w,d):
    v=c.derive(p,d)
    return dict(input=c.ss.prove(v['input'],xs,d),output=c.ss.prove(v['output'],w['codes'],d),
                **{name:r.prove(v[name],w[name],d) for name in c.RANGES})


def all_parent_rows(p,proof,d):
    for _,i,tables in c.parts(p,proof,d): assert all(r.sc.compose(i['terms'],x,d)==r.sc.scalar(0,d) for x in zip(*tables))


def attacks():
    d=4
    for scale,x,code,q,rem,broken,reason in ((1,-128,-128,128,1,'quotient','Quotient'),(2,-1,0,0,4,'remainder','Remainder')):
        p=spec('wide',1,scale,922); v=c.derive(p,d)
        w=dict(codes=[code],quotient=[q],remainder=[rem],carry=c.carry_words(p,[x],[q],[rem]))
        pairs=dict(input=c.ss.prove(v['input'],[x],d),output=c.ss.prove(v['output'],[code],d))
        for name in c.RANGES:
            pairs[name]=r.assemble(v[name],w[name],w[name]+[255],[1],d) if name==broken else r.prove(v[name],w[name],d)
        proof,_=c.assemble(p,pairs,d); all_parent_rows(p,proof,d)
        rejects(reason+':TerminalCarry:FinalEvaluationMismatch',lambda:c.verify(p,c.roots(p,proof),proof,d))
    p=spec('gated',1,1,923); v=c.derive(p,d); magnitude=(1<<30)-1; values=[]; incoming=3
    for j in range(4):
        sb=int(j==0); incoming=((incoming-2*(magnitude>>(8*j)&255)-sb+765)*pow(256,-1,r.sc.P))%r.sc.P; values.append(incoming)
    assert values==[8388609,32769,129,3] and 2*magnitude+1==r.sc.P
    pairs=dict(input=c.ss.prove(v['input'],[magnitude],d),output=c.ss.prove(v['output'],[0],d),
               quotient=r.prove(v['quotient'],[0],d),remainder=r.prove(v['remainder'],[0],d))
    _,bs,cs=r.witness(v['carry'],[3]*4); pairs['carry']=r.assemble(v['carry'],values+[0]*4,bs,cs,d)
    proof,_=c.assemble(p,pairs,d); all_parent_rows(p,proof,d)
    rejects('Carry:SourceCopy:RoundSumMismatch',lambda:c.verify(p,c.roots(p,proof),proof,d))
    print('static actual quotient/remainder and M31 alias attacks rejected',flush=True)


def controls():
    d=4; p=spec('wide',1,2,924); pairs=c.prepare(p,[-1],d); proof,_=c.assemble(p,pairs,d); expected=c.roots(p,proof); v=c.derive(p,d)
    for child,index,reason in (('input',0,'Input:Raw'),('input',1,'Input:Magnitude'),('output',0,'Output:Raw'),('output',1,'Output:Magnitude')):
        bad=copy.deepcopy(proof); bad[child]['ranges'][index]['words'][0]+=1
        rejects(reason+':CommitmentMismatch',lambda:c.verify(p,expected,bad,d))
    for name in c.RANGES:
        bad=copy.deepcopy(proof); bad[name]['words'][0]+=1
        rejects(name.title()+':CommitmentMismatch',lambda:c.verify(p,expected,bad,d))
    wrong=list(expected); wrong[1]=bytes(32); rejects('Scale:CommitmentMismatch',lambda:c.verify(p,wrong,proof,d))
    rejects('Scale:CommitmentMismatch',lambda:c.verify(replace(p,schema=replace(p.schema,scale=3)),expected,proof,d))
    for name,values,reason in (('quotient',[0],'Quotient:CommitmentMismatch'),('output',[1],'SignTransfer:FinalEvaluationMismatch')):
        ps=dict(pairs); ps[name]=(c.ss if name=='output' else r).prove(v[name],values,d); false,_=c.assemble(p,ps,d)
        rejects(reason,lambda:c.verify(p,c.roots(p,false),false,d))
    p=spec('wide',1,1,925); pairs=c.prepare(p,[0],d); proof,state=c.assemble(p,pairs,d); expected=c.roots(p,proof)
    # At Q=0, coordinated final changes preserve the polynomial but not its actual views.
    fs=proof['zero'][0]['final']; coefficients=[r.sc.add(r.sc.mul(r.sc.scalar(2,d),fs[1][0]),r.sc.scalar(-1,d)),
        r.sc.mul(r.sc.scalar(2,d),fs[0][0]),r.sc.scalar(1,d),r.sc.scalar(-2,d),r.sc.scalar(1,d),r.sc.scalar(-256,d)]
    for slot in range(6):
        bad=copy.deepcopy(proof); final=bad['zero'][0]['final']; other=4 if slot==2 else 2
        final[slot][0]=r.sc.add(final[slot][0],r.sc.scalar(1,d)); final[other][0]=r.sc.add(final[other][0],r.sc.neg(coefficients[slot]))
        rejects('RoundedDivision:ClaimMismatch',lambda:c.verify(p,expected,bad,d))
    for slot in range(3):
        bad=copy.deepcopy(proof); final=bad['zero'][2]['final']; final[slot][0]=r.sc.add(final[slot][0],r.sc.scalar(1,d))
        rejects('SignTransfer:ClaimMismatch',lambda:c.verify(p,expected,bad,d))
    bad=copy.deepcopy(proof); bad['zero'][1]['final'][0][0]=r.sc.scalar(4,d)
    rejects('TerminalCarry:FinalEvaluationMismatch',lambda:c.verify(p,expected,bad,d))
    t=c.transcript(p,c.bound(expected,proof),[pairs[name][1] for name in c.NAMES],d)
    assert [r.zc.prove(t,i,tables) for _,i,tables in c.parts(p,proof,d)]==proof['zero'] and t.state==state
    for mutate,reason in ((lambda q:q['zero'].pop(),'ProofShape'),(lambda q:q['zero'][0]['final'].pop(),'ProofShape'),
                         (lambda q:q['roots'].__setitem__('input_magnitude',b''),'Root')):
        bad=copy.deepcopy(proof); mutate(bad); rejects(reason,lambda:c.verify(p,expected,bad,d))
    bad=copy.deepcopy(proof); bad['zero'][0]['final'][0][0]=(False,0,0,0)
    rejects('RoundedDivision:NoncanonicalField',lambda:c.verify(p,expected,bad,d))
    for bad in (replace(p,identity=1<<44),replace(p,source=c.derive(p,d)['base']),replace(p,scale=p.output),replace(p,repetitions=True),
                replace(p,schema=replace(p.schema,scale=0)),replace(p,schema=replace(p.schema,mode='dynamic',scale=0))):
        rejects('Spec',lambda:c.derive(bad,d))
    for kind,count,scale in (('gated',1025,1),('wide',2049,1),('wide',1025,65535)):
        rejects('Capacity',lambda:c.witness(spec(kind,count,scale),None))
    for kind,count,scale in (('gated',1024,1),('wide',2048,1),('wide',1024,65535)):
        edge=c.derive(spec(kind,count,scale,(1<<44)-1,2),8); assert edge['base']+(1<<18)==(1<<63)+(1<<62)
    for kind,x in (('wide',32768),('wide',-32769),('gated',(1<<30)+1),('gated',-(1<<30)-1),('wide',True)):
        rejects('Input',lambda:c.witness(spec(kind,1,1),[x]))
    rejects('OutputRange',lambda:c.witness(spec('wide',1,1),[-128]))
    print('static sources, public scale, all ten claims and shape controls passed',flush=True)


def boundaries():
    for scale,xs,codes in ((1,[-127,127,1],[-127,127,1]),(2,[-1,1,0],[-1,1,0]),(3,[-1,1,0],[0,0,0]),(257,[32767],[127])):
        p=spec('wide',len(xs),scale,926); w=c.witness(p,xs); assert w['codes']==codes
        if scale==257: assert c.derive(p,4)['planes']==2 and w['remainder']==[513] and 2*32767+257>65535
        proof,state=c.prove(p,xs,4); assert c.verify(p,c.roots(p,proof),proof,4)['state']==state
    print('static half ties, canonical zero and two-plane overflow passed',flush=True)


if __name__=='__main__':
    modes={'--lemma':lemma,'--corpus':corpus,'--public':public,'--honest':honest,'--attacks':attacks,'--controls':controls,'--boundaries':boundaries}
    if sys.argv[1:]:
        assert all(x in modes for x in sys.argv[1:])
        for mode in sys.argv[1:]: modes[mode]()
    else:
        for test in modes.values(): test()
