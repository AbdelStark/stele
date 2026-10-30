# /// script
# requires-python = ">=3.12"
# dependencies = ["blake3==1.0.11", "python-flint==0.9.0"]
# ///
"""Q26/Q31 signed source proofs: independent integer bytes and actual consumers."""
import copy
from dataclasses import replace
import hashlib
import json
import random
import sys
import signed_source as s

r=s.r


def rejects(reason,call):
    try: call()
    except ValueError as error: assert str(error)==reason,(reason,str(error))
    else: raise AssertionError('accepted '+reason)


def corpus():
    rng=random.Random(2671); digest=hashlib.sha256(); cells=0
    for case in range(10000):
        bits=(8,16,32)[case%3]; count=1+case%9; high=1<<(bits-1)
        p=s.Spec(case,47,49,bits,count,1+case%2); v=s.derive(p,4)
        xs=[rng.randrange(-high,high) for _ in range(count)]
        xs[0]=(-high,high-1,-1,0,1)[case%5] if case%7==0 else xs[0]
        raw,mag,sign,carry=s.witness(p,xs); n,b=v['n'],v['width']
        ub=r.witness(v['ranges'][0],raw)[0]; mb=r.witness(v['ranges'][1],mag)[0]
        assert mag==[abs(x) for x in xs] and len(carry)==n*b
        assert raw==[int.from_bytes(x.to_bytes(b,'little',signed=True),'little') for x in xs]
        for i in range(n):
            x=xs[i] if i<count else 0; u=int.from_bytes(x.to_bytes(b,'little',signed=True),'little')
            assert sign[i]==int(x<0) and sign[n+i]==(u>>(8*(b-1)))%128
            assert ub[(b-1)*n+i]==128*sign[i]+sign[n+i]
            assert carry[(b-1)*n+i]==sign[i]
            for j in range(b):
                a,c=ub[j*n+i],mb[j*n+i]; incoming=carry[(j-1)*n+i] if j else 0
                assert 0<=a<=255 and 0<=c<=255 and carry[j*n+i] in (0,1)
                if sign[i]: assert a+c+incoming==256*carry[j*n+i]
                else: assert a==c and carry[j*n+i]==0
        digest.update(v['raw']+bytes(ub)+bytes(mb)+bytes(sign)+bytes(carry)); cells+=n*b
    assert cells==178872 and digest.hexdigest()=='566f2d7897b5e934fe865ba9c42c4db79a5f6bdac1b8faf608b81f7d5d7ae286'
    p=s.Spec(10001,47,49,32,2048,2); v=s.derive(p,8)
    assert v['n']==2048 and len(v['ranges'][2].caps)==4096 and len(s.witness(p,[0]*2048)[3])==8192
    print(json.dumps(dict(seed=2671,cases=10000,byte_cells=cells,sha256=digest.hexdigest()),sort_keys=True),flush=True)


def honest():
    digest=hashlib.sha256(); total=0
    for d in (4,8):
        for repetitions in (1,2):
            for bits in (8,16,32):
                for xs in ([-(1<<(bits-1))],[-1,0,(1<<(bits-1))-1]):
                    p=s.Spec(501+bits,47,49,bits,len(xs),repetitions); v=s.derive(p,d)
                    pairs,carry=s.ranges(p,xs,d); proof,state=s.assemble(p,pairs,carry,d)
                    expected=s.roots(p,[pair[0]['words'] for pair in pairs],carry)[:2]
                    out=s.verify(p,expected,proof,d); assert out['state']==state
                    a,b=v['a'],v['b']; dims=[a+b+1,a+b+1,a+2]; f=lambda x:3*x*(x-1)//2+2*x
                    assert out['account']==dict(identities=[((1<<k)+255,repetitions) for k in dims],
                        lookup_reduction_numerator=sum(repetitions*(f(k)+f(8)+3*k) for k in dims),
                        range_reduction_numerator=43*a+26*b+9,denominator=r.sc.P**d)
                    assert out['draws'].get(r.zc.WEIGHT,0)==out['draws'].get(r.zc.tr.CHALLENGE,0)==6*a+4*b
                    assert sum(x['numerator'] for x in out['sc'])==16*a+12*b and len(out['claims'])==16
                    records=[]; shapes=[]; words=[pair[0]['words'] for pair in pairs]
                    for _,i,tables in s.parts(p,words,carry,d):
                        m,degree=i['m'],r.sc.degree(i)
                        records.extend(dict(id=i['id'],phase=j,m=dim,degree=deg,field_degree=d,numerator=num)
                                       for j,dim,deg,num in ((0,m,1,m),(1,0,0,0),(2,m,degree,m*degree)))
                        shapes.extend((identity,m) for identity in i['ids'])
                    assert records==out['sc'] and shapes==[(identity,len(point)) for identity,point,_ in out['claims']]
                    for child,k in zip(out['ranges'],dims):
                        assert len(child['claims'])==9 and len(child['lookup_claims'])==2*repetitions
                        assert child['lookup_draws'].get(r.lu.UNIT,0)==0
                        assert child['lookup_draws'][r.lu.BETA]==child['lookup_draws'][r.lu.ALPHA]==repetitions
                        assert child['lookup_draws'][r.lu.ft.GAMMA]==child['lookup_draws'][r.lu.ft.FOLD]==repetitions*(k+8)
                        assert child['lookup_draws'][r.lu.ft.tr.CHALLENGE]==repetitions*(k*(k-1)//2+28+k)
                    if bits==8 and len(xs)==1:
                        t=s.transcript(p,s.roots(p,words,carry),[pair[1] for pair in pairs],d)
                        assert [r.zc.prove(t,i,tables) for _,i,tables in s.parts(p,words,carry,d)]==proof['zero']
                        assert t.state==state
                    digest.update(state); total+=1; print('proof',d,repetitions,bits,len(xs),flush=True)
    assert total==24
    assert digest.hexdigest()=='1f13dcf0ecc3e56a4ecd7331f871a96f1cf3bde92d14840c2aac5076549e1bb2'
    print(json.dumps(dict(proofs=total,sha256=digest.hexdigest()),sort_keys=True),flush=True)


def controls():
    d=4; p=s.Spec(597,47,49,16,1,1); v=s.derive(p,d)
    pairs,carry=s.ranges(p,[-257],d); proof,_=s.assemble(p,pairs,carry,d)
    expected=s.roots(p,[pair[0]['words'] for pair in pairs],carry)[:2]
    for j,name in enumerate(('Raw','Magnitude','Sign')):
        bad=copy.deepcopy(proof); bad['ranges'][j]['words'][0]+=1
        rejects(name+':CommitmentMismatch',lambda:s.verify(p,expected,bad,d))
    bad=copy.deepcopy(proof); bad['carry'][0]^=1
    rejects('Carry:CommitmentMismatch',lambda:s.verify(p,expected,bad,d))
    # A Python bool is numerically equal to 0, but is not a canonical field limb.
    bad=copy.deepcopy(proof); value=list(bad['zero'][0]['final'][0][0]); value[1]=False
    bad['zero'][0]['final'][0][0]=tuple(value)
    rejects('TopBit:NoncanonicalField',lambda:s.verify(p,expected,bad,d))
    bad=copy.deepcopy(proof); bad['zero'][0]['final'][0][0]=r.sc.add(bad['zero'][0]['final'][0][0],r.sc.scalar(1,d))
    rejects('TopBit:FinalEvaluationMismatch',lambda:s.verify(p,expected,bad,d))
    # Alter both linear finals coherently: their equation holds, original claims do not.
    bad['zero'][0]['final'][2][0]=r.sc.add(bad['zero'][0]['final'][2][0],r.sc.scalar(1,d))
    rejects('TopBit:ClaimMismatch',lambda:s.verify(p,expected,bad,d))

    def false_case(q,values,cs,reason):
        layout=s.derive(q,d); ps=[r.prove(child,x,d) for child,x in zip(layout['ranges'],values)]
        false,_=s.assemble(q,ps,cs,d); roots=s.roots(q,[pair[0]['words'] for pair in ps],cs)
        rejects(reason,lambda:s.verify(q,roots[:2],false,d))
    # All ranges are real proofs. Positive INT_MIN and negative zero must fail TopBit.
    false_case(p,([32768],[32768],[0,0]),[0,0],'TopBit:FinalEvaluationMismatch')
    false_case(p,([0],[0],[1,0]),[0,1],'TopBit:FinalEvaluationMismatch')
    false_case(p,([1],[2],[0,0]),[0,0],'Positive:RoundSumMismatch')
    false_case(p,([65535],[2],[1,127]),[1,1],'Negative:RoundSumMismatch')
    false_case(p,([0],[0],[0,0]),[2,0],'CarryBoolean:RoundSumMismatch')
    false_case(p,([0],[0],[0,0]),[1,0],'CarryInactive:RoundSumMismatch')
    # Field-valued fractional carries satisfy negative columns but are not bits.
    inv256=pow(256,-1,r.sc.P); first=257*inv256%r.sc.P; last=(255+first)*inv256%r.sc.P
    false_case(p,([65535],[2],[1,127]),[first,last],'CarryBoolean:RoundSumMismatch')
    # On either zero-coefficient branch, every original final is still consumed.
    for x,index in ((1,2),(-1,1)):
        ps,cs=s.ranges(p,[x],d); good,_=s.assemble(p,ps,cs,d)
        roots=s.roots(p,[pair[0]['words'] for pair in ps],cs); bad=copy.deepcopy(good)
        final=bad['zero'][index]['final']; position=1 if index==2 else 0
        final[position][0]=r.sc.add(final[position][0],r.sc.scalar(1,d))
        rejects(('Negative' if index==2 else 'Positive')+':ClaimMismatch',lambda:s.verify(p,roots[:2],bad,d))
    # Coherent terminal finals retain CB-S=0; both actual views must be consumed.
    bad=copy.deepcopy(proof)
    for row in bad['zero'][5]['final']: row[0]=r.sc.add(row[0],r.sc.scalar(1,d))
    rejects('Terminal:ClaimMismatch',lambda:s.verify(p,expected,bad,d))
    def wrapped(child,values):
        a,b,n,width,_,_=r.derive(child,d); padded=values+[0]*(n-len(values)); caps=list(child.caps)+[0]*(n-len(child.caps))
        slack=[(cap-x)%(1<<(8*width)) for cap,x in zip(caps,padded)]
        bs=[x>>(8*j)&255 for xs in (padded,slack) for j in range(width) for x in xs]; cs=[]; incoming=[0]*n
        for j in range(width):
            incoming=[(bs[j*n+i]+bs[(width+j)*n+i]+incoming[i])//256 for i in range(n)]; cs.extend(incoming)
        return r.assemble(child,bs[:n*width],bs,cs,d)
    # H7=128 falsely labels INT_MIN positive while all six signed identities hold.
    q=replace(p,bits=8); layout=s.derive(q,d); ps=[r.prove(layout['ranges'][j],[128],d) for j in (0,1)]
    ps.append(wrapped(layout['ranges'][2],[0,128])); false,_=s.assemble(q,ps,[0],d)
    roots=s.roots(q,[pair[0]['words'] for pair in ps],[0])
    for _,i,tables in s.parts(q,[pair[0]['words'] for pair in ps],[0],d):
        assert all(r.sc.compose(i['terms'],values,d)==r.sc.scalar(0,d) for values in zip(*tables))
    rejects('Sign:TerminalCarry:RoundSumMismatch',lambda:s.verify(q,roots[:2],false,d))
    # A valid magnitude cannot be replaced with cap+1, even under a new root.
    ps=[r.prove(layout['ranges'][0],[128],d),wrapped(layout['ranges'][1],[129]),r.prove(layout['ranges'][2],[1,0],d)]
    false,_=s.assemble(q,ps,[1],d); roots=s.roots(q,[pair[0]['words'] for pair in ps],[1])
    rejects('Magnitude:TerminalCarry:FinalEvaluationMismatch',lambda:s.verify(q,roots[:2],false,d))
    # Nonzero raw padding cannot use an otherwise valid range proof of zero.
    q=replace(p,bits=8,count=3); layout=s.derive(q,d); ps,cs=s.ranges(q,[0]*3,d)
    words,bs,carries=r.witness(layout['ranges'][0],[0]*3); words[3]=1
    ps[0]=r.assemble(layout['ranges'][0],words,bs,carries,d); false,_=s.assemble(q,ps,cs,d)
    roots=s.roots(q,[pair[0]['words'] for pair in ps],cs)
    rejects('Raw:SourceCopy:RoundSumMismatch',lambda:s.verify(q,roots[:2],false,d))
    # Shared A3 canonical parsing also applies inside the nested range consumer.
    q=replace(p,bits=8); ps,cs=s.ranges(q,[-1],d); good,_=s.assemble(q,ps,cs,d)
    roots=s.roots(q,[pair[0]['words'] for pair in ps],cs); bad=copy.deepcopy(good)
    value=list(bad['ranges'][0]['zero'][0]['final'][0][0]); value[1]=False
    bad['ranges'][0]['zero'][0]['final'][0][0]=tuple(value)
    rejects('Raw:SourceCopy:NoncanonicalField',lambda:s.verify(q,roots[:2],bad,d))
    for mutate,reason in ((lambda q:q['zero'].pop(),'ProofShape'),
                          (lambda q:q['zero'][0]['final'].pop(),'ProofShape'),
                          (lambda q:q['carry'].append(0),'OpeningShape'),
                          (lambda q:q['carry'].__setitem__(0,True),'NoncanonicalField'),
                          (lambda q:q['zero'][0]['final'][0].__setitem__(0,(True,0,0,0)),'TopBit:NoncanonicalField')):
        bad=copy.deepcopy(proof); mutate(bad); rejects(reason,lambda:s.verify(p,expected,bad,d))
    rejects('Raw:CommitmentMismatch',lambda:s.verify(replace(p,source=51),expected,proof,d))
    rejects('Magnitude:CommitmentMismatch',lambda:s.verify(replace(p,magnitude=51),expected,proof,d))
    for q in (replace(p,identity=1<<53),replace(p,source=v['base']),replace(p,magnitude=p.source),
              replace(p,bits=24),replace(p,repetitions=True),replace(p,count=0),replace(p,count=True)):
        rejects('Spec',lambda:s.derive(q,d))
    rejects('Capacity',lambda:s.witness(replace(p,count=2049),None))
    for xs in ([32768],[-32769],[True],[],(0,)):
        rejects('Input',lambda:s.witness(p,xs))
    print('signed-source controls passed',flush=True)


if __name__=='__main__':
    modes={'--corpus':corpus,'--honest':honest,'--controls':controls}
    if sys.argv[1:]:
        assert all(x in modes for x in sys.argv[1:])
        for mode in sys.argv[1:]: modes[mode]()
    else:
        for test in modes.values(): test()
