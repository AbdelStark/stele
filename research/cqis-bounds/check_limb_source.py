# /// script
# requires-python = ">=3.12"
# dependencies = ["blake3==1.0.11", "python-flint==0.9.0"]
# ///
"""Q26/Q31 actual limb input roots, whole ranges and byte/nibble consumers."""
import copy
from dataclasses import replace
import hashlib
import json
import random
import sys
import limb_source as s

r=s.r


def rejects(reason,call):
    try: call()
    except ValueError as error: assert str(error)==reason,(reason,str(error))
    else: raise AssertionError('accepted '+reason)


def corpus():
    rng=random.Random(2669); digest=hashlib.sha256(); cells=0
    for case in range(10000):
        bits=(4,8)[case%2]; count=1+case%9; length=case%161
        spec=s.limbs.Spec(count,rng.getrandbits(length),rng.getrandbits(length),bits)
        p=s.Spec(spec,case,37,1+case%2); v=s.derive(p,4)
        left=tuple(rng.randrange(spec.left_max+1) for _ in range(count))
        right=tuple(rng.randrange(spec.right_max+1) for _ in range(count))
        ds=lambda xs,key:tuple(tuple(x>>(bits*j)&((1<<bits)-1) for j in range(len(v['cert'][key+'_caps']))) for x in xs)
        digits=s.source(p,ds(left,'left'),ds(right,'right'))
        n,rows=v['n'],v['rows']; values=list(left)+[0]*(n-count)+list(right)+[0]*(n-count)
        assert rows==2*n and len(digits)==v['cells']==rows*v['planes']
        assert v['whole'].caps==(spec.left_max,)*count+(0,)*(n-count)+(spec.right_max,)*count+(0,)*(n-count)
        for i,value in enumerate(values):
            assert sum(digits[j*rows+i]<<(bits*j) for j in range(v['planes']))==value
        assert all(0<=x<1<<bits for x in digits)
        digest.update(v['raw']+bytes(digits)); cells+=len(digits)
    assert cells==2904862 and digest.hexdigest()=='e1c7b7e67d8d95cc8d9997119f1f72a397cf1cfe834eeb71c4570ab20e141704'
    for bits,count,limit in ((8,2048,255),(4,32,(1<<159)+1)):
        p=s.Spec(s.limbs.Spec(count,limit,1,bits),10001,37,1); v=s.derive(p,8)
        assert v['cells']==4096 and v['rows']<=4096
        if bits==4: assert len(v['nibbles'].caps)==4096
        zeros=lambda key:((0,)*len(v['cert'][key+'_caps']),)*count
        assert s.source(p,zeros('left'),zeros('right'))==[0]*4096
    print(json.dumps(dict(seed=2669,cases=10000,cells=cells,sha256=digest.hexdigest()),sort_keys=True),flush=True)


def honest():
    digest=hashlib.sha256(); total=0
    for d in (4,8):
        for bits in (4,8):
            for repetitions in (1,2):
                for case,(count,left_max,right_max) in enumerate(((1,0,0),(3,257,31),(1,(1<<159)+257,1))):
                    spec=s.limbs.Spec(count,left_max,right_max,bits); p=s.Spec(spec,401+case,41,repetitions)
                    left=tuple(left_max//(i+1) for i in range(count)); right=tuple(right_max//(i+1) for i in range(count))
                    w=s.limbs.witness(spec,left,right); digits=s.source(p,w['left'],w['right']); v=s.derive(p,d)
                    proof,state=s.prove(p,digits,d); out=s.verify(p,s.source_root(p,digits),proof,d)
                    assert out['state']==state and len(out['packing']['claims'])==(3 if bits==4 else 2)
                    a,b=v['a'],v['b']; m=a+b+1; f=lambda x:3*x*(x-1)//2+2*x
                    dimensions=([a+b+3] if bits==4 else [])+[a+b+2]
                    assert out['account']==dict(identities=[((1<<k)+255,repetitions) for k in dimensions],
                        lookup_reduction_numerator=sum(repetitions*(f(k)+f(8)+3*k) for k in dimensions),
                        range_reduction_numerator=(20*a+18*b+29 if bits==4 else 11*a+11+9*b),denominator=r.sc.P**d)
                    assert out['draws']=={r.zc.WEIGHT:m,r.zc.tr.CHALLENGE:m}
                    assert out['packing']['sc']==[
                        dict(id=16*p.identity+12,phase=j,m=dim,degree=degree,field_degree=d,numerator=num)
                        for j,dim,degree,num in ((0,m,1,m),(1,0,0,0),(2,m,1,m))]
                    i,tables=s.packing(p,digits,proof['word']['words'],d)
                    assert [(identity,len(point)) for identity,point,_ in out['packing']['claims']]==[(identity,m) for identity in i['ids']]
                    children=([out['nibbles']] if bits==4 else [])+[out['word']]
                    assert all(len(child['claims'])==9 and len(child['lookup_claims'])==2*repetitions for child in children)
                    for label in (r.zc.WEIGHT,r.zc.tr.CHALLENGE):
                        assert out['draws'][label]+sum(child['draws'].get(label,0) for child in children)==(9*a+8*b+13 if bits==4 else 5*a+4*b+5)
                    for child,k in zip(children,dimensions):
                        assert child['lookup_draws'].get(r.lu.UNIT,0)==0
                        assert child['lookup_draws'][r.lu.BETA]==child['lookup_draws'][r.lu.ALPHA]==repetitions
                        assert child['lookup_draws'][r.lu.ft.GAMMA]==child['lookup_draws'][r.lu.ft.FOLD]==repetitions*(k+8)
                        assert child['lookup_draws'][r.lu.ft.tr.CHALLENGE]==repetitions*(k*(k-1)//2+28+k)
                    if case==0:
                        states=[child['state'] for child in children]
                        t=s.transcript(p,s.source_root(p,digits),proof['word_root'],d,states)
                        assert r.zc.prove(t,i,tables)==proof['packing'] and t.state==state
                    digest.update(state); total+=1; print('proof',d,bits,repetitions,case,flush=True)
    assert total==24
    assert digest.hexdigest()=='e74f376c32e0e05d07fb2338aff13a6ec2c4714a06bb0fd1f3ac6556de902620'
    print(json.dumps(dict(proofs=total,sha256=digest.hexdigest()),sort_keys=True),flush=True)


def controls():
    d=4
    for bits in (4,8):
        p=s.Spec(s.limbs.Spec(1,257,31,bits),497,43,1); v=s.derive(p,d)
        w=s.limbs.witness(p.schema,(17,),(2,)); digits=s.source(p,w['left'],w['right'])
        proof,_=s.prove(p,digits,d); expected=s.source_root(p,digits)
        changed=copy.deepcopy(proof); changed['digits'][0]+=1
        rejects('CommitmentMismatch',lambda:s.verify(p,expected,changed,d))
        changed=copy.deepcopy(proof); changed['word']['words'][0]+=1
        rejects('WholeWord:CommitmentMismatch',lambda:s.verify(p,expected,changed,d))
        changed=copy.deepcopy(proof); changed['packing']['final'][0][0]=r.sc.add(changed['packing']['final'][0][0],r.sc.scalar(1,d))
        rejects('LimbPacking:FinalEvaluationMismatch',lambda:s.verify(p,expected,changed,d))
        changed['packing']['final'][-1][0]=r.sc.add(changed['packing']['final'][-1][0],r.sc.scalar(1,d))
        rejects('LimbPacking:ClaimMismatch',lambda:s.verify(p,expected,changed,d))
        # A newly authenticated original and (for nibbles) valid digit proof
        # cannot use the whole-word proof of a different numerical operand.
        other=list(digits); other[0]+=1
        word_pair=r.prove(v['whole'],[17,2],d)
        nibble_pair=r.prove(v['nibbles'],other,d) if bits==4 else None
        false,_=s.assemble(p,other,word_pair,nibble_pair,d)
        rejects('LimbPacking:RoundSumMismatch',lambda:s.verify(p,s.source_root(p,other),false,d))
        # Canonical digits representing 511 still violate the expected whole cap.
        rows=v['rows']; width=v['width']; values=[511,2]
        other=[x>>(bits*j)&((1<<bits)-1) for j in range(v['planes']) for x in values]
        words,bs,cs=r.witness(v['whole'],[0,2]); slack=(1<<(8*width))+257-511; carry=0
        for j in range(width):
            words[j*rows]=bs[j*rows]=511>>(8*j)&255; bs[(width+j)*rows]=slack>>(8*j)&255
            carry=(bs[j*rows]+bs[(width+j)*rows]+carry)//256; cs[j*rows]=carry
        word_pair=r.assemble(v['whole'],words,bs,cs,d)
        nibble_pair=r.prove(v['nibbles'],other,d) if bits==4 else None
        false,_=s.assemble(p,other,word_pair,nibble_pair,d)
        rejects('WholeWord:TerminalCarry:RoundSumMismatch',lambda:s.verify(p,s.source_root(p,other),false,d))
        for mutate,reason in ((lambda q:q['packing']['final'].pop(),'ProofShape'),
                              (lambda q:q['digits'].append(0),'OpeningShape'),
                              (lambda q:q['digits'].__setitem__(0,True),'NoncanonicalField')):
            changed=copy.deepcopy(proof); mutate(changed)
            rejects(reason,lambda:s.verify(p,expected,changed,d))
        rejects('CommitmentMismatch',lambda:s.verify(replace(p,source=44),expected,proof,d))
        zero=s.Spec(s.limbs.Spec(1,1,0,bits),499,43,1); zd=[0]*s.derive(zero,d)['cells']
        zp,_=s.prove(zero,zd,d)
        rejects('WholeWord:CapRelation:ClaimMismatch',lambda:s.verify(replace(zero,schema=s.limbs.Spec(1,0,0,bits)),s.source_root(zero,zd),zp,d))
        # Real-count padding and high planes remain original source coordinates.
        for schema,index in ((s.limbs.Spec(3,257,31,bits),3),
                             (s.limbs.Spec(1,1<<159,1,bits),63 if bits==8 else 127)):
            pad=replace(p,schema=schema); pv=s.derive(pad,d); other=[0]*pv['cells']; other[index]=1
            word_pair=r.prove(pv['whole'],[0]*pv['rows'],d)
            nibble_pair=r.prove(pv['nibbles'],other,d) if bits==4 else None
            false,_=s.assemble(pad,other,word_pair,nibble_pair,d)
            rejects('LimbPacking:RoundSumMismatch',lambda:s.verify(pad,s.source_root(pad,other),false,d))
    # A noncanonical nibble can pack to a valid byte: the independent <=15
    # proof must reject it at its real final-carry consumer.
    p=s.Spec(s.limbs.Spec(1,31,0,4),498,43,1); v=s.derive(p,d); digits=[16,0,0,0]
    word_pair=r.prove(v['whole'],[16,0],d)
    words,bs,cs=r.witness(v['nibbles'],[0]*4); words[0]=bs[0]=16; bs[4]=255; cs[0]=1
    nibble_pair=r.assemble(v['nibbles'],words,bs,cs,d)
    false,_=s.assemble(p,digits,word_pair,nibble_pair,d)
    rejects('Nibbles:TerminalCarry:RoundSumMismatch',lambda:s.verify(p,s.source_root(p,digits),false,d))
    good,_=s.prove(p,[0]*4,d); expected=s.source_root(p,[0]*4)
    changed=copy.deepcopy(good); changed['nibbles']=None
    rejects('ProofShape',lambda:s.verify(p,expected,changed,d))
    rejects('Nibbles:CommitmentMismatch',lambda:s.verify(p,expected,{**good,'nibbles':nibble_pair[0]},d))
    for bad in (replace(p,identity=1<<54),replace(p,source=s.derive(p,d)['base']+64),replace(p,repetitions=True)):
        rejects('Spec',lambda:s.derive(bad,d))
    for schema in (s.limbs.Spec(2049,255,1,8),s.limbs.Spec(33,(1<<159)+1,1,4)):
        rejects('Capacity',lambda:s.source(replace(p,schema=schema),None,None))
    rejects('SourceShape',lambda:s.source(p,(),()))
    print('limb-source controls passed',flush=True)


if __name__=='__main__':
    modes={'--corpus':corpus,'--honest':honest,'--controls':controls}
    if sys.argv[1:]:
        assert all(x in modes for x in sys.argv[1:])
        for mode in sys.argv[1:]: modes[mode]()
    else:
        for test in modes.values(): test()
