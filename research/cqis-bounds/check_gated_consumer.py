# /// script
# requires-python = ">=3.12"
# dependencies = ["numpy==2.3.4", "blake3==1.0.11", "python-flint==0.9.0"]
# ///
"""Q26/Q31 actual signed gated products and row-code source composition."""
import copy
from dataclasses import replace
import hashlib
import json
import random
import sys
import numpy as np
import gated_consumer as c

r=c.r


def rejects(reason,call):
    try: call()
    except ValueError as error: assert str(error)==reason,(reason,str(error))
    else: raise AssertionError('accepted '+reason)


def spec(count,identity=930,repetitions=1):
    return c.Spec(c.g.Spec(count,30,14),identity,61,67,71,repetitions)


def corpus():
    rng=random.Random(2678); digest=hashlib.sha256(); cells=0; largest=0; edge=(-32768,-32767,-1,0,1,32767)
    for magnitude in range(32769): assert magnitude>>8<=128
    bound=0; bounds=[]
    for coefficient in (65025,65280,16384,0): bound=(coefficient+bound)//256; bounds.append(bound)
    assert bounds==[254,255,64,0] and c.COLUMN_BOUND==65535 and 2*c.COLUMN_BOUND<r.sc.P
    for case in range(10000):
        count=1+case%9; xs=[rng.randrange(-32768,32768) for _ in range(count)]; ys=[rng.randrange(-32768,32768) for _ in range(count)]
        if case<36: xs=[edge[case//6]]; ys=[edge[case%6]]; count=1
        p=spec(count,case,1+case%2); p=replace(p,schema=replace(p.schema,up_fraction=case%31,silu_fraction=case%15)); v=c.derive(p,4)
        w=c.witness(p,xs,ys); expected=[x*y for x,y in zip(xs,ys)]
        assert w['output']==expected==(np.array(xs,dtype=np.int64)*np.array(ys,dtype=np.int64)).tolist()
        n=v['n']; cells+=4*n; largest=max(largest,max(w['carry'])); assert w['carry'][-n:]==[0]*n and all(0<=x<=255 for x in w['carry'])
        for i in range(n):
            x,y,z=(abs(xs[i]),abs(ys[i]),abs(expected[i])) if i<count else (0,0,0)
            left=list(x.to_bytes(2,'little')); right=list(y.to_bytes(2,'little')); coefficients=np.convolve(left,right).tolist()+[0]
            for j in range(4):
                incoming=w['carry'][(j-1)*n+i] if j else 0
                assert coefficients[j]+incoming==z.to_bytes(4,'little')[j]+256*w['carry'][j*n+i]
        digest.update(v['raw']+b''.join(z.to_bytes(4,'little',signed=True) for z in expected)+bytes(w['carry']))
    p=spec(1024); w=c.witness(p,[-32768]*1024,[-32768]*1024); assert w['output']==[1<<30]*1024
    assert (cells,largest)==(261400,254) and digest.hexdigest()=='09304ad8f8a13e24a195620d4d7cc6c8f71a80e4d3277f2a0c7bdb771e8e5aa1'
    print(json.dumps(dict(seed=2678,cases=10000,byte_cells=cells,largest_carry=largest,sha256=digest.hexdigest()),sort_keys=True),flush=True)


def honest():
    digest=hashlib.sha256(); total=0
    cases=(([0],[0]),([-1],[0]),([-32768,32767,-32768],[-32768,32767,32767]),([0,1,-32768],[32767,-1,0]))
    for d in (4,8):
        for repetitions in (1,2):
            for xs,ys in cases:
                p=spec(len(xs),931,repetitions); v=c.derive(p,d); a=v['a']; proof,state=c.prove(p,xs,ys,d)
                out=c.verify(p,c.roots(p,proof),proof,d); assert out['state']==state
                dims=[a+2]*6+[a+3,a+3,a+2,a+3]; f=lambda m:3*m*(m-1)//2+2*m
                assert out['account']==dict(identities=[((1<<m)+255,repetitions) for m in dims],
                    lookup_reduction_numerator=sum(repetitions*(f(m)+f(8)+3*m) for m in dims),range_reduction_numerator=147*a+163,denominator=r.sc.P**d)
                assert len(out['claims'])==12 and sum(x['numerator'] for x in out['sc'])==9*a+14
                ranges=sum((child['ranges'] for child in out['children'][:3]),[])+out['children'][3:]
                draws=[out['draws']]+[child['draws'] for child in out['children'][:3]+ranges]
                for label in (r.zc.WEIGHT,r.zc.tr.CHALLENGE):
                    assert out['draws'].get(label,0)==3*a+4 and sum(x.get(label,0) for x in draws)==61*a+64
                for child,m in zip(ranges,dims):
                    account=child['account']; assert (account['identity_numerator'],account['identity_power'])==((1<<m)+255,repetitions)
                    assert account['lookup_reduction_numerator']==repetitions*(f(m)+f(8)+3*m)
                digest.update(state); total+=1; print('proof',d,repetitions,len(xs),total,flush=True)
    assert total==16 and digest.hexdigest()=='8c555126eb17eb0bb7fd9f3e0c16c85f83c103d7be4202439193fb35e29864cb'
    print(json.dumps(dict(proofs=total,sha256=digest.hexdigest()),sort_keys=True),flush=True)


def attacks():
    d=4; p=spec(1,932); v=c.derive(p,d); pairs=c.prepare(p,[-1],[1],d)
    pairs['output']=c.ss.prove(v['output'],[-(1<<31)],d); values=[]; incoming=0
    for j in range(4):
        incoming=((int(j==0)+incoming-(128 if j==3 else 0))*pow(256,-1,r.sc.P))%r.sc.P; values.append(incoming)
    assert values==[8388608,32768,128,0] and (-(1<<31)+1)%r.sc.P==0
    _,bs,cs=r.witness(v['carry'],[0]*4); pairs['carry']=r.assemble(v['carry'],values,bs,cs,d); false,_=c.assemble(p,pairs,d)
    for _,i,tables in c.parts(p,false,d): assert all(r.sc.compose(i['terms'],x,d)==r.sc.scalar(0,d) for x in zip(*tables))
    rejects('Carry:SourceCopy:RoundSumMismatch',lambda:c.verify(p,c.roots(p,false),false,d))
    p=spec(1,933); v=c.derive(p,d); pairs=c.prepare(p,[-32768],[-32768],d)
    for value,reason in ((-(1<<30),'SignTransfer:RoundSumMismatch'),(-(1<<30)+1,'ProductColumns:RoundSumMismatch')):
        ps=dict(pairs); ps['output']=c.ss.prove(v['output'],[value],d); false,_=c.assemble(p,ps,d)
        if value==-(1<<30)+1: assert ((1<<30)-value)%r.sc.P==0
        rejects(reason,lambda:c.verify(p,c.roots(p,false),false,d))
    print('gated actual carry, signed alias and wrong-sign attacks rejected',flush=True)


def controls():
    d=4; p=spec(1,934); pairs=c.prepare(p,[-1],[0],d); proof,state=c.assemble(p,pairs,d); expected=c.roots(p,proof)
    for name in c.SIGNED:
        for index,label in ((0,'Raw'),(1,'Magnitude'),(2,'Sign')):
            bad=copy.deepcopy(proof); bad[name]['ranges'][index]['words'][0]+=1
            rejects(name.title()+':'+label+':CommitmentMismatch',lambda:c.verify(p,expected,bad,d))
    bad=copy.deepcopy(proof); bad['carry']['words'][0]+=1; rejects('Carry:CommitmentMismatch',lambda:c.verify(p,expected,bad,d))
    # Genuine different input proof with unchanged expected source is not interchangeable.
    ps=dict(pairs); ps['left']=c.ss.prove(c.derive(p,d)['left'],[0],d); false,_=c.assemble(p,ps,d)
    rejects('Left:Raw:CommitmentMismatch',lambda:c.verify(p,expected,false,d))
    # At zero output all sign finals remain obligations, including the zero magnitude.
    # Keep both signs zero for the magnitude mutation's equation-preserving control.
    p=spec(1,935); pairs=c.prepare(p,[0],[0],d); proof,state=c.assemble(p,pairs,d); expected=c.roots(p,proof)
    for slot in range(7):
        bad=copy.deepcopy(proof); fs=bad['zero'][0]['final']; fs[slot][0]=r.sc.add(fs[slot][0],r.sc.scalar(1,d))
        if slot>=4:
            other=5 if slot==4 else 4; delta=256 if slot==6 else 1
            fs[other][0]=r.sc.add(fs[other][0],r.sc.scalar(delta,d))
        rejects('ProductColumns:ClaimMismatch',lambda:c.verify(p,expected,bad,d))
    for slot in range(4):
        bad=copy.deepcopy(proof); fs=bad['zero'][2]['final']; fs[slot][0]=r.sc.add(fs[slot][0],r.sc.scalar(1,d))
        rejects('SignTransfer:ClaimMismatch',lambda:c.verify(p,expected,bad,d))
    bad=copy.deepcopy(proof); bad['zero'][1]['final'][0][0]=r.sc.scalar(1,d)
    rejects('TerminalCarry:FinalEvaluationMismatch',lambda:c.verify(p,expected,bad,d))
    t=c.transcript(p,c.bound(expected,proof),[pairs[name][1] for name in c.NAMES],d)
    assert [r.zc.prove(t,i,tables) for _,i,tables in c.parts(p,proof,d)]==proof['zero'] and t.state==state
    for mutate,reason in ((lambda q:q['zero'].pop(),'ProofShape'),(lambda q:q['zero'][2]['final'].pop(),'ProofShape'),
                         (lambda q:q['roots'].__setitem__('left_magnitude',b''),'Root')):
        bad=copy.deepcopy(proof); mutate(bad); rejects(reason,lambda:c.verify(p,expected,bad,d))
    bad=copy.deepcopy(proof); bad['zero'][2]['final'][0][0]=(False,0,0,0)
    rejects('SignTransfer:NoncanonicalField',lambda:c.verify(p,expected,bad,d))
    for bad in (replace(p,identity=1<<44),replace(p,left=c.derive(p,d)['base']),replace(p,right=p.output),replace(p,repetitions=True),
                replace(p,schema=replace(p.schema,up_fraction=31)),replace(p,schema=replace(p.schema,silu_fraction=15))):
        rejects('Spec',lambda:c.derive(bad,d))
    for xs,ys in (([32768],[0]),([0],[-32769]),([True],[0]),([],[])):
        rejects('Input',lambda:c.witness(p,xs,ys))
    rejects('Capacity',lambda:c.witness(spec(1025),None,None)); edge=c.derive(spec(1024,(1<<44)-1,2),8)
    assert edge['base']+(1<<18)==(1<<63)+(1<<62)
    print('gated sources, all twelve claims, shapes and static bounds passed',flush=True)


def compose():
    import row_code as dynamic
    import static_row_code as static
    d=4; p=spec(3,936); xs=[-32768,0,127]; ys=[1,-128,-2]; proof,state=c.prove(p,xs,ys,d); expected=c.roots(p,proof)
    assert c.verify(p,expected,proof,d)['state']==state; products=[x*y for x,y in zip(xs,ys)]
    for module,mode,scale in ((dynamic,'dynamic',0),(static,'static',259)):
        schema=static.row.Spec('gated',3,c.derive(p,d)['cert']['product_fraction'],mode,scale)
        rp=module.Spec(schema,937,p.output,73,79,1); rowproof,rowstate=module.prove(rp,products,d)
        roots=module.roots(rp,rowproof); roots[0]=expected[2]
        assert module.verify(rp,roots,rowproof,d)['state']==rowstate
        false,_=module.prove(rp,[products[0]+1]+products[1:],d)
        reason='Scale:Maximum:Input:Raw:CommitmentMismatch' if mode=='dynamic' else 'Input:Raw:CommitmentMismatch'
        rejects(reason,lambda:module.verify(rp,roots,false,d))
        print('gated product-to-row source composition',mode,'passed',flush=True)


if __name__=='__main__':
    modes={'--corpus':corpus,'--honest':honest,'--attacks':attacks,'--controls':controls,'--compose':compose}
    if sys.argv[1:]:
        assert all(x in modes for x in sys.argv[1:])
        for mode in sys.argv[1:]: modes[mode]()
    else:
        for test in modes.values(): test()
