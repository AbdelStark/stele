# /// script
# requires-python = ">=3.12"
# dependencies = ["numpy==2.3.4", "blake3==1.0.11", "python-flint==0.9.0"]
# ///
"""Actual signed RMSNorm statistic sources, complete consumers and alias controls."""
import copy
from dataclasses import replace
import hashlib
import json
import random
import struct
import sys
import numpy as np
import norm_statistic as c

r=c.r


def rejects(reason,call):
    try: call()
    except ValueError as error: assert str(error)==reason,(reason,str(error))
    else: raise AssertionError('accepted '+reason)


def spec(count,identity=960,repetitions=1):
    return c.Spec(c.norm.Spec(count,14,14,14,1,100000),identity,61,67,repetitions)


def corpus():
    rng=random.Random(2684); digest=hashlib.sha256(); cells=0
    for case in range(10000):
        count=1+case%17; p=spec(count,case,1+case%2)
        p=replace(p,schema=replace(p.schema,F=rng.randrange(31),G=rng.randrange(31),E=rng.randrange(15),ed=rng.randrange(1,1<<32)))
        xs=[rng.randrange(-32768,32768) for _ in range(count)]
        xs[case%count]=(-32768,-32767,-1,0,1,32767)[case%6]
        w=c.witness(p,xs); v=c.derive(p,4); a=np.array(xs,dtype=np.int64); value=int(np.sum(a*a,dtype=np.int64))
        assert value==sum(x*x for x in xs)==sum(x<<(8*j) for j,x in enumerate(w['result']))<=count<<30
        mag=c.ss.witness(v['signed'],xs)[1]; ms=r.witness(c.ss.derive(v['signed'],4)['ranges'][1],mag)[0]
        digits=c.duplicate(ms,v['n']); assert digits==c.lp.ls.source(v['layout']['input'],w['left'],w['right'])
        assert v['layout']['s']==8 and v['layout']['k']==(4 if count<=3 else 5)
        cells+=len(digits); digest.update(v['raw']+struct.pack('<Q',value)+bytes(digits))
    for count in (1023,1024,2048):
        p=spec(count,(1<<44)-1,2); v=c.derive(p,8); xs=[-32768]*count; w=c.witness(p,xs)
        assert sum(x<<(8*j) for j,x in enumerate(w['result']))==count<<30 and v['layout']['k']==(5 if count==1023 else 6)
        assert v['base']+(1<<18)==(1<<63)+(1<<62)
    p=spec(1)
    for bad in (replace(p,identity=1<<44),replace(p,repetitions=True),replace(p,source=p.output),replace(p,source=c.derive(p,4)['base']),
                replace(p,source=True),replace(p,schema=replace(p.schema,en=2,ed=2)),replace(p,schema=replace(p.schema,d=True))):
        rejects('Spec',lambda:c.derive(bad,4))
    rejects('Spec',lambda:c.derive(p,True)); rejects('Capacity',lambda:c.witness(spec(2049),None))
    rejects('Input',lambda:c.witness(p,[32768])); rejects('Input',lambda:c.witness(p,[False]))
    assert digest.hexdigest()=='e80946b5f83e32d5307e37e6ff7a058d5d835a18a533417955e3bae64ea668c5'
    print(json.dumps(dict(seed=2684,cases=10000,source_cells=cells,sha256=digest.hexdigest()),sort_keys=True),flush=True)


def account(p,proof,out,d):
    v=c.derive(p,d); a=v['a']; f=lambda m:3*m*(m-1)//2+2*m; dims=[a+2]*3+[a+3,6,6]
    assert out['account']==dict(identities=[((1<<m)+255,p.repetitions) for m in dims],
        lookup_reduction_numerator=sum(p.repetitions*(f(m)+f(8)+3*m) for m in dims),range_reduction_numerator=54*a+129,
        product_identity_numerator=v['layout']['k']-1,product_reduction_numerator=2*a+4,denominator=r.sc.P**d)
    signed,product=out['signed'],out['product']; src=product['input']
    draws=[signed['draws']]+[x['draws'] for x in signed['ranges']]+[src['draws'],src['word']['draws'],product['output']['draws'],product['carry']['draws'],product['core']['draws']]
    assert out['draws']=={} and sum(x.get(r.zc.WEIGHT,0) for x in draws)==23*a+55
    assert sum(x.get(r.zc.tr.CHALLENGE,0) for x in draws)==24*a+58
    assert len(product['core']['original_claims'])==len(product['core']['public_claims'])==2
    assert proof['product']['input']['digits']==c.duplicate(proof['source']['ranges'][1]['words'],v['n'])


def honest():
    digest=hashlib.sha256(); cases=0
    for d in (4,8):
        for reps in (1,2):
            for xs in ([0],[-32768],[-32768,32767,-1],[-32768,-32768,0,0]):
                p=spec(len(xs),961+cases,reps); proof,state=c.prove(p,xs,d)
                expected=c.expected_roots(p,xs,sum(x*x for x in xs)); out=c.verify(p,expected,proof,d)
                assert out['state']==state; account(p,proof,out,d); digest.update(state); cases+=1
                print('honest',cases,d,reps,len(xs),flush=True)
    assert cases==16 and digest.hexdigest()=='244008775e9ce204f15139af98e3301c74d8117de43c88d36edefac7d6881d05'
    print(json.dumps(dict(proofs=cases,sha256=digest.hexdigest()),sort_keys=True),flush=True)


def controls():
    d=4; p=spec(1,980); v=c.derive(p,d); pairs=c.prepare(p,[0],d); proof,state=c.assemble(p,pairs,d)
    expected=c.expected_roots(p,[0],0); assert c.verify(p,expected,proof,d)['state']==state
    for index,label in ((0,'Raw'),(1,'Magnitude'),(2,'Sign')):
        bad=copy.deepcopy(proof); bad['source']['ranges'][index]['words'][0]+=1
        rejects('Source:'+label+':CommitmentMismatch',lambda:c.verify(p,expected,bad,d))
    for name in ('output','carry'):
        bad=copy.deepcopy(proof); bad['product'][name]['words'][0]+=1
        rejects('Product:'+name.title()+':CommitmentMismatch',lambda:c.verify(p,expected,bad,d))
    for side in (0,1):
        bad=copy.deepcopy(proof); bad['product']['input']['digits'][side]+=1
        rejects('Product:SourceJoin',lambda:c.verify(p,expected,bad,d))
        operands=[(0,),(0,)]; operands[side]=(1,)
        w=c.lp.limbs.witness(v['product'].schema,*operands); child=c.lp.prove(v['product'],w,d)
        substituted=dict(pairs,product=child); false,_=c.assemble(p,substituted,d)
        rejects('Product:SourceJoin',lambda:c.verify(p,expected,false,d))
    bad=copy.deepcopy(proof); bad['product']['input']['digits'][0]=False
    rejects('Product:NoncanonicalField',lambda:c.verify(p,expected,bad,d))
    for key in ('left','right'):
        bad=copy.deepcopy(proof); bad['product']['core'][key]['final'][0]=r.sc.scalar(2,d)
        bad['product']['core'][key]['final'][1]=r.sc.mul(bad['product']['core'][key]['final'][1],r.sc.scalar(pow(2,-1,r.sc.P),d))
        rejects('Product:'+key.title()+'Source:PowerClaimMismatch',lambda:c.verify(p,expected,bad,d))
    for slot,name in enumerate(('Source:Raw','Product:Output')):
        changed=list(expected); changed[slot]=bytes(32)
        rejects(name+':CommitmentMismatch',lambda:c.verify(p,changed,proof,d))
    bad=copy.deepcopy(proof); bad['product']['core']['main']['final'][0]=(True,0,0,0)
    rejects('Product:NoncanonicalField',lambda:c.verify(p,expected,bad,d))
    rejects('ProofShape',lambda:c.verify(p,expected,dict(proof,certificate={}),d))
    rejects('Root',lambda:c.verify(p,[False,expected[1]],proof,d))
    # Genuine false output ranges and complete arithmetic producer, not a bypass.
    p=spec(2,981); v=c.derive(p,d); xs=[-32768,-32768]; assert sum(x*x for x in xs)==1+r.sc.P
    children=c.lp.ranges(v['product'],c.witness(p,xs),d); children[1]=c.lp.cr.prove(v['layout']['output'],[1]+[0]*7,d)
    false,_=c.assemble(p,dict(source=c.ss.prove(v['signed'],xs,d),product=c.lp.assemble(v['product'],children,d)),d)
    rejects('Product:Product:RoundSumMismatch',lambda:c.verify(p,c.expected_roots(p,xs,1),false,d))
    # A high ignored output digit does not enter the product target; its actual range must still reject.
    p=spec(1,982); v=c.derive(p,d); w=c.witness(p,[0]); children=c.lp.ranges(v['product'],w,d)
    words,bs,cs=c.lp.cr.witness(v['layout']['output'],[0]*8); words[-1]=1
    children[1]=c.lp.cr.assemble(v['layout']['output'],words,bs,cs,d)
    false,_=c.assemble(p,dict(source=c.ss.prove(v['signed'],[0],d),product=c.lp.assemble(v['product'],children,d)),d)
    target=c.expected_roots(p,[0],0); target[1]=r.root(p.output,words)
    rejects('Product:Output:Reconstruction:RoundSumMismatch',lambda:c.verify(p,target,false,d))
    p=spec(3,983); proof,_=c.prove(p,[1,0,-1],d); expected=c.expected_roots(p,[1,0,-1],2)
    proof['product']['input']['digits'][-1]=1
    rejects('Product:SourceJoin',lambda:c.verify(p,expected,proof,d))
    print('norm statistic roots, both zero factors, field alias, high padding and final controls passed',flush=True)


if __name__=='__main__':
    modes={'--corpus':corpus,'--honest':honest,'--controls':controls}
    if sys.argv[1:]:
        assert all(mode in modes for mode in sys.argv[1:])
        for mode in sys.argv[1:]: modes[mode]()
    else:
        for test in modes.values(): test()
