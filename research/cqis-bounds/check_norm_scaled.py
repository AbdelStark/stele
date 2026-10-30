# /// script
# requires-python = ">=3.12"
# dependencies = ["numpy==2.3.4", "blake3==1.0.11", "python-flint==0.9.0"]
# ///
"""Actual numerator/exponent sources and closed scaled product consumers."""
import copy
from dataclasses import replace
import hashlib
import json
from math import gcd
import random
import sys
import numpy as np
import norm_scaled as c

r=c.r


def rejects(reason,call):
    try: call()
    except ValueError as error: assert str(error)==reason,(reason,str(error))
    else: raise AssertionError('accepted '+reason)


def spec(count=1,f=0,en=1,ed=3,identity=1100,repetitions=1):
    return c.Spec(c.norm.Spec(count,f,30,14,en,ed),identity,73,79,89,repetitions)


def corpus():
    rng=random.Random(2688); digest=hashlib.sha256(); cells=0
    for case in range(10000):
        en,ed=rng.randrange(1,1<<32),rng.randrange(1,1<<32); common=gcd(en,ed)
        p=spec(1+case%16384,rng.randrange(31),en//common,ed//common,case,1+case%2); v=c.derive(p,4)
        n=rng.randrange(v['cert']['N_max']+1); a=rng.randrange(-23,10); w=c.witness(p,n,a); answer=n*4**max(-a,0)
        assert int(np.prod(np.array([n,4**max(-a,0)],dtype=object)))==answer
        coeff=np.convolve(np.array(w['left'][0],dtype=np.int64),np.array(w['right'][0],dtype=np.int64))
        for j,z in enumerate(w['result']): assert (int(coeff[j]) if j<len(coeff) else 0)+w['carry'][j]==z+256*w['carry'][j+1]
        digits,z,_=c.lp.witness(v['product'],w); numerator=c.numerator_source(v,digits)
        assert int.from_bytes(bytes(numerator),'little')==n and sum(x<<(8*j) for j,x in enumerate(z))==answer
        assert c.source(v,digits,c.ex.witness(v['exponent'],a)[1])==digits
        digest.update(v['raw']+bytes(numerator)+bytes(z)+bytes(digits)); cells+=len(digits)
    p=spec(16384,30,(1<<32)-1,(1<<32)-2,(1<<44)-1,2); v=c.derive(p,8)
    assert v['base']+(1<<18)==(1<<63)+(1<<62) and v['layout']['s']==32 and v['cert']['A_max'].bit_length()==153
    c.witness(p,v['cert']['N_max'],-23)
    for bad in (replace(p,identity=1<<44),replace(p,repetitions=True),replace(p,source=p.output),replace(p,exponent=p.source),
                replace(p,exponent=v['base']),replace(p,schema=replace(p.schema,F=True))): rejects('Spec',lambda:c.derive(bad,4))
    rejects('Spec',lambda:c.derive(p,True))
    for n in (True,-1,v['cert']['N_max']+1): rejects('Numerator',lambda:c.witness(p,n,0))
    assert cells==319248 and digest.hexdigest()=='ad1cbf9a4f72f12b4cbb519c2a069d5db59a00ca4756bca2e3255d54446a55b2'
    print(json.dumps(dict(seed=2688,cases=10000,source_cells=cells,sha256=digest.hexdigest()),sort_keys=True),flush=True)


def account(p,out,d):
    v=c.derive(p,d); b=v['layout']['h']; g=v['layout']['g']; f=lambda m:3*m*(m-1)//2+2*m; dims=[7,b+2,g+3,g+3]
    assert out['account']==dict(identities=[((1<<m)+255,p.repetitions) for m in dims],
        lookup_reduction_numerator=sum(p.repetitions*(f(m)+f(8)+3*m) for m in dims),range_reduction_numerator=133+9*b+18*g,
        selection_reduction_numerator=6,product_identity_numerator=v['layout']['k']-1,product_reduction_numerator=4*b,denominator=r.sc.P**d)
    ex=out['exponent']; prod=out['product']; src=prod['input']
    draws=[ex['draws'],ex['indicator']['draws'],src['draws'],src['word']['draws'],prod['output']['draws'],prod['carry']['draws'],prod['core']['draws']]
    assert out['draws']=={} and sum(x.get(r.zc.WEIGHT,0) for x in draws)==53+4*b+8*g
    assert sum(x.get(r.zc.tr.CHALLENGE,0) for x in draws)==60+6*b+8*g
    assert len(prod['core']['original_claims'])==len(prod['core']['public_claims'])==2


def honest():
    digest=hashlib.sha256(); count=0
    cases=((1,0,1,3,-23,0),(1,0,(1<<32)-1,(1<<32)-2,0,None),(16384,30,(1<<32)-1,(1<<32)-2,-1,None),(16384,30,1,3,9,1))
    for d in (4,8):
        for reps in (1,2):
            for length,f,en,ed,a,n in cases:
                p=spec(length,f,en,ed,1101+count,reps); v=c.derive(p,d); n=v['cert']['N_max'] if n is None else n
                proof,state=c.prove(p,n,a,d); expected=c.expected_roots(p,n,a,n*4**max(-a,0)); out=c.verify(p,expected,proof,d)
                assert out['state']==state; account(p,out,d); digest.update(state); count+=1
                print('honest',count,d,reps,length,f,a,flush=True)
    assert count==16 and digest.hexdigest()=='39e88124a4a0456dfbafa7750d122e092aff973cc6474eafd79f2a75fd7c1db3'
    print(json.dumps(dict(proofs=count,sha256=digest.hexdigest()),sort_keys=True),flush=True)


def controls():
    d=4; p=spec(identity=1120); v=c.derive(p,d); pairs=c.prepare(p,0,0,d); proof,state=c.assemble(p,pairs,d); expected=c.expected_roots(p,0,0,0)
    assert c.verify(p,expected,proof,d)['state']==state
    for slot,reason in ((0,'Numerator:CommitmentMismatch'),(1,'Product:SourceJoin')):
        bad=copy.deepcopy(proof); bad['product']['input']['digits'][slot]+=1; rejects(reason,lambda:c.verify(p,expected,bad,d))
    bad=copy.deepcopy(proof); bad['exponent']['factors'][0]+=1
    rejects('Exponent:Exponent:RoundSumMismatch',lambda:c.verify(p,expected,bad,d))
    for name in ('output','carry'):
        bad=copy.deepcopy(proof); bad['product'][name]['words'][0]+=1
        rejects('Product:'+name.title()+':CommitmentMismatch',lambda:c.verify(p,expected,bad,d))
    # Genuine changed right factor at N=0 preserves A=0 but must fail the source join.
    w=c.lp.limbs.witness(v['product'].schema,(0,),(2,)); changed=c.lp.prove(v['product'],w,d); ds,z,cs=c.lp.witness(v['product'],w)
    assert c.lp.verify(v['product'],c.lp.roots(v['product'],ds,z,cs)[:2],changed[0],d)['state']==changed[1]
    false,_=c.assemble(p,dict(pairs,product=changed),d); rejects('Product:SourceJoin',lambda:c.verify(p,expected,false,d))
    false,_=c.prove(p,1,0,d); target=c.expected_roots(p,1,0,1); target[0]=expected[0]
    rejects('Numerator:CommitmentMismatch',lambda:c.verify(p,target,false,d))
    false,_=c.prove(p,0,1,d); rejects('Exponent:Offset:CommitmentMismatch',lambda:c.verify(p,expected,false,d))
    # A+p fits output ranges and collides at rho=256, but not at the actual challenge.
    w=c.witness(p,1,0); children=c.lp.ranges(v['product'],w,d); answer=1+r.sc.P
    words=list(c.lp.limbs.digits(answer,8,v['layout']['s'])); children[1]=c.lp.cr.prove(v['layout']['output'],words,d)
    _,_,carry=c.lp.witness(v['product'],w); assert c.lp.target(v['product'],v['layout'],words,carry,r.sc.scalar(256,d),d)==r.sc.scalar(1,d)
    false,_=c.assemble(p,dict(pairs,product=c.lp.assemble(v['product'],children,d)),d)
    rejects('Product:Product:FinalEvaluationMismatch',lambda:c.verify(p,c.expected_roots(p,1,0,answer),false,d))
    p=spec(en=(1<<32)-1,ed=(1<<32)-2,identity=1121); v=c.derive(p,d); assert v['nslots']==16 and v['layout']['layout']['planes']==8
    proof,state=c.prove(p,1,0,d); expected=c.expected_roots(p,1,0,1); assert c.verify(p,expected,proof,d)['state']==state
    high=[1]+[0]*14+[1]; expected[0]=r.root(p.source,high); rejects('Numerator:CommitmentMismatch',lambda:c.verify(p,expected,proof,d))
    expected=c.expected_roots(p,1,0,1)
    for mutate,reason in ((lambda q:q['product']['input']['digits'].__setitem__(0,False),'Product:NoncanonicalField'),
                          (lambda q:q['exponent']['factors'].__setitem__(0,r.sc.P),'Exponent:NoncanonicalField')):
        bad=copy.deepcopy(proof); mutate(bad); rejects(reason,lambda:c.verify(p,expected,bad,d))
    rejects('ProofShape',lambda:c.verify(p,expected,dict(proof,numerator=[]),d)); rejects('Root',lambda:c.verify(p,[False]*3,proof,d))
    print('scaled numerator/factor roots, zero-product substitution, field alias and high-slot controls passed',flush=True)


def maximum():
    digest=hashlib.sha256(); count=0
    for d in (4,8):
        for reps in (1,2):
            p=spec(16384,30,(1<<32)-1,(1<<32)-2,1130+count,reps); v=c.derive(p,d); n=v['cert']['N_max']; answer=n<<46
            assert answer==v['cert']['A_max'] and answer.bit_length()==153
            proof,state=c.prove(p,n,-23,d); out=c.verify(p,c.expected_roots(p,n,-23,answer),proof,d)
            assert out['state']==state and proof['product']['output']['words'][19]>0
            account(p,out,d); digest.update(state); count+=1; print('maximum',d,reps,flush=True)
    assert count==4 and digest.hexdigest()=='02d8d2063ee66b31c030491c4e9a3d23ede86d9ce36b0de01022f4ac0d3d15d5'
    print(json.dumps(dict(maximum_proofs=count,sha256=digest.hexdigest()),sort_keys=True),flush=True)


def compose():
    import norm_numerator as num
    p=spec(identity=1123); np=num.Spec(p.schema,1122,67,p.source,1); d=4
    source,state=num.prove(np,0,d); nr=num.expected_roots(np,0,1); assert num.verify(np,nr,source,d)['state']==state
    proof,state=c.prove(p,1,-8,d); roots=c.expected_roots(p,1,-8,65536); roots[0]=nr[1]
    assert c.verify(p,roots,proof,d)['state']==state
    false,_=c.prove(p,2,-8,d); roots=c.expected_roots(p,2,-8,131072); roots[0]=nr[1]
    rejects('Numerator:CommitmentMismatch',lambda:c.verify(p,roots,false,d))
    print('actual numerator-to-scaled source composition passed',flush=True)


if __name__=='__main__':
    modes={'--corpus':corpus,'--honest':honest,'--controls':controls,'--compose':compose,'--maximum':maximum}
    if sys.argv[1:]:
        assert all(mode in modes for mode in sys.argv[1:])
        for mode in sys.argv[1:]: modes[mode]()
    else:
        for test in modes.values(): test()
