# /// script
# requires-python = ">=3.12"
# dependencies = ["numpy==2.3.4", "blake3==1.0.11", "python-flint==0.9.0"]
# ///
"""Actual RMSNorm statistic bounds, public numerator factors and byte-root joins."""
import copy
from dataclasses import replace
import hashlib
import json
from math import gcd
import random
import sys
import numpy as np
import norm_numerator as c

r=c.r


def rejects(reason,call):
    try: call()
    except ValueError as error: assert str(error)==reason,(reason,str(error))
    else: raise AssertionError('accepted '+reason)


def spec(count=1,f=0,en=1,ed=3,identity=1000,repetitions=1):
    return c.Spec(c.norm.Spec(count,f,30,14,en,ed),identity,67,73,repetitions)


def corpus():
    rng=random.Random(2685); digest=hashlib.sha256(); cells=0
    for case in range(10000):
        en,ed=rng.randrange(1,1<<32),rng.randrange(1,1<<32); common=gcd(en,ed)
        p=spec(1+case%16384,rng.randrange(31),en//common,ed//common,case,1+case%2); v=c.derive(p,4)
        s=rng.randrange(v['cert']['S_max']+1); w=c.witness(p,s); u=v['cert']['unit']; answer=p.schema.ed*s+p.schema.en*u
        left=np.array([s,u],dtype=object); right=np.array([p.schema.ed,p.schema.en],dtype=object)
        assert int(np.sum(left*right))==answer==sum(x<<(8*j) for j,x in enumerate(w['result']))<=v['cert']['N_max']
        coefficients=np.zeros(32,dtype=np.int64)
        for ar,br in zip(w['left'],w['right']):
            row=np.convolve(np.array(ar,dtype=np.int64),np.array(br,dtype=np.int64)); coefficients[:len(row)]+=row
        for k,z in enumerate(w['result']): assert int(coefficients[k])+w['carry'][k]==z+256*w['carry'][k+1]
        words=r.witness(v['statistic'],[s])[0]; digits=c.source(v,words)
        assert digits==c.lp.ls.source(v['layout']['input'],w['left'],w['right']) and len(c.full_source(v,words))==8
        cells+=len(digits); digest.update(v['raw']+s.to_bytes(8,'little')+answer.to_bytes(14,'little')+bytes(digits))
    p=spec(16384,30,(1<<32)-1,(1<<32)-2,(1<<44)-1,2); v=c.derive(p,8)
    assert v['base']+(1<<18)==(1<<63)+(1<<62) and v['width']==8 and v['layout']['layout']['planes']==16
    c.witness(p,v['cert']['S_max']); assert v['cert']['unit']==1<<74 and v['layout']['s']==16
    for bad in (replace(p,identity=1<<44),replace(p,repetitions=True),replace(p,source=p.output),replace(p,source=v['base']),
                replace(p,schema=replace(p.schema,d=16385)),replace(p,schema=replace(p.schema,en=2,ed=2)),replace(p,schema=replace(p.schema,F=True))):
        rejects('Spec',lambda:c.derive(bad,4))
    rejects('Spec',lambda:c.derive(p,True)); rejects('Statistic',lambda:c.witness(p,False)); rejects('Statistic',lambda:c.witness(p,v['cert']['S_max']+1))
    assert digest.hexdigest()=='944f39a2b0338a1dacbc36be6899cdb4c9a21330c2d25cb1e4eaed8b6ca6e9e8'
    print(json.dumps(dict(seed=2685,cases=10000,source_cells=cells,sha256=digest.hexdigest()),sort_keys=True),flush=True)


def account(p,out,d):
    v=c.derive(p,d); bs=v['b']; b=v['layout']['h']; g=v['layout']['g']; f=lambda m:3*m*(m-1)//2+2*m; dims=[bs+1,b+3,g+3,g+3]
    assert out['account']==dict(identities=[((1<<m)+255,p.repetitions) for m in dims],
        lookup_reduction_numerator=sum(p.repetitions*(f(m)+f(8)+3*m) for m in dims),range_reduction_numerator=7*bs+9*b+18*g+42,
        product_identity_numerator=v['layout']['k']-1,product_reduction_numerator=2+4*b,denominator=r.sc.P**d)
    product=out['product']; src=product['input']; draws=[out['statistic']['draws'],src['draws'],src['word']['draws'],product['output']['draws'],product['carry']['draws'],product['core']['draws']]
    assert out['draws']=={} and sum(x.get(r.zc.WEIGHT,0) for x in draws)==3*bs+4*b+8*g+18
    assert sum(x.get(r.zc.tr.CHALLENGE,0) for x in draws)==3*bs+6*b+8*g+20
    assert len(product['core']['original_claims'])==len(product['core']['public_claims'])==2


def honest():
    digest=hashlib.sha256(); cases=0
    inputs=((1,0,1,3,0),(2,0,1,3,1<<31),(1,30,(1<<32)-1,(1<<32)-2,1),(16384,30,(1<<32)-1,(1<<32)-2,1<<44))
    for d in (4,8):
        for reps in (1,2):
            for count,f,en,ed,s in inputs:
                p=spec(count,f,en,ed,1001+cases,reps); v=c.derive(p,d); answer=ed*s+en*v['cert']['unit']
                proof,state=c.prove(p,s,d); out=c.verify(p,c.expected_roots(p,s,answer),proof,d)
                assert out['state']==state; account(p,out,d); digest.update(state); cases+=1
                print('honest',cases,d,reps,count,f,flush=True)
    assert cases==16 and digest.hexdigest()=='3511814162bdb6666fa55e566e676766ee3c49ee2f0cac24563ca99e6f2479cd'
    print(json.dumps(dict(proofs=cases,sha256=digest.hexdigest()),sort_keys=True),flush=True)


def minimum():
    digest=hashlib.sha256(); cases=0
    for d in (4,8):
        for reps in (1,2):
            p=spec(ed=1,identity=1030+cases,repetitions=reps); v=c.derive(p,d); assert v['layout']['k']==4 and v['layout']['s']==8
            proof,state=c.prove(p,123,d); out=c.verify(p,c.expected_roots(p,123,124),proof,d)
            assert out['state']==state; account(p,out,d); digest.update(state); cases+=1
    assert cases==4 and digest.hexdigest()=='fafef6442b62e766a8928a470266126b1a557d1d1251ebb37f6f419216c93c33'
    print(json.dumps(dict(minimum_proofs=cases,sha256=digest.hexdigest()),sort_keys=True),flush=True)


def controls():
    d=4; p=spec(identity=1020); v=c.derive(p,d); pairs=c.prepare(p,0,d); proof,state=c.assemble(p,pairs,d)
    expected=c.expected_roots(p,0,1); assert c.verify(p,expected,proof,d)['state']==state
    bad=copy.deepcopy(proof); bad['statistic']['words'][0]+=1
    rejects('Statistic:CommitmentMismatch',lambda:c.verify(p,expected,bad,d))
    changed=list(expected); changed[0]=r.root(p.source,c.full_source(v,bad['statistic']['words']))
    rejects('Statistic:SourceCopy:ClaimMismatch',lambda:c.verify(p,changed,bad,d))
    for name in ('output','carry'):
        bad=copy.deepcopy(proof); bad['product'][name]['words'][0]+=1
        rejects('Product:'+name.title()+':CommitmentMismatch',lambda:c.verify(p,expected,bad,d))
    for slot in range(4):
        bad=copy.deepcopy(proof); bad['product']['input']['digits'][slot]+=1
        rejects('Product:SourceJoin',lambda:c.verify(p,expected,bad,d))
        left=[0,1]; right=[3,1]
        if slot<2: left[slot]+=1
        else: right[slot-2]+=(-1 if slot==2 else 1)
        w=c.lp.limbs.witness(v['product'].schema,tuple(left),tuple(right)); child=c.lp.prove(v['product'],w,d)
        ds,z,cs=c.lp.witness(v['product'],w)
        assert c.lp.verify(v['product'],c.lp.roots(v['product'],ds,z,cs)[:2],child[0],d)['state']==child[1]
        false,_=c.assemble(p,dict(pairs,product=child),d); target=c.expected_roots(p,0,sum(x*y for x,y in zip(left,right)))
        rejects('Product:SourceJoin',lambda:c.verify(p,target,false,d))
    for name in ('statistic','product'):
        bad=copy.deepcopy(proof)
        (bad['statistic']['words'] if name=='statistic' else bad['product']['input']['digits'])[0]=False
        rejects(name.title()+':NoncanonicalField',lambda:c.verify(p,expected,bad,d))
    high=[0]*8; high[-1]=1; rejects('Statistic:CommitmentMismatch',lambda:c.verify(p,[r.root(p.source,high),expected[1]],proof,d))
    for schema in (replace(p.schema,F=1),replace(p.schema,en=2)):
        rejects('Product:SourceJoin',lambda:c.verify(replace(p,schema=schema),expected,proof,d))
    rejects('ProofShape',lambda:c.verify(p,expected,dict(proof,factors=[]),d))
    rejects('Root',lambda:c.verify(p,[False,expected[1]],proof,d))
    # Valid wide output range, but N+p must not hide in a whole-field equality.
    p=spec(2,identity=1021); v=c.derive(p,d); s=1; answer=5+r.sc.P; w=c.witness(p,s); children=c.lp.ranges(v['product'],w,d)
    words=list(c.lp.limbs.digits(answer,8,v['layout']['s'])); children[1]=c.lp.cr.prove(v['layout']['output'],words,d)
    _,_,carry=c.lp.witness(v['product'],w)
    assert c.lp.target(v['product'],v['layout'],words,carry,r.sc.scalar(256,d),d)==r.sc.scalar(5,d)
    false,_=c.assemble(p,dict(statistic=r.prove(v['statistic'],[s],d),product=c.lp.assemble(v['product'],children,d)),d)
    rejects('Product:Product:RoundSumMismatch',lambda:c.verify(p,c.expected_roots(p,s,answer),false,d))
    # Smax+1 fits the larger product domain; only the actual strict S bound closes it.
    p=spec(f=30,identity=1022); v=c.derive(p,d); s=v['cert']['S_max']+1; width=v['width']; words=list(c.lp.limbs.digits(s,8,width))
    bs=words+[255]*width; carry=[1]*width; source=r.assemble(v['statistic'],words,bs,carry,d)
    w=c.lp.limbs.witness(v['product'].schema,(s,v['cert']['unit']),(p.schema.ed,p.schema.en)); child=c.lp.prove(v['product'],w,d)
    false,_=c.assemble(p,dict(statistic=source,product=child),d); answer=p.schema.ed*s+p.schema.en*v['cert']['unit']
    target=[r.root(p.source,c.full_source(v,words)),r.root(p.output,c.lp.limbs.digits(answer,8,v['layout']['s']))]
    rejects('Statistic:TerminalCarry:FinalEvaluationMismatch',lambda:c.verify(p,target,false,d))
    print('numerator public roles, zero factors, S bound, field alias and high-source controls passed',flush=True)


def compose():
    import norm_statistic as stat
    d=4; p=spec(3,14,1,100000,1024); sp=stat.Spec(p.schema,1023,61,p.source,1); xs=[-32768,1,-1]; s=sum(x*x for x in xs)
    source,state=stat.prove(sp,xs,d); sr=stat.expected_roots(sp,xs,s); assert stat.verify(sp,sr,source,d)['state']==state
    answer=p.schema.ed*s+p.schema.en*c.derive(p,d)['cert']['unit']; proof,state=c.prove(p,s,d); roots=c.expected_roots(p,s,answer); roots[0]=sr[1]
    assert c.verify(p,roots,proof,d)['state']==state
    false,_=c.prove(p,s+1,d); roots=c.expected_roots(p,s+1,answer+p.schema.ed); roots[0]=sr[1]
    rejects('Statistic:CommitmentMismatch',lambda:c.verify(p,roots,false,d))
    print('actual signed statistic-to-numerator root composition passed',flush=True)


if __name__=='__main__':
    modes={'--corpus':corpus,'--honest':honest,'--minimum':minimum,'--controls':controls,'--compose':compose}
    if sys.argv[1:]:
        assert all(mode in modes for mode in sys.argv[1:])
        for mode in sys.argv[1:]: modes[mode]()
    else:
        for test in modes.values(): test()
