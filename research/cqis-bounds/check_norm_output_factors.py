# /// script
# requires-python = ">=3.12"
# dependencies = ["numpy==2.3.4", "blake3==1.0.11", "python-flint==0.9.0"]
# ///
"""Same-exponent output branches/factors and complete public-grid consumers."""
import copy
from dataclasses import replace
import hashlib
import json
from math import gcd
import random
import sys
import numpy as np
import norm_output_factors as c

r=c.r


def rejects(reason,call):
    try:call()
    except ValueError as error:assert str(error)==reason,(reason,str(error))
    else:raise AssertionError('accepted '+reason)


def spec(count=1,f=0,g=0,e=14,en=1,ed=3,identity=1600,repetitions=1):
    return c.Spec(c.norm.Spec(count,f,g,e,en,ed),identity,73,79,89,97,113,repetitions)


def reference(p,a):
    e=p.schema.F+p.schema.G+21+a-p.schema.E
    divisor=int(np.prod(np.array([2]*max(e,0),dtype=object)));left=int(np.prod(np.array([2]*max(-e,0),dtype=object)))
    bias=divisor//2 if e>0 else 0
    return [int(e<0),int(e>=0)]+np.frombuffer(divisor.to_bytes(16,'little')+bias.to_bytes(16,'little')+left.to_bytes(8,'little'),dtype=np.uint8).tolist()+[0]*22


def corpus():
    rng=random.Random(2710);digest=hashlib.sha256();shifts=set()
    for case in range(10000):
        en,ed=rng.randrange(1,1<<32),rng.randrange(1,1<<32);common=gcd(en,ed)
        p=spec(1+case%16384,rng.randrange(31),rng.randrange(31),rng.randrange(15),en//common,ed//common,case,1+case%2);v=c.derive(p,4);a=case%33-23
        words=c.words(p.schema,a);assert words==reference(p,a);grid=c.public_grid(p.schema)
        assert len(grid)==4096 and all(grid[64*j+a+23]==words[j] for j in range(64)) and all(grid[64*j+i]==0 for j in range(64) for i in range(33,64))
        shifts.add(p.schema.F+p.schema.G+21+a-p.schema.E);digest.update(v['raw']+bytes(words)+bytes(grid))
    p=spec(identity=(1<<32)-1,repetitions=2);v=c.derive(p,8);assert v['base']+(1<<30)==(1<<63)+(1<<62)
    for bad in (replace(p,identity=1<<32),replace(p,repetitions=True),replace(p,output=p.divisor),replace(p,source=v['base']),replace(p,schema=replace(p.schema,F=True))):rejects('Spec',lambda:c.derive(bad,4))
    rejects('Spec',lambda:c.derive(p,True))
    for a in (False,-24,10):rejects('Exponent',lambda:c.words(p.schema,a))
    assert int.from_bytes(bytes(c.words(spec().schema,-23)[34:42]),'little')==1<<16
    assert int.from_bytes(bytes(c.words(spec(f=30,g=30,e=0).schema,9)[2:18]),'little')==1<<90
    assert digest.hexdigest()=='e2e63680d4653ee01222e07b0eda9dc0409527e0475271116bf13643e1b2f1df'
    print(json.dumps(dict(seed=2710,cases=10000,exponents=33,shift_min=min(shifts),shift_max=max(shifts),sha256=digest.hexdigest()),sort_keys=True),flush=True)


def public(d):
    rng=random.Random(2711+d);digest=hashlib.sha256()
    def basis(point,index):
        value=r.sc.scalar(1,d)
        for bit,x in enumerate(reversed(point)):value=r.sc.mul(value,x if index>>bit&1 else r.sc.add(r.sc.scalar(1,d),r.sc.neg(x)))
        return value
    for case in range(10000):
        p=spec(1+case%16384,rng.randrange(31),rng.randrange(31),rng.randrange(15),1,rng.randrange(1,1<<32),case);grid=c.public_grid(p.schema)
        point=[tuple(rng.randrange(r.sc.P) for _ in range(d)) for _ in range(12)]
        if case%31<2:point=[r.sc.scalar(case%31,d)]*12
        elif case%31==2:point=[r.sc.scalar(rng.randrange(2),d) for _ in range(12)]
        elif case%31==3:point=[r.sc.scalar(-1,d)]*12
        iw=[basis(point[6:],i) for i in range(33)];jw=[basis(point[:6],j) for j in range(64)];answer=r.sc.scalar(0,d)
        for i in range(33):
            row=reference(p,i-23);term=tuple(sum(byte*w[k] for byte,w in zip(row,jw))%r.sc.P for k in range(d));answer=r.sc.add(answer,r.sc.mul(term,iw[i]))
        assert r.zc.folded([r.sc.scalar(x,d) for x in grid],point)==answer;digest.update(r.sc.encode(answer))
        if case%1000==999:print('public',d,case+1,flush=True)
    print(json.dumps(dict(field=d,public_points=10000,sha256=digest.hexdigest()),sort_keys=True),flush=True)


def account(p,out,d):
    v=c.derive(p,d);dv=c.dv.derive(v['paired'],d);sv=c.dv.s.derive(dv['scaled'],d);b=sv['layout']['h'];g=sv['layout']['g'];f=lambda m:3*m*(m-1)//2+2*m;dims=[7,b+2,g+3,g+3]
    assert out['account']==dict(identities=[((1<<m)+255,p.repetitions) for m in dims],lookup_reduction_numerator=sum(p.repetitions*(f(m)+f(8)+3*m) for m in dims),
        range_reduction_numerator=199+9*b+18*g,selection_reduction_numerator=6,product_identity_numerator=sv['layout']['k']-1,product_reduction_numerator=4*b,denominator=r.sc.P**d)
    assert out['draws']=={r.zc.WEIGHT:12,r.zc.tr.CHALLENGE:12} and len(out['claims'])==3
    paired=out['paired'];scaled=paired['scaled'];ex=scaled['exponent'];prod=scaled['product'];src=prod['input']
    draws=[out['draws'],paired['draws'],scaled['draws'],ex['draws'],ex['indicator']['draws'],src['draws'],src['word']['draws'],prod['output']['draws'],prod['carry']['draws'],prod['core']['draws']]
    assert sum(x.get(r.zc.WEIGHT,0) for x in draws)==75+4*b+8*g and sum(x.get(r.zc.tr.CHALLENGE,0) for x in draws)==82+6*b+8*g


def honest():
    digest=hashlib.sha256();count=0;cases=((1,0,0,14,1,3,-23,0),(1,0,0,14,1,3,-8,1),(1,0,0,14,1,3,-7,1),(1,0,0,14,1,3,-6,1),(16384,30,30,0,(1<<32)-1,(1<<32)-2,9,None))
    for d in (4,8):
        for reps in (1,2):
            for length,f,g,e,en,ed,a,n in cases:
                p=spec(length,f,g,e,en,ed,1601+count,reps);cert=c.norm.constants(p.schema);n=cert['N_max'] if n is None else n
                proof,state=c.prove(p,n,a,d);A=n<<(-2*min(a,0));D=cert['P']<<(2*max(a,0));words=reference(p,a)
                out=c.verify(p,c.expected_roots(p,n,a,A,D,words),proof,d);assert out['state']==state;account(p,out,d)
                if length==16384:assert words[13]==4 and int.from_bytes(bytes(words[2:18]),'little').bit_length()==91
                digest.update(state);count+=1;print('honest',count,d,reps,p.schema.F+p.schema.G+21+a-p.schema.E,flush=True)
    print(json.dumps(dict(proofs=count,sha256=digest.hexdigest()),sort_keys=True),flush=True)


def controls():
    d=4;p=spec(identity=1630);pair,words=c.prepare(p,0,-7,d);proof,state=c.assemble(p,pair,words,d);expected=c.expected_roots(p,0,-7,0,3,words)
    assert c.verify(p,expected,proof,d)['state']==state
    for index in (0,1,2,18,34,42,63):
        bad=copy.deepcopy(proof);bad['factors'][index]+=1;rejects('Factors:CommitmentMismatch',lambda:c.verify(p,expected,bad,d))
        wrong=list(words);wrong[index]+=1;false,_=c.assemble(p,pair,wrong,d)
        rejects('Factors:RoundSumMismatch',lambda:c.verify(p,c.expected_roots(p,0,-7,0,3,wrong),false,d))
    wrong=list(words);wrong[2:18]=list((1+r.sc.P).to_bytes(16,'little'));false,_=c.assemble(p,pair,wrong,d)
    rejects('Factors:RoundSumMismatch',lambda:c.verify(p,c.expected_roots(p,0,-7,0,3,wrong),false,d))
    wrong=list(words);wrong[2]=2;bad=dict(paired=pair[0],factors=wrong);v=c.derive(p,d);i,tables=c.parts(p,bad,d);tables[2][2*64+16]=r.sc.scalar(2,d)
    assert all(r.sc.compose(i['terms'],[xs[j] for xs in tables],d)==r.sc.scalar(0,d) for j in range(4096))
    t=c.transcript(v,c.roots(p,bad),pair[1],d);bad['zero']=r.zero_prove(t,i,tables)
    rejects('Factors:ClaimMismatch',lambda:c.verify(p,c.expected_roots(p,0,-7,0,3,wrong),bad,d))
    bad=copy.deepcopy(proof)
    for j in (1,2):bad['zero']['final'][j][0]=r.sc.add(bad['zero']['final'][j][0],r.sc.scalar(1,d))
    rejects('Factors:ClaimMismatch',lambda:c.verify(p,expected,bad,d))
    other,_=c.prove(p,0,-8,d);target=c.expected_roots(p,0,-8,0,3,c.words(p.schema,-8));target[1]=expected[1]
    rejects('Paired:Scaled:Exponent:Offset:CommitmentMismatch',lambda:c.verify(p,target,other,d))
    bad=copy.deepcopy(proof);bad['factors'][0]=False;rejects('NoncanonicalField',lambda:c.verify(p,expected,bad,d))
    bad=copy.deepcopy(proof);bad['factors'].append(0);rejects('OpeningShape',lambda:c.verify(p,expected,bad,d))
    rejects('ProofShape',lambda:c.verify(p,expected,dict(proof,shift=0),d));rejects('Root',lambda:c.verify(p,[False]*5,proof,d))
    print('factor/flag/padding/field-alias, genuine wrong-grid, actual finals and same-result exponent substitution controls passed',flush=True)


if __name__=='__main__':
    modes={'--corpus':corpus,'--public4':lambda:public(4),'--public8':lambda:public(8),'--honest':honest,'--controls':controls}
    if sys.argv[1:]:
        assert all(mode in modes for mode in sys.argv[1:])
        for mode in sys.argv[1:]:modes[mode]()
    else:
        for test in modes.values():test()
