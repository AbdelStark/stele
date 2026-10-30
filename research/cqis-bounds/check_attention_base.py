# /// script
# requires-python = ">=3.12"
# dependencies = ["numpy==2.3.4", "blake3==1.0.11", "python-flint==0.9.0"]
# ///
"""Draft RFC-0004 A3/A6: actual probability sum and configured offset factor."""
import copy
from dataclasses import replace
import hashlib
import json
import random
import sys
import numpy as np
import attention_base as c

r=c.r


def rejects(reason,call):
    try:call()
    except ValueError as error:assert str(error)==reason,(reason,str(error))
    else:raise AssertionError('accepted '+reason)


def spec(count=3,E=14,mode='dynamic',scale=0,identity=4700,repetitions=1):
    return c.Spec(c.bounds.Spec(1<<20,13,7,E,mode,scale,'exact'),count,identity,1511,1523,repetitions)


def oracle(p,z):
    s=127*259 if p.schema.value_mode=='dynamic' else p.schema.scale*min(127,(65536+p.schema.scale)//(2*p.schema.scale));h=int(np.int64(z)*np.int64(s))
    return h,[r.root(p.source,list(np.array([z],dtype='<u4').tobytes())),r.root(p.output,list(np.array([h],dtype='<u8').tobytes()))]


def corpus():
    rng=random.Random(2736);digest=hashlib.sha256();widths=set();cells=0
    for index in range(10000):
        mode='dynamic' if index%2 else 'static';scale=0 if mode=='dynamic' else rng.choice((1,2,259,65535));p=spec(1 if index%17==0 else rng.randrange(1,16385),index%15,mode,scale,100000+index,1+index%2)
        if index%3==0:p=replace(p,schema=replace(p.schema,accumulation='block1024'),count=min(p.count,1024))
        v=c.derive(p,4);z=rng.randrange(v['zmax']+1);h,roots=oracle(p,z);w=c.witness(p,z);words=r.witness(v['weight_sum'],[z])[0];source=c.source(v,words)
        assert c.expected_roots(p,z,h)==roots and sum(x<<(8*j) for j,x in enumerate(w['result']))==h
        assert source==c.lp.ls.source(v['layout']['input'],w['left'],w['right']) and len(c.full_source(v,words))==4
        coeff=np.convolve(np.array(w['left'][0],dtype=np.int64),np.array(w['right'][0],dtype=np.int64)).tolist()
        for k,out in enumerate(w['result']):assert (coeff[k] if k<len(coeff) else 0)+w['carry'][k]==out+256*w['carry'][k+1]
        assert c.full_output(v,list(w['result'])+[0]*(v['layout']['s']-len(w['result'])))==list(h.to_bytes(8,'little'))
        widths.add((v['bz'],v['layout']['h'],v['layout']['g']));cells+=len(source);digest.update(v['raw']+b''.join(roots))
    p=spec(16384,14,'static',65535,(1<<44)-1,2);v=c.derive(p,8);assert v['zmax']==1<<28 and v['hmax']==((1<<44)-(1<<28)) and v['layout']['s']==8 and v['base']+(1<<18)==(1<<63)+(1<<62)
    for bad in (replace(p,identity=1<<44),replace(p,repetitions=True),replace(p,source=p.output),replace(p,source=v['base']),replace(p,count=False),replace(p,count=0),replace(p,schema=replace(p.schema,accumulation='block1024'))):rejects('Spec',lambda:c.derive(bad,4))
    rejects('Capacity',lambda:c.derive(replace(p,count=16385),4));rejects('WeightSum',lambda:c.witness(p,True));rejects('WeightSum',lambda:c.witness(p,v['zmax']+1))
    assert {a for a,b,g in widths}=={0,1,2} and {g for a,b,g in widths}=={1,2,3}
    assert digest.hexdigest()=='ce46ecda5b6958819169b8f74fbb7c43d594ef21138313f492b889e892bdfa88'
    print(json.dumps(dict(seed=2736,cases=10000,source_cells=cells,sha256=digest.hexdigest()),sort_keys=True),flush=True)


def account(p,out,d):
    v=c.derive(p,d);bz,b,g=v['bz'],v['layout']['h'],v['layout']['g'];dims=[bz+1,b+2,g+3,g+3];f=lambda m:3*m*(m-1)//2+2*m
    assert out['account']==dict(identities=[((1<<m)+255,p.repetitions) for m in dims],lookup_reduction_numerator=sum(p.repetitions*(f(m)+f(8)+3*m) for m in dims),range_reduction_numerator=7*bz+9*b+18*g+31,product_identity_numerator=v['layout']['k']-1,product_reduction_numerator=4*b,denominator=r.sc.P**d)
    product=out['product'];src=product['input'];draws=[out['weight_sum']['draws'],src['draws'],src['word']['draws'],product['output']['draws'],product['carry']['draws'],product['core']['draws']]
    assert out['draws']=={} and sum(x.get(r.zc.WEIGHT,0) for x in draws)==3*bz+4*b+8*g+13
    assert sum(x.get(r.zc.tr.CHALLENGE,0) for x in draws)==3*bz+6*b+8*g+14
    assert len(product['core']['original_claims'])==len(product['core']['public_claims'])==2


def honest(maximum=False):
    digest=hashlib.sha256();done=0;cases=((1,0,'static',1,0),(1,0,'static',1,1),(3,8,'dynamic',0,257),(65,14,'static',65535,65*(1<<14)))
    if maximum:cases=((16384,14,'static',65535,1<<28),)
    for d,reps in (((4,1),) if maximum else ((4,1),(4,2),(8,1),(8,2))):
        for count,E,mode,scale,z in cases:
            p=spec(count,E,mode,scale,4710+done,reps);h,roots=oracle(p,z);print('honest start',done+1,d,reps,count,E,flush=True);proof,state=c.prove(p,z,d);out=c.verify(p,roots,proof,d);assert out['state']==state;account(p,out,d);digest.update(state);done+=1;print('honest passed',done,d,reps,count,E,flush=True)
    print(json.dumps(dict(maximum=maximum,proofs=done,sha256=digest.hexdigest()),sort_keys=True),flush=True)


def controls():
    p=spec();d=4;v=c.derive(p,d);pairs=c.prepare(p,0,d);proof,state=c.assemble(p,pairs,d);roots=oracle(p,0)[1];out=c.verify(p,roots,proof,d);assert out['state']==state;account(p,out,d)
    for index,name in enumerate(('WeightSum','Output')):
        bad=roots.copy();bad[index]=bytes(32);rejects(name+':CommitmentMismatch',lambda:c.verify(p,bad,proof,d))
    for z,s in ((1,v['S']),(0,v['S']-1)):
        w=c.lp.limbs.witness(v['product'].schema,(z,),(s,));child=c.lp.prove(v['product'],w,d);ds,os,cs=c.lp.witness(v['product'],w);assert c.lp.verify(v['product'],c.lp.roots(v['product'],ds,os,cs)[:2],child[0],d)['state']==child[1]
        bad,_=c.assemble(p,dict(pairs,product=child),d);rejects('Product:SourceJoin',lambda:c.verify(p,c.expected_roots(p,0,z*s),bad,d))
    bad,_=c.assemble(p,dict(pairs,weight_sum=r.prove(v['weight_sum'],[1],d)),d);rejects('Product:SourceJoin',lambda:c.verify(p,c.roots(p,bad),bad,d))
    for key in ('receipt','factor','certificate'):rejects('ProofShape',lambda:c.verify(p,roots,dict(proof,**{key:{}}),d))
    rejects('ProofShape',lambda:c.verify(p,roots,dict(weight_sum=proof['weight_sum']),d))
    for name,words in (('WeightSum',proof['weight_sum']['words']),('Product',proof['product']['input']['digits'])):
        bad=copy.deepcopy(proof);target=bad['weight_sum']['words'] if name=='WeightSum' else bad['product']['input']['digits'];target[0]=False;rejects(name+':NoncanonicalField',lambda:c.verify(p,roots,bad,d))
    print('external roots, valid changed Z/product sources, zero-hidden configured factor and mandatory children reject',flush=True)


def boundaries():
    p=spec(3,14,'static',65535,4750);d=4;v=c.derive(p,d);z=1;h=v['S']+r.sc.P;w=c.witness(p,z);children=c.lp.ranges(v['product'],w,d);words=list(c.lp.limbs.digits(h,8,v['layout']['s']));children[1]=c.lp.cr.prove(v['layout']['output'],words,d)
    bad,_=c.assemble(p,dict(weight_sum=r.prove(v['weight_sum'],[z],d),product=c.lp.assemble(v['product'],children,d)),d);rejects('Product:Product:FinalEvaluationMismatch',lambda:c.verify(p,c.expected_roots(p,z,h),bad,d))
    p=spec(16384,14,'static',65535,4751);v=c.derive(p,d);child=v['weight_sum'];z=r.sc.P+1;false=r.assemble(child,*r.witness(replace(child,caps=(z,)),[z]),d);pairs=c.prepare(p,0,d);bad,_=c.assemble(p,dict(pairs,weight_sum=false),d);rejects('WeightSum:CapRelation:RoundSumMismatch',lambda:c.verify(p,c.roots(p,bad),bad,d))
    p=spec(1,0,'static',1,4752);proof,state=c.prove(p,1,d);roots=oracle(p,1)[1];assert c.verify(p,roots,proof,d)['state']==state
    for index,source,size,value in ((0,p.source,4,1),(1,p.output,8,127)):
        words=list(value.to_bytes(size,'little'));words[-1]=1;bad=roots.copy();bad[index]=r.root(source,words);rejects(('WeightSum' if index==0 else 'Output')+':CommitmentMismatch',lambda:c.verify(p,bad,proof,d))
    print('bounded H+p, actual Z cap and complete four/eight-byte extensions reject',flush=True)


def composition():
    import attention_probability_sum as probability
    for index,(count,E) in enumerate(((1,0),(3,8),(65,14))):
        p=spec(count,E,identity=4760+index);d=4;positions=tuple(31*j for j in range(count));row=probability.attained.Spec(probability.attained.maximum.Spec(p.schema.length,127,7,6),positions[-1],positions,0,0,p.schema.length,4780+index,1531,1543,1549,1553,1);pp=probability.Spec(row,E,4790+index,1559,p.source)
        xs=[(1<<E)//2]*count;child,st=probability.prove(pp,xs,d);pr=probability.expected_roots(pp,xs);assert probability.verify(pp,pr,child,d)['state']==st;z=sum(xs);proof,state=c.prove(p,z,d);roots=oracle(p,z)[1];assert roots[0]==pr[1] and c.verify(p,roots,proof,d)['state']==state
        changed=xs.copy();changed[0]+=1;other,st=probability.prove(pp,changed,d);other_roots=probability.expected_roots(pp,changed);assert probability.verify(pp,other_roots,other,d)['state']==st;bad,st=c.prove(p,z+1,d);assert c.verify(p,oracle(p,z+1)[1],bad,d)['state']==st;rejects('WeightSum:CommitmentMismatch',lambda:c.verify(p,roots,bad,d));print('actual probability sum to offset base composition passed',count,E,flush=True)


if __name__=='__main__':
    modes={'--corpus':corpus,'--controls':controls,'--boundaries':boundaries,'--composition':composition,'--honest':honest,'--maximum':lambda:honest(True)}
    if sys.argv[1:]:
        assert all(mode in modes for mode in sys.argv[1:])
        for mode in sys.argv[1:]:modes[mode]()
    else:
        for test in modes.values():test()
