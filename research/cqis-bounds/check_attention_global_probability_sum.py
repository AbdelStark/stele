# /// script
# requires-python = ">=3.12"
# dependencies = ["numpy==2.3.4", "blake3==1.0.11", "python-flint==0.9.0"]
# ///
"""Draft RFC-0004 A3/A6: complete eight-byte probability aggregation."""
import copy
from dataclasses import replace
import hashlib
import json
import random
import sys
import numpy as np
import attention_global_probability_sum as c

r=c.r


def rejects(reason,call):
    try:call()
    except ValueError as error:assert str(error)==reason,(reason,str(error))
    else:raise AssertionError('accepted '+reason)


def spec(blocks=3,E=14,identity=5800,repetitions=1):
    ids=tuple(range(blocks)) if blocks==1024 else tuple(2*j for j in range(blocks))
    return c.Spec(c.bounds.Spec(1<<20,13,7,E,'dynamic',0,25),ids,identity,tuple(7001+j for j in range(blocks)),8501,repetitions)


def oracle(p,zs):
    total=int(np.array(zs,dtype=np.int64).sum());roots=[r.root(identity,list(np.array([z],dtype='<u4').tobytes())) for identity,z in zip(p.sources,zs)]
    return total,roots+[r.root(p.output,list(np.array([total],dtype='<u8').tobytes()))]


def corpus():
    rng=random.Random(2741);digest=hashlib.sha256();cells=zeros=0;widths=set();shifts=set()
    for case in range(10000):
        length=rng.choice((1,1024,1025,2049,1<<20));bmax=(length+1023)//1024;count=min(1+case%65,bmax);ids=tuple(sorted(rng.sample(range(bmax),count)));mode='dynamic' if case%2 else 'static';scale=0 if mode=='dynamic' else rng.choice((1,2,259,65535));E=case%15
        if case<61:mode='static';scale=1;E=0
        S=127*259 if mode=='dynamic' else scale*min(127,(65536+scale)//(2*scale));H=1024*(1<<E)*S;minimum=next(drop for drop in range(63) if (H+(1<<drop)//2)//(1<<drop)<=32767);drop=case+2 if case<61 else minimum+case%(63-minimum)
        p=replace(spec(count,E,case,1+case%2),schema=c.bounds.Spec(length,1+case%65,case%31,E,mode,scale,drop),blocks=ids);v=c.derive(p,4);caps=[min(1024,length-1024*b)*(1<<E) for b in ids];assert list(v['caps'])==caps
        zs=[0 if case%7==0 else rng.randrange(cap+1) for cap in caps]
        if case%7==1:zs=caps.copy()
        total,roots=oracle(p,zs);w=c.witness(p,zs);words=r.witness(v['source'],zs)[0];digits=c.source(v,words);assert c.expected_roots(p,zs)==roots and digits==c.lp.ls.source(v['layout']['input'],w['left'],w['right'])
        assert sum(x<<(8*k) for k,x in enumerate(w['result']))==total and c.full_output(v,list(w['result'])+[0]*(v['layout']['s']-len(w['result'])))==list(np.array([total],dtype='<u8').tobytes())
        columns=np.array(w['left'],dtype=np.int64).sum(axis=0).tolist()
        for k,x in enumerate(w['result']):assert (columns[k] if k<len(columns) else 0)+w['carry'][k]==x+256*w['carry'][k+1]
        assert total<=sum(caps)<=length*(1<<E)<=1<<34;digest.update(v['raw']+b''.join(roots));cells+=count;zeros+=not total;widths.add((v['b'],v['layout']['g']));shifts.add(drop)
    p=replace(spec(1024,14,(1<<44)-1,2),schema=replace(spec().schema,width=16384));v=c.derive(p,8);assert v['zmax']==1<<34 and v['layout']['s']==8 and v['base']+(1<<18)==(1<<63)+(1<<62)
    product=v['layout'];inner=product['layout'];spans=sorted(((r.derive(v['source'],8)[4],64),(product['base'],64),(inner['base'],64),(r.derive(inner['whole'],8)[4],64),(c.lp.cr.derive(product['output'],8)[2],64),(c.lp.cr.derive(product['carry'],8)[2],64)))
    assert all(v['base']+3<lo and lo+size<=v['base']+(1<<18) for lo,size in spans) and all(lo+size<=nxt for (lo,size),(nxt,_) in zip(spans,spans[1:]))
    p=spec();v=c.derive(p,4)
    for bad in (replace(p,identity=1<<44),replace(p,repetitions=True),replace(p,blocks=()),replace(p,blocks=(2,0,4)),replace(p,blocks=(0,0,4)),replace(p,blocks=(0,2,1024)),replace(p,sources=(p.output,7002,7003)),replace(p,sources=(v['base'],7002,7003)),replace(p,sources=(7001,7002)),replace(p,schema=replace(p.schema,drop=True))):rejects('Spec',lambda:c.derive(bad,4))
    rejects('Spec',lambda:c.derive(p,True))
    for values in ([False]*3,[-1]*3,[v['caps'][0]+1]*3,[0]):rejects('Input',lambda:c.witness(p,values))
    assert zeros>1000 and shifts==set(range(2,63)) and {b for b,g in widths}=={0,1,2} and {g for b,g in widths}=={1,2,3}
    assert (cells,zeros,digest.hexdigest())==(79504,1552,'8038fb212d844cc75ea49c5540ba58248b85b28a19caf5415c47eaed41ea23ee')
    print(json.dumps(dict(seed=2741,cases=10000,source_cells=cells,zero_totals=zeros,widths=sorted(widths),sha256=digest.hexdigest()),sort_keys=True),flush=True)


def account(p,out,d):
    v=c.derive(p,d);a,b,g=v['a'],v['b'],v['layout']['g'];dims=[a+b+1,a+b+2,g+3,g+3];f=lambda m:3*m*(m-1)//2+2*m
    assert out['account']==dict(identities=[((1<<m)+255,p.repetitions) for m in dims],lookup_reduction_numerator=sum(p.repetitions*(f(m)+f(8)+3*m) for m in dims),range_reduction_numerator=20*a+16*b+18*g+31,product_identity_numerator=v['layout']['k']-1,product_reduction_numerator=2*a+4*b,denominator=r.sc.P**d)
    product=out['sum'];src=product['input'];draws=[out['source']['draws'],src['draws'],src['word']['draws'],product['output']['draws'],product['carry']['draws'],product['core']['draws']]
    assert out['draws']=={} and sum(x.get(r.zc.WEIGHT,0) for x in draws)==9*a+7*b+8*g+13
    assert sum(x.get(r.zc.tr.CHALLENGE,0) for x in draws)==10*a+9*b+8*g+14
    assert len(product['core']['original_claims'])==len(product['core']['public_claims'])==2


def honest(maximum=False):
    digest=hashlib.sha256();done=0;cases=((1,1,0),(3,2049,8),(16,1<<20,14),(65,1<<20,0))
    if maximum:cases=((1024,1<<20,14),)
    for d,reps in (((4,1),) if maximum else ((4,1),(4,2),(8,1),(8,2))):
        for blocks,length,E in cases:
            p=replace(spec(blocks,E,5810+done,reps),schema=replace(spec().schema,length=length,exponent=E),blocks=tuple(range(blocks)));v=c.derive(p,d);zs=list(v['caps']) if maximum else [0 if j%3==0 else cap for j,cap in enumerate(v['caps'])]
            print('honest start',done+1,d,reps,blocks,length,E,flush=True);pairs=c.prepare(p,zs,d);proof,state=c.assemble(p,pairs,d);out=c.verify(p,oracle(p,zs)[1],proof,d);assert out['state']==state;account(p,out,d);digest.update(state);done+=1;print('honest passed',done,d,reps,blocks,length,E,flush=True)
            if maximum:
                assert sum(zs)==1<<34;product=copy.deepcopy(proof['sum']);layout=v['layout'];words=list((sum(zs)-r.sc.P).to_bytes(layout['s'],'little'));assert all(x<=cap for x,cap in zip(words,layout['output'].caps))
                children=[(product[name],out['sum'][name]['state']) for name in ('input','output','carry')];children[1]=c.lp.cr.prove(layout['output'],words,d);bad,_=c.assemble(p,dict(pairs,sum=c.lp.assemble(v['sum'],children,d)),d);rejects('Sum:Product:RoundSumMismatch',lambda:c.verify(p,c.roots(p,bad),bad,d));print('full total-minus-p alias passes output byte ranges and rejects the actual sum',flush=True)
    if not maximum:assert digest.hexdigest()=='7459d9bdd7da9dbc27fb6a1109534b241f7836429fa2b368dbf2495f97e09d9d'
    print(json.dumps(dict(maximum=maximum,proofs=done,sha256=digest.hexdigest()),sort_keys=True),flush=True)


def controls():
    p=spec();d=4;v=c.derive(p,d);zs=[0]*3;pairs=c.prepare(p,zs,d);proof,state=c.assemble(p,pairs,d);roots=oracle(p,zs)[1];out=c.verify(p,roots,proof,d);assert out['state']==state;account(p,out,d)
    for index,name in enumerate(['Block:'+str(b) for b in p.blocks]+['Output']):
        bad=roots.copy();bad[index]=bytes(32);rejects(name+':CommitmentMismatch',lambda:c.verify(p,bad,proof,d))
    bad=copy.deepcopy(proof);bad['source']['words'][0]=1;rejects('Source:SourceCopy:ClaimMismatch',lambda:c.verify(p,roots,bad,d))
    for left,right in (((1,0,0),(1,1,1)),((0,0,0),(0,1,1))):
        w=c.lp.limbs.witness(v['sum'].schema,left,right);pair=c.lp.prove(v['sum'],w,d);ds,os,cs=c.lp.witness(v['sum'],w);assert c.lp.verify(v['sum'],c.lp.roots(v['sum'],ds,os,cs)[:2],pair[0],d)['state']==pair[1];bad,_=c.assemble(p,dict(pairs,sum=pair),d);rejects('Sum:SourceJoin',lambda:c.verify(p,c.roots(p,bad),bad,d))
    bad,_=c.assemble(p,dict(pairs,source=r.prove(v['source'],[1,0,0],d)),d);rejects('Sum:SourceJoin',lambda:c.verify(p,c.roots(p,bad),bad,d))
    children=[(proof['sum'][name],out['sum'][name]['state']) for name in ('input','output','carry')]
    for name,index in (('output',0),('carry',1)):
        values=proof['sum'][name]['words'].copy();values[index]+=1;changed=children.copy();changed[1 if name=='output' else 2]=c.lp.cr.prove(v['layout'][name],values,d);bad,_=c.assemble(p,dict(pairs,sum=c.lp.assemble(v['sum'],changed,d)),d);rejects('Sum:Product:RoundSumMismatch',lambda:c.verify(p,c.roots(p,bad),bad,d))
    for side,reason in ((0,'LeftSource'),(1,'RightSource')):
        product=copy.deepcopy(proof['sum']);digits=product['input']['digits'].copy();n=v['n']
        if side==0:digits[0]=1;digits[1]=r.sc.P-1
        else:digits[n:2*n]=[0]*n
        bound=c.lp.roots(v['sum'],product['input']['digits'],product['output']['words'],product['carry']['words']);product['core'],st=c.lp.core_prove(v['sum'],bound,[pair[1] for pair in children],digits,product['output']['words'],product['carry']['words'],d);bad,_=c.assemble(p,dict(pairs,sum=(product,st)),d);rejects('Sum:'+reason+':SourceClaimMismatch',lambda:c.verify(p,roots,bad,d))
    for name in ('left','right'):
        bad=copy.deepcopy(proof);values=bad['sum']['core'][name]['final'];values[0]=r.sc.mul(values[0],r.sc.scalar(2,d));values[1]=r.sc.mul(values[1],r.sc.scalar((r.sc.P+1)//2,d));rejects('Sum:'+name.title()+'Source:PowerClaimMismatch',lambda:c.verify(p,roots,bad,d))
    for other in (replace(p,schema=replace(p.schema,fraction=8)),replace(p,blocks=(0,2,5))):assert c.verify(other,roots,proof,d)['state']!=state
    for key in ('receipt','certificate','factor'):rejects('ProofShape',lambda:c.verify(p,roots,dict(proof,**{key:{}}),d))
    rejects('Root',lambda:c.verify(p,roots[:-1],proof,d));bad=copy.deepcopy(proof);bad['sum']['input']['digits'][0]=False;rejects('Sum:NoncanonicalField',lambda:c.verify(p,roots,bad,d))
    print('every external root, actual byte join, zero-hidden one, false total/carry, both originals and both public powers retain consumers; metadata changes state',flush=True)


def boundaries():
    p=replace(spec(identity=5840),schema=replace(spec().schema,length=2049),blocks=(0,1,2));d=4;v=c.derive(p,d);zs=[0]*3;pairs=c.prepare(p,zs,d)
    for index,value in ((2,v['caps'][2]+1),(0,r.sc.P+1),(3,1)):
        caps=list(v['source'].caps);values=zs.copy()
        if index==len(caps):caps.append(0);values.append(0)
        caps[index]=values[index]=value;pair=r.assemble(v['source'],*r.witness(replace(v['source'],caps=tuple(caps)),values),d);bad,_=c.assemble(p,dict(pairs,source=pair),d);rejects('Source:CapRelation:RoundSumMismatch',lambda:c.verify(p,c.roots(p,bad),bad,d))
    proof,state=c.assemble(p,pairs,d);out=c.verify(p,oracle(p,zs)[1],proof,d);assert out['state']==state;children=[(proof['sum'][name],out['sum'][name]['state']) for name in ('input','output','carry')]
    for name,index in (('carry',0),('carry',v['layout']['k']),('output',v['layout']['k'])):
        child=v['layout'][name];values=proof['sum'][name]['words'].copy();caps=list(child.caps);assert caps[index]==0;values[index]=caps[index]=1;pair=c.lp.cr.assemble(child,*c.lp.cr.witness(replace(child,caps=tuple(caps)),values),d);changed=children.copy();changed[1 if name=='output' else 2]=pair;bad,_=c.assemble(p,dict(pairs,sum=c.lp.assemble(v['sum'],changed,d)),d);rejects('Sum:'+name.title()+':CapRelation:RoundSumMismatch',lambda:c.verify(p,c.roots(p,bad),bad,d))
    p=replace(spec(1,0,5841),schema=replace(spec(1,0).schema,length=1,exponent=0),blocks=(0,));proof,state=c.prove(p,[1],d);roots=oracle(p,[1])[1];assert c.verify(p,roots,proof,d)['state']==state
    for index,identity,size in ((0,p.sources[0],4),(1,p.output,8)):
        words=[1]+[0]*(size-1);words[-1]=1;bad=roots.copy();bad[index]=r.root(identity,words);rejects(('Block:0' if index==0 else 'Output')+':CommitmentMismatch',lambda:c.verify(p,bad,proof,d))
    print('short final block, source modulus alias, dense padding, carry endpoints, output padding and complete external high planes reject',flush=True)


def composition():
    import attention_probability_sum as probability
    for zero in (False,True):
        p=spec(2,8,5850+int(zero));d=4;zs=[];sources=[]
        for j,block in enumerate(p.blocks):
            positions=(1024*block,1024*block+31,1024*block+62);row=probability.attained.Spec(probability.attained.maximum.Spec(p.schema.length,127,7,6),p.schema.length-1,positions,0,0,p.schema.length,5940+j,8601+10*j,8603+10*j,8605+10*j,8607+10*j,1);pp=probability.Spec(row,p.schema.exponent,5950+j,8609+10*j,p.sources[j]);xs=[0 if zero else 128]*3;child,st=probability.prove(pp,xs,d);pr=probability.expected_roots(pp,xs);assert probability.verify(pp,pr,child,d)['state']==st;zs.append(sum(xs));sources.append((pp,xs,pr[1]))
        proof,state=c.prove(p,zs,d);roots=oracle(p,zs)[1];assert roots[:-1]==[entry[2] for entry in sources] and c.verify(p,roots,proof,d)['state']==state
        pp,xs,_=sources[0];xs[0]+=1;other,st=probability.prove(pp,xs,d);rr=probability.expected_roots(pp,xs);assert probability.verify(pp,rr,other,d)['state']==st;bad=roots.copy();bad[0]=rr[1];rejects('Block:0:CommitmentMismatch',lambda:c.verify(p,bad,proof,d));print('complete per-block probability sums compose and valid replacement rejects; global attainment remains separate',zero,flush=True)


if __name__=='__main__':
    modes={'--corpus':corpus,'--controls':controls,'--boundaries':boundaries,'--composition':composition,'--honest':honest,'--maximum':lambda:honest(True)}
    if sys.argv[1:]:
        assert all(mode in modes for mode in sys.argv[1:])
        for mode in sys.argv[1:]:modes[mode]()
    else:
        for test in modes.values():test()
