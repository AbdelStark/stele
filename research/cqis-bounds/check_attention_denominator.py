# /// script
# requires-python = ">=3.12"
# dependencies = ["numpy==2.3.4", "blake3==1.0.11", "python-flint==0.9.0"]
# ///
"""Draft RFC-0004 A3/A6: positive full-width attention denominators."""
import copy
from dataclasses import replace
import hashlib
import json
import random
import sys
import numpy as np
import attention_denominator as c

r=c.r


def rejects(reason,call):
    try:call()
    except ValueError as error:assert str(error)==reason,(reason,str(error))
    else:raise AssertionError('accepted '+reason)


def spec(identity=6200,repetitions=1):
    return c.Spec(c.bounds.Spec(65,3,7,3,8,'static',1,'exact',0),identity,9001,9007,repetitions)


def oracle(p,z):
    factor=1<<max(p.schema.fraction-p.schema.output_fraction-p.schema.drop,0);D=int((np.array([z],dtype=object)*np.array([factor],dtype=object))[0]);words=list(np.array([D&((1<<64)-1),D>>64],dtype='<u8').tobytes())
    return D,[r.root(p.source,list(np.array([z],dtype='<u8').tobytes())),r.root(p.output,words)]


def corpus():
    rng=random.Random(2742);digest=hashlib.sha256();cells=zeros=0;shifts=set();widths=[set() for _ in range(5)];modes=set();directions=set()
    for case in range(10000):
        length=rng.choice((1,3,65,1024,1025,1<<20));width=rng.choice((1,3,65,16384));E=case%15;mode='block1024' if case%2 else 'exact';policy='dynamic' if case%4<2 else 'static';scale=0 if policy=='dynamic' else rng.choice((1,2,259,65535));fv=case%31;fo=(case//31)%31
        if case<61:mode='block1024';policy='static';scale=1;E=0
        S=127*259 if policy=='dynamic' else scale*min(127,(65536+scale)//(2*scale));H=1024*(1<<E)*S;minimum=next(k for k in range(63) if (H+(1<<k)//2)//(1<<k)<=32767);drop=0 if mode=='exact' else case+2 if case<61 else minimum+case%(63-minimum)
        if case==61:length=1<<20;E=14;fv=30;fo=0;mode='exact';drop=0
        p=replace(spec(case,1+case%2),schema=c.bounds.Spec(length,width,fv,fo,E,policy,scale,mode,drop));v=c.derive(p,4);Q=1<<E;z=(Q,length*Q,(Q+length*Q)//2,rng.randrange(Q,length*Q+1))[case%4];w=c.witness(p,z);D,roots=oracle(p,z);assert c.expected_roots(p,z)==roots and w['gap']==[int(np.int64(z)-np.int64(Q))]
        gap_words=r.witness(v['gap'],w['gap'])[0];positive=v['layouts']['positive'];denominator=v['layouts']['denominator'];pw=w['positive'];pos_words=list(pw['result'])+[0]*(positive['s']-len(pw['result']))
        assert c.positive_source(v,gap_words)==c.lp.ls.source(positive['input'],pw['left'],pw['right']) and c.denominator_source(v,pos_words)==c.lp.ls.source(denominator['input'],w['denominator']['left'],w['denominator']['right'])
        for role,answer in (('positive',z),('denominator',D)):
            item=w[role];columns=[0]*len(item['result'])
            for left,right in zip(item['left'],item['right']):
                for k,x in enumerate(np.convolve(np.array(left,dtype=np.int64),np.array(right,dtype=np.int64))):columns[k]+=int(x)
            assert sum(x<<(8*k) for k,x in enumerate(item['result']))==answer
            for k,x in enumerate(item['result']):assert columns[k]+item['carry'][k]==x+256*item['carry'][k+1]
            cells+=len(item['result'])
        dw=w['denominator'];assert c.full_output(v,list(dw['result'])+[0]*(denominator['s']-len(dw['result'])))==list(np.array([D&((1<<64)-1),D>>64],dtype='<u8').tobytes())
        digest.update(v['raw']+b''.join(roots));zeros+=z==Q;shifts.add(drop);modes.add(mode);directions.add((fo-fv+drop>0)-(fo-fv+drop<0))
        for seen,value in zip(widths,(v['bg'],positive['h'],positive['g'],denominator['h'],denominator['g'])):seen.add(value)
    p=replace(spec((1<<44)-1,2),schema=c.bounds.Spec(1<<20,16384,30,0,14,'static',1,'exact',0));v=c.derive(p,8);assert v['constants']['denominator_max']==1<<64 and v['layouts']['denominator']['s']==16 and v['base']+(1<<18)==(1<<63)+(1<<62)
    spans=[(r.derive(v['gap'],8)[4],64)]
    for product in v['layouts'].values():
        inner=product['layout'];spans.extend(((product['base'],64),(inner['base'],64),(r.derive(inner['whole'],8)[4],64),(c.lp.cr.derive(product['output'],8)[2],64),(c.lp.cr.derive(product['carry'],8)[2],64)))
    spans.sort();assert all(v['base']+5<lo and lo+size<=v['base']+(1<<18) for lo,size in spans) and all(lo+size<=nxt for (lo,size),(nxt,_) in zip(spans,spans[1:]))
    for bad in (replace(p,identity=1<<44),replace(p,repetitions=True),replace(p,source=p.output),replace(p,source=v['base']),replace(p,schema=replace(p.schema,output_fraction=True)),replace(p,schema=replace(p.schema,drop=1))):rejects('Spec',lambda:c.derive(bad,4))
    for z in (False,-1,0,(1<<14)-1,(1<<34)+1):rejects('WeightSum',lambda:c.witness(p,z))
    rejects('Spec',lambda:c.derive(p,True));assert shifts=={0}|set(range(2,63)) and modes=={'exact','block1024'} and directions=={-1,0,1} and zeros>1000
    assert widths==[{0,1,2,3},{0,1,2,3},{1,2,3},{0,1,2,3},{1,2,3,4}]
    assert (cells,zeros,digest.hexdigest())==(52440,3711,'de3d8ef594b88bdb8a3bf6a3fe8394b2fc7cb39b8ab7e1da76eba50977fff5bd')
    print(json.dumps(dict(seed=2742,cases=10000,column_cells=cells,zero_gaps=zeros,widths=[sorted(x) for x in widths],sha256=digest.hexdigest()),sort_keys=True),flush=True)


def account(p,out,d):
    v=c.derive(p,d);bg=v['bg'];pos,den=(v['layouts'][role] for role in ('positive','denominator'));bp,gp,bd,gd=pos['h'],pos['g'],den['h'],den['g'];dims=[bg+1,bp+3,gp+3,gp+3,bd+2,gd+3,gd+3];f=lambda m:3*m*(m-1)//2+2*m
    assert out['account']==dict(identities=[((1<<m)+255,p.repetitions) for m in dims],lookup_reduction_numerator=sum(p.repetitions*(f(m)+f(8)+3*m) for m in dims),range_reduction_numerator=7*bg+9*(bp+bd)+18*(gp+gd)+73,product_identity_numerators=[pos['k']-1,den['k']-1],product_reduction_numerator=2+4*(bp+bd),denominator=r.sc.P**d)
    draws=[out['gap']['draws']]
    for role in ('positive','denominator'):
        product=out[role];src=product['input'];draws.extend((src['draws'],src['word']['draws'],product['output']['draws'],product['carry']['draws'],product['core']['draws']));assert len(product['core']['original_claims'])==len(product['core']['public_claims'])==2
    assert out['draws']=={} and sum(x.get(r.zc.WEIGHT,0) for x in draws)==3*bg+4*(bp+bd)+8*(gp+gd)+31
    assert sum(x.get(r.zc.tr.CHALLENGE,0) for x in draws)==3*bg+6*(bp+bd)+8*(gp+gd)+34


def honest(maximum=False):
    digest=hashlib.sha256();done=0;cases=((1,0,0,0,'exact',0,'static',1),(3,8,30,0,'exact',0,'static',259),(65,14,0,30,'block1024',25,'dynamic',0),(1<<20,14,30,0,'exact',0,'static',1))
    if maximum:cases=(cases[-1],(1<<20,0,30,0,'block1024',2,'static',1))
    for d,reps in (((4,1),) if maximum else ((4,1),(4,2),(8,1),(8,2))):
        for length,E,fv,fo,mode,drop,policy,scale in cases:
            p=replace(spec(6210+done,reps),schema=c.bounds.Spec(length,16384 if maximum else 3,fv,fo,E,policy,scale,mode,drop));z=length*(1<<E);print('honest start',done+1,d,reps,length,mode,drop,flush=True);proof,state=c.prove(p,z,d);D,roots=oracle(p,z);out=c.verify(p,roots,proof,d);assert out['state']==state;account(p,out,d)
            if maximum:assert D==(1<<64 if mode=='exact' else 1<<48)
            digest.update(state);done+=1;print('honest passed',done,d,reps,length,mode,drop,flush=True)
    print(json.dumps(dict(maximum=maximum,proofs=done,sha256=digest.hexdigest()),sort_keys=True),flush=True)


def controls():
    p=spec();d=4;v=c.derive(p,d);Q=v['constants']['z_min'];F=v['constants']['right_factor'];pairs=c.prepare(p,Q,d);proof,state=c.assemble(p,pairs,d);roots=oracle(p,Q)[1];out=c.verify(p,roots,proof,d);assert out['state']==state;account(p,out,d)
    for index,name in enumerate(('WeightSum','Denominator')):
        bad=roots.copy();bad[index]=bytes(32);rejects(name+':CommitmentMismatch',lambda:c.verify(p,bad,proof,d))
    bad=copy.deepcopy(proof);bad['gap']['words'][0]=1;rejects('Gap:SourceCopy:ClaimMismatch',lambda:c.verify(p,roots,bad,d))
    bad,_=c.assemble(p,dict(pairs,gap=r.prove(v['gap'],[1],d)),d);rejects('Positive:SourceJoin',lambda:c.verify(p,c.roots(p,bad),bad,d))
    for role,left,right in (('positive',(0,Q-1),(1,1)),('positive',(0,Q),(0,1)),('denominator',(Q+1,),(F,)),('denominator',(Q,),(F-1,))):
        w=c.lp.limbs.witness(v[role].schema,left,right);pair=c.lp.prove(v[role],w,d);ds,zs,cs=c.lp.witness(v[role],w);assert c.lp.verify(v[role],c.lp.roots(v[role],ds,zs,cs)[:2],pair[0],d)['state']==pair[1];bad,_=c.assemble(p,dict(pairs,**{role:pair}),d);rejects(role.title()+':SourceJoin',lambda:c.verify(p,c.roots(p,bad),bad,d))
    for role,left,right,reason in (('positive',(1,Q),(1,1),'LeftSource'),('positive',(0,Q),(0,1),'RightSource'),('denominator',(Q+1,),(F,),'LeftSource'),('denominator',(Q,),(F-1,),'RightSource')):
        w=c.lp.limbs.witness(v[role].schema,left,right);ds,zs,cs=c.lp.witness(v[role],w);layout=v['layouts'][role];children=[(proof[role]['input'],out[role]['input']['state']),c.lp.cr.prove(layout['output'],zs,d),c.lp.cr.prove(layout['carry'],cs,d)];product,_=c.lp.assemble(v[role],children,d);bound=c.lp.roots(v[role],product['input']['digits'],zs,cs);product['core'],st=c.lp.core_prove(v[role],bound,[pair[1] for pair in children],ds,zs,cs,d);bad,_=c.assemble(p,dict(pairs,**{role:(product,st)}),d);rejects(role.title()+':'+reason+':SourceClaimMismatch',lambda:c.verify(p,c.roots(p,bad),bad,d))
    for role in ('positive','denominator'):
        for side in ('left','right'):
            bad=copy.deepcopy(proof);values=bad[role]['core'][side]['final'];values[0]=r.sc.mul(values[0],r.sc.scalar(2,d));values[1]=r.sc.mul(values[1],r.sc.scalar((r.sc.P+1)//2,d));rejects(role.title()+':'+side.title()+'Source:PowerClaimMismatch',lambda:c.verify(p,roots,bad,d))
    for other in (replace(p,schema=replace(p.schema,width=4)),replace(p,schema=replace(p.schema,fraction=8,output_fraction=4))):assert c.verify(other,roots,proof,d)['state']!=state
    for key in ('receipt','certificate','factor'):rejects('ProofShape',lambda:c.verify(p,roots,dict(proof,**{key:{}}),d))
    rejects('Root',lambda:c.verify(p,roots[:-1],proof,d));bad=copy.deepcopy(proof);bad['denominator']['input']['digits'][0]=False;rejects('Denominator:NoncanonicalField',lambda:c.verify(p,roots,bad,d))
    print('external roots, exact gap/Q/one/Z/factor joins, all four actual originals and four public powers retain consumers; equivalent metadata changes state',flush=True)


def boundaries():
    p=replace(spec(6240),schema=c.bounds.Spec(1<<20,16384,30,0,14,'static',1,'exact',0));d=4;v=c.derive(p,d);Z=v['constants']['z_max'];pairs=c.prepare(p,Z,d);proof,state=c.assemble(p,pairs,d);out=c.verify(p,oracle(p,Z)[1],proof,d);assert out['state']==state
    for role,value in (('positive',Z-r.sc.P),('denominator',(1<<64)-r.sc.P)):
        layout=v['layouts'][role];values=list(value.to_bytes(layout['s'],'little'));assert all(x<=cap for x,cap in zip(values,layout['output'].caps));children=[(proof[role][name],out[role][name]['state']) for name in ('input','output','carry')];children[1]=c.lp.cr.prove(layout['output'],values,d);bad,_=c.assemble(p,dict(pairs,**{role:c.lp.assemble(v[role],children,d)}),d);rejects(role.title()+':Product:'+('RoundSumMismatch' if role=='positive' else 'FinalEvaluationMismatch'),lambda:c.verify(p,c.roots(p,bad),bad,d))
    values=[v['gap'].caps[0]+1];pair=r.assemble(v['gap'],*r.witness(replace(v['gap'],caps=tuple(values)),values),d);bad,_=c.assemble(p,dict(pairs,gap=pair),d);rejects('Gap:CapRelation:RoundSumMismatch',lambda:c.verify(p,c.roots(p,bad),bad,d))
    p=spec(6241);v=c.derive(p,d);Q=v['constants']['z_min'];pairs=c.prepare(p,Q,d);proof,state=c.assemble(p,pairs,d);out=c.verify(p,oracle(p,Q)[1],proof,d)
    for z in (0,Q-1):
        layout=v['layouts']['positive'];children=[(proof['positive'][name],out['positive'][name]['state']) for name in ('input','output','carry')];children[1]=c.lp.cr.prove(layout['output'],list(z.to_bytes(layout['s'],'little')),d);positive=c.lp.assemble(v['positive'],children,d);den=c.lp.prove(v['denominator'],c.lp.limbs.witness(v['denominator'].schema,(z,),(v['constants']['right_factor'],)),d);bad,_=c.assemble(p,dict(pairs,positive=positive,denominator=den),d);rejects('Positive:Product:RoundSumMismatch',lambda:c.verify(p,c.roots(p,bad),bad,d))
    for index,identity,size,value in ((0,p.source,8,Q),(1,p.output,16,oracle(p,Q)[0])):
        words=list(value.to_bytes(size,'little'));words[-1]=1;bad=oracle(p,Q)[1];bad[index]=r.root(identity,words);rejects(('WeightSum' if index==0 else 'Denominator')+':CommitmentMismatch',lambda:c.verify(p,bad,proof,d))
    p=replace(spec(6242),schema=c.bounds.Spec(1,1,0,0,0,'static',1,'exact',0));v=c.derive(p,d);pairs=c.prepare(p,1,d);proof,state=c.assemble(p,pairs,d);out=c.verify(p,oracle(p,1)[1],proof,d);assert out['state']==state;account(p,out,d);pair=r.assemble(v['gap'],*r.witness(replace(v['gap'],caps=(1,)),[1]),d);bad,_=c.assemble(p,dict(pairs,gap=pair),d);rejects('Gap:CapRelation:FinalEvaluationMismatch',lambda:c.verify(p,c.roots(p,bad),bad,d))
    print('genuinely output-ranged Z-p and D-p aliases, zero/below-Q sums, gap overflow, high external planes and zero-gap overflow reject',flush=True)


def composition():
    import attention_global_probability_sum as upstream
    p=replace(spec(6250),schema=c.bounds.Spec(2049,3,30,0,8,'static',1,'block1024',10));d=4;bp=upstream.bounds.Spec(p.schema.length,p.schema.width,p.schema.fraction,p.schema.exponent,p.schema.value_mode,p.schema.scale,p.schema.drop);sp=upstream.Spec(bp,(0,1,2),6350,(9101,9103,9109),p.source,1);zs=[256,128,1];child,st=upstream.prove(sp,zs,d);sr=upstream.expected_roots(sp,zs);assert upstream.verify(sp,sr,child,d)['state']==st
    proof,state=c.prove(p,sum(zs),d);roots=oracle(p,sum(zs))[1];assert roots[0]==sr[-1] and c.verify(p,roots,proof,d)['state']==state
    for changed in ([257,128,1],[0,0,0]):
        other,st=upstream.prove(sp,changed,d);rr=upstream.expected_roots(sp,changed);assert upstream.verify(sp,rr,other,d)['state']==st;bad=roots.copy();bad[0]=rr[-1];rejects('WeightSum:CommitmentMismatch',lambda:c.verify(p,bad,proof,d))
        if not any(changed):rejects('WeightSum',lambda:c.prove(p,0,d))
    print('actual complete global probability sum composes; valid changed and zero sums cannot replace the admitted divisor source',flush=True)


if __name__=='__main__':
    modes={'--corpus':corpus,'--controls':controls,'--boundaries':boundaries,'--composition':composition,'--honest':honest,'--maximum':lambda:honest(True)}
    if sys.argv[1:]:
        assert all(mode in modes for mode in sys.argv[1:])
        for mode in sys.argv[1:]:modes[mode]()
    else:
        for test in modes.values():test()
