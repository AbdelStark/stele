# /// script
# requires-python = ">=3.12"
# dependencies = ["numpy==2.3.4", "blake3==1.0.11", "python-flint==0.9.0"]
# ///
"""Draft RFC-0004 A3/A6: global eight-byte offset bases and source controls."""
import copy
from dataclasses import replace
import hashlib
import json
import random
import sys
import numpy as np
import attention_global_base as c

r=c.r


def rejects(reason,call):
    try:call()
    except ValueError as error:assert str(error)==reason,(reason,str(error))
    else:raise AssertionError('accepted '+reason)


def spec(identity=7500,repetitions=1):
    return c.Spec(c.bounds.Spec(65,3,7,3,14,'static',65535,'exact',0),identity,10001,10007,repetitions)


def restored(p):
    return 127*259 if p.schema.value_mode=='dynamic' else p.schema.scale*min(127,(65536+p.schema.scale)//(2*p.schema.scale))


def oracle(p,z):
    h=int((np.array([z],dtype=np.uint64)*np.uint64(restored(p)))[0])
    return h,[r.root(identity,list(np.array([value],dtype='<u8').tobytes())) for identity,value in ((p.source,z),(p.output,h))]


def corpus():
    rng=random.Random(2749);digest=hashlib.sha256();cells=zeros=0;widths=set();exponents=set();directions=set();policies=set()
    for case in range(10000):
        length=rng.choice((1,3,65,255,256,257,1024,1025,1<<20));width=rng.choice((1,3,65,16384));fv=case%31;fo=(case//31)%31;E=case%15;policy='dynamic' if case%2 else 'static';scale=0 if policy=='dynamic' else rng.choice((1,2,127,259,32768,65535))
        p=replace(spec(case,1+case%2),schema=c.bounds.Spec(length,width,fv,fo,E,policy,scale,'exact',0));v=c.derive(p,4);cap=length*(1<<E);assert cap==v['constants']['z_max'] and restored(p)==v['constants']['restored_max'];z=(0,cap,rng.randrange(cap+1))[case%3]
        w=c.witness(p,z);digits,hs,cs=c.lp.witness(v['product'],w);answer,roots=oracle(p,z)
        assert c.expected_roots(p,z)==roots and c.source(v,digits)==list(z.to_bytes(8,'little')) and c.output(v,hs)==list(answer.to_bytes(8,'little'))
        columns=list(np.convolve(np.array(w['left'][0],dtype=np.int64),np.array(w['right'][0],dtype=np.int64)));columns+=[0]*(len(w['result'])-len(columns));assert all(int(x)+w['carry'][k]==w['result'][k]+256*w['carry'][k+1] for k,x in enumerate(columns)) and w['carry'][0]==w['carry'][-1]==0
        cells+=len(columns);zeros+=z==0;widths.add((v['layout']['h'],v['layout']['g']));exponents.add(E);directions.add((fo>fv)-(fo<fv));policies.add(policy);digest.update(v['raw']+b''.join(roots))
    p=replace(spec((1<<44)-1,2),schema=c.bounds.Spec(1<<20,16384,30,0,14,'static',65535,'exact',0));v=c.derive(p,8);assert v['constants']['z_max']==1<<34 and v['constants']['total_max']==65535*(1<<34) and v['layout']['s']==8 and v['base']+(1<<18)==(1<<63)+(1<<62)
    product=v['layout'];inner=product['layout'];spans=sorted(((product['base'],64),(inner['base'],64),(r.derive(inner['whole'],8)[4],64),(c.lp.cr.derive(product['output'],8)[2],64),(c.lp.cr.derive(product['carry'],8)[2],64)));assert all(v['base']+2<lo and lo+size<=v['base']+(1<<18) for lo,size in spans) and all(lo+size<=nxt for (lo,size),(nxt,_) in zip(spans,spans[1:]))
    for bad in (replace(p,identity=1<<44),replace(p,repetitions=True),replace(p,source=p.output),replace(p,output=v['base']),replace(p,schema=replace(p.schema,drop=1)),replace(p,schema=replace(p.schema,accumulation='block1024',drop=30))):rejects('Spec',lambda:c.derive(bad,4))
    rejects('Spec',lambda:c.derive(p,True))
    for z in (False,-1,(1<<34)+1):rejects('WeightSum',lambda:c.witness(p,z))
    assert exponents==set(range(15)) and directions=={-1,0,1} and policies=={'dynamic','static'} and zeros>3000 and (3,3) in widths
    print(json.dumps(dict(seed=2749,cases=10000,column_cells=cells,zero_sources=zeros,widths=sorted(widths),sha256=digest.hexdigest()),sort_keys=True),flush=True)


def account(p,out,d):
    v=c.derive(p,d);b,g,k=v['layout']['h'],v['layout']['g'],v['layout']['k'];dims=[b+2,g+3,g+3];f=lambda m:3*m*(m-1)//2+2*m
    assert out['account']==dict(identities=[((1<<m)+255,p.repetitions) for m in dims],lookup_reduction_numerator=sum(p.repetitions*(f(m)+f(8)+3*m) for m in dims),range_reduction_numerator=9*b+18*g+31,product_identity_numerator=k-1,product_reduction_numerator=4*b,denominator=r.sc.P**d)
    product=out['product'];src=product['input'];draws=[src['draws'],src['word']['draws'],product['output']['draws'],product['carry']['draws'],product['core']['draws']]
    assert out['draws']=={} and len(product['core']['original_claims'])==len(product['core']['public_claims'])==2
    assert sum(x.get(r.zc.WEIGHT,0) for x in draws)==4*b+8*g+13 and sum(x.get(r.zc.tr.CHALLENGE,0) for x in draws)==6*b+8*g+14


def honest(maximum=False):
    digest=hashlib.sha256();done=0;cases=((1,1,0,0,0,'static',1),(65,3,8,30,0,'static',2),(1025,65,14,0,30,'dynamic',0),(1<<20,16384,14,30,0,'static',65535))
    if maximum:cases=(cases[-1],(1<<20,16384,14,0,30,'dynamic',0))
    for d,reps in (((4,1),) if maximum else ((4,1),(4,2),(8,1),(8,2))):
        for length,width,E,fv,fo,policy,scale in cases:
            p=replace(spec(7510+done,reps),schema=c.bounds.Spec(length,width,fv,fo,E,policy,scale,'exact',0));z=0 if length==1 else length*(1<<E)
            print('honest start',done+1,d,reps,length,policy,flush=True);proof,state=c.prove(p,z,d);answer,roots=oracle(p,z);out=c.verify(p,roots,proof,d);assert out['state']==state;account(p,out,d)
            if maximum:assert z==1<<34 and answer==restored(p)*(1<<34)
            digest.update(state);done+=1;print('honest passed',done,d,reps,length,policy,flush=True)
    print(json.dumps(dict(maximum=maximum,proofs=done,sha256=digest.hexdigest()),sort_keys=True),flush=True)


def controls():
    p=spec();d=4;v=c.derive(p,d);S=restored(p);pair=c.prepare(p,0,d);proof,state=c.assemble(p,pair,d);roots=oracle(p,0)[1];out=c.verify(p,roots,proof,d);assert out['state']==state;account(p,out,d)
    for index,name in enumerate(('WeightSum','Base')):
        bad=roots.copy();bad[index]=bytes(32);rejects(name+':CommitmentMismatch',lambda:c.verify(p,bad,proof,d))
    for factor in (0,1,S-1):
        w=c.lp.limbs.witness(v['product'].schema,(0,),(factor,));child=c.lp.prove(v['product'],w,d);bad,_=c.assemble(p,child,d);rejects('Product:Factor',lambda:c.verify(p,c.roots(p,bad),bad,d))
    bad=copy.deepcopy(proof);bad['product']['input']['digits'][-1]=1;rejects('Product:Factor',lambda:c.verify(p,c.roots(p,bad),bad,d))
    bad=copy.deepcopy(proof);bad['product']['input']['digits'][0]=1;rejects('Product:Input:LimbPacking:ClaimMismatch',lambda:c.verify(p,c.roots(p,bad),bad,d))
    for left,right,reason in (((1,),(S,),'LeftSource'),((0,),(1,),'RightSource')):
        w=c.lp.limbs.witness(v['product'].schema,left,right);digits,hs,cs=c.lp.witness(v['product'],w);layout=v['layout'];children=[(proof['product']['input'],out['product']['input']['state']),c.lp.cr.prove(layout['output'],hs,d),c.lp.cr.prove(layout['carry'],cs,d)];product,_=c.lp.assemble(v['product'],children,d);bound=c.lp.roots(v['product'],product['input']['digits'],hs,cs);product['core'],st=c.lp.core_prove(v['product'],bound,[part[1] for part in children],digits,hs,cs,d);bad,_=c.assemble(p,(product,st),d);rejects('Product:'+reason+':SourceClaimMismatch',lambda:c.verify(p,c.roots(p,bad),bad,d))
    for side in ('left','right'):
        bad=copy.deepcopy(proof);values=bad['product']['core'][side]['final'];values[0]=r.sc.mul(values[0],r.sc.scalar(2,d));values[1]=r.sc.mul(values[1],r.sc.scalar((r.sc.P+1)//2,d));rejects('Product:'+side.title()+'Source:PowerClaimMismatch',lambda:c.verify(p,roots,bad,d))
    for other in (replace(p,schema=replace(p.schema,width=4)),replace(p,schema=replace(p.schema,fraction=8,output_fraction=4))):assert c.verify(other,roots,proof,d)['state']!=state
    for key in ('receipt','certificate','factor'):rejects('ProofShape',lambda:c.verify(p,roots,dict(proof,**{key:{}}),d))
    rejects('Root',lambda:c.verify(p,roots[:-1],proof,d));bad=copy.deepcopy(proof);bad['product']['input']['digits'][0]=False;rejects('Product:NoncanonicalField',lambda:c.verify(p,roots,bad,d))
    print('external roots, exact zero-hidden factor and high bytes, both actual operands and both public powers retain consumers; equivalent metadata changes state',flush=True)


def boundaries():
    p=replace(spec(7540),schema=c.bounds.Spec(1<<20,16384,30,0,14,'static',65535,'exact',0));d=4;v=c.derive(p,d);z=1<<33;H=z*65535;pair=c.prepare(p,z,d);proof,state=c.assemble(p,pair,d);out=c.verify(p,oracle(p,z)[1],proof,d);assert out['state']==state;account(p,out,d);layout=v['layout'];children=[(proof['product'][name],out['product'][name]['state']) for name in ('input','output','carry')]
    for alias in (H-r.sc.P,H+r.sc.P):
        values=list(alias.to_bytes(layout['s'],'little'));assert all(x<=cap for x,cap in zip(values,layout['output'].caps));bad,_=c.assemble(p,c.lp.assemble(v['product'],[children[0],c.lp.cr.prove(layout['output'],values,d),children[2]],d),d);rejects('Product:Product:FinalEvaluationMismatch',lambda:c.verify(p,c.roots(p,bad),bad,d))
    source=layout['input'];whole=layout['layout']['whole'];caps=list(whole.caps);caps[0]+=1;words,bs,cs=r.witness(replace(whole,caps=tuple(caps)),[(1<<34)+1,65535]);word_pair=r.assemble(whole,words,bs,cs,d);input_pair=c.lp.ls.assemble(source,words,word_pair,None,d);bad,_=c.assemble(p,c.lp.assemble(v['product'],[input_pair,*children[1:]],d),d);rejects('Product:Input:WholeWord:CapRelation:RoundSumMismatch',lambda:c.verify(p,c.roots(p,bad),bad,d))
    for name,index in (('output',layout['k']),('carry',0),('carry',layout['k'])):
        child=layout[name];values=proof['product'][name]['words'].copy();values[index]=1;caps=list(child.caps);caps[index]=1;part=c.lp.cr.assemble(child,*c.lp.cr.witness(replace(child,caps=tuple(caps)),values),d);changed=children.copy();changed[1 if name=='output' else 2]=part;bad,_=c.assemble(p,c.lp.assemble(v['product'],changed,d),d);rejects('Product:'+name.title()+':CapRelation:RoundSumMismatch',lambda:c.verify(p,c.roots(p,bad),bad,d))
    for index,identity,value in ((0,p.source,z),(1,p.output,H)):
        words=list(value.to_bytes(8,'little'));words[-1]=1;roots=oracle(p,z)[1];roots[index]=r.root(identity,words);rejects(('WeightSum' if index==0 else 'Base')+':CommitmentMismatch',lambda:c.verify(p,roots,proof,d))
    print('genuine output-ranged H-p/H+p, whole global Z overflow, initial/final carries, output padding and all eight external planes reject',flush=True)


def composition():
    import attention_global_probability_sum as upstream
    import attention_denominator as denominator
    import attention_sign as sign
    p=replace(spec(7550),schema=c.bounds.Spec(2049,3,7,3,8,'static',1,'exact',0));d=4;bs=upstream.bounds.Spec(2049,3,7,8,'static',1,10);sp=upstream.Spec(bs,(0,1,2),7650,(10101,10102,10103),p.source,1);zs=[256,128,1];z=sum(zs)
    child,st=upstream.prove(sp,zs,d);sr=upstream.expected_roots(sp,zs);assert upstream.verify(sp,sr,child,d)['state']==st
    proof,state=c.prove(p,z,d);H,roots=oracle(p,z);assert roots[0]==sr[-1] and c.verify(p,roots,proof,d)['state']==state
    dp=denominator.Spec(p.schema,7750,p.source,10104,1);den,st=denominator.prove(dp,z,d);dr=denominator.expected_roots(dp,z);assert dr[0]==roots[0] and denominator.verify(dp,dr,den,d)['state']==st
    ss=sign.bounds.Spec(2049,3,7,8,'static',1,'exact');ap=sign.Spec(ss,7850,10105,p.output,10106,10107,1);offsets=[H-1,H,H+2];sg,st=sign.prove(ap,offsets,H,d);ar=sign.expected_roots(ap,offsets,H,[1,0,2],[1,0,0]);assert ar[1]==roots[1] and sign.verify(ap,ar,sg,d)['state']==st
    other,st=upstream.prove(sp,[256,128,2],d);rr=upstream.expected_roots(sp,[256,128,2]);assert upstream.verify(sp,rr,other,d)['state']==st;rejects('WeightSum:CommitmentMismatch',lambda:c.verify(p,[rr[-1],roots[1]],proof,d));rejects('WeightSum:CommitmentMismatch',lambda:denominator.verify(dp,[rr[-1],dr[1]],den,d))
    other,st=c.prove(p,z+1,d);rr=oracle(p,z+1)[1];assert c.verify(p,rr,other,d)['state']==st;rejects('Base:CommitmentMismatch',lambda:sign.verify(ap,[ar[0],rr[1],*ar[2:]],sg,d))
    zero,st=c.prove(p,0,d);zr=oracle(p,0)[1];assert c.verify(p,zr,zero,d)['state']==st;rejects('WeightSum:CommitmentMismatch',lambda:c.verify(p,[sr[-1],zr[1]],zero,d))
    print('complete global probability, positive denominator and canonical sign compose; valid changed Z/H and standalone zero cannot replace pinned sources',flush=True)


if __name__=='__main__':
    modes={'--corpus':corpus,'--controls':controls,'--boundaries':boundaries,'--composition':composition,'--honest':honest,'--maximum':lambda:honest(True)}
    if sys.argv[1:]:
        assert all(mode in modes for mode in sys.argv[1:])
        for mode in sys.argv[1:]:modes[mode]()
    else:
        for test in modes.values():test()
