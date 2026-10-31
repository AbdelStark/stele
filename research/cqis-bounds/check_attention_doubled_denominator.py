# /// script
# requires-python = ">=3.12"
# dependencies = ["numpy==2.3.4", "blake3==1.0.11", "python-flint==0.9.0"]
# ///
"""Draft RFC-0004 A3/A6: complete doubled attention denominators and controls."""
import copy
from dataclasses import replace
import hashlib
import json
import random
import sys
import numpy as np
import attention_doubled_denominator as c

r=c.r


def rejects(reason,call):
    try:call()
    except ValueError as error:assert str(error)==reason,(reason,str(error))
    else:raise AssertionError('accepted '+reason)


def spec(identity=7000,repetitions=1):
    return c.Spec(c.bounds.Spec(65,3,7,3,8,'static',1,'exact',0),identity,9601,9607,repetitions)


def oracle(p,D):
    doubled=int((np.array([D],dtype=object)*2)[0])
    def words(value):return list(np.array([value&((1<<64)-1),value>>64],dtype='<u8').tobytes())
    return doubled,[r.root(p.source,words(D)),r.root(p.output,words(doubled))]


def corpus():
    rng=random.Random(2744);digest=hashlib.sha256();cells=zeros=0;widths=set();shifts=set();modes=set();directions=set()
    for case in range(10000):
        length=rng.choice((1,3,65,1024,1025,1<<20));width=rng.choice((1,3,65,16384));fv=case%31;fo=(case//31)%31;E=case%15;mode='block1024' if case%2 else 'exact';policy='dynamic' if case%4<2 else 'static';scale=0 if policy=='dynamic' else rng.choice((1,2,259,65535))
        if case<61:mode='block1024';policy='static';scale=1;E=0
        S=127*259 if policy=='dynamic' else scale*min(127,(65536+scale)//(2*scale));H=1024*(1<<E)*S;minimum=next(k for k in range(63) if (H+(1<<k)//2)//(1<<k)<=32767);drop=0 if mode=='exact' else case+2 if case<61 else minimum+case%(63-minimum)
        if case==61:length=1<<20;E=14;fv=30;fo=0;mode='exact';drop=0
        p=replace(spec(case,1+case%2),schema=c.bounds.Spec(length,width,fv,fo,E,policy,scale,mode,drop));v=c.derive(p,4);cap=length*(1<<E)*(1<<max(fv-fo-drop,0));assert cap==v['constants']['denominator_max'];D=(0,cap,rng.randrange(cap+1))[case%3];w=c.witness(p,D);digits,zs,cs=c.lp.witness(v['double'],w);answer,roots=oracle(p,D)
        assert c.expected_roots(p,D)==roots and c.source(v,digits)==list(D.to_bytes(16,'little')) and c.output(v,zs)==list(answer.to_bytes(16,'little'))
        columns=list(np.convolve(np.array(w['left'][0],dtype=np.int64),np.array(w['right'][0],dtype=np.int64)));columns+=[0]*(len(w['result'])-len(columns));assert all(int(x)+w['carry'][k]==w['result'][k]+256*w['carry'][k+1] for k,x in enumerate(columns)) and w['carry'][0]==w['carry'][-1]==0
        cells+=len(columns);zeros+=D==0;widths.add((v['layout']['h'],v['layout']['g']));shifts.add(drop);modes.add(mode);directions.add((fo-fv+drop>0)-(fo-fv+drop<0));digest.update(v['raw']+b''.join(roots))
    p=replace(spec((1<<44)-1,2),schema=c.bounds.Spec(1<<20,16384,30,0,14,'static',1,'exact',0));v=c.derive(p,8);assert v['constants']['double_denominator_max']==1<<65 and v['layout']['s']==16 and v['base']+(1<<18)==(1<<63)+(1<<62)
    product=v['layout'];inner=product['layout'];spans=sorted(((product['base'],64),(inner['base'],64),(r.derive(inner['whole'],8)[4],64),(c.lp.cr.derive(product['output'],8)[2],64),(c.lp.cr.derive(product['carry'],8)[2],64)));assert all(v['base']+2<lo and lo+size<=v['base']+(1<<18) for lo,size in spans) and all(lo+size<=nxt for (lo,size),(nxt,_) in zip(spans,spans[1:]))
    for bad in (replace(p,identity=1<<44),replace(p,repetitions=True),replace(p,source=p.output),replace(p,output=v['base']),replace(p,schema=replace(p.schema,drop=1))):rejects('Spec',lambda:c.derive(bad,4))
    rejects('Spec',lambda:c.derive(p,True))
    for D in (False,-1,(1<<64)+1):rejects('Denominator',lambda:c.witness(p,D))
    assert modes=={'exact','block1024'} and shifts=={0}|set(range(2,63)) and directions=={-1,0,1} and zeros>3000 and (4,4) in widths
    assert (cells,zeros,digest.hexdigest())==(28651,3358,'e07ddd1c2b56c031b3583849c0804d2114c6bbe7c9c7c4ef5f984f7429c87975')
    print(json.dumps(dict(seed=2744,cases=10000,column_cells=cells,zero_sources=zeros,widths=sorted(widths),sha256=digest.hexdigest()),sort_keys=True),flush=True)


def account(p,out,d):
    v=c.derive(p,d);b,g,k=v['layout']['h'],v['layout']['g'],v['layout']['k'];dims=[b+2,g+3,g+3];f=lambda m:3*m*(m-1)//2+2*m
    assert out['account']==dict(identities=[((1<<m)+255,p.repetitions) for m in dims],lookup_reduction_numerator=sum(p.repetitions*(f(m)+f(8)+3*m) for m in dims),range_reduction_numerator=9*b+18*g+31,product_identity_numerator=k-1,product_reduction_numerator=4*b,denominator=r.sc.P**d)
    product=out['double'];src=product['input'];draws=[src['draws'],src['word']['draws'],product['output']['draws'],product['carry']['draws'],product['core']['draws']]
    assert out['draws']=={} and len(product['core']['original_claims'])==len(product['core']['public_claims'])==2
    assert sum(x.get(r.zc.WEIGHT,0) for x in draws)==4*b+8*g+13 and sum(x.get(r.zc.tr.CHALLENGE,0) for x in draws)==6*b+8*g+14


def honest(maximum=False):
    digest=hashlib.sha256();done=0;cases=((1,0,0,0,'exact',0),(3,8,30,0,'exact',0),(65,14,0,30,'block1024',25),(1<<20,14,30,0,'exact',0))
    if maximum:cases=(cases[-1],(1<<20,0,30,0,'block1024',2))
    for d,reps in (((4,1),) if maximum else ((4,1),(4,2),(8,1),(8,2))):
        for length,E,fv,fo,mode,drop in cases:
            p=replace(spec(7010+done,reps),schema=c.bounds.Spec(length,16384 if maximum else 3,fv,fo,E,'static',1,mode,drop));cap=c.derive(p,d)['constants']['denominator_max'];D=0 if not maximum and length==1 else cap
            print('honest start',done+1,d,reps,length,mode,drop,flush=True);proof,state=c.prove(p,D,d);answer,roots=oracle(p,D);out=c.verify(p,roots,proof,d);assert out['state']==state;account(p,out,d)
            if maximum:assert answer==(1<<65 if mode=='exact' else 1<<49)
            digest.update(state);done+=1;print('honest passed',done,d,reps,length,mode,drop,flush=True)
    if not maximum:assert (done,digest.hexdigest())==(16,'4e1b11841e44afb486319288865815ad8ddf56359ed810ea4ec5e3bf15f4b0d5')
    else:assert (done,digest.hexdigest())==(2,'f9ef9e44c50b52bdcfb3ac2ca4950be1d6603bd6868d8c21925f094fc95318ca')
    print(json.dumps(dict(maximum=maximum,proofs=done,sha256=digest.hexdigest()),sort_keys=True),flush=True)


def controls():
    p=spec();d=4;v=c.derive(p,d);pair=c.prepare(p,0,d);proof,state=c.assemble(p,pair,d);roots=oracle(p,0)[1];out=c.verify(p,roots,proof,d);assert out['state']==state;account(p,out,d)
    for index,name in enumerate(('Denominator','Doubled')):
        bad=roots.copy();bad[index]=bytes(32);rejects(name+':CommitmentMismatch',lambda:c.verify(p,bad,proof,d))
    for factor in (0,1):
        w=c.lp.limbs.witness(v['double'].schema,(0,),(factor,));child=c.lp.prove(v['double'],w,d);bad,_=c.assemble(p,child,d);rejects('Double:Factor',lambda:c.verify(p,c.roots(p,bad),bad,d))
    bad=copy.deepcopy(proof);bad['double']['input']['digits'][0]=1;rejects('Double:Input:LimbPacking:ClaimMismatch',lambda:c.verify(p,c.roots(p,bad),bad,d))
    for left,right,reason in (((1,),(2,),'LeftSource'),((0,),(1,),'RightSource')):
        w=c.lp.limbs.witness(v['double'].schema,left,right);digits,zs,cs=c.lp.witness(v['double'],w);layout=v['layout'];children=[(proof['double']['input'],out['double']['input']['state']),c.lp.cr.prove(layout['output'],zs,d),c.lp.cr.prove(layout['carry'],cs,d)];product,_=c.lp.assemble(v['double'],children,d);bound=c.lp.roots(v['double'],product['input']['digits'],zs,cs);product['core'],st=c.lp.core_prove(v['double'],bound,[part[1] for part in children],digits,zs,cs,d);bad,_=c.assemble(p,(product,st),d);rejects('Double:'+reason+':SourceClaimMismatch',lambda:c.verify(p,c.roots(p,bad),bad,d))
    for side in ('left','right'):
        bad=copy.deepcopy(proof);values=bad['double']['core'][side]['final'];values[0]=r.sc.mul(values[0],r.sc.scalar(2,d));values[1]=r.sc.mul(values[1],r.sc.scalar((r.sc.P+1)//2,d));rejects('Double:'+side.title()+'Source:PowerClaimMismatch',lambda:c.verify(p,roots,bad,d))
    for other in (replace(p,schema=replace(p.schema,width=4)),replace(p,schema=replace(p.schema,fraction=8,output_fraction=4))):assert c.verify(other,roots,proof,d)['state']!=state
    for key in ('receipt','certificate','factor'):rejects('ProofShape',lambda:c.verify(p,roots,dict(proof,**{key:{}}),d))
    rejects('Root',lambda:c.verify(p,roots[:-1],proof,d));bad=copy.deepcopy(proof);bad['double']['input']['digits'][0]=False;rejects('Double:NoncanonicalField',lambda:c.verify(p,roots,bad,d))
    print('external roots, exact zero-hidden coefficient two, both actual operands and both public powers retain consumers; equivalent metadata changes state',flush=True)


def boundaries():
    p=replace(spec(7040),schema=c.bounds.Spec(1<<20,16384,30,0,14,'static',1,'exact',0));d=4;v=c.derive(p,d);D=1<<64;pair=c.prepare(p,D,d);proof,state=c.assemble(p,pair,d);out=c.verify(p,oracle(p,D)[1],proof,d);account(p,out,d);layout=v['layout'];children=[(proof['double'][name],out['double'][name]['state']) for name in ('input','output','carry')]
    values=list(((1<<65)-r.sc.P).to_bytes(layout['s'],'little'));assert all(x<=cap for x,cap in zip(values,layout['output'].caps));bad,_=c.assemble(p,c.lp.assemble(v['double'],[children[0],c.lp.cr.prove(layout['output'],values,d),children[2]],d),d);rejects('Double:Product:FinalEvaluationMismatch',lambda:c.verify(p,c.roots(p,bad),bad,d))
    source=layout['input'];whole=layout['layout']['whole'];caps=list(whole.caps);caps[0]+=1;words,bs,cs=r.witness(replace(whole,caps=tuple(caps)),[D+1,2]);word_pair=r.assemble(whole,words,bs,cs,d);digits=words;input_pair=c.lp.ls.assemble(source,digits,word_pair,None,d);bad,_=c.assemble(p,c.lp.assemble(v['double'],[input_pair,*children[1:]],d),d);rejects('Double:Input:WholeWord:CapRelation:RoundSumMismatch',lambda:c.verify(p,c.roots(p,bad),bad,d))
    for name,index in (('output',layout['k']),('carry',0),('carry',layout['k'])):
        child=layout[name];values=proof['double'][name]['words'].copy();values[index]=1;caps=list(child.caps);caps[index]=1;part=c.lp.cr.assemble(child,*c.lp.cr.witness(replace(child,caps=tuple(caps)),values),d);changed=children.copy();changed[1 if name=='output' else 2]=part;bad,_=c.assemble(p,c.lp.assemble(v['double'],changed,d),d);rejects('Double:'+name.title()+':CapRelation:RoundSumMismatch',lambda:c.verify(p,c.roots(p,bad),bad,d))
    for index,identity,value in ((0,p.source,D),(1,p.output,2*D)):
        words=list(value.to_bytes(16,'little'));words[-1]=1;roots=oracle(p,D)[1];roots[index]=r.root(identity,words);rejects(('Denominator' if index==0 else 'Doubled')+':CommitmentMismatch',lambda:c.verify(p,roots,proof,d))
    print('genuine output-ranged 2D-p, whole source overflow, initial/final carries, output padding and all sixteen external planes reject',flush=True)


def composition():
    import attention_denominator as upstream
    p=replace(spec(7050),schema=c.bounds.Spec(2049,3,30,0,8,'static',1,'block1024',10));d=4;sp=upstream.Spec(p.schema,7150,9701,p.source,1);z=385;child,st=upstream.prove(sp,z,d);sr=upstream.expected_roots(sp,z);assert upstream.verify(sp,sr,child,d)['state']==st;D=z*(1<<20);proof,state=c.prove(p,D,d);roots=oracle(p,D)[1];assert roots[0]==sr[1] and c.verify(p,roots,proof,d)['state']==state
    other,st=upstream.prove(sp,z+1,d);rr=upstream.expected_roots(sp,z+1);assert upstream.verify(sp,rr,other,d)['state']==st;rejects('Denominator:CommitmentMismatch',lambda:c.verify(p,[rr[1],roots[1]],proof,d))
    zero,st=c.prove(p,0,d);zr=oracle(p,0)[1];assert c.verify(p,zr,zero,d)['state']==st;rejects('Denominator:CommitmentMismatch',lambda:c.verify(p,[sr[1],zr[1]],zero,d));print('complete positive denominator composes; valid changed source and standalone zero cannot replace it',flush=True)


if __name__=='__main__':
    modes={'--corpus':corpus,'--controls':controls,'--boundaries':boundaries,'--composition':composition,'--honest':honest,'--maximum':lambda:honest(True)}
    if sys.argv[1:]:
        assert all(mode in modes for mode in sys.argv[1:])
        for mode in sys.argv[1:]:modes[mode]()
    else:
        for test in modes.values():test()
