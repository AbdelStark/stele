# /// script
# requires-python = ">=3.12"
# dependencies = ["numpy==2.3.4", "blake3==1.0.11", "python-flint==0.9.0"]
# ///
"""Draft RFC-0004 A3/A6/A7: canonical rotary sources and signed rounding."""
import copy
from dataclasses import replace
from fractions import Fraction as Q
import hashlib
import json
import random
import sys
import numpy as np
import rotary_consumer as c
from check_rope import oracle as coefficient_oracle

r=c.r


def rejects(reason,call):
    try:call()
    except ValueError as error:assert str(error)==reason,(reason,str(error))
    else:raise AssertionError('accepted '+reason)


def spec(heads=1,width=3,rotary=2,layout='adjacent',mode='base',position=1,identity=3300,repetitions=1):
    schema=c.rotary.Spec(heads,width,rotary,layout,12,64)
    rotation=c.rope.Parameters(rotary,64,Q(10000),mode,layout,Q(1) if mode=='base' else Q(8),Q(1) if mode=='llama3' else Q(0),Q(4) if mode=='llama3' else Q(0),8192 if mode=='llama3' else 0) if rotary else None
    return c.Spec(schema,rotation,position,identity,1009,1013,1019,1021,1031,1033,repetitions)


def oracle(p,xs,coeff):
    s=p.schema;X=np.array(xs,dtype=np.int64).reshape(s.heads,s.width);N=X*16384
    for h in range(s.heads):
        for j,(co,si) in enumerate(coeff):
            left,right=(2*j,2*j+1) if s.layout=='adjacent' else (j,j+s.rotary//2)
            N[h,[left,right]]=np.array([[co,-si],[si,co]],dtype=np.int64)@X[h,[left,right]]
    N=N.reshape(-1);M=np.abs(N);S=(N<0).astype(np.int64);qs=(M+8192)//16384;rs=M+8192-qs*16384;Z=np.where(S,-qs,qs)
    for num,z in zip(N,Z):
        f=Q(abs(int(num)),16384);q=(2*f.numerator+f.denominator)//(2*f.denominator);assert int(z)==(-q if num<0 else q)
    return dict(numerator=N.tolist(),magnitude=M.tolist(),sign=S.tolist(),predecessor=(M-S).tolist(),quotient=qs.tolist(),remainder=rs.tolist(),output=Z.tolist())


def corpus():
    rng=random.Random(2729);digest=hashlib.sha256();cache={};accepted=overflow=0;families=set();layouts=set();modes=set();negative_zero=False
    for case in range(10000):
        heads=1+case%4;width=(1,2,3,5,8,9,16)[case%7];rotary=0 if case%5==0 else 2*(width//2) if case%3 else 2*((width//2)//2)
        p=spec(heads,width,rotary,('adjacent','split')[case%2],('base','linear','llama3')[case%3],(0,1,7,31)[case%4],case,1+case%2);p=replace(p,schema=replace(p.schema,fraction=case%31));v=c.derive(p,4);count=heads*width
        key=(c.rope.encode(p.rotation) if p.rotation else b'',p.position)
        if key not in cache:cache[key]=tuple(tuple(z[0] for z in coefficient_oracle(p.rotation,p.position,j)) for j in range(rotary//2))
        coeff=cache[key];assert c.coefficients(p)==coeff
        xs=[rng.randrange(-32768,32768) for _ in range(count)] if case%11 else [1]*count;w=oracle(p,xs,coeff)
        if case%4:
            while any(not -32768<=z<=32767 for z in w['output']):xs=[(1 if x>=0 else -1)*(abs(x)//2) for x in xs];w=oracle(p,xs,coeff)
        digest.update(v['raw']+json.dumps([xs,w],sort_keys=True,separators=(',',':')).encode());families.add(p.rotation.mode if p.rotation else 'none');layouts.add(p.schema.layout);modes.add('none' if not rotary else 'full' if rotary==width else 'partial')
        if any(not -32768<=z<=32767 for z in w['output']):rejects('OutputRange',lambda:c.witness(p,xs));overflow+=1;continue
        accepted+=1;assert c.witness(p,xs)==w;roots=c.expected_roots(p,xs);rows=([x%65536 for x in xs],[z%65536 for z in w['output']],w['magnitude'],w['sign'],w['quotient'],w['remainder']);manual=[]
        for name,values,width in zip(c.ROLES,rows,(2,2,4,1,2,2)):
            words=[x>>(8*k)&255 for k in range(width) for x in values+[0]*(v['n']-count)];manual.append(r.root(getattr(p,name),words))
        assert roots==manual;digest.update(b''.join(roots));negative_zero|=any(num<0 and z==0 for num,z in zip(w['numerator'],w['output']))
    assert accepted+overflow==10000 and accepted>0 and overflow>0 and families=={'none','base','linear','llama3'} and layouts=={'adjacent','split'} and modes=={'none','partial','full'} and negative_zero
    p=spec(128,128,128,'split','llama3',31,(1<<48)-1,2);v=c.derive(p,8);assert v['count']==16384 and v['base']+(1<<14)==(1<<63)+(1<<62)
    spans=sorted([(c.signed.derive(v[name],8)['base'],512) for name in ('input','output')]+[(r.derive(child,8)[4],64) for child in v['ranges'].values()]);assert all(v['base']+31<lo and lo+size<=v['base']+(1<<14) for lo,size in spans) and all(lo+size<=nxt for (lo,size),(nxt,_) in zip(spans,spans[1:]))
    for bad in (replace(p,identity=1<<48),replace(p,repetitions=True),replace(p,source=p.output),replace(p,remainder=v['base']),replace(p,rotation=None),replace(p,schema=replace(p.schema,fraction=True)),replace(spec(),rotation=c.rope.Parameters(4,64,Q(10000)))):rejects('Spec',lambda:c.derive(bad,4))
    rejects('Position',lambda:c.derive(replace(p,position=True),4));rejects('Position',lambda:c.derive(replace(p,position=64),4));rejects('Spec',lambda:c.derive(p,True));rejects('Spec',lambda:c.derive(replace(p,schema=replace(p.schema,width=129)),4))
    zero=spec(1,3,0);rejects('Spec',lambda:c.derive(replace(zero,rotation=spec().rotation),4))
    for xs in ([False]*3,[-32769]*3,[32768]*3,[0],(0,0,0)):rejects('Input',lambda:c.witness(spec(),xs))
    envelope=replace(spec(1,4,4),rotation=c.rope.Parameters(4,64,Q(16213,10000)));assert c.coefficients(envelope)[1]==(11586,11585) and sum(map(abs,c.coefficients(envelope)[1]))==23171
    print(json.dumps(dict(seed=2729,cases=10000,accepted=accepted,overflow=overflow,canonical_rows=len(cache),sha256=digest.hexdigest()),sort_keys=True),flush=True)


def account(p,out,d):
    a=c.derive(p,d)['a'];dims=[a+2]*6+[a+3,a+1,a+3,a+2];f=lambda m:3*m*(m-1)//2+2*m
    assert out['account']==dict(identities=[((1<<m)+255,p.repetitions) for m in dims],lookup_reduction_numerator=sum(p.repetitions*(f(m)+f(8)+3*m) for m in dims),range_reduction_numerator=132*a+105,denominator=r.sc.P**d)
    assert len(out['claims'])==16 and len(out['children'])==6 and sum(x['numerator'] for x in out['sc'])==10*a and out['draws']==({r.zc.WEIGHT:4*a,r.zc.tr.CHALLENGE:4*a} if a else {})
    draws=[out]+out['children']+[child for source in out['children'][:2] for child in source['ranges']]
    assert all(sum(x['draws'].get(label,0) for x in draws)==56*a+43 for label in (r.zc.WEIGHT,r.zc.tr.CHALLENGE))


def honest(maximum=False):
    digest=hashlib.sha256();count=0;cases=((1,1,0,'adjacent','base',0),(1,3,2,'adjacent','base',1),(2,8,8,'split','linear',7),(5,13,12,'adjacent','llama3',31))
    for d,reps in (((4,1),) if maximum else ((4,1),(4,2),(8,1),(8,2))):
        for args in (((128,128,128,'split','llama3',31),) if maximum else cases):
            p=spec(*args,identity=3310+count,repetitions=reps);size=p.schema.heads*p.schema.width;xs=([-16384,0,16383,-1,255,-255,12,-12]*((size+7)//8))[:size]
            if size==1:xs=[-32768]
            print('honest start',count+1,d,reps,size,flush=True);proof,state=c.prove(p,xs,d);out=c.verify(p,c.expected_roots(p,xs),proof,d);assert out['state']==state;account(p,out,d);digest.update(state);count+=1;print('honest passed',count,d,reps,size,flush=True)
    print(json.dumps(dict(maximum=maximum,proofs=count,sha256=digest.hexdigest()),sort_keys=True),flush=True)


def controls():
    p=spec();d=4;xs=[0,8192,0];v=c.derive(p,d);w=c.witness(p,xs);pairs=c.prepare(p,xs,d);proof,state=c.assemble(p,pairs,d);roots=c.expected_roots(p,xs);out=c.verify(p,roots,proof,d);assert out['state']==state;account(p,out,d)
    for index,name in enumerate(('Input:Raw','Output:Raw','Magnitude','Sign','Output:Magnitude','Remainder')):
        bad=roots.copy();bad[index]=bytes([bad[index][0]^1])+bad[index][1:];rejects(name+':CommitmentMismatch',lambda:c.verify(p,bad,proof,d))
    for name,reason in (('input_magnitude','Input:Magnitude'),('predecessor','Predecessor')):
        bad=copy.deepcopy(proof);value=bad['roots'][name];bad['roots'][name]=bytes([value[0]^1])+value[1:];rejects(reason+':CommitmentMismatch',lambda:c.verify(p,roots,bad,d))
    for name,reason in (('magnitude','Numerator'),('predecessor','CanonicalZero'),('remainder','Rounding')):
        values=w[name].copy();values[0]+=1;bad,_=c.assemble(p,dict(pairs,**{name:r.prove(v['ranges'][name],values,d)}),d);rejects(reason+':RoundSumMismatch',lambda:c.verify(p,c.roots(p,bad),bad,d))
    alt=c.signed.prove(v['input'],[0,-8192,0],d);ar=[r.root(p.source,alt[0]['ranges'][0]['words']),proof['roots']['input_magnitude']];assert c.signed.verify(v['input'],ar,alt[0],d)['state']==alt[1];bad,_=c.assemble(p,dict(pairs,input=alt),d);rejects('Numerator:RoundSumMismatch',lambda:c.verify(p,c.roots(p,bad),bad,d))
    alt=c.signed.prove(v['output'],[-z for z in w['output']],d);ar=[r.root(p.output,alt[0]['ranges'][0]['words']),roots[4]];assert c.signed.verify(v['output'],ar,alt[0],d)['state']==alt[1];bad,_=c.assemble(p,dict(pairs,output=alt),d);rejects('SignedOutput:RoundSumMismatch',lambda:c.verify(p,c.roots(p,bad),bad,d))
    qs=w['quotient'].copy();rs=w['remainder'].copy();zs=w['output'].copy();assert rs[0]==0 and zs[0]<0;qs[0]-=1;rs[0]=16384;zs[0]+=1;assert all(m+8192==q*16384+rem for m,q,rem in zip(w['magnitude'],qs,rs));child=v['ranges']['remainder'];caps=list(child.caps);caps[0]=16384;rp=r.assemble(child,*r.witness(replace(child,caps=tuple(caps)),rs),d);bad,_=c.assemble(p,dict(pairs,remainder=rp,output=c.signed.prove(v['output'],zs,d)),d);rejects('Remainder:CapRelation:RoundSumMismatch',lambda:c.verify(p,c.roots(p,bad),bad,d))
    for key in ('receipt','certificate','coefficients','position','mask'):rejects('ProofShape',lambda:c.verify(p,roots,dict(proof,**{key:{}}),d))
    bad=copy.deepcopy(proof);bad['zero'][0]['rounds'][0][0]=(False,0,0,0);rejects('NoncanonicalField',lambda:c.verify(p,roots,bad,d))
    print('six external/two auxiliary roots, actual source/sign substitutions, exact ranges and coherent r=16384 reject',flush=True)


def originals():
    p=spec(identity=3340);d=4;v=c.derive(p,d);pairs=c.prepare(p,[0]*3,d);proof,state=c.assemble(p,pairs,d);roots=c.expected_roots(p,[0]*3);assert c.verify(p,roots,proof,d)['state']==state;one=r.sc.scalar(1,d)
    cases=[(0,[(j,one)]) for j in (1,3,5)]+[(0,[(0,one),(4,proof['zero'][0]['final'][1][0])]),(0,[(2,one),(4,proof['zero'][0]['final'][3][0])]),(1,[(0,one),(2,one)]),(1,[(0,one),(1,one)]),(2,[(0,one),(3,one)]),(2,[(1,one),(3,one)]),(2,[(2,one),(3,r.sc.scalar(-16384,d))])]+[(3,[(j,one)]) for j in range(3)]
    for index,changes in cases:
        bad=copy.deepcopy(proof)
        for j,delta in changes:bad['zero'][index]['final'][j][0]=r.sc.add(bad['zero'][index]['final'][j][0],delta)
        rejects(('Numerator','CanonicalZero','Rounding','SignedOutput')[index]+':ClaimMismatch',lambda:c.verify(p,roots,bad,d))
    signs=[1,0,0];bad,_=c.assemble(p,dict(pairs,sign=r.prove(v['ranges']['sign'],signs,d)),d);rejects('CanonicalZero:RoundSumMismatch',lambda:c.verify(p,c.roots(p,bad),bad,d))
    t=c.transcript(v,roots+[proof['roots'][name] for name in ('input_magnitude','predecessor')],[pairs[name][1] for name in c.CHILDREN],d);parts=[]
    for index,(_,i,tables) in enumerate(c.parts(p,proof,d)):
        if index==0:tables[1][-1]=one
        parts.append(r.zero_prove(t,i,tables))
    rejects('Numerator:ClaimMismatch',lambda:c.verify(p,roots,dict(proof,zero=parts),d))
    for changed in (replace(p,position=2),replace(p,schema=replace(p.schema,fraction=13)),replace(p,schema=replace(p.schema,layout='split'),rotation=replace(p.rotation,layout='split'))):rejects('Numerator:ClaimMismatch',lambda:c.verify(changed,roots,proof,d))
    print('all sixteen originals, public padded coefficients, negative zero and expected position/layout/units reject',flush=True)


def boundaries():
    p=spec(identity=3350);d=4;v=c.derive(p,d);xs=[0]*3;pairs=c.prepare(p,xs,d);w=c.witness(p,xs)
    for name,value in (('magnitude',759267329),('magnitude',r.sc.P),('predecessor',759267329)):
        child=v['ranges'][name];caps=list(child.caps);caps[0]=value;values=w[name].copy();values[0]=value;changed=r.assemble(child,*r.witness(replace(child,caps=tuple(caps)),values),d);bad,_=c.assemble(p,dict(pairs,**{name:changed}),d);rejects(name.title()+':CapRelation:RoundSumMismatch',lambda:c.verify(p,c.roots(p,bad),bad,d))
    co,si=c.coefficients(p)[0];y=-((32768*16384-co*32767+si//2)//si);xs=[32767,y,0];w=oracle(p,xs,c.coefficients(p));assert w['output'][0]==32768;zs=w['output'].copy();zs[0]=-32768;rejects('OutputRange',lambda:c.witness(p,xs))
    pairs=dict(input=c.signed.prove(v['input'],xs,d),output=c.signed.prove(v['output'],zs,d),**{name:r.prove(child,w[name],d) for name,child in v['ranges'].items()});bad,_=c.assemble(p,pairs,d);roots=c.roots(p,bad);assert c.signed.verify(v['output'],[roots[1],roots[4]],bad['output'],d)['state']==pairs['output'][1];rejects('SignedOutput:RoundSumMismatch',lambda:c.verify(p,roots,bad,d))
    p=spec(identity=3351);v=c.derive(p,d);pairs=c.prepare(p,[0]*3,d);sp,cs=c.signed.ranges(v['output'],[0]*3,d);sv=c.signed.derive(v['output'],d);child=sv['ranges'][0];sp[0]=r.assemble(child,*r.witness(replace(child,caps=child.caps+(1,)),[0,0,0,1]),d);bad,_=c.assemble(p,dict(pairs,output=c.signed.assemble(v['output'],sp,cs,d)),d);rejects('Output:Raw:CapRelation:RoundSumMismatch',lambda:c.verify(p,c.roots(p,bad),bad,d))
    p=spec(1,3,0,identity=3352);v=c.derive(p,d);pairs=c.prepare(p,[-32768,0,32767],d);proof,state=c.assemble(p,pairs,d);assert c.verify(p,c.expected_roots(p,[-32768,0,32767]),proof,d)['state']==state;bad,_=c.assemble(p,dict(pairs,output=c.signed.prove(v['output'],[-32767,0,32767],d)),d);rejects('Rounding:RoundSumMismatch',lambda:c.verify(p,c.roots(p,bad),bad,d))
    print('whole bounds and M31 aliases, positive32768, output padding and full passthrough substitution reject',flush=True)


if __name__=='__main__':
    modes={'--corpus':corpus,'--controls':controls,'--originals':originals,'--boundaries':boundaries,'--honest':honest,'--maximum':lambda:honest(True)}
    if sys.argv[1:]:
        assert all(mode in modes for mode in sys.argv[1:])
        for mode in sys.argv[1:]:modes[mode]()
    else:
        for test in modes.values():test()
