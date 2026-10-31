# /// script
# requires-python = ">=3.12"
# dependencies = ["numpy==2.3.4", "blake3==1.0.11", "python-flint==0.9.0"]
# ///
"""Draft RFC-0004 A3/A6: full attention quotient products and controls."""
import copy
from dataclasses import replace
import hashlib
import json
import random
import sys
import numpy as np
import attention_quotient_product as c

r=c.r


def rejects(reason,call):
    try:call()
    except ValueError as error:assert str(error)==reason,(reason,str(error))
    else:raise AssertionError('accepted '+reason)


def spec(width=3,identity=7600,repetitions=1):
    return c.Spec(c.bounds.Spec(65,width,3,8,8,'static',1,'exact',0),identity,10001,10007,10011,repetitions)


def oracle(p,qs,D):
    n=1<<(p.schema.width-1).bit_length();products=(np.array(qs,dtype=object)*D).tolist()
    def planes(xs,size,width):
        xs=xs+[0]*(size-len(xs));rows=np.array([[x&((1<<64)-1),x>>64] for x in xs],dtype='<u8');return np.frombuffer(rows.tobytes(),dtype=np.uint8).reshape(size,16)[:,:width].T.reshape(-1).tolist()
    return products,[r.root(p.quotient,planes(qs,n,2)),r.root(p.denominator,planes([D],1,16)),r.root(p.output,planes(products,n,16))]


def corpus():
    rng=random.Random(2746);digest=hashlib.sha256();cells=high=0;groups=set();widths=set()
    def check(p,qs,D):
        nonlocal cells,high
        v=c.derive(p,4);w=c.witness(p,qs,D);products,roots=oracle(p,qs,D);n=v['n'];assert c.expected_roots(p,qs,D)==roots and w['quotient']==qs and w['denominator']==[D]
        actual=sum((w['product_'+str(j)] for j in range(v['groups'])),[]);assert actual[:p.schema.width]==products and not any(actual[p.schema.width:])
        padded=qs+[0]*(n-len(qs));low=np.array([x&255 for x in padded],dtype=np.int64);upper=np.array([x>>8 for x in padded],dtype=np.int64);carry=np.zeros(n,dtype=np.int64);cs=[]
        for k in range(16):
            total=low*(D>>(8*k)&255)+upper*(D>>(8*(k-1))&255 if k else 0)+carry;byte=total%256;carry=total//256
            assert byte.tolist()==[x>>(8*k)&255 for x in products+[0]*(n-len(products))];cs.extend(carry.tolist())
        assert cs==sum((w['carry_'+str(j)] for j in range(4)),[]) and cs[-n:]==[0]*n and max(cs)<=510
        assert all(0<=x<=cap for name,child in v['ranges'].items() for x,cap in zip(w[name],child.caps)) and all(r.derive(child,4)[2]*r.derive(child,4)[3]<=131072 for child in v['ranges'].values())
        proof={name:{'words':r.witness(child,w[name])[0]} for name,child in v['ranges'].items()};assert c.roots(p,proof)==roots and c.carry_values(v,proof)==cs
        digest.update(v['raw']+b''.join(roots)+np.array(cs,dtype='<u2').tobytes());cells+=len(qs);high+=sum(x>255 for x in cs);groups.add(v['groups']);widths.add((v['bp'],v['bd']))
    for case in range(10000):
        width=1+case%65;length=rng.choice((1,65,1024,1025,1<<20));fv=case%31;fo=(case//31)%31;E=case%15;mode='block1024' if case%2 else 'exact';policy='dynamic' if case%4<2 else 'static';scale=0 if policy=='dynamic' else rng.choice((1,2,259,65535))
        S=127*259 if policy=='dynamic' else scale*min(127,(65536+scale)//(2*scale));H=1024*(1<<E)*S;minimum=next(k for k in range(63) if (H+(1<<k)//2)//(1<<k)<=32767);drop=0 if mode=='exact' else minimum+case%(63-minimum)
        p=replace(spec(width,case,1+case%2),schema=c.bounds.Spec(length,width,fv,fo,E,policy,scale,mode,drop));v=c.derive(p,4);Dmax=length*(1<<E)*(1<<max(fv-fo-drop,0));assert v['constants']['denominator_max']==Dmax and v['constants']['scaled_quotient_max']==32768*Dmax
        qs=[rng.randrange(32769) for _ in range(width)];D=(0,Dmax,Dmax-1,rng.randrange(Dmax+1))[case%4]
        for j,x in enumerate((0,1,32767,32768)[:width]):qs[j]=x
        check(p,qs,D)
    for width in (8193,16384):
        for fv,fo,E,wanted in ((0,0,14,1),(30,0,14,2)):
            p=replace(spec(width,(1<<48)-1,2),schema=c.bounds.Spec(1<<20,width,fv,fo,E,'static',1,'exact',0));v=c.derive(p,8);assert v['groups']==wanted;check(p,[32767+i%2 for i in range(width)],v['constants']['denominator_max']-1)
            spans=sorted((r.derive(child,8)[4],64) for child in v['ranges'].values());assert all(v['base']+22<lo and lo+size<=v['base']+(1<<14) for lo,size in spans) and all(lo+size<=nxt for (lo,size),(nxt,_) in zip(spans,spans[1:]))
    p=spec();v=c.derive(p,4)
    for bad in (replace(p,identity=1<<48),replace(p,repetitions=True),replace(p,denominator=p.quotient),replace(p,output=v['base']),replace(p,schema=replace(p.schema,width=16385)),replace(p,schema=replace(p.schema,drop=1))):rejects('Spec',lambda:c.derive(bad,4))
    rejects('Spec',lambda:c.derive(p,True))
    for qs,D in (([False]*3,0),([-1]*3,0),([32769]*3,0),([0],0),([0]*3,False),([0]*3,-1),([0]*3,v['constants']['denominator_max']+1)):rejects('Input',lambda:c.witness(p,qs,D))
    assert groups=={1,2} and high>0
    print(json.dumps(dict(seed=2746,cases=10000,capacity_cases=4,cells=cells,high_carry_cells=high,widths=sorted(widths),sha256=digest.hexdigest()),sort_keys=True),flush=True)


def account(p,out,d):
    v=c.derive(p,d);a,bp,bd,g=v['a'],v['bp'],v['bd'],v['groups'];dims=[a+2]+[a-(g-1)+bp+1]*g+[bd+1]+[a+4]*4;f=lambda m:3*m*(m-1)//2+2*m
    assert out['account']==dict(identities=[((1<<m)+255,p.repetitions) for m in dims],lookup_reduction_numerator=sum(p.repetitions*(f(m)+f(8)+3*m) for m in dims),range_reduction_numerator=57*a+7*bp+7*bd+119 if g==1 else 66*a+14*bp+7*bd+101,denominator=r.sc.P**d)
    assert out['draws']=={r.zc.WEIGHT:a+4,r.zc.tr.CHALLENGE:a+4} and [claim[0] for claim in out['claims']]==[v['base']+j for j in range(16,23)] and [x['numerator'] for x in out['sc']]==[a+4,0,2*(a+4)]
    for label in (r.zc.WEIGHT,r.zc.tr.CHALLENGE):assert sum(child['draws'].get(label,0) for child in [out]+out['children'])==(25*a+3*bp+3*bd+51 if g==1 else 29*a+6*bp+3*bd+43)


def honest(mode='matrix'):
    digest=hashlib.sha256();done=0;cases=((1,1,0,30,0,'block1024',62),(3,65,3,8,8,'exact',0),(16,1025,30,0,0,'block1024',2),(65,1<<20,30,0,14,'exact',0))
    if mode!='matrix':cases=((16384,1<<20,30 if mode=='maximum' else 0,0,14,'exact',0),)
    for d,reps in (((4,1),) if mode!='matrix' else ((4,1),(4,2),(8,1),(8,2))):
        for width,length,fv,fo,E,acc,drop in cases:
            p=replace(spec(width,7610+done,reps),schema=c.bounds.Spec(length,width,fv,fo,E,'static',1,acc,drop));v=c.derive(p,d);D=0 if width==1 else v['constants']['denominator_max']-(mode=='full-carry');qs=[(0,1,32767,32768)[i%4] for i in range(width)]
            if mode=='full-carry':assert max(c.carry_values(v,{name:{'words':r.witness(child,c.witness(p,qs,D)[name])[0]} for name,child in v['ranges'].items()}))>255
            print('honest start',done+1,d,reps,width,v['groups'],flush=True);proof,state=c.prove(p,qs,D,d);out=c.verify(p,oracle(p,qs,D)[1],proof,d);assert out['state']==state;account(p,out,d);digest.update(state);done+=1;print('honest passed',done,d,reps,width,v['groups'],flush=True)
    if mode=='matrix':assert done==16 and digest.hexdigest()=='7a800845a194a1d8a35f11ddef32eadebeef199c92b8a675edd1b42159e468e2'
    print(json.dumps(dict(mode=mode,proofs=done,sha256=digest.hexdigest()),sort_keys=True),flush=True)


def controls():
    p=spec();d=4;v=c.derive(p,d);qs=[32767,257,1];D=16383;w=c.witness(p,qs,D);pairs=c.prepare(p,qs,D,d);proof,state=c.assemble(p,pairs,d);roots=oracle(p,qs,D)[1];out=c.verify(p,roots,proof,d);assert out['state']==state;account(p,out,d)
    for index,name in enumerate(('Quotient','Denominator','Product')):
        bad=roots.copy();bad[index]=bytes(32);rejects(name+':CommitmentMismatch',lambda:c.verify(p,bad,proof,d))
    for name in v['ranges']:
        bad=copy.deepcopy(proof);bad[name]['words'][0]^=1;rejects(name.title()+':CommitmentMismatch',lambda:c.verify(p,roots,bad,d));bad=copy.deepcopy(proof);bad['roots'][name]=bytes(32);rejects(name.title()+':CommitmentMismatch',lambda:c.verify(p,roots,bad,d))
    for name,delta in (('quotient',1),('product_0',1),('denominator',1),('carry_0',1),('carry_0',256)):
        values=w[name].copy();values[0]+=delta;assert values[0]<=v['ranges'][name].caps[0];bad,_=c.assemble(p,dict(pairs,**{name:r.prove(v['ranges'][name],values,d)}),d);rejects('Product:RoundSumMismatch',lambda:c.verify(p,c.roots(p,bad),bad,d))
    zp,zs=c.prove(p,[0]*3,0,d);zr=c.roots(p,zp);assert c.verify(p,zr,zp,d)['state']==zs
    for changes in (((0,1),),((1,1),),((2,1),),((3,1),),((4,1),(5,1)),((5,256),(6,-1)),((6,1),(4,256))):
        bad=copy.deepcopy(zp)
        for column,delta in changes:bad['zero'][0]['final'][column][0]=r.sc.add(bad['zero'][0]['final'][column][0],r.sc.scalar(delta,d))
        rejects('Product:ClaimMismatch',lambda:c.verify(p,zr,bad,d))
    other=replace(p,schema=replace(p.schema,fraction=4,output_fraction=9));rejects('Product:ClaimMismatch',lambda:c.verify(other,roots,proof,d))
    for key in ('receipt','certificate','broadcast','group'):rejects('ProofShape',lambda:c.verify(p,roots,dict(proof,**{key:{}}),d))
    bad=copy.deepcopy(proof);bad['zero'][0]['rounds'][0][0]=(False,0,0,0);rejects('NoncanonicalField',lambda:c.verify(p,roots,bad,d));rejects('Root',lambda:c.verify(p,roots[:-1],proof,d));print('all roots, complete children, fresh false values, high carry byte and all seven compensated original views reject',flush=True)


def boundaries():
    p=spec(identity=7640);d=4;v=c.derive(p,d);w=c.witness(p,[0]*3,0);pairs=c.prepare(p,[0]*3,0,d)
    for name,child in v['ranges'].items():
        indices=[0]+([p.schema.width] if name!='denominator' else [])+([len(child.caps)-1] if name.startswith('carry_') else [])
        for index in indices:
            caps=list(child.caps);values=w[name].copy()
            if index==len(caps):caps.append(0);values.append(0)
            caps[index]+=1;values[index]=caps[index];pair=r.assemble(child,*r.witness(replace(child,caps=tuple(caps)),values),d);bad,_=c.assemble(p,dict(pairs,**{name:pair}),d);rejects(name.title()+':CapRelation:RoundSumMismatch',lambda:c.verify(p,c.roots(p,bad),bad,d))
    p=replace(spec(1,7641),schema=c.bounds.Spec(1<<20,1,30,0,14,'static',1,'exact',0));v=c.derive(p,d);D=1<<64;pairs=c.prepare(p,[32768],D,d);values=[(1<<79)-r.sc.P];bad,_=c.assemble(p,dict(pairs,product_0=r.prove(v['ranges']['product_0'],values,d)),d);rejects('Product:RoundSumMismatch',lambda:c.verify(p,c.roots(p,bad),bad,d))
    p=spec(identity=7642);v=c.derive(p,d);pairs=c.prepare(p,[0]*3,17,d);proof,state=c.assemble(p,pairs,d);roots=oracle(p,[0]*3,17)[1];assert c.verify(p,roots,proof,d)['state']==state
    for index,identity,words in ((0,p.quotient,proof['quotient']['words'].copy()),(1,p.denominator,c.denominator_words(v,proof)),(2,p.output,c.full(v,proof))):
        words[-1]=1;bad=roots.copy();bad[index]=r.root(identity,words);rejects(('Quotient','Denominator','Product')[index]+':CommitmentMismatch',lambda:c.verify(p,bad,proof,d))
    _,i,tables=c.parts(p,proof,d)[0];changed=copy.deepcopy(tables);changed[4][0]=r.sc.scalar(1,d);changed[5][0]=r.sc.scalar(1,d);t=c.transcript(v,roots+[proof['roots'][name] for name in v['ranges']],[pairs[name][1] for name in v['ranges']],d);bad=copy.deepcopy(proof);bad['zero']=[r.zero_prove(t,i,changed)];rejects('Product:ClaimMismatch',lambda:c.verify(p,roots,bad,d))
    print('whole caps, dense padding, carry endpoints, genuine ranged Qp-p, compensated initial carry and full external planes reject',flush=True)


def composition():
    import attention_denominator as denominator
    for mode in ('exact','block1024'):
        p=replace(spec(identity=7650+(mode=='exact')),schema=c.bounds.Spec(2049,3,3 if mode=='exact' else 30,8 if mode=='exact' else 0,0 if mode=='exact' else 8,'static',1,mode,0 if mode=='exact' else 10));d=4;dp=denominator.Spec(p.schema,7751,10107,p.denominator,1);qs=[0,32767,32768];z=385
        down,st=denominator.prove(dp,z,d);dr=denominator.expected_roots(dp,z);assert denominator.verify(dp,dr,down,d)['state']==st;D=z*c.derive(p,d)['constants']['right_factor'];proof,state=c.prove(p,qs,D,d);roots=oracle(p,qs,D)[1];assert roots[1]==dr[1] and c.verify(p,roots,proof,d)['state']==state
        other,st=denominator.prove(dp,z+1,d);rr=denominator.expected_roots(dp,z+1);assert denominator.verify(dp,rr,other,d)['state']==st;rejects('Denominator:CommitmentMismatch',lambda:c.verify(p,[roots[0],rr[1],roots[2]],proof,d));print('complete positive denominator composes; valid replacement rejects',mode,flush=True)


if __name__=='__main__':
    modes={'--corpus':corpus,'--controls':controls,'--boundaries':boundaries,'--composition':composition,'--honest':honest,'--maximum':lambda:honest('maximum'),'--full-carry':lambda:honest('full-carry')}
    if sys.argv[1:]:
        assert all(mode in modes for mode in sys.argv[1:])
        for mode in sys.argv[1:]:modes[mode]()
    else:
        for test in list(modes.values())[:-2]:test()
