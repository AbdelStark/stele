# /// script
# requires-python = ">=3.12"
# dependencies = ["numpy==2.3.4", "blake3==1.0.11", "python-flint==0.9.0"]
# ///
"""Draft RFC-0004 A3/A6: complete biased attention numerators and controls."""
import copy
from dataclasses import replace
import hashlib
import json
import random
import sys
import numpy as np
import attention_biased_numerator as c

r=c.r


def rejects(reason,call):
    try:call()
    except ValueError as error:assert str(error)==reason,(reason,str(error))
    else:raise AssertionError('accepted '+reason)


def spec(width=3,identity=7400,repetitions=1):
    return c.Spec(c.bounds.Spec(65,width,3,8,8,'static',1,'exact',0),identity,9801,9807,9811,repetitions)


def oracle(p,us,D):
    n=1<<(p.schema.width-1).bit_length();ws=(2*np.array(us,dtype=object)+D).tolist()
    def planes(xs,size):
        xs=xs+[0]*(size-len(xs));rows=np.array([[x&((1<<64)-1),x>>64] for x in xs],dtype='<u8');return np.frombuffer(rows.tobytes(),dtype=np.uint8).reshape(size,16).T.reshape(-1).tolist()
    return ws,[r.root(p.numerator,planes(us,n)),r.root(p.denominator,planes([D],1)),r.root(p.output,planes(ws,n))]


def corpus():
    rng=random.Random(2745);digest=hashlib.sha256();cells=zeros=0;widths=set();groups=set();shifts=set()
    def check(p,us,D):
        nonlocal cells,zeros
        v=c.derive(p,4);w=c.witness(p,us,D);ws,roots=oracle(p,us,D);n=v['n'];assert c.expected_roots(p,us,D)==roots and w['denominator']==[D]
        for role,values in (('numerator',us),('biased',ws)):
            actual=sum((w[role+'_'+str(j)] for j in range(v['groups'][role])),[]);assert actual[:p.schema.width]==values and not any(actual[p.schema.width:])
        padded=us+[0]*(n-len(us));carry=np.array([0]*n,dtype=np.int64);cs=[]
        for k in range(16):
            source=np.array([x>>(8*k)&255 for x in padded],dtype=np.int64);divisor=np.array([D>>(8*k)&255 if i<len(us) else 0 for i in range(n)],dtype=np.int64);total=2*source+divisor+carry;byte=total%256;carry=total//256
            assert byte.tolist()==[x>>(8*k)&255 for x in ws+[0]*(n-len(ws))];cs.extend(carry.tolist())
        assert cs==sum((w['carry_'+str(j)] for j in range(4)),[]) and cs[-n:]==[0]*n
        assert all(0<=x<=cap for name,child in v['ranges'].items() for x,cap in zip(w[name],child.caps)) and all(r.derive(child,4)[2]*r.derive(child,4)[3]<=131072 for child in v['ranges'].values())
        proof={name:{'words':r.witness(child,w[name])[0]} for name,child in v['ranges'].items()};assert c.roots(p,proof)==roots
        digest.update(v['raw']+b''.join(roots)+bytes(cs));cells+=len(us);zeros+=not v['constants']['numerator_max'];widths.add((v['bu'],v['bw'],v['bd']));groups.add(tuple(v['groups'].values()));shifts.add(p.schema.drop)
    for case in range(10000):
        width=1+case%65;length=rng.choice((1,65,1024,1025,1<<20));fv=case%31;fo=(case//31)%31;E=case%15;mode='block1024' if case%2 else 'exact';policy='dynamic' if case%4<2 else 'static';scale=0 if policy=='dynamic' else rng.choice((1,2,259,65535))
        if case<61:mode='block1024';policy='static';scale=1;E=0
        S=127*259 if policy=='dynamic' else scale*min(127,(65536+scale)//(2*scale));H=1024*(1<<E)*S;minimum=next(k for k in range(63) if (H+(1<<k)//2)//(1<<k)<=32767);drop=0 if mode=='exact' else case+2 if case<61 else minimum+case%(63-minimum)
        p=replace(spec(width,case,1+case%2),schema=c.bounds.Spec(length,width,fv,fo,E,policy,scale,mode,drop));v=c.derive(p,4);T=length*(1<<E)*S if mode=='exact' else ((length+1023)//1024)*((H+(1<<drop)//2)//(1<<drop));U=T*(1<<max(fo-fv+drop,0));Dmax=length*(1<<E)*(1<<max(fv-fo-drop,0));assert (U,Dmax,2*U+Dmax)==tuple(v['constants'][name] for name in ('numerator_max','denominator_max','biased_max'))
        us=[rng.randrange(U+1) for _ in range(width)];D=(0,Dmax,rng.randrange(Dmax+1))[case%3]
        for j,x in enumerate((0,U,max(0,U-1))[:width]):us[j]=x
        check(p,us,D)
    for width in (8193,16384):
        for fv,fo,E,scale,wanted in ((7,7,0,1,(1,1)),(30,0,14,1,(1,2)),(0,30,14,65535,(2,2))):
            p=replace(spec(width,(1<<48)-1,2),schema=c.bounds.Spec(1<<20,width,fv,fo,E,'static',scale,'exact',0));v=c.derive(p,8);assert tuple(v['groups'].values())==wanted;check(p,[v['constants']['numerator_max']*(i%2) for i in range(width)],v['constants']['denominator_max'])
            spans=sorted((r.derive(child,8)[4],64) for child in v['ranges'].values());assert all(v['base']+20<lo and lo+size<=v['base']+(1<<14) for lo,size in spans) and all(lo+size<=nxt for (lo,size),(nxt,_) in zip(spans,spans[1:]))
    p=spec();v=c.derive(p,4)
    for bad in (replace(p,identity=1<<48),replace(p,repetitions=True),replace(p,denominator=p.numerator),replace(p,output=v['base']),replace(p,schema=replace(p.schema,width=16385)),replace(p,schema=replace(p.schema,drop=1))):rejects('Spec',lambda:c.derive(bad,4))
    rejects('Spec',lambda:c.derive(p,True))
    for us,D in (([False]*3,0),([-1]*3,0),([v['constants']['numerator_max']+1]*3,0),([0],0),([0]*3,False),([0]*3,-1),([0]*3,v['constants']['denominator_max']+1)):rejects('Input',lambda:c.witness(p,us,D))
    assert groups=={(1,1),(1,2),(2,2)} and zeros>1000 and shifts=={0}|set(range(2,63))
    print(json.dumps(dict(seed=2745,cases=10000,capacity_cases=6,cells=cells,zero_bound_cases=zeros,widths=sorted(widths),sha256=digest.hexdigest()),sort_keys=True),flush=True)


def account(p,out,d):
    v=c.derive(p,d);a,bu,bw,bd=v['a'],v['bu'],v['bw'],v['bd'];gu,gw=v['groups'].values();dims=[a-(gu-1)+bu+1]*gu+[a-(gw-1)+bw+1]*gw+[bd+1]+[a+3]*4;f=lambda m:3*m*(m-1)//2+2*m;weighted=gu*bu+gw*bw+bd;halves=gu*(gu-1)+gw*(gw-1)
    assert out['account']==dict(identities=[((1<<m)+255,p.repetitions) for m in dims],lookup_reduction_numerator=sum(p.repetitions*(f(m)+f(8)+3*m) for m in dims),range_reduction_numerator=(9*(gu+gw)+38)*a+7*weighted+80-9*halves,denominator=r.sc.P**d)
    assert out['draws']=={r.zc.WEIGHT:a+4,r.zc.tr.CHALLENGE:a+4} and [claim[0] for claim in out['claims']]==[v['base']+j for j in range(16,21)] and [x['numerator'] for x in out['sc']]==[a+4,0,a+4]
    for label in (r.zc.WEIGHT,r.zc.tr.CHALLENGE):assert sum(child['draws'].get(label,0) for child in [out]+out['children'])==(4*(gu+gw)+17)*a+3*weighted+36-4*halves


def honest(mode='matrix'):
    digest=hashlib.sha256();done=0;cases=((1,1,0,30,0,'block1024',62,1),(3,65,3,8,8,'exact',0,1),(16,1025,30,0,0,'block1024',2,1),(65,1<<20,0,30,14,'exact',0,65535))
    full={'maximum':(0,30,14,65535),'full-denominator':(30,0,14,1),'full-small':(7,7,0,1)}
    if mode in full:
        fv,fo,E,scale=full[mode];cases=((16384,1<<20,fv,fo,E,'exact',0,scale),)
    for d,reps in (((4,1),) if mode!='matrix' else ((4,1),(4,2),(8,1),(8,2))):
        for width,length,fv,fo,E,acc,drop,scale in cases:
            p=replace(spec(width,7410+done,reps),schema=c.bounds.Spec(length,width,fv,fo,E,'static',scale,acc,drop));v=c.derive(p,d);cap=v['constants']['numerator_max'];D=0 if width==1 else v['constants']['denominator_max'];us=[(0,cap,max(0,cap-1),1 if cap else 0)[i%4] for i in range(width)]
            print('honest start',done+1,d,reps,width,tuple(v['groups'].values()),flush=True);proof,state=c.prove(p,us,D,d);out=c.verify(p,oracle(p,us,D)[1],proof,d);assert out['state']==state;account(p,out,d);digest.update(state);done+=1;print('honest passed',done,d,reps,width,tuple(v['groups'].values()),flush=True)
    print(json.dumps(dict(mode=mode,proofs=done,sha256=digest.hexdigest()),sort_keys=True),flush=True)


def controls():
    p=spec();d=4;v=c.derive(p,d);us=[0,257,1<<16];D=17;w=c.witness(p,us,D);pairs=c.prepare(p,us,D,d);proof,state=c.assemble(p,pairs,d);roots=oracle(p,us,D)[1];out=c.verify(p,roots,proof,d);assert out['state']==state;account(p,out,d)
    for index,name in enumerate(('Numerator','Denominator','Biased')):
        bad=roots.copy();bad[index]=bytes(32);rejects(name+':CommitmentMismatch',lambda:c.verify(p,bad,proof,d))
    for name in v['ranges']:
        bad=copy.deepcopy(proof);bad[name]['words'][0]^=1;rejects(name.title()+':CommitmentMismatch',lambda:c.verify(p,roots,bad,d));bad=copy.deepcopy(proof);bad['roots'][name]=bytes(32);rejects(name.title()+':CommitmentMismatch',lambda:c.verify(p,roots,bad,d))
    for name in ('numerator_0','biased_0','denominator','carry_0'):
        values=w[name].copy();values[0]+=1;bad,_=c.assemble(p,dict(pairs,**{name:r.prove(v['ranges'][name],values,d)}),d);rejects('Bias:RoundSumMismatch',lambda:c.verify(p,c.roots(p,bad),bad,d))
    zp,zs=c.prove(p,[0]*3,0,d);zr=c.roots(p,zp);assert c.verify(p,zr,zp,d)['state']==zs
    for changes in (((0,1),(3,2)),((1,1),(3,1)),((2,1),(3,1)),((3,256),(4,-1)),((4,1),(2,256))):
        bad=copy.deepcopy(zp)
        for column,delta in changes:bad['zero'][0]['final'][column][0]=r.sc.add(bad['zero'][0]['final'][column][0],r.sc.scalar(delta,d))
        rejects('Bias:ClaimMismatch',lambda:c.verify(p,zr,bad,d))
    other=replace(p,schema=replace(p.schema,fraction=4,output_fraction=9));rejects('Bias:ClaimMismatch',lambda:c.verify(other,roots,proof,d))
    for key in ('receipt','certificate','broadcast','group'):rejects('ProofShape',lambda:c.verify(p,roots,dict(proof,**{key:{}}),d))
    bad=copy.deepcopy(proof);bad['zero'][0]['rounds'][0][0]=(False,0,0,0);rejects('NoncanonicalField',lambda:c.verify(p,roots,bad,d));rejects('Root',lambda:c.verify(p,roots[:-1],proof,d));print('all external/internal roots, complete children, false inputs/output/carry and all five compensated original views reject',flush=True)


def boundaries():
    p=spec(identity=7440);d=4;v=c.derive(p,d);w=c.witness(p,[0]*3,0);pairs=c.prepare(p,[0]*3,0,d)
    for name,child in v['ranges'].items():
        indices=[0]+([p.schema.width] if name!='denominator' else [])+([len(child.caps)-1] if name.startswith('carry_') else [])
        for index in indices:
            caps=list(child.caps);values=w[name].copy()
            if index==len(caps):caps.append(0);values.append(0)
            caps[index]+=1;values[index]=caps[index];pair=r.assemble(child,*r.witness(replace(child,caps=tuple(caps)),values),d);bad,_=c.assemble(p,dict(pairs,**{name:pair}),d);rejects(name.title()+':CapRelation:RoundSumMismatch',lambda:c.verify(p,c.roots(p,bad),bad,d))
    p=replace(spec(1,7441),schema=c.bounds.Spec(1<<20,1,0,30,14,'static',65535,'exact',0));v=c.derive(p,d);us=[v['constants']['numerator_max']];D=v['constants']['denominator_max'];pairs=c.prepare(p,us,D,d);values=c.witness(p,us,D)['biased_0'];values[0]-=r.sc.P;assert values[0]>=0;bad,_=c.assemble(p,dict(pairs,biased_0=r.prove(v['ranges']['biased_0'],values,d)),d);rejects('Bias:RoundSumMismatch',lambda:c.verify(p,c.roots(p,bad),bad,d))
    p=spec(identity=7442);v=c.derive(p,d);pairs=c.prepare(p,[0]*3,17,d);proof,state=c.assemble(p,pairs,d);roots=oracle(p,[0]*3,17)[1];assert c.verify(p,roots,proof,d)['state']==state
    for index,identity,words in ((0,p.numerator,c.full(v,proof,'numerator')),(1,p.denominator,c.denominator_words(v,proof)),(2,p.output,c.full(v,proof,'biased'))):
        words[-1]=1;bad=roots.copy();bad[index]=r.root(identity,words);rejects(('Numerator','Denominator','Biased')[index]+':CommitmentMismatch',lambda:c.verify(p,bad,proof,d))
    _,i,tables=c.parts(p,proof,d)[0];bad=copy.deepcopy(proof);changed=copy.deepcopy(tables);changed[1]=[r.sc.scalar(17>>(8*k)&255,d) for k in range(16) for _ in range(v['n'])];t=c.transcript(v,roots+[proof['roots'][name] for name in v['ranges']],[pairs[name][1] for name in v['ranges']],d);bad['zero']=[r.zero_prove(t,i,changed)];rejects('Bias:RoundSumMismatch',lambda:c.verify(p,roots,bad,d))
    print('whole caps, dense padding, carry endpoints, genuine ranged W-p, shared-denominator padding and full external planes reject',flush=True)


def composition():
    import attention_numerator as numerator
    import attention_denominator as denominator
    for mode in ('exact','block1024'):
        p=replace(spec(identity=7450+(mode=='exact')),schema=c.bounds.Spec(2049,3,3 if mode=='exact' else 30,8 if mode=='exact' else 0,0 if mode=='exact' else 8,'static',1,mode,0 if mode=='exact' else 10));d=4;np_spec=numerator.Spec(p.schema,7550,9901,p.numerator,1);dp=denominator.Spec(p.schema,7551,9907,p.denominator,1);ms=[0,1,2];z=385
        up,st=numerator.prove(np_spec,ms,d);ur=numerator.expected_roots(np_spec,ms);assert numerator.verify(np_spec,ur,up,d)['state']==st;down,st=denominator.prove(dp,z,d);dr=denominator.expected_roots(dp,z);assert denominator.verify(dp,dr,down,d)['state']==st;constants=c.derive(p,d)['constants'];us=[m*constants['left_factor'] for m in ms];D=z*constants['right_factor'];proof,state=c.prove(p,us,D,d);roots=oracle(p,us,D)[1];assert roots[:2]==[ur[1],dr[1]] and c.verify(p,roots,proof,d)['state']==state
        other,st=numerator.prove(np_spec,[0,1,3],d);rr=numerator.expected_roots(np_spec,[0,1,3]);assert numerator.verify(np_spec,rr,other,d)['state']==st;rejects('Numerator:CommitmentMismatch',lambda:c.verify(p,[rr[1],*roots[1:]],proof,d))
        other,st=denominator.prove(dp,z+1,d);rr=denominator.expected_roots(dp,z+1);assert denominator.verify(dp,rr,other,d)['state']==st;rejects('Denominator:CommitmentMismatch',lambda:c.verify(p,[roots[0],rr[1],roots[2]],proof,d));print('complete scaled numerator and positive denominator compose; valid replacements reject',mode,flush=True)


if __name__=='__main__':
    modes={'--corpus':corpus,'--controls':controls,'--boundaries':boundaries,'--composition':composition,'--honest':honest,'--maximum':lambda:honest('maximum'),'--full-denominator':lambda:honest('full-denominator'),'--full-small':lambda:honest('full-small')}
    if sys.argv[1:]:
        assert all(mode in modes for mode in sys.argv[1:])
        for mode in sys.argv[1:]:modes[mode]()
    else:
        for test in list(modes.values())[:-3]:test()
