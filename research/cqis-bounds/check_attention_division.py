# /// script
# requires-python = ">=3.12"
# dependencies = ["numpy==2.3.4", "blake3==1.0.11", "python-flint==0.9.0"]
# ///
"""Draft RFC-0004 A3/A6: complete strict attention division and controls."""
import copy
from dataclasses import replace
import hashlib
import json
import random
import sys
import numpy as np
import attention_division as c

r=c.r


def rejects(reason,call):
    try:call()
    except ValueError as error:assert str(error)==reason,(reason,str(error))
    else:raise AssertionError('accepted '+reason)


def spec(width=3,identity=7800,repetitions=1):
    return c.Spec(c.bounds.Spec(65,width,3,8,8,'static',1,'exact',0),identity,10201,10207,10211,10213,10217,10223,10229,repetitions)


def oracle(p,us,D):
    n=1<<(p.schema.width-1).bit_length();ws=2*np.array(us,dtype=object)+D;qs=(ws//(2*D)).tolist();rs=(ws%(2*D)).tolist();products=(np.array(qs,dtype=object)*D).tolist()
    def planes(xs,size,width=16):
        xs=xs+[0]*(size-len(xs));rows=np.array([[x&((1<<64)-1),x>>64] for x in xs],dtype='<u8');return np.frombuffer(rows.tobytes(),dtype=np.uint8).reshape(size,16)[:,:width].T.reshape(-1).tolist()
    sources=((p.numerator,us,n,16),(p.denominator,[D],1,16),(p.quotient,qs,n,2),(p.product,products,n,16),(p.biased,ws.tolist(),n,16),(p.doubled,[2*D],1,16),(p.remainder,rs,n,16))
    return qs,rs,[r.root(identity,planes(xs,size,width)) for identity,xs,size,width in sources]


def inputs(p,D):
    cap=min(c.derive(p,4)['constants']['numerator_max'],(65537*D-1)//2);points=(0,cap,min(cap,D//2),min(cap,(D-1)//2));return [points[i%4] for i in range(p.schema.width)]


def corpus():
    rng=random.Random(2747);digest=hashlib.sha256();cells=zeros=edges=0;groups=set()
    def check(p,us,D):
        nonlocal cells,zeros,edges
        v=c.derive(p,4);qs,rs,roots=oracle(p,us,D);w=c.witness(p,us,D,qs,rs);n=v['n'];assert c.expected_roots(p,us,D,qs,rs)==roots
        for role,values in (('remainder',rs),('gap',[2*D-1-x for x in rs])):
            actual=sum((w[role+'_'+str(j)] for j in range(v['groups'])),[]);assert actual[:p.schema.width]==values and not any(actual[p.schema.width:])
        for prefix,left,right,factor,initial,target in (('equal',[q*D for q in qs],rs,2,0,[2*u+D for u in us]),('strict',rs,[2*D-1-x for x in rs],1,1,[2*D]*len(us))):
            left=left+[0]*(n-len(left));right=right+[0]*(n-len(right));target=target+[0]*(n-len(target));carry=np.array([initial]*len(us)+[0]*(n-len(us)),dtype=np.int64);cs=[]
            for k in range(16):
                total=factor*np.array([x>>(8*k)&255 for x in left],dtype=np.int64)+np.array([x>>(8*k)&255 for x in right],dtype=np.int64)+carry;byte=total%256;carry=total//256;assert byte.tolist()==[x>>(8*k)&255 for x in target];cs.extend(carry.tolist())
            assert cs==sum((w[prefix+'_'+str(j)] for j in range(4)),[]) and cs[-n:]==[0]*n
        assert all(0<=x<=cap for name,child in v['ranges'].items() for x,cap in zip(w[name],child.caps)) and all(r.derive(child,4)[2]*r.derive(child,4)[3]<=131072 for child in v['ranges'].values())
        proof={name:{'words':r.witness(child,w[name])[0]} for name,child in v['ranges'].items()};assert r.root(p.remainder,c.full(v,proof,'remainder'))==roots[-1]
        digest.update(v['raw']+b''.join(roots)+bytes(sum((w[name] for name in v['ranges'] if name.startswith(('equal_','strict_'))),[])));cells+=len(us);zeros+=rs.count(0);edges+=rs.count(2*D-1);groups.add(v['groups'])
    for case in range(10000):
        width=1+case%65;length=rng.choice((1,65,1024,1025,1<<20));fv=case%31;fo=(case//31)%31;E=case%15;mode='block1024' if case%2 else 'exact';policy='dynamic' if case%4<2 else 'static';scale=0 if policy=='dynamic' else rng.choice((1,2,259,65535))
        S=127*259 if policy=='dynamic' else scale*min(127,(65536+scale)//(2*scale));H=1024*(1<<E)*S;minimum=next(k for k in range(63) if (H+(1<<k)//2)//(1<<k)<=32767);drop=0 if mode=='exact' else minimum+case%(63-minimum)
        p=replace(spec(width,case,1+case%2),schema=c.bounds.Spec(length,width,fv,fo,E,policy,scale,mode,drop));v=c.derive(p,4);Dmax=length*(1<<E)*(1<<max(fv-fo-drop,0));assert v['constants']['denominator_max']==Dmax;D=(1,Dmax,max(1,Dmax-1),rng.randrange(1,Dmax+1))[case%4];us=inputs(p,D);limit=min(v['constants']['numerator_max'],(65537*D-1)//2)
        for i in range(4,width):us[i]=rng.randrange(limit+1)
        check(p,us,D)
    for width in (8193,16384):
        for fv,wanted in ((0,1),(30,2)):
            p=replace(spec(width,(1<<38)-1,2),schema=c.bounds.Spec(1<<20,width,fv,0,14,'static',65535,'exact',0));v=c.derive(p,8);assert v['groups']==wanted;D=v['constants']['denominator_max'];check(p,inputs(p,D),D)
            spans=[(r.derive(child,8)[4],64) for child in v['ranges'].values()]+[(c.qp.derive(v['quotient_product'],8)['base'],1<<14),(c.bias.derive(v['bias'],8)['base'],1<<14),(c.double.derive(v['double'],8)['base'],1<<18)];spans.sort();assert all(v['base']+41<lo and lo+size<=v['base']+(1<<24) for lo,size in spans) and all(lo+size<=nxt for (lo,size),(nxt,_) in zip(spans,spans[1:]))
    p=spec();v=c.derive(p,4)
    for bad in (replace(p,identity=1<<38),replace(p,repetitions=True),replace(p,quotient=p.numerator),replace(p,remainder=v['base']),replace(p,schema=replace(p.schema,width=16385))):rejects('Spec',lambda:c.derive(bad,4))
    rejects('Spec',lambda:c.derive(p,True))
    for us,D,qs,rs in (([0]*3,0,[0]*3,[0]*3),([False]*3,1,[0]*3,[1]*3),([0],1,[0]*3,[1]*3),([0]*3,1,[32769]*3,[1]*3),([0]*3,1,[0]*3,[2]*3),([0]*3,1,[0]*3,[False]*3)):rejects('Input',lambda:c.witness(p,us,D,qs,rs))
    assert groups=={1,2} and zeros>0 and edges>0
    assert (cells,zeros,edges,digest.hexdigest())==(378879,7844,92247,'390669772c84ae3667822f7417690d395e2b76389df305bbe9b654a37bb196b7')
    print(json.dumps(dict(seed=2747,cases=10000,capacity_cases=4,cells=cells,zero_remainders=zeros,maximal_remainders=edges,sha256=digest.hexdigest()),sort_keys=True),flush=True)


def account(p,out,d):
    import check_attention_quotient_product as qp_check
    import check_attention_biased_numerator as bias_check
    import check_attention_doubled_denominator as double_check
    v=c.derive(p,d)
    for name,check,child in zip(('quotient_product','bias','double'),(qp_check,bias_check,double_check),out['children']):check.account(v[name],child,d)
    a,br,g=v['a'],v['br'],v['groups'];dims=[a-(g-1)+br+1]*(2*g)+[a+3]*8;f=lambda m:3*m*(m-1)//2+2*m;inherited=[child['account'] for child in out['children']]
    assert out['account']==dict(identities=sum((x['identities'] for x in inherited),[])+[((1<<m)+255,p.repetitions) for m in dims],lookup_reduction_numerator=sum(x['lookup_reduction_numerator'] for x in inherited)+sum(p.repetitions*(f(m)+f(8)+3*m) for m in dims),range_reduction_numerator=sum(x['range_reduction_numerator'] for x in inherited)+(94*a+14*br+160 if g==1 else 112*a+28*br+124),product_identity_numerator=inherited[2]['product_identity_numerator'],product_reduction_numerator=inherited[2]['product_reduction_numerator'],denominator=r.sc.P**d)
    assert out['draws']=={r.zc.WEIGHT:2*(a+4),r.zc.tr.CHALLENGE:2*(a+4)} and [claim[0] for claim in out['claims']]==[v['base']+j for j in range(32,42)] and [x['numerator'] for x in out['sc']]==[a+4,0,a+4]*2
    for label in (r.zc.WEIGHT,r.zc.tr.CHALLENGE):assert sum(child['draws'].get(label,0) for child in [out]+out['ranges'])==(42*a+6*br+72 if g==1 else 50*a+12*br+56)


def honest(mode='matrix'):
    digest=hashlib.sha256();done=0;cases=((1,1,0,30,0,'block1024',62),(3,65,3,8,8,'exact',0),(16,1025,30,0,0,'block1024',2),(65,1<<20,30,0,14,'exact',0))
    if mode!='matrix':cases=((16384,1<<20,30 if mode=='maximum' else 0,0,14,'exact',0),)
    for d,reps in (((4,1),) if mode!='matrix' else ((4,1),(4,2),(8,1),(8,2))):
        for width,length,fv,fo,E,acc,drop in cases:
            p=replace(spec(width,7810+done,reps),schema=c.bounds.Spec(length,width,fv,fo,E,'static',65535 if mode=='full-quotient' else 1,acc,drop));v=c.derive(p,d);D=v['constants']['denominator_max'];us=inputs(p,D);qs,rs,roots=oracle(p,us,D)
            if mode=='full-quotient':assert max(qs)==32768
            print('honest start',done+1,d,reps,width,v['groups'],flush=True);proof,state=c.prove(p,us,D,qs,rs,d);out=c.verify(p,roots,proof,d);assert out['state']==state;account(p,out,d);digest.update(state);done+=1;print('honest passed',done,d,reps,width,v['groups'],flush=True)
    print(json.dumps(dict(mode=mode,proofs=done,sha256=digest.hexdigest()),sort_keys=True),flush=True)


def controls():
    p=spec();d=4;v=c.derive(p,d);us=[0,1,257];D=3;qs,rs,roots=oracle(p,us,D);w=c.witness(p,us,D,qs,rs);pairs=c.prepare(p,us,D,qs,rs,d);proof,state=c.assemble(p,pairs,d);out=c.verify(p,roots,proof,d);assert out['state']==state;account(p,out,d)
    labels=('Bias:Numerator','QuotientProduct:Denominator','QuotientProduct:Quotient','QuotientProduct:Product','Bias:Biased','Double:Doubled','Remainder')
    for index,label in enumerate(labels):
        bad=roots.copy();bad[index]=bytes(32);rejects(label+':CommitmentMismatch',lambda:c.verify(p,bad,proof,d))
    for name in v['ranges']:
        bad=copy.deepcopy(proof);bad[name]['words'][0]^=1;rejects(name.title()+':CommitmentMismatch',lambda:c.verify(p,roots,bad,d));bad=copy.deepcopy(proof);bad['roots'][name]=bytes(32);rejects(name.title()+':CommitmentMismatch',lambda:c.verify(p,roots,bad,d))
    for name,label in (('remainder_0','Equality'),('gap_0','StrictRemainder'),('equal_0','Equality'),('strict_0','StrictRemainder')):
        values=w[name].copy();values[0]+=1;bad,_=c.assemble(p,dict(pairs,**{name:r.prove(v['ranges'][name],values,d)}),d);rejects(label+':RoundSumMismatch',lambda:c.verify(p,c.roots(p,bad),bad,d))
    for j,label in enumerate(('Equality','StrictRemainder')):
        for changes in (((0,1),(3,2 if j==0 else 1)),((1,1),(3,1)),((2,1),(3,1)),((3,256),(4,-1)),((4,1),(2,256))):
            bad=copy.deepcopy(proof)
            for column,delta in changes:bad['zero'][j]['final'][column][0]=r.sc.add(bad['zero'][j]['final'][column][0],r.sc.scalar(delta,d))
            rejects(label+':ClaimMismatch',lambda:c.verify(p,roots,bad,d))
    for name,changed,label in (('quotient_product',c.qp.prove(v['quotient_product'],[q+1 for q in qs],D,d),'QuotientProduct:Quotient'),('bias',c.bias.prove(v['bias'],[u+1 for u in us],D,d),'Bias:Numerator'),('double',c.double.prove(v['double'],D+1,d),'Double:Denominator')):
        bad=copy.deepcopy(proof);bad[name]=changed[0];rejects(label+':CommitmentMismatch',lambda:c.verify(p,roots,bad,d))
    for key in ('receipt','certificate','broadcast','group'):rejects('ProofShape',lambda:c.verify(p,roots,dict(proof,**{key:{}}),d))
    bad=copy.deepcopy(proof);bad['zero'][0]['rounds'][0][0]=(False,0,0,0);rejects('NoncanonicalField',lambda:c.verify(p,roots,bad,d));rejects('Root',lambda:c.verify(p,roots[:-1],proof,d));print('all roots, fresh false ranges, all ten compensated originals and complete child substitutions reject',flush=True)


def boundaries():
    p=spec(identity=7840);d=4;v=c.derive(p,d);us=[0]*3;D=2;qs,rs,roots=oracle(p,us,D);w=c.witness(p,us,D,qs,rs);pairs=c.prepare(p,us,D,qs,rs,d);proof,state=c.assemble(p,pairs,d);assert c.verify(p,roots,proof,d)['state']==state
    for name,child in v['ranges'].items():
        for index in (0,p.schema.width,len(child.caps)-1):
            caps=list(child.caps);values=w[name].copy()
            if index==len(caps):caps.append(0);values.append(0)
            caps[index]+=1;values[index]=caps[index];pair=r.assemble(child,*r.witness(replace(child,caps=tuple(caps)),values),d);bad,_=c.assemble(p,dict(pairs,**{name:pair}),d);rejects(name.title()+':CapRelation:RoundSumMismatch',lambda:c.verify(p,c.roots(p,bad),bad,d))
    v=c.derive(p,d);bad=copy.deepcopy(proof);t=c.transcript(v,roots+[proof['roots'][name] for name in v['ranges']],[pairs[name][1] for name in ('quotient_product','bias','double')]+[pairs[name][1] for name in v['ranges']],d);bad['zero']=[]
    for j,(_,i,tables) in enumerate(c.parts(p,proof,d)):
        if j:tables[2][0]=r.sc.scalar(0,d);tables[1][0]=r.sc.add(tables[1][0],r.sc.scalar(1,d))
        bad['zero'].append(r.zero_prove(t,i,tables))
    rejects('StrictRemainder:ClaimMismatch',lambda:c.verify(p,roots,bad,d))
    # A wrong q can preserve equality with R=2D; its independently ranged gap
    # still cannot satisfy the strict relation. Assemble outside witness().
    us=[1]*3;pairs['bias']=c.bias.prove(v['bias'],us,D,d);values=[4]*3;pairs['remainder_0']=r.prove(v['ranges']['remainder_0'],values,d);pairs['gap_0']=r.prove(v['ranges']['gap_0'],[0]*3,d);bad,_=c.assemble(p,pairs,d);rejects('StrictRemainder:RoundSumMismatch',lambda:c.verify(p,c.roots(p,bad),bad,d))
    p=replace(spec(1,7841),schema=c.bounds.Spec(1<<20,1,30,0,14,'static',1,'exact',0));v=c.derive(p,d);D=1<<64;qs,rs,roots=oracle(p,[0],D);pairs=c.prepare(p,[0],D,qs,rs,d);bad,_=c.assemble(p,dict(pairs,remainder_0=r.prove(v['ranges']['remainder_0'],[rs[0]+r.sc.P],d)),d);rejects('Equality:RoundSumMismatch',lambda:c.verify(p,c.roots(p,bad),bad,d))
    # Complete zero-D children cannot make R+gap+1=0 over faithful columns.
    p=spec(identity=7842);v=c.derive(p,d);qs,rs,roots=oracle(p,[0]*3,1);pairs=c.prepare(p,[0]*3,1,qs,rs,d);pairs.update(quotient_product=c.qp.prove(v['quotient_product'],[0]*3,0,d),bias=c.bias.prove(v['bias'],[0]*3,0,d),double=c.double.prove(v['double'],0,d),remainder_0=r.prove(v['ranges']['remainder_0'],[0]*3,d),gap_0=r.prove(v['ranges']['gap_0'],[0]*3,d));bad,_=c.assemble(p,pairs,d);rejects('StrictRemainder:RoundSumMismatch',lambda:c.verify(p,c.roots(p,bad),bad,d))
    print('whole caps, padding, carry endpoints, strict initial one, ranged R=2D, genuine ranged R+p and zero denominator reject',flush=True)
    joins()


def joins():
    p=spec(identity=7843);d=4;v=c.derive(p,d);us=[0]*3;D=3;qs,rs,roots=oracle(p,us,D);pairs=c.prepare(p,us,D,qs,rs,d);proof,state=c.assemble(p,pairs,d);assert c.verify(p,roots,proof,d)['state']==state
    other=replace(p,schema=replace(p.schema,fraction=4,output_fraction=9));rejects('QuotientProduct:Product:ClaimMismatch',lambda:c.verify(other,roots,proof,d))
    words=c.full(v,proof,'remainder');words[-1]=1;bad=roots.copy();bad[-1]=r.root(p.remainder,words);rejects('Remainder:CommitmentMismatch',lambda:c.verify(p,bad,proof,d))
    for name,module,values,label in (('quotient_product',c.qp,qs,'QuotientProduct'),('bias',c.bias,us,'Bias')):
        changed,st=module.prove(v[name],values,D+1,d);rr=module.expected_roots(v[name],values,D+1);assert module.verify(v[name],rr,changed,d)['state']==st;bad=copy.deepcopy(proof);bad[name]=changed;rejects(label+':Denominator:CommitmentMismatch',lambda:c.verify(p,roots,bad,d))
    bad=copy.deepcopy(proof);t=c.transcript(v,roots+[proof['roots'][name] for name in v['ranges']],[pairs[name][1] for name in ('quotient_product','bias','double')]+[pairs[name][1] for name in v['ranges']],d);bad['zero']=[]
    for j,(_,i,tables) in enumerate(c.parts(p,proof,d)):
        if j:tables[3]=[r.sc.scalar(2*D>>(8*k)&255,d) for k in range(16) for _ in range(v['n'])]
        bad['zero'].append(r.zero_prove(t,i,tables))
    rejects('StrictRemainder:RoundSumMismatch',lambda:c.verify(p,roots,bad,d));print('metadata replay, full remainder planes, shared denominator substitutions at zero q and unmasked scalar broadcast reject',flush=True)


def composition():
    import attention_numerator as numerator
    import attention_denominator as denominator
    for mode in ('exact','block1024'):
        p=replace(spec(identity=7850+(mode=='exact')),schema=c.bounds.Spec(2049,3,3 if mode=='exact' else 30,8 if mode=='exact' else 0,0 if mode=='exact' else 8,'static',1,mode,0 if mode=='exact' else 10));d=4;np_spec=numerator.Spec(p.schema,7950,10301,p.numerator,1);dp=denominator.Spec(p.schema,7951,10307,p.denominator,1);ms=[0,1,32767];z=385
        up,st=numerator.prove(np_spec,ms,d);ur=numerator.expected_roots(np_spec,ms);assert numerator.verify(np_spec,ur,up,d)['state']==st;down,st=denominator.prove(dp,z,d);dr=denominator.expected_roots(dp,z);assert denominator.verify(dp,dr,down,d)['state']==st;constants=c.derive(p,d)['constants'];us=[m*constants['left_factor'] for m in ms];D=z*constants['right_factor'];qs,rs,roots=oracle(p,us,D);proof,state=c.prove(p,us,D,qs,rs,d);assert roots[:2]==[ur[1],dr[1]] and c.verify(p,roots,proof,d)['state']==state
        other,st=numerator.prove(np_spec,[0,2,32767],d);rr=numerator.expected_roots(np_spec,[0,2,32767]);assert numerator.verify(np_spec,rr,other,d)['state']==st;rejects('Bias:Numerator:CommitmentMismatch',lambda:c.verify(p,[rr[1],*roots[1:]],proof,d))
        other,st=denominator.prove(dp,z+1,d);rr=denominator.expected_roots(dp,z+1);assert denominator.verify(dp,rr,other,d)['state']==st;rejects('QuotientProduct:Denominator:CommitmentMismatch',lambda:c.verify(p,[roots[0],rr[1],*roots[2:]],proof,d));print('complete scaled numerator and positive denominator compose; valid replacements reject',mode,flush=True)


if __name__=='__main__':
    modes={'--corpus':corpus,'--controls':controls,'--boundaries':boundaries,'--composition':composition,'--honest':honest,'--maximum':lambda:honest('maximum'),'--full-quotient':lambda:honest('full-quotient')}
    if sys.argv[1:]:
        assert all(mode in modes for mode in sys.argv[1:])
        for mode in sys.argv[1:]:modes[mode]()
    else:
        for test in list(modes.values())[:-2]:test()
