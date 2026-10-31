# /// script
# requires-python = ">=3.12"
# dependencies = ["numpy==2.3.4", "blake3==1.0.11", "python-flint==0.9.0"]
# ///
"""Draft RFC-0004 A3/A6: complete conditional normalization and source swaps."""
import copy
from dataclasses import replace
import hashlib
import json
import random
import sys
import numpy as np
import attention_normalization as c

r=c.r


def rejects(reason,call):
    try:call()
    except ValueError as error:assert str(error)==reason,(reason,str(error))
    else:raise AssertionError('accepted '+reason)


def spec(mode='exact',width=3,identity=8100,repetitions=1):
    schema=c.bounds.Spec(65,width,0,0,0,'static',1,mode,0 if mode=='exact' else 2)
    return c.Spec(schema,identity,11001,11002 if mode=='exact' else 0,11003,11004,11005,11006,11007,11008,11009,11010,11011,11012,11013,repetitions)


def constants(p):
    s=p.schema;Q=1<<s.exponent;S=127*259 if s.value_mode=='dynamic' else s.scale*min(127,(65536+s.scale)//(2*s.scale));drop=1<<s.drop;G=s.length*Q*S if s.accumulation=='exact' else ((s.length+1023)//1024)*((1024*Q*S+drop//2)//drop);shift=s.output_fraction-s.fraction+s.drop
    return Q,S,G,1<<max(shift,0),1<<max(-shift,0)


def oracle(p,z,totals):
    Q,S,G,A,B=constants(p);T=np.array(totals,dtype=object);M=np.abs(T);U=M*A;D=z*B;q=(2*U+D)//(2*D);R=(2*U+D)%(2*D);Y=np.where(T<0,-q,q);H=z*S if p.schema.accumulation=='exact' else G
    if any(y < -32768 or y > 32767 for y in Y):raise ValueError('OutputRange')
    values=dict(offset=[int(x) for x in T+H],probability=z,magnitude=[int(x) for x in M],sign=[int(x<0) for x in T],numerator=[int(x) for x in U],denominator=D,quotient=[int(x) for x in q],product=[int(x) for x in q*D],biased=[int(x) for x in 2*U+D],doubled=2*D,remainder=[int(x) for x in R],output=[int(x) for x in Y])
    if p.schema.accumulation=='exact':values['base_source']=H
    roles=('offset','base_source','probability','magnitude','sign','numerator','denominator','quotient','product','biased','doubled','remainder','output');roles=tuple(x for x in roles if x!='base_source' or p.schema.accumulation=='exact');roots=[];n=1<<(p.schema.width-1).bit_length()
    for role in roles:
        size=1 if role=='sign' else 2 if role in ('quotient','output') else 8 if role in ('offset','base_source','probability','magnitude') else 16
        xs=[values[role]] if role in ('base_source','probability','denominator','doubled') else values[role]+[0]*(n-p.schema.width)
        words=np.array([[int(x)>>(8*j)&255 for x in xs] for j in range(size)],dtype=np.uint8).reshape(-1).tolist();roots.append(r.root(getattr(p,role),words))
    return values,roots


def corpus():
    rng=random.Random(2750);digest=hashlib.sha256();accepted=rejected=cells=zeros=ties=0;directions=set();modes=set();exponents=set()
    def check(p,z,totals):
        nonlocal accepted,rejected,cells,zeros,ties
        Q,S,G,A,B=constants(p);v=c.derive(p,4);assert v['constants']['total_max']==G and v['constants']['left_factor']==A and v['constants']['right_factor']==B
        try:values,roots=oracle(p,z,totals)
        except ValueError:
            rejects('OutputRange',lambda:c.witness(p,z,totals));rejected+=1;digest.update(b'reject'+v['raw']);return
        w=c.witness(p,z,totals);assert w==values and c.expected_roots(p,z,totals)==roots
        assert all(0<=rest<2*values['denominator'] for rest in values['remainder']);accepted+=1;cells+=len(totals);zeros+=sum(t<0 and y==0 for t,y in zip(totals,values['output']));ties+=sum(2*u% (2*values['denominator'])==values['denominator'] for u in values['numerator']);digest.update(v['raw']+b''.join(roots))
    for case in range(10000):
        mode='exact' if case%2 else 'block1024';length=rng.choice((1,3,65,1024,1025,1<<20));width=rng.choice((1,3,16,65));fv=case%31;fo=(case//31)%31;E=case%15;policy='dynamic' if case%4<2 else 'static';scale=0 if policy=='dynamic' else rng.choice((1,2,259,65535));S=127*259 if policy=='dynamic' else scale*min(127,(65536+scale)//(2*scale));raw=1024*(1<<E)*S;minimum=next(k for k in range(63) if (raw+(1<<k)//2)//(1<<k)<=32767);drop=0 if mode=='exact' else rng.randrange(minimum,63)
        p=replace(spec(mode,width,case,1+case%2),schema=c.bounds.Spec(length,width,fv,fo,E,policy,scale,mode,drop));Q,S,G,A,B=constants(p);z=rng.randrange(Q,length*Q+1);cap=z*S if mode=='exact' else G
        totals=[rng.choice((0,-min(1,cap),-cap,cap,rng.randint(-cap,cap))) for _ in range(width)]
        if case%7==0:totals=[0]*width;totals[0]=-min(cap,max(1,(z*B-1)//(2*A)))
        check(p,z,totals);directions.add((A>1)-(B>1));modes.add(mode);exponents.add(E)
    for mode in ('exact','block1024'):
        for width in (8193,16384):
            p=replace(spec(mode,width,10000+width),schema=c.bounds.Spec(1<<20,width,30 if mode=='exact' else 0,0,14 if mode=='exact' else 0,'static',65535,mode,0 if mode=='exact' else 12));z=(1<<34) if mode=='exact' else 1<<20;totals=([0,-1,1] if mode=='exact' else [-(1<<23),0,(32767<<8)])*((width+2)//3);check(p,z,totals[:width])
    p=replace(spec('exact',3),schema=c.bounds.Spec(2,3,0,0,0,'static',65535,'exact',0));check(p,2,[-1,1,-65536]);rejects('OutputRange',lambda:c.witness(p,2,[65536,0,0]))
    assert accepted>1000 and rejected>1000 and zeros>1000 and ties>0 and modes=={'exact','block1024'} and directions=={-1,0,1} and exponents==set(range(15))
    print(json.dumps(dict(seed=2750,cases=10000,capacity_cases=4,tie_cases=1,accepted=accepted,rejected=rejected,cells=cells,negative_input_zero=zeros,ties=ties,sha256=digest.hexdigest()),sort_keys=True),flush=True)


def namespaces():
    context()
    for mode in ('exact','block1024'):
        p=replace(spec(mode,16384,(1<<32)-1,2),schema=c.bounds.Spec(1<<20,16384,30 if mode=='exact' else 0,0,14 if mode=='exact' else 0,'static',65535,mode,0 if mode=='exact' else 12))
        for d in (4,8):
            v=c.derive(p,d);spans=[]
            for name,module,child,roles,label in v['children']:
                layout=module.derive(child,d);span=1<<24 if name=='division' else 1<<18 if name in ('base','denominator') else 1<<14;spans.append((layout['base'],span));assert v['base']<=layout['base'] and layout['base']+span<=v['base']+(1<<30)<1<<64
                if name=='division':assert layout['groups']==(2 if mode=='exact' else 1)
                if name=='sign' and mode=='block1024':assert child.blocks==tuple(range(1024))
            spans.sort();assert all(lo+size<=nxt for (lo,size),(nxt,_) in zip(spans,spans[1:]))
        for bad in (replace(p,identity=1<<32),replace(p,repetitions=True),replace(p,output=p.sign),replace(p,probability=v['base']),replace(p,base_source=0 if mode=='exact' else 11002)):rejects('Spec',lambda:c.derive(bad,4))
    print('full-width maximum-identity child namespaces, mode roles and fixed block membership metadata pass',flush=True)


def context():
    for mode in ('exact','block1024'):
        for d,reps in ((4,1),(4,2),(8,1),(8,2)):
            p=spec(mode,3,8450,reps);v=c.derive(p,d);roots=[hashlib.sha256(role.encode()).digest() for role in v['roles']];states=[hashlib.sha256(name.encode()).digest() for name,module,child,routes,label in v['children']];t=c.transcript(v,roots,states,d);assert not t.draws
            for index in range(len(states)):
                changed=states.copy();changed[index]=bytes([states[index][0]^1])+states[index][1:];assert c.transcript(v,roots,changed,d).state!=t.state
            for other in (replace(p,schema=replace(p.schema,fraction=1,output_fraction=1)),replace(p,output=11213)):
                assert c.transcript(c.derive(other,d),roots,states,d).state!=t.state
            rejects('Root',lambda:c.transcript(v,roots,states[:-1],d));rejects('Root',lambda:c.transcript(v,roots+[bytes(32)],states,d))
    print('each child state, schema and role binds the normalization context without a wrapper draw',flush=True)


def account(p,out,d):
    import check_attention_global_base as base_check
    import check_attention_sign as sign_check
    import check_attention_block_total_sign as block_check
    import check_attention_numerator as numerator_check
    import check_attention_denominator as denominator_check
    import check_attention_division as division_check
    import check_attention_signed_output as output_check
    checks=dict(base=base_check,sign=sign_check if p.schema.accumulation=='exact' else block_check,numerator=numerator_check,denominator=denominator_check,division=division_check,output=output_check);v=c.derive(p,d)
    for name,module,child,roles,label in v['children']:checks[name].account(child,out['children'][name],d)
    ac=[out['children'][name]['account'] for name in checks if name in out['children']];losses=out['children']['denominator']['account']['product_identity_numerators']+[out['children']['division']['account']['product_identity_numerator']]
    if p.schema.accumulation=='exact':losses=[out['children']['base']['account']['product_identity_numerator']]+losses
    assert out['draws']=={} and out['account']==dict(identities=sum((x['identities'] for x in ac),[]),lookup_reduction_numerator=sum(x['lookup_reduction_numerator'] for x in ac),range_reduction_numerator=sum(x['range_reduction_numerator'] for x in ac),product_identity_numerators=losses,product_reduction_numerator=sum(x.get('product_reduction_numerator',0) for x in ac),denominator=r.sc.P**d)


def controls():
    for mode in ('exact','block1024'):
        p=spec(mode,3,8200+(mode=='block1024'));d=4;z=33;totals=[0,0,0];proof,state=c.prove(p,z,totals,d);values,roots=oracle(p,z,totals);out=c.verify(p,roots,proof,d);assert out['state']==state;account(p,out,d);v=c.derive(p,d)
        reasons={'offset':'Sign:Offset:CommitmentMismatch','base_source':'GlobalBase:Base:CommitmentMismatch','probability':('GlobalBase' if mode=='exact' else 'Denominator')+':WeightSum:CommitmentMismatch','magnitude':'Sign:Magnitude:CommitmentMismatch','sign':'Sign:Sign:CommitmentMismatch','numerator':'Numerator:Numerator:CommitmentMismatch','denominator':'Denominator:Denominator:CommitmentMismatch','quotient':'Division:QuotientProduct:Quotient:CommitmentMismatch','product':'Division:QuotientProduct:Product:CommitmentMismatch','biased':'Division:Bias:Biased:CommitmentMismatch','doubled':'Division:Double:Doubled:CommitmentMismatch','remainder':'Division:Remainder:CommitmentMismatch','output':'SignedOutput:Output:Raw:CommitmentMismatch'}
        for index,role in enumerate(v['roles']):
            bad=roots.copy();bad[index]=bytes(32);rejects(reasons[role],lambda:c.verify(p,bad,proof,d))
        for name in proof:rejects('ProofShape',lambda:c.verify(p,roots,{k:x for k,x in proof.items() if k!=name},d))
        for extra in ('receipt','certificate','unused_base'):rejects('ProofShape',lambda:c.verify(p,roots,dict(proof,**{extra:{}}),d))
        rejects('Root',lambda:c.verify(p,roots[:-1],proof,d));rejects('Spec',lambda:c.derive(p,True))
        for changed,chosen in (([-1,0,0],('sign','numerator','division','output')),([0,0,0],('base','denominator') if mode=='exact' else ('denominator',))):
            zz=z if changed[0] else z+1;alternate,st=c.prove(p,zz,changed,d);rr=oracle(p,zz,changed)[1];assert c.verify(p,rr,alternate,d)['state']==st and rr[-1]==roots[-1]
            for name in chosen:
                bad=dict(proof,**{name:alternate[name]});reason={'sign':'Sign:Offset:CommitmentMismatch','numerator':'Numerator:Magnitude:CommitmentMismatch','division':'Division:Bias:Numerator:CommitmentMismatch','output':'SignedOutput:Sign:CommitmentMismatch','base':'GlobalBase:WeightSum:CommitmentMismatch','denominator':'Denominator:WeightSum:CommitmentMismatch'}[name];rejects(reason,lambda:c.verify(p,roots,bad,d))
                rejects('SourceJoin',lambda:c.roots(p,bad))
        other=replace(p,schema=replace(p.schema,accumulation='block1024' if mode=='exact' else 'exact',drop=2 if mode=='exact' else 0),base_source=0 if mode=='exact' else 11002);rejects('ProofShape',lambda:c.verify(other,roots[:12] if mode=='exact' else [roots[0],bytes(32),*roots[1:]],proof,d))
        print('every external root, missing child, mode shape and all zero-output-preserving child substitutions reject',mode,flush=True)


def boundaries():
    namespaces()
    for mode in ('exact','block1024'):
        p=replace(spec(mode,3,8250+(mode=='block1024')),schema=c.bounds.Spec(1<<20,3,0,0,0,'static',65535,mode,0 if mode=='exact' else 12));z=1<<20;unit=1 if mode=='exact' else 4096;t=-(32768*z//unit);pairs=c.prepare(p,z,[t,0,0],4);proof,state=c.assemble(p,pairs,4);values,roots=oracle(p,z,[t,0,0]);assert values['output']==[-32768,0,0] and c.verify(p,roots,proof,4)['state']==state;rejects('OutputRange',lambda:c.witness(p,z,[-t,0,0]));rejects('Divisor',lambda:c.witness(p,0,[0,0,0]))
        v=c.derive(p,4);changed=pairs.copy();H=z*65535 if mode=='exact' else constants(p)[2]
        for name,module,child,routes,label in v['children']:
            if name=='sign':changed[name]=module.prove(child,*(([H-t,H,H],H) if mode=='exact' else ([H-t,H,H],)),4)
            if name=='output':changed[name]=module.prove(child,[0,0,0],[-32768,0,0],4)
        bad,_=c.assemble(p,changed,4);rejects('SignedOutput:SignedOutput:RoundSumMismatch',lambda:c.verify(p,c.roots(p,bad),bad,4))
        assert c.transcript(v,roots,[bytes(32)]*len(proof),4).state!=state
    print('int16 negative endpoint accepts; fresh positive-source q32768 with negative int16 output and zero divisor reject; every child state binds the final context',flush=True)


def composition():
    import attention_global_probability_sum as upstream
    for mode in ('exact','block1024'):
        p=replace(spec(mode,3,8300+(mode=='block1024')),schema=c.bounds.Spec(1025,3,0,0,0,'static',1,mode,0 if mode=='exact' else 2));z=65;totals=[-1,-32,33];sp=upstream.Spec(upstream.bounds.Spec(1025,3,0,0,'static',1,2),(0,1),8400+(mode=='block1024'),(11101,11102),p.probability,1);child,st=upstream.prove(sp,[64,1],4);sr=upstream.expected_roots(sp,[64,1]);assert upstream.verify(sp,sr,child,4)['state']==st
        proof,state=c.prove(p,z,totals,4);roots=oracle(p,z,totals)[1];index=c.derive(p,4)['roles'].index('probability');assert roots[index]==sr[-1] and c.verify(p,roots,proof,4)['state']==state
        other,st=upstream.prove(sp,[63,1],4);rr=upstream.expected_roots(sp,[63,1]);assert upstream.verify(sp,rr,other,4)['state']==st;bad=roots.copy();bad[index]=rr[-1];rejects(('GlobalBase' if mode=='exact' else 'Denominator')+':WeightSum:CommitmentMismatch',lambda:c.verify(p,bad,proof,4))
        print('complete global probability source composes with normalization; valid alternate Z rejects',mode,flush=True)


def honest(mode='matrix'):
    digest=hashlib.sha256();done=0;cases=(('block1024',1,1,0,30,0,'static',1,62),('exact',3,65,0,0,0,'static',1,0),('block1024',16,1025,0,0,0,'static',1,2),('exact',65,1<<20,30,0,14,'static',65535,0))
    if mode=='maximum':cases=(('exact',16384,1<<20,30,0,14,'static',65535,0),)
    if mode=='full-block':cases=(('block1024',16384,1<<20,0,0,0,'static',65535,12),)
    for d,reps in (((4,1),) if mode!='matrix' else ((4,1),(4,2),(8,1),(8,2))):
        for acc,width,length,fv,fo,E,policy,scale,drop in cases:
            p=replace(spec(acc,width,8350+done,reps),schema=c.bounds.Spec(length,width,fv,fo,E,policy,scale,acc,drop));Q,S,G,A,B=constants(p);z=length*Q;cap=z*S if acc=='exact' else G;vs=[0,-min(1,cap),min(cap,31),-min(cap,32)]
            if mode=='full-block':vs=[-(1<<23),0,32767<<8,-1]
            totals=(vs*((width+3)//4))[:width];print('honest start',done+1,d,reps,acc,width,flush=True);proof,state=c.prove(p,z,totals,d);values,roots=oracle(p,z,totals);out=c.verify(p,roots,proof,d);assert out['state']==state;account(p,out,d);digest.update(state);done+=1;print('honest passed',done,d,reps,acc,width,flush=True)
            if mode=='full-block':assert values['output'][0]==-32768 and values['quotient'][0]==32768
    print(json.dumps(dict(mode=mode,proofs=done,sha256=digest.hexdigest()),sort_keys=True),flush=True)


if __name__=='__main__':
    modes={'--corpus':corpus,'--controls':controls,'--boundaries':boundaries,'--composition':composition,'--honest':honest,'--maximum':lambda:honest('maximum'),'--full-block':lambda:honest('full-block')}
    if sys.argv[1:]:
        assert all(mode in modes for mode in sys.argv[1:])
        for mode in sys.argv[1:]:modes[mode]()
    else:
        for test in modes.values():test()
