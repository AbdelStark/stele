# /// script
# requires-python = ">=3.12"
# dependencies = ["numpy==2.3.4", "blake3==1.0.11", "python-flint==0.9.0"]
# ///
"""RFC-0022 left role: complete sources, high zeros and zero-hidden factors."""
import copy
from dataclasses import replace
import hashlib
import json
import random
import sys
import numpy as np
import norm_left as c

r=c.r


def rejects(reason,call):
    try:call()
    except ValueError as error:assert str(error)==reason,(reason,str(error))
    else:raise AssertionError('accepted '+reason)


def spec(count=3,identity=2500,repetitions=1,exponent=16):
    schema=c.norm.Spec(count,2,0,0,1,3) if exponent==0 else c.norm.Spec(count,1,0,exponent-1,1,3) if exponent<=15 else c.norm.Spec(count,0,0,14,1,3)
    return c.Spec(schema,identity,439,443,449,repetitions)


def corpus():
    rng=random.Random(2721);digest=hashlib.sha256();cells=0
    for case in range(10000):
        count=1+case%63;p=spec(count,case,1+case%2,case%17);v=c.derive(p,4);factor=rng.randrange(1,v['limit']+1)
        if case%3==0:factor=v['limit']
        ts=np.array([rng.randrange((1<<44)+1) for _ in range(count)],dtype=np.int64);ts[0]=(0,1<<44,255,(1<<44)-1)[case%4];qs=[rng.randrange(32769) for _ in range(count)];w=c.witness(p,ts.tolist(),factor,qs);n=v['n'];padded=np.pad(ts,(0,n-count))
        # Large t*L values intentionally exceed the output range in this producer
        # corpus; complete honest/forged proofs below test that range and equality.
        assert w['product']==ts.tolist() and w['quotient']==qs and w['offset']==[factor-1]
        raw=np.zeros((8,n),dtype=np.int64)
        for k in range(8):
            for j in range(3):
                if k>=j:raw[k]+=((padded>>(8*(k-j)))&255)*((factor>>(8*j))&255)
        carry=np.zeros(n,dtype=np.int64);all_carry=[];out=[]
        for row in raw:out.extend(((row+carry)%256).tolist());carry=(row+carry)//256;all_carry.extend(carry.tolist())
        assert not carry.any() and out==[int(x)>>(8*k)&255 for k in range(8) for x in padded*factor]
        for g in range(2):
            name='carry_'+str(g);values=all_carry[4*g*n:4*(g+1)*n]
            if name in w:assert w[name]==values
            else:assert not any(values)
        assert all(0<=x<=cap for name in w for x,cap in zip(w[name],v['ranges'][name].caps))
        digest.update(v['raw']+factor.to_bytes(8,'little')+bytes(out)+b''.join(x.to_bytes(2,'little') for x in all_carry));cells+=8*n
    for exponent in range(17):
        v=c.derive(spec(16384,(1<<44)-1,2,exponent),8);assert v['limit']==1<<exponent
        assert all(r.derive(child,8)[2]*r.derive(child,8)[3]<=131072 and r.lookup_plan(child,8)['m']<=18 for child in v['ranges'].values())
        assert len(v['ranges'])==(3 if exponent==0 else 5) and max(v['cert']['lhs']+v['cert']['rhs'])<=130815
    assert v['cert']['carry_caps']==(0,254,509,510,510,510,272,17,0)
    p=spec();v=c.derive(p,4)
    for bad in (replace(p,identity=1<<44),replace(p,repetitions=True),replace(p,factor=p.quotient),replace(p,product=v['base']),replace(p,schema=replace(p.schema,F=True))):rejects('Spec',lambda:c.derive(bad,4))
    rejects('Spec',lambda:c.derive(spec(16385),4));rejects('Spec',lambda:c.derive(p,True))
    for ts,factor,qs in (([False]*3,1,[0]*3),([(1<<44)+1]*3,1,[0]*3),([0],1,[0]*3),([0]*3,0,[0]*3),([0]*3,65537,[0]*3),([0]*3,True,[0]*3),([0]*3,1,[32769]*3),([0]*3,1,[False]*3)):
        rejects('Input',lambda:c.witness(p,ts,factor,qs))
    assert cells==3383720 and digest.hexdigest()=='9857f6eaa1196e14d0e2dd30d2427cdd427ef315188d057d13a86425a50cb6dc'
    print(json.dumps(dict(seed=2721,cases=10000,column_cells=cells,sha256=digest.hexdigest()),sort_keys=True),flush=True)


def account(p,out,d):
    v=c.derive(p,d);a=v['a'];bs={name:r.derive(child,d)[1] for name,child in v['ranges'].items()};bl=bs['offset'];bg=[b for name,b in bs.items() if name.startswith('carry_')];g=len(bg);dims=[a+4,a+2,bl+1]+[a+b+3 for b in bg];f=lambda m:3*m*(m-1)//2+2*m
    assert out['account']==dict(identities=[((1<<m)+255,p.repetitions) for m in dims],lookup_reduction_numerator=sum(p.repetitions*(f(m)+f(8)+3*m) for m in dims),range_reduction_numerator=(21+9*g)*a+37+7*bl+18*g+7*sum(bg),denominator=r.sc.P**d)
    assert len(out['claims'])==9 and out['draws']=={r.zc.WEIGHT:a+3,r.zc.tr.CHALLENGE:a+3}
    assert all(sum(row.get(label,0) for row in [out['draws']]+[child['draws'] for child in out['children']])==(9+4*g)*a+15+3*bl+8*g+3*sum(bg) for label in (r.zc.WEIGHT,r.zc.tr.CHALLENGE))


def honest(maximum=False,nonzero=False):
    digest=hashlib.sha256();count=0;cases=((1,0,1),(3,8,255),(16,9,511),(65,16,65536))
    for d,reps in (((4,1),) if maximum else ((4,1),(4,2),(8,1),(8,2))):
        for size,exponent,factor in (((16384,16,511 if nonzero else 65536),) if maximum else cases):
            p=spec(size,2510+count,reps,exponent);limit=32768//factor;ts=([limit,0,min(limit,1),max(0,limit-1),min(limit,255)]*((size+4)//5))[:size];qs=[t*factor for t in ts]
            print('honest start',count+1,d,reps,size,factor,flush=True);proof,state=c.prove(p,ts,factor,qs,d);out=c.verify(p,c.expected_roots(p,ts,factor,qs),proof,d)
            assert out['state']==state;account(p,out,d);digest.update(state);count+=1;print('honest passed',count,d,reps,size,factor,flush=True)
    if not maximum:assert digest.hexdigest()=='c80e8554fa030d0a4d98634faf0d35f0e856041d48c1c32d308d7eeb581a7b18'
    print(json.dumps(dict(maximum=maximum,nonzero=nonzero,proofs=count,sha256=digest.hexdigest()),sort_keys=True),flush=True)


def controls():
    p=spec();d=4;ts=[64,0,1];factor=511;qs=[x*factor for x in ts];v=c.derive(p,d);w=c.witness(p,ts,factor,qs);pairs=c.prepare(p,ts,factor,qs,d);proof,state=c.assemble(p,pairs,d);roots=c.expected_roots(p,ts,factor,qs)
    assert c.verify(p,roots,proof,d)['state']==state
    for name in v['ranges']:
        bad=copy.deepcopy(proof);bad[name]['words'][0]^=1;rejects(name.title()+':CommitmentMismatch',lambda:c.verify(p,roots,bad,d))
    for name,index,delta in (('quotient',1,1),('product',1,r.sc.P),('carry_0',0,1),('carry_1',0,1)):
        values=w[name].copy();values[index]+=delta;changed=dict(pairs);changed[name]=r.prove(v['ranges'][name],values,d);bad,_=c.assemble(p,changed,d)
        rejects('LeftColumns:RoundSumMismatch',lambda:c.verify(p,c.roots(p,bad),bad,d))
    bad=copy.deepcopy(proof);bad['zero']['final'][6][0]=r.sc.add(bad['zero']['final'][6][0],r.sc.scalar(1,d));bad['zero']['final'][7][0]=r.sc.add(bad['zero']['final'][7][0],r.sc.scalar(1,d));rejects('LeftColumns:ClaimMismatch',lambda:c.verify(p,roots,bad,d))
    zero=spec(1,2530);proof,_=c.prove(zero,[0],65536,[0],d);roots=c.expected_roots(zero,[0],65536,[0])
    for index in (1,3,5):
        bad=copy.deepcopy(proof);bad['zero']['final'][index][0]=r.sc.add(bad['zero']['final'][index][0],r.sc.scalar(1,d));rejects('LeftColumns:ClaimMismatch',lambda:c.verify(zero,roots,bad,d))
    bad,_=c.prove(zero,[0],65535,[0],d);rejects('Factor:CommitmentMismatch',lambda:c.verify(zero,roots,bad,d))
    bad,_=c.prove(zero,[1<<44],65536,[0],d);rejects('LeftColumns:RoundSumMismatch',lambda:c.verify(zero,c.expected_roots(zero,[1<<44],65536,[0]),bad,d))
    for key in ('mask','certificate','carry_2'):rejects('ProofShape',lambda:c.verify(zero,roots,dict(proof,**{key:{}}),d))
    bad=copy.deepcopy(proof);bad['zero']['rounds'][0][0]=(False,0,0,0);rejects('NoncanonicalField',lambda:c.verify(zero,roots,bad,d))
    print('false q, product+p, carry/original mutations and zero-hidden factor claims reject',flush=True)


def boundaries():
    p=spec(3,2540);d=4;ts=[64,0,1];factor=511;qs=[t*factor for t in ts];v=c.derive(p,d);w=c.witness(p,ts,factor,qs);pairs=c.prepare(p,ts,factor,qs,d);proof,_=c.assemble(p,pairs,d);roots=c.roots(p,proof);n=v['n']
    for name,index in (('carry_0',n-1),('carry_1',3*n)):
        child=v['ranges'][name];caps=list(child.caps);values=w[name].copy();caps[index]=values[index]=1;changed=dict(pairs);changed[name]=r.assemble(child,*r.witness(replace(child,caps=tuple(caps)),values),d);bad,_=c.assemble(p,changed,d)
        rejects(name.title()+':CapRelation:RoundSumMismatch',lambda:c.verify(p,roots,bad,d))
    for name in ('product','quotient'):
        bad=copy.deepcopy(proof);bad[name]['words'][n-1]=1;rejects(name.title()+':CommitmentMismatch',lambda:c.verify(p,roots,bad,d))
    child=v['ranges']['quotient'];values=[32769,0,511];loose=replace(child,caps=(65535,)*3);badpair=r.assemble(child,*r.witness(loose,values),d);bad,_=c.assemble(p,dict(pairs,quotient=badpair),d);rejects('Quotient:CapRelation:RoundSumMismatch',lambda:c.verify(p,c.roots(p,bad),bad,d))
    small=spec(1,2541,1,8);sv=c.derive(small,d);child=sv['ranges']['offset']
    # An overflow that changes the child byte width is rejected as shape, before
    # it can be mistaken for an allowed factor reconstruction.
    rejects('OpeningShape',lambda:r.assemble(child,*r.witness(replace(child,caps=(256,)),[256]),d))
    child=v['ranges']['offset'];rejects('OpeningShape',lambda:r.assemble(child,*r.witness(replace(child,caps=(65536,)),[65536]),d))
    small=spec(1,2542,1,0);bad,_=c.prove(small,[32768],1,[32768],d);expect=c.expected_roots(small,[32768],1,[32768]);expect[1]=r.root(small.factor,[1]+[0]*6+[1]);rejects('Factor:CommitmentMismatch',lambda:c.verify(small,expect,bad,d))
    sv=c.derive(small,d);parts=c.prepare(small,[0],1,[0],d);child=sv['ranges']['offset'];badpair=r.assemble(child,*r.witness(replace(child,caps=(1,)),[1]),d);bad,_=c.assemble(small,dict(parts,offset=badpair),d)
    # One scalar byte has dimension zero: no round exists before the final check.
    rejects('Offset:CapRelation:FinalEvaluationMismatch',lambda:c.verify(small,c.roots(small,bad),bad,d))
    print('ragged sources, carry endpoints, q overflow, offset widths and factor extensions checked',flush=True)


def composition():
    import norm_product as product
    import norm_output_factors as factors
    import signed_source as signed
    p=spec(3,2550,1,1);d=4;ts=[0,8192,16384];factor=2;qs=[t*factor for t in ts];proof,state=c.prove(p,ts,factor,qs,d);roots=c.expected_roots(p,ts,factor,qs)
    pp=product.Spec(p.schema,2551,457,461,p.product,1);child,st=product.prove(pp,[0,1,2],8192,d);pr=product.expected_roots(pp,[0,1,2],8192,ts);assert product.verify(pp,pr,child,d)['state']==st and pr[2]==roots[0]
    sp=signed.Spec(2552,463,p.quotient,16,3,1);child,st=signed.prove(sp,[0,16384,-32768],d);sv=signed.derive(sp,d);raw=r.source_root(sv['ranges'][0],child['ranges'][0]['words']);assert signed.verify(sp,[raw,roots[2]],child,d)['state']==st
    fp=factors.Spec(p.schema,2553,467,479,487,491,499,1);child,st=factors.prove(fp,0,-23,d);fc=c.norm.constants(p.schema);fr=factors.expected_roots(fp,0,-23,0,fc['P'],child['factors']);assert factors.verify(fp,fr,child,d)['state']==st
    roots[1]=r.root(p.factor,child['factors'][34:42]);assert c.verify(p,roots,proof,d)['state']==state
    print('actual product, signed-Y magnitude and verified factor L compose',flush=True)


if __name__=='__main__':
    modes={'--corpus':corpus,'--honest':honest,'--maximum':lambda:honest(True),'--full-nonzero':lambda:honest(True,True),'--controls':controls,'--boundaries':boundaries,'--composition':composition}
    if sys.argv[1:]:
        assert all(mode in modes for mode in sys.argv[1:])
        for mode in sys.argv[1:]:modes[mode]()
    else:
        for test in modes.values():test()
