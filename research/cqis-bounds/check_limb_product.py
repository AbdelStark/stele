# /// script
# requires-python = ">=3.12"
# dependencies = ["blake3==1.0.11", "python-flint==0.9.0"]
# ///
"""Q26/Q31 complete revealing unsigned limb product consumers."""
import copy
from dataclasses import replace
import hashlib
import json
import random
import struct
import sys
import limb_product as m


def rejects(reason,call):
    try: call()
    except ValueError as error: assert str(error)==reason,(reason,str(error))
    else: raise AssertionError('accepted '+reason)


def public():
    rng=random.Random(2671); digest=hashlib.sha256()
    for case in range(10000):
        d=(4,8)[case%2]; h=case%7
        rho=tuple(rng.randrange(m.sc.P) for _ in range(d))
        if case%11<3: rho=m.sc.scalar((0,1,-1)[case%11],d)
        point=[tuple(rng.randrange(m.sc.P) for _ in range(d)) for _ in range(h)]
        if case%13<2: point=[m.sc.scalar(case%13,d)]*h
        powers=m.powers(rho,1<<h,d)
        expected=m.cr.zc.folded(powers,point)
        assert m.power_mle(rho,point,d)==expected
        digest.update(m.sc.encode(expected))
    assert digest.hexdigest()=='145f5f68e34642cd41e8b640155b50d7d8327270f34a913e359107b9a8695ff7'
    print(json.dumps(dict(public_cases=10000,sha256=digest.hexdigest()),sort_keys=True),flush=True)


def corpus():
    rng=random.Random(2670); digest=hashlib.sha256(); columns=0
    for case in range(10000):
        bits=(4,8)[case%2]; count=1+case%5; width=case%161
        schema=m.limbs.Spec(count,rng.getrandbits(width),rng.getrandbits(width),bits)
        p=m.Spec(schema,case,47,53,1+case%2); v=m.derive(p,4)
        left=tuple(rng.randrange(schema.left_max+1) for _ in range(count)); right=tuple(rng.randrange(schema.right_max+1) for _ in range(count))
        witness=m.limbs.witness(schema,left,right); digits,z,c=m.witness(p,witness)
        assert sum(z[j]<<(bits*j) for j in range(v['s']))==sum(x*y for x,y in zip(left,right))
        assert z[v['k']:]==[0]*(v['s']-v['k']) and c[0]==c[v['k']]==0 and c[v['k']+1:]==[0]*(v['s']-v['k']-1)
        assert all(2*x<m.sc.P for x in v['cert']['lhs']+v['cert']['rhs'])
        if case<100:
            for d in (4,8):
                for rho in (m.sc.scalar(0,d),m.sc.scalar(1,d),m.sc.scalar(-1,d),tuple(rng.randrange(m.sc.P) for _ in range(d))):
                    tables=m.collapse(v,digits,rho,d)
                    actual=m.cr.zc.total((m.sc.mul(x,y) for x,y in zip(*tables)),d)
                    assert actual==m.target(p,v,z,c,rho,d)
        digest.update(v['raw']+bytes(digits)+bytes(z)+b''.join(struct.pack('<I',x) for x in c)); columns+=v['k']
    assert columns==301747 and digest.hexdigest()=='4ec874facbb032e3b1ac6b612227ea1350e35d28877acfbb0baeeb6de01b8a4c'
    print(json.dumps(dict(seed=2670,cases=10000,columns=columns,sha256=digest.hexdigest()),sort_keys=True),flush=True)


def honest():
    digest=hashlib.sha256(); total=0
    for d in (4,8):
        for bits in (4,8):
            for repetitions in (1,2):
                for case,(count,lmax,rmax) in enumerate(((1,0,0),(3,257,31),(1,(1<<159)+257,1))):
                    schema=m.limbs.Spec(count,lmax,rmax,bits); p=m.Spec(schema,501+case,47,53,repetitions)
                    w=m.limbs.witness(schema,tuple(lmax//(i+1) for i in range(count)),tuple(rmax//(i+1) for i in range(count)))
                    digits,z,c=m.witness(p,w); roots=m.roots(p,digits,z,c); proof,state=m.prove(p,w,d)
                    out=m.verify(p,roots[:2],proof,d); v=m.derive(p,d); a,b=v['layout']['a'],v['layout']['b']; h,g=v['h'],v['g']
                    assert out['state']==state
                    dims=([a+b+3] if bits==4 else [])+[a+b+2,g+3,g+3]; f=lambda n:3*n*(n-1)//2+2*n
                    assert out['account']==dict(identities=[((1<<k)+255,repetitions) for k in dims],
                        lookup_reduction_numerator=sum(repetitions*(f(k)+f(8)+3*k) for k in dims),
                        range_reduction_numerator=(20*a+18*b+29 if bits==4 else 11*a+11+9*b)+2*(9*g+10),
                        product_identity_numerator=v['k']-1,product_reduction_numerator=2*a+4*h,denominator=m.sc.P**d)
                    core=out['core']; assert core['draws']=={m.cr.zc.tr.CHALLENGE:1+a+2*h}
                    assert core['sc']==[dict(id=256*p.identity+128+j,m=n,degree=2,field_degree=d,numerator=2*n) for j,n in enumerate((a,h,h))]
                    assert len(core['original_claims'])==2 and len(core['public_claims'])==2
                    for side,(identity,point,value) in enumerate(core['original_claims']):
                        assert identity==p.source and point==core['sources'][side]['point']+[m.sc.scalar(side,d)]+core['main']['point']
                        assert len(point)==h+1+a
                    digest.update(state); total+=1; print('proof',d,bits,repetitions,case,flush=True)
    assert total==24
    assert digest.hexdigest()=='5b7a12834d5289240440c70ab8d33b5e291f8bc69ec4141c171f880e3f57abd3'
    print(json.dumps(dict(proofs=total,sha256=digest.hexdigest()),sort_keys=True),flush=True)


def controls():
    d=4; p=m.Spec(m.limbs.Spec(1,5,5,8),597,59,61,1)
    w=m.limbs.witness(p.schema,(2,),(3,)); digits,z,c=m.witness(p,w); expected=m.roots(p,digits,z,c)[:2]
    proof,_=m.prove(p,w,d)
    for key,path in (('input','digits'),('output','words'),('carry','words')):
        changed=copy.deepcopy(proof); changed[key][path][0]+=1
        rejects(key.title()+':CommitmentMismatch',lambda:m.verify(p,expected,changed,d))
    changed=copy.deepcopy(proof); changed['core']['main']['final'][0]=m.sc.scalar(3,d)
    rejects('Product:FinalEvaluationMismatch',lambda:m.verify(p,expected,changed,d))
    for key in ('left','right'):
        changed=copy.deepcopy(proof); changed['core'][key]['final'][0]=m.sc.scalar(2,d)
        changed['core'][key]['final'][1]=m.sc.mul(changed['core'][key]['final'][1],m.sc.scalar(pow(2,-1,m.sc.P),d))
        rejects(key.title()+'Source:PowerClaimMismatch',lambda:m.verify(p,expected,changed,d))
    # Wrong product in valid ranges reaches the actual multiplication check.
    wrong={**w,'result':(7,)}; false,_=m.prove(p,wrong,d); ds,zs,cs=m.witness(p,wrong)
    rejects('Product:FinalEvaluationMismatch',lambda:m.verify(p,m.roots(p,ds,zs,cs)[:2],false,d))
    # Coherent B^2 arithmetic satisfies all core equations but is not A*B.
    for right,answer,fake_left in ((3,9,3),(0,0,5)):
        w=m.limbs.witness(p.schema,(2,),(right,)); w={**w,'result':(answer,)}
        pairs=m.ranges(p,w,d); false,_=m.assemble(p,pairs,d); ds,zs,cs=m.witness(p,w); roots=m.roots(p,ds,zs,cs)
        fake=list(ds); fake[0]=fake_left
        false['core'],_=m.core_prove(p,roots,[x[1] for x in pairs],fake,zs,cs,d)
        rejects('LeftSource:SourceClaimMismatch',lambda:m.verify(p,roots[:2],false,d))
    # The two virtual values must refer to the same original row pairing.
    pair=replace(p,schema=m.limbs.Spec(2,3,3,8)); w=m.limbs.witness(pair.schema,(1,2),(2,3)); w={**w,'result':(7,)}
    pairs=m.ranges(pair,w,d); false,_=m.assemble(pair,pairs,d); ds,zs,cs=m.witness(pair,w); roots=m.roots(pair,ds,zs,cs)
    fake=ds[:2]+list(reversed(ds[2:])); false['core'],_=m.core_prove(pair,roots,[x[1] for x in pairs],fake,zs,cs,d)
    rejects('RightSource:SourceClaimMismatch',lambda:m.verify(pair,roots[:2],false,d))
    # At fixed rho=radix every interior carry change cancels. The real fresh
    # challenge must reject this legal-range wrong carry instead.
    carry=replace(p,schema=m.limbs.Spec(1,255,255,8)); w=m.limbs.witness(carry.schema,(200,),(199,)); bad=list(w['carry']); bad[1]+=1
    wrong={**w,'carry':tuple(bad)}; ds,zs,cs=m.witness(carry,wrong); v=m.derive(carry,d); rho=m.sc.scalar(256,d)
    assert m.target(carry,v,zs,cs,rho,d)==m.sc.scalar(200*199,d)
    assert m.target(carry,v,zs,cs,m.sc.scalar(1,d),d)!=m.sc.scalar(200*199,d)
    false,_=m.prove(carry,wrong,d)
    rejects('Product:FinalEvaluationMismatch',lambda:m.verify(carry,m.roots(carry,ds,zs,cs)[:2],false,d))
    # All product equations can hold with C0=1 and result7, or with a nonzero
    # ignored output padding digit. Only the actual range consumers rule them out.
    def wrapped(spec,values,index):
        assert spec.caps[index]==0 and values[index]==1
        honest=list(values); honest[index]=0; words,bs,cs=m.cr.witness(spec,honest); n=len(words)
        words[index]=bs[index]=1
        for j in range(4): bs[(4+j)*n+index]=255; cs[j*n+index]=1
        return m.cr.assemble(spec,words,bs,cs,d)
    v=m.derive(p,d); w=m.limbs.witness(p.schema,(2,),(3,)); ds,zs,cs=m.witness(p,w)
    for role in ('carry','output'):
        oz=list(zs); oc=list(cs)
        if role=='carry': oz[0]=7; oc[0]=1
        else: oz[1]=1
        assert m.target(p,v,oz,oc,m.sc.scalar(17,d),d)==m.sc.scalar(6,d)
        output=wrapped(v['output'],oz,1) if role=='output' else m.cr.prove(v['output'],oz,d)
        carries=wrapped(v['carry'],oc,0) if role=='carry' else m.cr.prove(v['carry'],oc,d)
        false,_=m.assemble(p,[m.ls.prove(v['input'],ds,d),output,carries],d)
        rejects(role.title()+':TerminalCarry:RoundSumMismatch',lambda:m.verify(p,m.roots(p,ds,oz,oc)[:2],false,d))
    for mutate,reason in ((lambda q:q['core'].pop('right'),'ProofShape'),
                          (lambda q:q['core']['left']['final'].pop(),'ProofShape'),
                          (lambda q:q['core']['main']['final'].__setitem__(0,(True,0,0,0)),'NoncanonicalField')):
        changed=copy.deepcopy(proof); mutate(changed); rejects(reason,lambda:m.verify(p,expected,changed,d))
    rejects('Input:CommitmentMismatch',lambda:m.verify(replace(p,source=60),expected,proof,d))
    rejects('Output:CommitmentMismatch',lambda:m.verify(replace(p,output=62),expected,proof,d))
    for bad in (replace(p,identity=1<<50),replace(p,output=p.source),replace(p,source=m.derive(p,d)['base']),replace(p,repetitions=True)):
        rejects('Spec',lambda:m.derive(bad,d))
    rejects('Capacity',lambda:m.prove(replace(p,schema=m.limbs.Spec(2049,255,1,8)),None,d))
    print('limb-product controls passed',flush=True)


if __name__=='__main__':
    modes={'--public':public,'--corpus':corpus,'--honest':honest,'--controls':controls}
    if sys.argv[1:]:
        assert all(x in modes for x in sys.argv[1:])
        for mode in sys.argv[1:]: modes[mode]()
    else:
        for test in modes.values(): test()
