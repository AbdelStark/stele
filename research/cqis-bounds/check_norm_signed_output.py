# /// script
# requires-python = ">=3.12"
# dependencies = ["numpy==2.3.4", "blake3==1.0.11", "python-flint==0.9.0"]
# ///
"""RFC-0022 signed output: canonical product signs survive rounded zeros."""
import copy
from dataclasses import replace
import hashlib
import json
import random
import sys
import numpy as np
import norm_signed_output as c

r=c.r


def rejects(reason,call):
    try:call()
    except ValueError as error:assert str(error)==reason,(reason,str(error))
    else:raise AssertionError('accepted '+reason)


def spec(count=3,identity=2600,repetitions=1):
    return c.Spec(c.norm.Spec(count,30,30,0,1,3),identity,503,509,521,523,541,547,repetitions)


def corpus():
    rng=random.Random(2722);digest=hashlib.sha256();cells=0
    for case in range(10000):
        count=1+case%127;p=replace(spec(count,case,1+case%2),schema=c.norm.Spec(count,rng.randrange(31),rng.randrange(31),rng.randrange(15),1,3));v=c.derive(p,4);n=v['n']
        xs=np.array([rng.randrange(-32768,32768) for _ in range(count)],dtype=np.int64);gs=np.array([rng.randrange(-32768,32768) for _ in range(count)],dtype=np.int64);xs[0],gs[0]=((-32768,1),(-1,1),(0,-32768),(-32768,-32768),(1,1))[case%5]
        signs=((xs*gs)<0).astype(np.int64);qs=np.array([rng.randrange(32768+int(s)) for s in signs],dtype=np.int64);qs[0]=(32768 if signs[0] else 32767) if case%3==0 else 0;ys=qs*(1-2*signs)
        c.inputs(p,xs.tolist(),gs.tolist(),ys.tolist());nw=c.ns.witness(v['sign'],xs.tolist(),gs.tolist());raw,mag,flags,carry=c.signed.witness(v['output'],ys.tolist())
        magnitude=[x>>(8*k)&255 for k in range(2) for x in mag+[0]*(n-count)];proof={'sign':{'flags':{'words':nw['flags']+[0]*n}},'output':{'ranges':[{}, {'words':magnitude},{'words':flags}]}}
        actual=c.views(p,proof);expected=[np.pad(qs,(0,n-count)),np.pad(signs,(0,n-count)),np.pad((ys<0).astype(np.int64),(0,n-count))]
        assert actual==[row.tolist() for row in expected] and np.all(expected[0]*expected[1]==expected[0]*expected[2])
        assert np.all(ys+32768+2*signs*qs==32768+qs) and raw==(ys%65536).tolist() and mag==qs.tolist()
        digest.update(v['raw']+b''.join(x.to_bytes(2,'little') for x in actual[0])+bytes(actual[1]+actual[2]));cells+=3*n
    p=spec(16384,(1<<40)-1,2);v=c.derive(p,8);assert v['base']+(1<<22)==(1<<63)+(1<<62)
    nv=c.ns.derive(v['sign'],8);sv=c.signed.derive(v['output'],8);assert sv['base']==v['base']+512 and nv['base']==v['base']+(1<<20)
    for bad in (replace(p,identity=1<<40),replace(p,repetitions=True),replace(p,output=p.left),replace(p,sign=v['base']),replace(p,schema=replace(p.schema,G=True))):rejects('Spec',lambda:c.derive(bad,4))
    rejects('Spec',lambda:c.derive(spec(16385),4));rejects('Spec',lambda:c.derive(p,True))
    for xs,gs,ys in (([False]*3,[1]*3,[0]*3),([0]*3,[32768]*3,[0]*3),([0]*3,[1]*3,[32768]*3),([0]*3,[1]*3,[-32769]*3),([0]*3,[1]*3,[True]*3),([0],[1]*3,[0]*3)):
        rejects('Input',lambda:c.inputs(spec(),xs,gs,ys))
    assert cells==2545743 and digest.hexdigest()=='1b8c73debc78bcb8f1e30525b558ced4008d42f96490569fb8f294ab4a3c28a3'
    print(json.dumps(dict(seed=2722,cases=10000,view_cells=cells,sha256=digest.hexdigest()),sort_keys=True),flush=True)


def account(p,out,d):
    a=c.derive(p,d)['a'];dims=[a+2]*6+[a+3]*4+[a+2]*3;f=lambda m:3*m*(m-1)//2+2*m
    assert out['account']==dict(identities=[((1<<m)+255,p.repetitions) for m in dims],lookup_reduction_numerator=sum(p.repetitions*(f(m)+f(8)+3*m) for m in dims),range_reduction_numerator=177*a+183,denominator=r.sc.P**d)
    assert len(out['claims'])==3 and out['draws']==({r.zc.WEIGHT:a,r.zc.tr.CHALLENGE:a} if a else {})
    sign,output=out['children'];xy=sign['xy'];draws=[out['draws'],sign['draws'],xy['draws'],output['draws']]+[part['draws'] for part in xy['children']+sign['ranges']+output['ranges']]
    draws += [part['draws'] for source in xy['children'][:2] for part in source['ranges']]
    assert all(sum(row.get(label,0) for row in draws)==74*a+75 for label in (r.zc.WEIGHT,r.zc.tr.CHALLENGE))


def honest(maximum=False):
    digest=hashlib.sha256();count=0
    for d,reps in (((4,1),) if maximum else ((4,1),(4,2),(8,1),(8,2))):
        for size in ((16384,) if maximum else (1,5,16,65)):
            p=spec(size,2610+count,reps);xs=([-32768,0,32767,-1,255,1,0,-1]*((size+7)//8))[:size];gs=([1,-32768,1,1,-255,-1,0,-32768]*((size+7)//8))[:size];ys=([-32768,0,32767,0,-255,-1,0,1]*((size+7)//8))[:size]
            print('honest start',count+1,d,reps,size,flush=True);proof,state=c.prove(p,xs,gs,ys,d);out=c.verify(p,c.expected_roots(p,xs,gs,ys),proof,d)
            assert out['state']==state;account(p,out,d);digest.update(state);count+=1;print('honest passed',count,d,reps,size,flush=True)
    print(json.dumps(dict(maximum=maximum,proofs=count,sha256=digest.hexdigest()),sort_keys=True),flush=True)


def controls():
    p=spec();d=4;xs=[-32768,-1,0];gs=[1,1,-32768];ys=[-32768,0,0];v=c.derive(p,d);pairs=c.prepare(p,xs,gs,ys,d);proof,state=c.assemble(p,pairs,d);roots=c.expected_roots(p,xs,gs,ys);assert c.verify(p,roots,proof,d)['state']==state
    reasons=['ProductSign:XY:Left:Raw:CommitmentMismatch','ProductSign:XY:Right:Raw:CommitmentMismatch','ProductSign:XY:Output:CommitmentMismatch','ProductSign:Sign:CommitmentMismatch','Output:Raw:CommitmentMismatch','Output:Magnitude:CommitmentMismatch']
    for index,reason in enumerate(reasons):
        bad=roots.copy();bad[index]=bytes([bad[index][0]^1])+bad[index][1:];rejects(reason,lambda:c.verify(p,bad,proof,d))
    bad,_=c.prove(p,xs,gs,[32767,0,0],d);rejects('SignedOutput:RoundSumMismatch',lambda:c.verify(p,c.expected_roots(p,xs,gs,[32767,0,0]),bad,d))
    bad=copy.deepcopy(proof)
    for index in (1,2):bad['zero']['final'][index][0]=r.sc.add(bad['zero']['final'][index][0],r.sc.scalar(1,d))
    rejects('SignedOutput:ClaimMismatch',lambda:c.verify(p,roots,bad,d))
    nv=c.ns.derive(v['sign'],d);nw=c.ns.witness(v['sign'],xs,gs);npairs=c.ns.prepare(v['sign'],xs,gs,d);flags=nw['flags'].copy();flags[2*v['n']+1]=0;changed=dict(npairs,flags=r.prove(nv['flags'],flags,d));bad,_=c.assemble(p,dict(pairs,sign=c.ns.assemble(v['sign'],changed,d)),d)
    rejects('ProductSign:Sign:RoundSumMismatch',lambda:c.verify(p,c.roots(p,bad),bad,d))
    flags=nw['flags'].copy();flags[1]=0;pred=nw['predecessor'].copy();pred[1]=1;changed=dict(npairs,flags=r.prove(nv['flags'],flags,d),predecessor=r.prove(nv['predecessor'],pred,d));bad,_=c.assemble(p,dict(pairs,sign=c.ns.assemble(v['sign'],changed,d)),d)
    rejects('ProductSign:Predicates:RoundSumMismatch',lambda:c.verify(p,c.roots(p,bad),bad,d))
    sv=c.signed.derive(v['output'],d);spairs,cs=c.signed.ranges(v['output'],ys,d);spairs[1]=r.prove(sv['ranges'][1],[32768,1,0],d);bad,_=c.assemble(p,dict(pairs,output=c.signed.assemble(v['output'],spairs,cs,d)),d)
    rejects('Output:Positive:RoundSumMismatch',lambda:c.verify(p,c.roots(p,bad),bad,d))
    for key in ('mask','certificate','receipt'):rejects('ProofShape',lambda:c.verify(p,roots,dict(proof,**{key:{}}),d))
    bad=copy.deepcopy(proof);bad['zero']['rounds'][0][0]=(False,0,0,0);rejects('NoncanonicalField',lambda:c.verify(p,roots,bad,d))
    print('all six roots, wrong output sign, q=0 predicates/sign, preserving originals and signed reconstruction reject',flush=True)


def zeros():
    p=spec(1,2630);d=4
    for x,indices in ((-1,(1,2)),(1,(0,))):
        proof,state=c.prove(p,[x],[1],[0],d);roots=c.expected_roots(p,[x],[1],[0]);assert c.verify(p,roots,proof,d)['state']==state
        for index in indices:
            bad=copy.deepcopy(proof);bad['zero']['final'][index][0]=r.sc.add(bad['zero']['final'][index][0],r.sc.scalar(1,d));rejects('SignedOutput:ClaimMismatch',lambda:c.verify(p,roots,bad,d))
    print('negative products round to canonical zero; every zero-hidden original remains consumed',flush=True)


def boundaries():
    p=spec(3,2640);d=4;xs=[-1,0,1];gs=[1,1,1];ys=[-32768,0,32767];v=c.derive(p,d);pairs=c.prepare(p,xs,gs,ys,d);proof,_=c.assemble(p,pairs,d);roots=c.roots(p,proof);n=v['n']
    for index,name in ((0,'Raw'),(1,'Magnitude')):
        bad=copy.deepcopy(proof);bad['output']['ranges'][index]['words'][n-1]=1;rejects('Output:'+name+':CommitmentMismatch',lambda:c.verify(p,roots,bad,d))
        sv=c.signed.derive(v['output'],d);spairs,cs=c.signed.ranges(v['output'],ys,d);child=sv['ranges'][index];values=([y%65536 for y in ys] if index==0 else list(map(abs,ys)))+[1];loose=replace(child,caps=child.caps+(1,));spairs[index]=r.assemble(child,*r.witness(loose,values),d);bad,_=c.assemble(p,dict(pairs,output=c.signed.assemble(v['output'],spairs,cs,d)),d)
        rejects('Output:'+name+':CapRelation:RoundSumMismatch',lambda:c.verify(p,c.roots(p,bad),bad,d))
    nv=c.ns.derive(v['sign'],d);npairs=c.ns.prepare(v['sign'],xs,gs,d);flags=c.ns.witness(v['sign'],xs,gs)['flags'];child=nv['flags'];caps=list(child.caps);flags[3*n-1]=caps[3*n-1]=1;npairs['flags']=r.assemble(child,*r.witness(replace(child,caps=tuple(caps)),flags),d);bad,_=c.assemble(p,dict(pairs,sign=c.ns.assemble(v['sign'],npairs,d)),d)
    rejects('ProductSign:Flags:CapRelation:RoundSumMismatch',lambda:c.verify(p,c.roots(p,bad),bad,d))
    print('signed endpoints, padded raw/magnitude sources and canonical product-sign padding checked',flush=True)


def composition():
    import norm_left as left
    import norm_division as division
    import norm_product as product
    p=replace(spec(3,2650),schema=c.norm.Spec(3,1,0,0,1,3));d=4;xs=[-1,0,1];gs=[1,1,1];ts=[8192,0,8192]
    pp=product.Spec(p.schema,2651,p.product,557,563,1);prod,st=product.prove(pp,[1,0,1],8192,d);pr=product.expected_roots(pp,[1,0,1],8192,ts);assert product.verify(pp,pr,prod,d)['state']==st
    ys=[-16384,0,16384];proof,state=c.prove(p,xs,gs,ys,d);roots=c.expected_roots(p,xs,gs,ys);assert roots[2]==pr[0] and c.verify(p,roots,proof,d)['state']==state
    lp=left.Spec(p.schema,2652,563,569,p.magnitude,1);child,st=left.prove(lp,ts,2,list(map(abs,ys)),d);lr=left.expected_roots(lp,ts,2,list(map(abs,ys)));assert lr[0]==pr[2] and lr[2]==roots[5] and left.verify(lp,lr,child,d)['state']==st
    ys=[-32,0,32];p=replace(p,identity=2653);proof,state=c.prove(p,xs,gs,ys,d);roots=c.expected_roots(p,xs,gs,ys);assert c.verify(p,roots,proof,d)['state']==state
    dp=division.Spec(p.schema,2654,p.magnitude,571,577,563,587,593,599,1);child,st=division.prove(dp,ts,128,list(map(abs,ys)),256,[128]*3,d);dr=division.expected_roots(dp,ts,128,list(map(abs,ys)),256,[128]*3)
    assert dr[0]==roots[5] and dr[3]==pr[2] and division.verify(dp,dr,child,d)['state']==st
    print('same actual xy/product sources and signed magnitude compose with left and division proofs',flush=True)


if __name__=='__main__':
    modes={'--corpus':corpus,'--honest':honest,'--maximum':lambda:honest(True),'--controls':controls,'--zeros':zeros,'--boundaries':boundaries,'--composition':composition}
    if sys.argv[1:]:
        assert all(mode in modes for mode in sys.argv[1:])
        for mode in sys.argv[1:]:modes[mode]()
    else:
        for test in modes.values():test()
