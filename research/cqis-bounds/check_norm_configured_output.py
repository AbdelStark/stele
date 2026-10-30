# /// script
# requires-python = ">=3.12"
# dependencies = ["numpy==2.3.4", "blake3==1.0.11", "python-flint==0.9.0"]
# ///
"""RFC-0022 configured branch selection and complete output source joins."""
import copy
from dataclasses import replace
import hashlib
import json
import random
import sys
import numpy as np
import norm_configured_output as c
from check_norm_output_factors import account as factor_account
from check_norm_signed_output import account as sign_account
from check_norm_product import account as product_account
from check_norm_left import account as left_account
from check_norm_division import account as division_account

r=c.r


def rejects(reason,call):
    try:call()
    except ValueError as error:assert str(error)==reason,(reason,str(error))
    else:raise AssertionError('accepted '+reason)


def spec(count=3,identity=2700,repetitions=1):
    return c.Spec(c.norm.Spec(count,0,0,14,1,3),identity,*range(601,616),repetitions)


def reference(p,xs,hs,j,a):
    x=np.array(xs,dtype=np.int64);h=np.array(hs,dtype=np.int64);e=p.schema.F+p.schema.G+21+a-p.schema.E;b=2**max(e,0);bias=b//2 if e>0 else 0;left=2**max(-e,0)
    xy=np.abs(x*h);ts=xy*j;qs=ts*left if e<0 else (ts.astype(object)+bias)//b;ys=qs*np.sign(x*h)
    return dict(xy=xy.tolist(),t=ts.tolist(),q=qs.tolist(),y=ys.tolist(),qd=([0]*len(xs) if e<0 else (qs*b).tolist()),remainder=([0]*len(xs) if e<0 else ((ts.astype(object)+bias)%b).tolist()),b=b,h=bias,l=left,branch='left' if e<0 else 'division')


def planes(xs,width,n):
    return [x>>(8*k)&255 for k in range(width) for x in xs+[0]*(n-len(xs))]


def corpus():
    rng=random.Random(2723);digest=hashlib.sha256();branches=set();shifts=set()
    for case in range(10000):
        count=1+case%31;p=replace(spec(count,case,1+case%2),schema=c.norm.Spec(count,rng.randrange(31),rng.randrange(31),rng.randrange(15),1,3));a=case%33-23
        if case<2:p=replace(p,schema=c.norm.Spec(count,30*case,30*case,14*(1-case),1,3));a=(-23,9)[case]
        e=p.schema.F+p.schema.G+21+a-p.schema.E;j=(8192,16384)[case%2]
        cap=min(32767,(32767*2**max(e,0))//(2*j*2**max(-e,0)));xs=[rng.randrange(-cap,cap+1) for _ in range(count)];hs=[rng.randrange(-2,3) for _ in xs]
        expected=reference(p,xs,hs,j,a);v=c.derive(p,4);w=c.witness(p,xs,hs,j,a);assert w==expected
        roots=c.expected_roots(p,1,a,xs,hs,j);manual=[r.root(identity,planes(values,width,v['n'])) for identity,values,width in ((p.left,[x%65536 for x in xs],2),(p.right,[h%65536 for h in hs],2),(p.xy,expected['xy'],4),(p.output,[y%65536 for y in expected['y']],2),(p.magnitude,expected['q'],2),(p.product,expected['t'],8),(p.quotient_product,expected['qd'],16),(p.remainder,expected['remainder'],16))]
        assert [roots[i] for i in (5,6,7,9,10,12,13,14)]==manual and roots[8]==r.root(p.sign,[int(x*h<0) for x,h in zip(xs,hs)]+[0]*(v['n']-count)) and roots[11]==r.root(p.reciprocal,[j])
        digest.update(v['raw']+b''.join(roots));branches.add(w['branch']);shifts.add(e)
    p=spec(16384,(1<<28)-1,2);v=c.derive(p,8);assert v['base']+(1<<34)==(1<<63)+(1<<62)
    spans=[(c.factors.derive(v['factors'],8)['base'],1<<30),(c.signed.derive(v['signed'],8)['base'],1<<22),(c.product.derive(v['product'],8)['base'],1<<18),(c.left.derive(v['left'],8)['base'],1<<18),(c.division.derive(v['division'],8)['base'],1<<22)]
    spans.sort();assert all(lo>=v['base']+4 and lo+size<=v['base']+(1<<34) for lo,size in spans) and all(x+s<=y for (x,s),(y,_) in zip(spans,spans[1:]))
    for bad in (replace(p,identity=1<<28),replace(p,repetitions=True),replace(p,left=p.right),replace(p,source=v['base']),replace(p,schema=replace(p.schema,F=True))):rejects('Spec',lambda:c.derive(bad,4))
    rejects('Spec',lambda:c.derive(spec(16385),4));rejects('Spec',lambda:c.derive(p,True))
    assert branches=={'left','division'} and -16 in shifts and 90 in shifts
    assert digest.hexdigest()=='d2ef8a356c060d6a8f7b23a1d0f9189600b1f5675ffb562a26f623e5d42c41aa'
    print(json.dumps(dict(seed=2723,cases=10000,shift_min=min(shifts),shift_max=max(shifts),sha256=digest.hexdigest()),sort_keys=True),flush=True)


def account(p,out,d):
    v=c.derive(p,d);children=out['children'];factor_account(v['factors'],children[0],d);sign_account(v['signed'],children[1],d);product_account(v['product'],children[2],d)
    (left_account if out['branch']=='left' else division_account)(v[out['branch']],children[3],d)
    accounts=[x['account'] for x in children];expected=dict(accounts[0])
    expected['identities']=sum((x['identities'] for x in accounts),[])
    for name in ('lookup_reduction_numerator','range_reduction_numerator'):expected[name]=sum(x[name] for x in accounts)
    assert out['draws']=={} and out['account']==expected


def honest(mode='matrix'):
    digest=hashlib.sha256();count=0;cases=((1,-23,False),(3,-8,False),(1,-7,False),(3,-6,False),(5,6,False),(5,8,False),(3,9,True))
    if mode!='matrix':cases=((16384,-23 if mode=='maximum' else -8 if mode=='full-left' else 8,False),)
    for d,reps in (((4,1),) if mode!='matrix' else ((4,1),(4,2),(8,1),(8,2))):
        for size,a,wide in cases:
            p=spec(size,2710+count,reps)
            if wide:p=replace(p,schema=c.norm.Spec(size,30,30,0,1,3))
            pattern=([0] if a==-23 else [-1,0,1] if a<6 else [-32768,-1,0,32767,1]);xs=(pattern*((size+len(pattern)-1)//len(pattern)))[:size];hs=[1]*size;j=8192
            print('honest start',count+1,d,reps,size,a,wide,flush=True);proof,state=c.prove(p,1,a,xs,hs,j,d);roots=c.expected_roots(p,1,a,xs,hs,j);out=c.verify(p,roots,proof,d)
            assert out['state']==state;account(p,out,d);digest.update(state);count+=1;print('honest passed',count,d,reps,size,a,wide,flush=True)
    print(json.dumps(dict(mode=mode,proofs=count,sha256=digest.hexdigest()),sort_keys=True),flush=True)


def controls():
    p=spec();d=4;a=-7;xs=[-1,0,1];hs=[1]*3;v=c.derive(p,d);pairs=c.prepare(p,1,a,xs,hs,8192,d);proof,state=c.assemble(p,pairs,d);roots=c.expected_roots(p,1,a,xs,hs,8192);assert c.verify(p,roots,proof,d)['state']==state
    reasons=['Factors:Paired:Scaled:Numerator:CommitmentMismatch','Factors:Paired:Scaled:Exponent:Offset:CommitmentMismatch','Factors:Paired:Scaled:Product:Output:CommitmentMismatch','Factors:Paired:Divisor:CommitmentMismatch','Factors:Factors:CommitmentMismatch','Signed:ProductSign:XY:Left:Raw:CommitmentMismatch','Signed:ProductSign:XY:Right:Raw:CommitmentMismatch','Signed:ProductSign:XY:Output:CommitmentMismatch','Signed:ProductSign:Sign:CommitmentMismatch','Signed:Output:Raw:CommitmentMismatch','Signed:Output:Magnitude:CommitmentMismatch','Product:Reciprocal:CommitmentMismatch','Product:Output:CommitmentMismatch','Division:QuotientProduct:Output:CommitmentMismatch','Division:Remainder:CommitmentMismatch']
    for i,reason in enumerate(reasons):
        bad=roots.copy();bad[i]=bytes([bad[i][0]^1])+bad[i][1:];rejects(reason,lambda:c.verify(p,bad,proof,d))
    for key in ('branch','selector','receipt','left'):rejects('ProofShape',lambda:c.verify(p,roots,dict(proof,**{key:0}),d))
    bad=dict(proof,total_root=bytes([proof['total_root'][0]^1])+proof['total_root'][1:]);rejects('Division:Bias:Output:CommitmentMismatch',lambda:c.verify(p,roots,bad,d))
    rejects('Root',lambda:c.verify(p,roots,dict(proof,total_root=False),d))
    changed=dict(pairs,product=c.product.prove(v['product'],[1,1,1],8192,d));bad,_=c.assemble(p,changed,d);rejects('Product:Xy:CommitmentMismatch',lambda:c.verify(p,roots,bad,d))
    changed=dict(pairs,signed=c.signed.prove(v['signed'],xs,hs,[-8192,0,8191],d));bad,_=c.assemble(p,changed,d);br=roots.copy();br[9:11]=c.signed.expected_roots(v['signed'],xs,hs,[-8192,0,8191])[4:]
    rejects('Division:QuotientProduct:Quotient:CommitmentMismatch',lambda:c.verify(p,br,bad,d))
    other=c.factors.prove(v['factors'],1,-8,d);bad=dict(proof,factors=other[0]);br=roots.copy();br[:5]=c.factors.roots(v['factors'],other[0]);rejects('ProofShape',lambda:c.verify(p,br,bad,d))
    print('all fifteen roots, total root, exact branch shape and substituted xy/q children reject',flush=True)


def zero_branches():
    p=spec(1,2750);d=4;v=c.derive(p,d)
    for a in (-23,-8,-7,-6,8):
        pairs=c.prepare(p,0,a,[0],[1],8192,d);proof,state=c.assemble(p,pairs,d);roots=c.expected_roots(p,0,a,[0],[1],8192);assert c.verify(p,roots,proof,d)['state']==state
        changed=dict(pairs,product=c.product.prove(v['product'],[0],16384,d));bad,_=c.assemble(p,changed,d);rejects('Product:Reciprocal:CommitmentMismatch',lambda:c.verify(p,roots,bad,d))
        if a< -7:
            for index in (13,14):
                bad=roots.copy();bad[index]=r.root((p.quotient_product,p.remainder)[index-13],[1]+[0]*15);rejects(('UnusedQuotientProduct' if index==13 else 'UnusedRemainder')+':CommitmentMismatch',lambda:c.verify(p,bad,proof,d))
            wrong=65535 if a==-23 else 1;changed=dict(pairs,round=c.left.prove(v['left'],[0],wrong,[0],d));bad,_=c.assemble(p,changed,d);rejects('Left:Factor:CommitmentMismatch',lambda:c.verify(p,roots,bad,d))
        else:
            b=1<<(a+7);h=b//2 if a> -7 else 0
            changed=dict(pairs,round=c.division.prove(v['division'],[0],0,[0],b*2,[0],d));bad,_=c.assemble(p,changed,d);rejects('Division:QuotientProduct:Divisor:CommitmentMismatch',lambda:c.verify(p,roots,bad,d))
            if h:
                changed=dict(pairs,round=c.division.prove(v['division'],[0],0,[0],b,[0],d));bad,_=c.assemble(p,changed,d);rejects('Division:Bias:Bias:CommitmentMismatch',lambda:c.verify(p,roots,bad,d))
    print('zero products retain J/B/h/L joins and both inactive qd/r roots',flush=True)


if __name__=='__main__':
    modes={'--corpus':corpus,'--controls':controls,'--zeros':zero_branches,'--honest':honest,'--maximum':lambda:honest('maximum'),'--full-left':lambda:honest('full-left'),'--full-right':lambda:honest('full-right')}
    if sys.argv[1:]:
        assert all(mode in modes for mode in sys.argv[1:])
        for mode in sys.argv[1:]:modes[mode]()
    else:
        for test in modes.values():test()
