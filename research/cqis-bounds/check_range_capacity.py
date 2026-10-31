# /// script
# requires-python = ">=3.12"
# dependencies = ["numpy==2.3.4", "blake3==1.0.11", "python-flint==0.9.0"]
# ///
"""Full norm rows with the unchanged maximum range byte/lookup domain."""
import copy
from dataclasses import replace
import hashlib
import json
import sys
import wide_range as r
import signed_source as ss
import norm_xy as xy
from check_norm_xy import account as xy_account


def rejects(reason,call):
    try:call()
    except ValueError as error:assert str(error)==reason,(reason,str(error))
    else:raise AssertionError('accepted '+reason)


def shapes():
    digest=hashlib.sha256();cases=0
    for width in (1,2,4,8,16,32):
        cap=(1<<min(8*width,160))-1;limit=min(65536,131072//width)
        for count in (limit//2+1,limit-1,limit):
            p=r.Spec(1800+cases,101,(cap,)*count,1);a,b,n,w,_,raw=r.derive(p,4)
            assert n==limit and w==width and n*w<=131072
            plan=r.lookup_plan(p,4);assert plan['m']==plan['b']==a+b+1<=18 and len(plan['sigma'])==2*n*w<=262144<r.sc.P
            values=[(cap//3 if i%3 else cap) for i in range(count)];words,bs,cs=r.witness(p,values)
            assert len(words)==len(cs)==n*w and len(bs)==2*n*w
            for i in range(n):
                value=values[i] if i<count else 0;bound=cap if i<count else 0
                assert bytes(words[j*n+i] for j in range(w))==value.to_bytes(w,'little')
                assert int.from_bytes(bytes(bs[(w+j)*n+i] for j in range(w)),'little')+value==bound
                assert cs[(w-1)*n+i]==0
            digest.update(raw+bytes(words)+bytes(cs));cases+=1
        bad=replace(p,caps=(cap,)*(limit+1))
        rejects('Capacity',lambda:r.witness(bad,None));rejects('Capacity',lambda:r.verify(bad,None,None,4))
    # The count guard must run before examining malformed cap entries.
    rejects('Capacity',lambda:r.derive(r.Spec(1819,101,(None,)*65537,1),4))
    for bits in (8,16,32):
        p=ss.Spec(1820+bits,103,107,bits,16384,1);v=ss.derive(p,8)
        assert v['n']==16384 and all(r.derive(child,8)[2]*r.derive(child,8)[3]<=131072 for child in v['ranges'])
        rejects('Capacity',lambda:ss.witness(replace(p,count=16385),None))
    p=xy.Spec(xy.norm.Spec(16384,30,30,14,1,3),1830,109,113,127,1);v=xy.derive(p,4)
    assert v['n']==16384 and len(v['carry'].caps)==65536 and r.derive(v['output'],4)[2:4]==(16384,4)
    rejects('Spec',lambda:xy.derive(replace(p,schema=replace(p.schema,d=16385)),4))
    assert digest.hexdigest()=='4151eb7c6dee3a07237457f1b324255930df6baacff7829b78efd7d4374a03f5'
    print(json.dumps(dict(shape_cases=cases,word_byte_limit=131072,lookup_byte_limit=262144,sha256=digest.hexdigest()),sort_keys=True),flush=True)


def range_account(p,out,d):
    a,b,n,width,_,_=r.derive(p,d);m=a+b+1;f=lambda x:3*x*(x-1)//2+2*x
    assert out['account']==dict(identity_numerator=2*n*width+255,identity_power=p.repetitions,
        lookup_reduction_numerator=p.repetitions*(f(m)+f(8)+3*m),range_reduction_numerator=9*a+7*b,denominator=r.sc.P**d)
    assert out['draws']=={r.zc.WEIGHT:4*a+3*b,r.zc.tr.CHALLENGE:4*a+3*b} and len(out['claims'])==9
    assert len(out['lookup_claims'])==2*p.repetitions and out['lookup_draws'].get(r.lu.UNIT,0)==0


def wide():
    d=4;p=r.Spec(1840,131,(33025,)*65535,2);values=[(0,33025,256,16512)[i%4] for i in range(65535)]
    words=r.witness(p,values)[0];root=r.source_root(p,words);print('wide maximum start',flush=True)
    proof,state=r.prove(p,values,d);print('wide maximum produced',flush=True);out=r.verify(p,root,proof,d)
    assert out['state']==state;range_account(p,out,d);assert r.derive(p,d)[:4]==(16,1,65536,2)
    assert state.hex()=='82c9f6a03a90db11a243a4d21c4ae6ffaa7ec6c07adb75089cbe0349ebda77f7'
    bad=copy.deepcopy(proof);bad['words'][65535]=1;rejects('CommitmentMismatch',lambda:r.verify(p,root,bad,d))
    print(json.dumps(dict(kind='wide',field=d,repetitions=2,real_count=65535,word_bytes=len(words),state=state.hex()),sort_keys=True),flush=True)


def signed():
    d=8;p=ss.Spec(1841,137,139,32,16384,1);v=ss.derive(p,d);values=[(-(1<<31),(1<<31)-1,-257,0,1)[i%5] for i in range(p.count)]
    raw,mag,_,_=ss.witness(p,values);expected=[r.source_root(child,r.witness(child,xs)[0]) for child,xs in zip(v['ranges'],(raw,mag))]
    print('signed maximum start',flush=True);proof,state=ss.prove(p,values,d);print('signed maximum produced',flush=True);out=ss.verify(p,expected,proof,d)
    assert out['state']==state;a,b=v['a'],v['b'];dims=[a+b+1,a+b+1,a+2];f=lambda x:3*x*(x-1)//2+2*x
    assert out['account']==dict(identities=[((1<<m)+255,1) for m in dims],lookup_reduction_numerator=sum(f(m)+f(8)+3*m for m in dims),range_reduction_numerator=43*a+26*b+9,denominator=r.sc.P**d)
    for child,part in zip(v['ranges'],out['ranges']):range_account(child,part,d)
    bad=copy.deepcopy(proof);bad['ranges'][0]['words'][-1]^=1;rejects('Raw:CommitmentMismatch',lambda:ss.verify(p,expected,bad,d))
    print(json.dumps(dict(kind='signed32',field=d,count=p.count,state=state.hex()),sort_keys=True),flush=True)


def norm_xy():
    d=4;p=xy.Spec(xy.norm.Spec(16384,30,30,14,1,3),1842,149,151,157,1)
    xs=[(-32768,32767,0,-255,1)[i%5] for i in range(p.schema.d)];ys=[(-32768,-32768,-1,255,0)[i%5] for i in range(p.schema.d)]
    expected=xy.expected_roots(p,xs,ys,[abs(x*y) for x,y in zip(xs,ys)]);print('norm xy full16384 start',flush=True)
    proof,state=xy.prove(p,xs,ys,d);print('norm xy full16384 produced',flush=True);out=xy.verify(p,expected,proof,d)
    assert out['state']==state;xy_account(p,out,d)
    bad=copy.deepcopy(proof);bad['left']['ranges'][0]['words'][-1]^=1;rejects('Left:Raw:CommitmentMismatch',lambda:xy.verify(p,expected,bad,d))
    print(json.dumps(dict(kind='norm_xy',field=d,count=p.schema.d,state=state.hex()),sort_keys=True),flush=True)


if __name__=='__main__':
    modes={'--shapes':shapes,'--wide':wide,'--signed':signed,'--normxy':norm_xy}
    if sys.argv[1:]:
        assert all(mode in modes for mode in sys.argv[1:])
        for mode in sys.argv[1:]:modes[mode]()
    else:
        for test in modes.values():test()
