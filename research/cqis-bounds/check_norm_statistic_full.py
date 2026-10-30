# /// script
# requires-python = ">=3.12"
# dependencies = ["numpy==2.3.4", "blake3==1.0.11", "python-flint==0.9.0"]
# ///
"""RFC-0022 statistic: full row, actual byte sums, whole carries and sources."""
import copy
from dataclasses import replace
import hashlib
import json
from math import gcd
import random
import sys
import numpy as np
import norm_statistic_full as c

r=c.r


def rejects(reason,call):
    try:call()
    except ValueError as error:assert str(error)==reason,(reason,str(error))
    else:raise AssertionError('accepted '+reason)


def spec(count=3,identity=2100,repetitions=1):
    return c.Spec(c.norm.Spec(count,30,30,14,1,3),identity,233,239,repetitions)


def expected(p,xs,value=None):
    return c.expected_roots(p,xs,sum(x*x for x in xs) if value is None else value)


def corpus():
    rng=random.Random(2717);digest=hashlib.sha256();cells=0
    for case in range(10000):
        count=1+case%127;en,ed=rng.randrange(1,1<<32),rng.randrange(1,1<<32);common=gcd(en,ed)
        p=replace(spec(count,case,1+case%2),schema=c.norm.Spec(count,rng.randrange(31),rng.randrange(31),rng.randrange(15),en//common,ed//common))
        xs=np.array([rng.randrange(-32768,32768) for _ in range(count)],dtype=np.int64);xs[0]=(0,-32768,32767,-1,1)[case%5]
        v=c.derive(p,4);w=c.witness(p,xs.tolist());mag=np.abs(xs);lo=mag&255;hi=mag>>8
        columns=[int(lo@lo),int(2*(lo@hi)),int(hi@hi)];carry=[0];out=[]
        for k in range(len(v['cert']['result_caps'])):
            q,b=divmod((columns[k] if k<3 else 0)+carry[-1],256);carry.append(q);out.append(b)
        assert w==dict(output=[int(xs@xs)],carry=carry) and carry[-1]==0
        assert all(0<=x<=cap for x,cap in zip(carry,v['carry'].caps))
        assert out==[(int(xs@xs)>>(8*k))&255 for k in range(len(out))]
        digest.update(v['raw']+int(xs@xs).to_bytes(8,'little')+b''.join(x.to_bytes(4,'little') for x in carry));cells+=count
    for count in (1,2,3,4,255,256,1023,1024,2048,2049,16383,16384):
        p=spec(count,(1<<44)-1,2);v=c.derive(p,8);w=c.witness(p,[-32768]*count)
        assert w['output']==[count<<30] and w['carry'][-1]==0 and max(v['cert']['lhs']+v['cert']['rhs'])*2<r.sc.P
        assert r.derive(v['carry'],8)[2]==8
    v=c.derive(spec(16384),8);assert v['cert']['carry_caps']==(0,4161600,4194176,1064959,4159,16,0)
    assert max(v['cert']['lhs']+v['cert']['rhs'])==1073709311
    p=spec();v=c.derive(p,4)
    for bad in (replace(p,identity=1<<44),replace(p,repetitions=True),replace(p,source=p.output),replace(p,source=v['base']),replace(p,schema=replace(p.schema,G=True))):rejects('Spec',lambda:c.derive(bad,4))
    rejects('Spec',lambda:c.derive(spec(16385),4));rejects('Spec',lambda:c.derive(p,True))
    for xs in ([False]*3,[32768]*3,[0]):rejects('Input',lambda:c.witness(p,xs))
    print(json.dumps(dict(seed=2717,cases=10000,source_cells=cells,sha256=digest.hexdigest()),sort_keys=True),flush=True)


def account(p,out,d):
    v=c.derive(p,d);a,bs,bc=v['a'],v['bs'],v['bc'];dims=[a+2]*3+[bs+1,bc+4];f=lambda m:3*m*(m-1)//2+2*m
    assert out['account']==dict(identities=[((1<<m)+255,p.repetitions) for m in dims],lookup_reduction_numerator=sum(p.repetitions*(f(m)+f(8)+3*m) for m in dims),range_reduction_numerator=43*a+62+7*(bs+bc),statistic_reduction_numerator=6*a,denominator=r.sc.P**d)
    assert len(out['claims'])==4 and sum(x['numerator'] for x in out['sc'])==6*a
    assert out['draws']==({r.zc.tr.CHALLENGE:3*a} if a else {})
    draws=[out['draws'],out['signed']['draws']]+[x['draws'] for x in out['signed']['ranges']+out['ranges']]
    for label,total in ((r.zc.WEIGHT,18*a+26+3*(bs+bc)),(r.zc.tr.CHALLENGE,21*a+26+3*(bs+bc))):assert sum(x.get(label,0) for x in draws)==total


def honest(maximum=False):
    digest=hashlib.sha256();count=0
    for d,reps in (((4,1),) if maximum else ((4,1),(4,2),(8,1),(8,2))):
        for size in ((16384,) if maximum else (1,3,16,65)):
            p=spec(size,2110+count,reps);xs=([-32768,0,32767,-1,255,256,1]*((size+6)//7))[:size]
            print('honest start',count+1,d,reps,size,flush=True);proof,state=c.prove(p,xs,d);out=c.verify(p,expected(p,xs),proof,d)
            assert out['state']==state;account(p,out,d);digest.update(state);count+=1;print('honest passed',count,d,reps,size,flush=True)
    print(json.dumps(dict(maximum=maximum,proofs=count,sha256=digest.hexdigest()),sort_keys=True),flush=True)


def controls():
    p=spec();d=4;xs=[-32767,-7,0];v=c.derive(p,d);pairs=c.prepare(p,xs,d);proof,state=c.assemble(p,pairs,d);roots=expected(p,xs)
    assert c.verify(p,roots,proof,d)['state']==state
    for name in ('output','carry'):
        bad=copy.deepcopy(proof);bad[name]['words'][0]^=1;rejects(name.title()+':CommitmentMismatch',lambda:c.verify(p,roots,bad,d))
    bad=copy.deepcopy(proof);bad['source']['ranges'][0]['words'][0]^=1;rejects('Source:Raw:CommitmentMismatch',lambda:c.verify(p,roots,bad,d))
    for value in (sum(x*x for x in xs)+1,sum(x*x for x in xs)+r.sc.P):
        bad,_=c.assemble(p,dict(pairs,output=r.prove(v['output'],[value],d)),d)
        rejects('Column0:RoundSumMismatch',lambda:c.verify(p,expected(p,xs,value),bad,d))
    carry=c.witness(p,xs)['carry'];carry[1]^=1;bad,_=c.assemble(p,dict(pairs,carry=r.prove(v['carry'],carry,d)),d)
    rejects('Column0:RoundSumMismatch',lambda:c.verify(p,roots,bad,d))
    alias=spec(2,2130);badpairs=c.prepare(alias,[-32768]*2,d);badpairs['output']=r.prove(c.derive(alias,d)['output'],[1],d);bad,_=c.assemble(alias,badpairs,d)
    rejects('Column0:RoundSumMismatch',lambda:c.verify(alias,expected(alias,[-32768]*2,1),bad,d))
    one=spec(1,2131);bad,_=c.prove(one,[7],d);bad['columns'][0]['final'][0]=r.sc.neg(bad['columns'][0]['final'][0])
    rejects('Column0:ClaimMismatch',lambda:c.verify(one,expected(one,[7]),bad,d))
    bad,_=c.prove(one,[0],d);bad['columns'][1]['final'][1]=r.sc.scalar(1,d)
    rejects('Column1:ClaimMismatch',lambda:c.verify(one,expected(one,[0]),bad,d))
    bad=copy.deepcopy(proof);bad['columns'][0]['rounds'][0][0]=(False,0,0,0)
    rejects('Column0:NoncanonicalField',lambda:c.verify(p,roots,bad,d))
    bad=copy.deepcopy(proof);bad['columns'][-1]['final']=[r.sc.scalar(0,d)]
    rejects('Column7:ProofShape',lambda:c.verify(p,roots,bad,d))
    rejects('ProofShape',lambda:c.verify(p,roots,dict(proof,certificate={}),d));rejects('Root',lambda:c.verify(p,[False]*2,proof,d))
    print('false S/carry, p-alias, source, square-preserving and zero-hidden originals reject',flush=True)


def boundaries():
    p=spec(4,2140);d=4;xs=[-32768,0,-1,1];v=c.derive(p,d);pairs=c.prepare(p,xs,d);roots=expected(p,xs);w=c.witness(p,xs)
    for index in (0,len(w['carry'])-1,7):
        child=v['carry'];caps=list(child.caps)+[0]*(8-len(child.caps));values=w['carry']+[0]*(8-len(w['carry']));caps[index]=1;values[index]=1
        badpair=r.assemble(child,*r.witness(replace(child,caps=tuple(caps)),values),d);bad,_=c.assemble(p,dict(pairs,carry=badpair),d)
        rejects('Carry:CapRelation:RoundSumMismatch',lambda:c.verify(p,roots,bad,d))
    words,bs,cs=r.witness(v['output'],w['output']);words[7]=bs[7]=1;badpair=r.assemble(v['output'],words,bs,cs,d);bad,_=c.assemble(p,dict(pairs,output=badpair),d)
    rejects('Output:CapRelation:RoundSumMismatch',lambda:c.verify(p,[roots[0],r.root(p.output,words)],bad,d))
    padded=spec(3,2141);bad,_=c.prove(padded,[-32768,0,1],d);bad['source']['ranges'][0]['words'][3]=1
    rejects('Source:Raw:CommitmentMismatch',lambda:c.verify(padded,expected(padded,[-32768,0,1]),bad,d))
    print('zero endpoints, padded carry/source and high output bytes retain actual consumers',flush=True)


def composition():
    import norm_statistic as old
    import norm_numerator as numerator
    p=spec(3,2150);d=4;xs=[-7,0,255];value=sum(x*x for x in xs);proof,state=c.prove(p,xs,d);roots=expected(p,xs)
    assert c.verify(p,roots,proof,d)['state']==state
    previous=old.Spec(p.schema,2151,p.source,p.output,1);assert old.expected_roots(previous,xs,value)==roots
    child,st=old.prove(previous,xs,d);assert old.verify(previous,roots,child,d)['state']==st
    pp=numerator.Spec(p.schema,2152,p.output,241,1);nvalue=p.schema.ed*value+p.schema.en*c.norm.constants(p.schema)['unit'];child,st=numerator.prove(pp,value,d);nr=numerator.expected_roots(pp,value,nvalue);assert nr[0]==roots[1]
    assert numerator.verify(pp,nr,child,d)['state']==st
    bad,_=c.prove(p,[7,0,255],d);rejects('Source:Raw:CommitmentMismatch',lambda:c.verify(p,roots,bad,d))
    print('old statistic and numerator compose on actual roots; equal-S raw substitution rejects',flush=True)


if __name__=='__main__':
    modes={'--corpus':corpus,'--honest':honest,'--maximum':lambda:honest(True),'--controls':controls,'--boundaries':boundaries,'--composition':composition}
    if sys.argv[1:]:
        assert all(mode in modes for mode in sys.argv[1:])
        for mode in sys.argv[1:]:modes[mode]()
    else:
        for test in modes.values():test()
