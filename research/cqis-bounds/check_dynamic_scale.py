# /// script
# requires-python = ">=3.12"
# dependencies = ["blake3==1.0.11", "python-flint==0.9.0"]
# ///
"""Q26/Q31 dynamic scale: exact ceiling columns and complete source consumers."""
import copy
from dataclasses import replace
import hashlib
import json
import random
import sys
import dynamic_scale as s

r=s.r


def rejects(reason,call):
    try: call()
    except ValueError as error: assert str(error)==reason,(reason,str(error))
    else: raise AssertionError('accepted '+reason)


def spec(kind,count,identity=901,repetitions=1):
    return s.Spec(s.am.row.Spec(kind,count,0,'dynamic',0),identity,61,67,repetitions)


def corpus():
    rng=random.Random(2674); digest=hashlib.sha256(); negative=0; cells=0
    for case in range(10000):
        kind=('wide','gated')[case%2]; h=32768 if kind=='wide' else 1<<30; high=h-1 if kind=='wide' else h
        count=1+case%9; p=spec(kind,count,case,1+case%2); v=s.derive(p,4)
        xs=[rng.randrange(-h,high+1) for _ in range(count)]
        if case<11: xs=[-[0,1,126,127,128,254,255,256,32385,32386,h][case]]*count
        elif case%17==0: xs=[0]*count
        elif case%7==0: xs=[32386]*count
        maximum,scale,slack,carry=s.witness(p,xs); expected=sorted(abs(x) for x in xs)[-1]
        assert maximum==expected and scale==(expected+126)//127 and slack==127*scale-maximum
        assert 0<=slack<=126 and bool(scale)==bool(maximum) and carry[-1]==1
        assert all(0<=x<=127 for x in carry); negative+=int(0 in carry); b=v['width']; incoming=1
        for j in range(b):
            assert 127*scale.to_bytes(b,'little')[j]+incoming+255==maximum.to_bytes(b,'little')[j]+(slack if j==0 else 0)+256*carry[j]
            incoming=carry[j]
        digest.update(v['raw']+maximum.to_bytes(b,'little')+scale.to_bytes(b,'little')+bytes([slack])+bytes(carry)); cells+=b
    assert cells==30000 and negative==1410 and digest.hexdigest()=='d631f4eba362103b73969c4392dbcf337a0ed0ccf7826261b9621c58fdff0775'
    print(json.dumps(dict(seed=2674,cases=10000,byte_cells=cells,negative_carry_cases=negative,sha256=digest.hexdigest()),sort_keys=True),flush=True)


def honest():
    digest=hashlib.sha256(); count=0
    for d in (4,8):
        for repetitions in (1,2):
            for kind in ('wide','gated'):
                h=32768 if kind=='wide' else 1<<30; high=h-1 if kind=='wide' else h
                for xs in ([0],[-h,high,-h]):
                    p=spec(kind,len(xs),902,repetitions); v=s.derive(p,d); a,b=v['a'],v['b']
                    proof,state=s.prove(p,xs,d); out=s.verify(p,s.roots(p,proof),proof,d); assert state==out['state']
                    dims=[a+b+1,a+b+1,a+2,b+1,a+b+1,a+1,b+1,1,b+1]; f=lambda k:3*k*(k-1)//2+2*k
                    assert out['account']==dict(identities=[((1<<k)+255,repetitions) for k in dims],
                        lookup_reduction_numerator=sum(repetitions*(f(k)+f(8)+3*k) for k in dims),
                        range_reduction_numerator=71*a+66*b+9,selection_reduction_numerator=a,denominator=r.sc.P**d)
                    assert out['draws'].get(r.zc.WEIGHT,0)==b and out['draws'].get(r.zc.tr.CHALLENGE,0)==b
                    assert len(out['claims'])==6 and sum(x['numerator'] for x in out['sc'])==2*b
                    maximum=out['children'][0]; signed=maximum['children'][0]
                    all_draws=[out['draws'],maximum['draws'],signed['draws']]+[x['draws'] for x in signed['ranges']+maximum['children'][1:]+out['children'][1:]]
                    assert sum(x.get(r.zc.WEIGHT,0) for x in all_draws)==30*a+27*b+4
                    assert sum(x.get(r.zc.tr.CHALLENGE,0) for x in all_draws)==31*a+27*b+4
                    lookup_children=signed['ranges']+maximum['children'][1:]+out['children'][1:]
                    for child,k in zip(lookup_children,dims):
                        c=child['account']; assert (c['identity_numerator'],c['identity_power'])==((1<<k)+255,repetitions)
                        assert c['lookup_reduction_numerator']==repetitions*(f(k)+f(8)+3*k)
                    digest.update(state); count+=1; print('proof',d,repetitions,kind,len(xs),flush=True)
    assert count==16 and digest.hexdigest()=='a035e913f4b9fa78dc37132ab424172276b11735bcbb2363e93598a54fcad49a'
    print(json.dumps(dict(proofs=count,sha256=digest.hexdigest()),sort_keys=True),flush=True)


def controls():
    d=4; p=spec('wide',3,903); v=s.derive(p,d); xs=[32386,127,-3]
    pairs=s.prepare(p,xs,d); proof,state=s.assemble(p,pairs,d); expected=s.roots(p,proof)
    assert proof['carry']['words'][0]==0 and s.verify(p,expected,proof,d)['state']==state
    for name,reason in (('raw','Maximum:Input:Raw:CommitmentMismatch'),('maximum','Maximum:Maximum:CommitmentMismatch'),
                        ('scale','Scale:CommitmentMismatch'),('slack','Slack:CommitmentMismatch'),('carry','Carry:CommitmentMismatch')):
        bad=copy.deepcopy(proof)
        words=(bad['maximum']['input']['ranges'][0]['words'] if name=='raw' else
               bad['maximum']['maximum']['words'] if name=='maximum' else bad[name]['words'])
        words[0]+=1; rejects(reason,lambda:s.verify(p,expected,bad,d))
    # Every original/view claim remains consumed after preserving the linear identity.
    coefficients=[127,-1,-1,1,-256]
    for slot in range(5):
        bad=copy.deepcopy(proof); other=2 if slot==1 else 1; fs=bad['zero'][0]['final']
        fs[slot][0]=r.sc.add(fs[slot][0],r.sc.scalar(1,d)); fs[other][0]=r.sc.add(fs[other][0],r.sc.scalar(coefficients[slot],d))
        rejects('ScaleCeiling:ClaimMismatch',lambda:s.verify(p,expected,bad,d))
    bad=copy.deepcopy(proof); bad['zero'][1]['final'][0][0]=r.sc.scalar(0,d)
    rejects('TerminalCarry:FinalEvaluationMismatch',lambda:s.verify(p,expected,bad,d))
    for wrong in (255,257):
        ps=dict(pairs); ps['scale']=r.prove(v['scale'],[wrong],d); false,_=s.assemble(p,ps,d)
        rejects('ScaleCeiling:RoundSumMismatch',lambda:s.verify(p,s.roots(p,false),false,d))
    # Zero row, S1, slack127: all ceiling columns/terminal hold; slack range must reject.
    zero=spec('wide',1,904); zv=s.derive(zero,d); ps=s.prepare(zero,[0],d)
    ps['scale']=r.prove(zv['scale'],[1],d); ps['slack']=r.assemble(zv['slack'],[127],[127,255],[1],d)
    false,_=s.assemble(zero,ps,d)
    for _,i,tables in s.parts(zero,false,d): assert all(r.sc.compose(i['terms'],x,d)==r.sc.scalar(0,d) for x in zip(*tables))
    rejects('Slack:TerminalCarry:FinalEvaluationMismatch',lambda:s.verify(zero,s.roots(zero,false),false,d))
    bound=[expected[0],proof['maximum_root'],expected[1],proof['slack_root'],proof['carry_root']]
    t=s.transcript(p,bound,[pairs[name][1] for name in s.NAMES],d)
    assert [r.zc.prove(t,i,tables) for _,i,tables in s.parts(p,proof,d)]==proof['zero'] and t.state==state
    for mutate,reason in ((lambda q:q['zero'].pop(),'ProofShape'),(lambda q:q['zero'][1]['final'].pop(),'ProofShape'),
            (lambda q:q.__setitem__('maximum_root',b''),'Root')):
        bad=copy.deepcopy(proof); mutate(bad)
        rejects(reason,lambda:s.verify(p,expected,bad,d))
    bad=copy.deepcopy(proof); bad['zero'][1]['final'][0][0]=(True,0,0,0)
    rejects('TerminalCarry:NoncanonicalField',lambda:s.verify(p,expected,bad,d))
    for bad in (replace(p,identity=1<<40),replace(p,source=v['base']),replace(p,output=p.source),replace(p,repetitions=True)):
        rejects('Spec',lambda:s.derive(bad,d))
    rejects('Capacity',lambda:s.witness(spec('gated',16385),None))
    edge=s.derive(spec('gated',16384,(1<<40)-1,2),8); assert edge['base']+(1<<22)==(1<<63)+(1<<62)
    print('dynamic-scale controls passed',flush=True)


if __name__=='__main__':
    modes={'--corpus':corpus,'--honest':honest,'--controls':controls}
    if sys.argv[1:]:
        assert all(x in modes for x in sys.argv[1:])
        for mode in sys.argv[1:]: modes[mode]()
    else:
        for test in modes.values(): test()
