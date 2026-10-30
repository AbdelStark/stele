# /// script
# requires-python = ">=3.12"
# dependencies = ["numpy==2.3.4", "blake3==1.0.11"]
# ///
"""RFC-0009 §2 step3 / Draft A3: exact actual-source probability sums."""
import copy
from dataclasses import replace
import hashlib
import json
import random
import sys
import numpy as np
import attention_probability_sum as c

r=c.r


def rejects(reason,call):
    try:call()
    except ValueError as error:assert str(error)==reason,(reason,str(error))
    else:raise AssertionError('accepted '+reason)


def spec(count=3,E=8,identity=3800,repetitions=1):
    schema=c.attained.maximum.Spec(1<<20,127,7,6);positions=tuple(31*j for j in range(count));row=c.attained.Spec(schema,positions[max(0,count-2)],positions,0,0,1<<20,3600,1201,1213,1217,1223,repetitions)
    return c.Spec(row,E,identity,1249,1259)


def oracle(p,xs):
    n=1<<(len(xs)-1).bit_length();width=1 if p.exponent<=7 else 2;values=np.array(xs+[0]*(n-len(xs)),dtype='<u1' if width==1 else '<u2');total=int(values.sum(dtype=np.uint64))
    source=np.frombuffer(values.tobytes(),dtype=np.uint8).reshape(n,width).T.reshape(-1).tolist();output=list(np.array([total],dtype='<u4').tobytes())
    return total,[r.root(p.source,source),r.root(p.output,output)]


def corpus():
    rng=random.Random(2733);digest=hashlib.sha256();widths=set();zeros=0
    for case in range(10000):
        count=(1,3,5,16,17,65)[case%6];p=spec(count,case%15,50000+case,1+case%2);row=replace(p.row,position=p.row.positions[(case//6)%count],window=(0,31,63,1<<20)[(case//7)%4]);p=replace(p,row=row);v=c.derive(p,4)
        pos=np.array(row.positions,dtype=np.int64);allowed=(row.start<=pos)&(pos<row.stop)&(pos<=row.position)&((row.window==0)|((row.position-pos)<row.window));assert v['allowed']==tuple(bool(b) for b in allowed)
        xs=[rng.randint(0,1<<p.exponent) if bit else 0 for bit in allowed]
        if case%13==0:xs=[0]*count
        if case%17==0:xs=[(1<<p.exponent)*int(bit) for bit in allowed]
        total,roots=oracle(p,xs);assert c.witness(p,xs)==dict(source=xs,output=[total]) and c.expected_roots(p,xs)==roots
        assert v['cap']==int(allowed.sum())*(1<<p.exponent);widths.add((v['bp'],v['bz']));zeros+=total==0;digest.update(v['raw']+json.dumps([xs,total],separators=(',',':')).encode()+b''.join(roots))
    assert {bp for bp,bz in widths}=={0,1} and {bz for bp,bz in widths}=={0,1,2} and zeros>700
    p=spec(16384,14,(1<<48)-1,2);p=replace(p,row=replace(p.row,position=p.row.positions[-1]));v=c.derive(p,8);assert v['cap']==1<<28 and v['base']+(1<<14)==(1<<63)+(1<<62)
    spans=sorted((r.derive(child,8)[4],64) for child in v['ranges'].values());assert all(v['base']+16<lo and lo+size<=v['base']+(1<<14) for lo,size in spans) and spans[0][0]+64<=spans[1][0]
    for bad in (replace(p,identity=1<<48),replace(p,identity=p.row.identity),replace(p,source=p.output),replace(p,source=p.row.difference),replace(p,output=v['base']),replace(p,exponent=True),replace(p,exponent=15),replace(p,row=replace(p.row,repetitions=True))):rejects('Spec',lambda:c.derive(bad,4))
    rejects('Capacity',lambda:c.derive(spec(16385),4));rejects('Spec',lambda:c.derive(p,True))
    for xs in ([False]*3,[-1,0,0],[257,0,0],[0,0,1],[0],(0,0,0)):rejects('Input',lambda:c.witness(spec(),xs))
    assert digest.hexdigest()=='4142a2c7dcefd98d2d4fea0110a70bf9f55d09735dc342428e6317aef00c206f'
    print(json.dumps(dict(seed=2733,cases=10000,zeros=zeros,widths=sorted(widths),sha256=digest.hexdigest()),sort_keys=True),flush=True)


def account(p,out,d):
    v=c.derive(p,d);a,bp,bz=v['a'],v['bp'],v['bz'];f=lambda m:3*m*(m-1)//2+2*m;dims=(a+bp+1,bz+1);reps=p.row.repetitions
    assert out['account']==dict(identities=[((1<<m)+255,reps) for m in dims],lookup_reduction_numerator=sum(reps*(f(m)+f(8)+3*m) for m in dims),range_reduction_numerator=9*a+7*bp+7*bz,sum_reduction_numerator=a,denominator=r.sc.P**d)
    assert len(out['claims'])==1 and len(out['ranges'])==2 and out['draws']==({r.zc.tr.CHALLENGE:a} if a else {})
    assert sum(x['draws'].get(r.zc.WEIGHT,0) for x in [out]+out['ranges'])==4*a+3*bp+3*bz
    assert sum(x['draws'].get(r.zc.tr.CHALLENGE,0) for x in [out]+out['ranges'])==5*a+3*bp+3*bz


def honest(maximum=False):
    digest=hashlib.sha256();done=0
    for d,reps in (((4,1),) if maximum else ((4,1),(4,2),(8,1),(8,2))):
        for count,E in (((16384,14),) if maximum else ((1,0),(3,7),(16,8),(65,14))):
            p=spec(count,E,3810+done,reps)
            if maximum:p=replace(p,row=replace(p.row,position=p.row.positions[-1]))
            v=c.derive(p,d);xs=[(v['Q'] if maximum or done%4==1 else (0,v['Q'],v['Q']-1,1)[j%4])*int(bit) for j,bit in enumerate(v['allowed'])]
            print('honest start',done+1,d,reps,count,E,flush=True);proof,state=c.prove(p,xs,d);out=c.verify(p,c.expected_roots(p,xs),proof,d);assert out['state']==state;account(p,out,d);digest.update(state);done+=1;print('honest passed',done,d,reps,count,E,flush=True)
    print(json.dumps(dict(maximum=maximum,proofs=done,sha256=digest.hexdigest()),sort_keys=True),flush=True)


def controls():
    p=spec();d=4;v=c.derive(p,d);xs=[1,2,0];pairs=c.prepare(p,xs,d);proof,state=c.assemble(p,pairs,d);roots=c.expected_roots(p,xs);out=c.verify(p,roots,proof,d);assert out['state']==state;account(p,out,d)
    for j,name in enumerate(('Source','Output')):
        wrong=roots.copy();wrong[j]=bytes(32);rejects(name+':CommitmentMismatch',lambda:c.verify(p,wrong,proof,d))
    for total in (2,4):
        changed=r.prove(v['ranges']['output'],[total],d);bad,_=c.assemble(p,dict(pairs,output=changed),d);rejects('Sum:RoundSumMismatch',lambda:c.verify(p,c.roots(p,bad),bad,d))
    alternate=r.prove(v['ranges']['source'],[2,1,0],d);bad,_=c.assemble(p,dict(pairs,source=alternate),d);rejects('Source:CommitmentMismatch',lambda:c.verify(p,roots,bad,d))
    for key in ('receipt','certificate','mask','table','sum_value'):rejects('ProofShape',lambda:c.verify(p,roots,dict(proof,**{key:{}}),d))
    for bad in ([False,roots[1]],roots[:1],tuple(roots)):rejects('Root',lambda:c.verify(p,bad,proof,d))
    bad=copy.deepcopy(proof);bad['sum']['rounds'][0][0]=(False,0,0,0);rejects('NoncanonicalField',lambda:c.verify(p,roots,bad,d))
    bad=copy.deepcopy(proof);bad['sum']['final'][0]=r.sc.add(bad['sum']['final'][0],r.sc.scalar(1,d));rejects('Sum:FinalEvaluationMismatch',lambda:c.verify(p,roots,bad,d))
    print('external roots, genuine wrong sums/equal-sum source substitution, authority and final controls passed',flush=True)


def originals():
    p=spec(identity=3840);d=4;xs=[1,2,0];v=c.derive(p,d);pairs=c.prepare(p,xs,d);proof,_=c.assemble(p,pairs,d);roots=c.expected_roots(p,xs);i,tables=c.part(p,proof,d);tables[0][0],tables[0][1]=tables[0][1],tables[0][0]
    t=c.transcript(v,roots+[r.source_root(v['ranges']['output'],proof['output']['words'])],[pairs[name][1] for name in c.CHILDREN],d);bad=dict(proof,sum=r.sc.prove(t,i,tables)[0]);rejects('Sum:ClaimMismatch',lambda:c.verify(p,roots,bad,d))
    changed=replace(p,row=replace(p.row,window=32));rejects('Sum:RoundSumMismatch',lambda:c.verify(changed,roots,proof,d))
    changed=replace(p,exponent=9);rejects('Source:SourceCopy:ClaimMismatch',lambda:c.verify(changed,roots,proof,d))
    bad=copy.deepcopy(proof);bad['output']['words'] += [0,0];rejects('Output:OpeningShape',lambda:c.verify(p,roots,bad,d))
    print('equal-sum false original, expected mask/exponent replays and extended scalar source reject',flush=True)


def boundaries():
    p=spec(identity=3850);d=4;v=c.derive(p,d);xs=[1,2,0];pairs=c.prepare(p,xs,d)
    for pos in (2,3):
        child=v['ranges']['source'];values=xs+([0] if pos==3 else []);values[pos]=1;caps=list(child.caps)+([0] if pos==3 else []);caps[pos]=1;changed=r.assemble(child,*r.witness(replace(child,caps=tuple(caps)),values),d)
        bad,_=c.assemble(p,dict(pairs,source=changed,output=r.prove(v['ranges']['output'],[4],d)),d);rejects('Source:CapRelation:RoundSumMismatch',lambda:c.verify(p,c.roots(p,bad),bad,d))
    child=v['ranges']['source'];caps=list(child.caps);caps[0]=257;changed=r.assemble(child,*r.witness(replace(child,caps=tuple(caps)),[257,2,0]),d);bad,_=c.assemble(p,dict(pairs,source=changed,output=r.prove(v['ranges']['output'],[259],d)),d);rejects('Source:CapRelation:RoundSumMismatch',lambda:c.verify(p,c.roots(p,bad),bad,d))
    p=spec(5,14,3851);v=c.derive(p,d);pairs=c.prepare(p,[1,2,0,0,0],d);child=v['ranges']['output'];alias=3+r.sc.P;changed=r.assemble(child,*r.witness(replace(child,caps=(alias,)),[alias]),d);bad,_=c.assemble(p,dict(pairs,output=changed),d);rejects('Output:CapRelation:RoundSumMismatch',lambda:c.verify(p,c.roots(p,bad),bad,d))
    p=spec(1,0,3852);v=c.derive(p,d);pairs=c.prepare(p,[0],d);bad,_=c.assemble(p,dict(pairs,output=r.prove(v['ranges']['output'],[1],d)),d);rejects('Sum:FinalEvaluationMismatch',lambda:c.verify(p,c.roots(p,bad),bad,d))
    proof,state=c.prove(p,[0],d);assert c.verify(p,c.expected_roots(p,[0]),proof,d)['state']==state
    for key in c.CHILDREN+('sum',):
        bad=copy.deepcopy(proof);del bad[key];rejects('ProofShape',lambda:c.verify(p,c.expected_roots(p,[0]),bad,d))
    print('masked/padded probabilities, source upper cap, M31 sum alias and zero-dimensional wrong sum reject',flush=True)


def composition():
    import attention_exp as exp
    p=spec(identity=3860);d=4;xs=[0,-9,100];maximum,state=c.attained.prove(p.row,xs,d);mr=c.attained.expected_roots(p.row,xs);assert c.attained.verify(p.row,mr,maximum,d)['state']==state
    us=c.attained.witness(p.row,xs)['difference'];assert us==[0,9,0]
    for mode in (0,1,2):
        function=exp.fn.Function('exp_q/product' if mode==1 else 'exp_q/nearest',1,bytes([7,6,p.exponent])+(bytes([3]) if mode==1 else b''));rep=exp.fn.Representation(function,mode,bytes([3]) if mode==2 else b'');ep=exp.Spec(p.row,rep,3870+mode,p.source)
        proof,state=exp.prove(ep,us,d);er=exp.expected_roots(ep,us);assert er[0]==mr[3];assert exp.verify(ep,[mr[3],er[1]],proof,d)['state']==state;values=exp.witness(ep,us)['output']
        total,st=c.prove(p,values,d);roots=c.expected_roots(p,values);assert roots[0]==er[1] and sum(values)>=1<<p.exponent;assert c.verify(p,[er[1],roots[1]],total,d)['state']==st
        alternate,other=exp.prove(ep,[9,0,0],d);ar=exp.expected_roots(ep,[9,0,0]);assert exp.verify(ep,ar,alternate,d)['state']==other and ar[1]!=er[1];assert sum(exp.witness(ep,[9,0,0])['output'])==sum(values)
        rejects('Source:CommitmentMismatch',lambda:c.verify(p,[ar[1],roots[1]],total,d));print('composition passed',mode,flush=True)
    print('actual maximum/exp/sum composition passes all representations; valid equal-sum exponential substitutes reject',flush=True)


if __name__=='__main__':
    modes={'--corpus':corpus,'--controls':controls,'--originals':originals,'--boundaries':boundaries,'--composition':composition,'--honest':honest,'--maximum':lambda:honest(True)}
    if sys.argv[1:]:
        assert all(mode in modes for mode in sys.argv[1:])
        for mode in sys.argv[1:]:modes[mode]()
    else:
        for test in list(modes.values())[:-1]:test()
