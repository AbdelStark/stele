# /// script
# requires-python = ">=3.12"
# dependencies = ["numpy==2.3.4", "blake3==1.0.11"]
# ///
"""Draft RFC-0004 A3/A6: actual masked attention maximum and byte differences."""
import copy
from dataclasses import replace
import hashlib
import json
import random
import sys
import numpy as np
import attention_maximum as c

r=c.r


def rejects(reason,call):
    try:call()
    except ValueError as error:assert str(error)==reason,(reason,str(error))
    else:raise AssertionError('accepted '+reason)


def spec(count=3,score_max=(1<<31)-1,bits=31,identity=3400,repetitions=1):
    ids=tuple(31*j for j in range(count));position=ids[max(0,count-2)]
    return c.Spec(c.maximum.Spec(1<<20,score_max,bits,12),position,ids,0,0,1<<20,identity,1103,1109,1117,1123,repetitions)


def oracle(p,xs):
    ids=np.array(p.positions,dtype=np.int64);X=np.array(xs,dtype=np.int64)
    mask=(ids>=p.start)&(ids<p.stop)&(ids<=p.position)
    if p.window:mask&=p.position-ids<p.window
    selected=int(np.argmax(np.where(mask,X,np.iinfo(np.int64).min)));maximum=int(X[selected]);delta=np.where(mask,maximum-X,0);gap=delta-(mask&(ids<ids[selected]))
    return dict(selected=p.positions[selected],maximum=maximum,difference=delta.tolist(),gap=gap.tolist(),offset=(X+p.schema.score_max).tolist(),source=(X%(1<<32)).tolist()),mask.tolist()


def carries(left,right,n):
    assert len(left)==len(right)==n
    # Independent prefix sums avoid the producer's recursive carry algorithm.
    return [((x&((1<<(8*k))-1))+(y&((1<<(8*k))-1)))>>(8*k) for k in range(1,5) for x,y in zip(left,right)]


def forged_pairs(p,xs,selected,deltas,gaps,d=4):
    v=c.derive(p,d);n=v['n'];count=v['count'];S=p.schema.score_max;offset=[x+S for x in xs];raw=[x%(1<<32) for x in xs];pad=lambda row:row+[0]*(n-count)
    values=dict(source=raw,maximum=[xs[p.positions.index(selected)]%(1<<32)],offset=offset,difference=deltas,gap=gaps,
                source_carry=carries(pad(raw),[S]*count+[0]*(n-count),n),difference_carry=carries(pad([x*int(b) for x,b in zip(offset,v['allowed'])]),pad(deltas),n),first_carry=carries(pad(gaps),pad([int(b and j<selected) for b,j in zip(v['allowed'],p.positions)]),n))
    return {name:r.prove(child,values[name],d) for name,child in v['ranges'].items()}


def corpus():
    rng=random.Random(2730);digest=hashlib.sha256();accepted=domain=masked=ties=0;widths=set();policies=set()
    for case in range(10000):
        count=(1,3,5,16,17,65)[case%6];S=(0,1,127,128,32767,32768,(1<<23)-1,1<<23,(1<<30),(1<<31)-1)[case%10];bits=(7,15,31)[case%3]
        p=spec(count,S,bits,case,1+case%2);ids=tuple(sorted(rng.sample(range(1<<20),count)));position=ids[rng.randrange(count)];policy=case%3
        p=replace(p,positions=ids,position=position,window=0 if policy==0 else (1,65536,1<<20)[(case//3)%3],start=0 if policy!=2 else max(0,position-100000),stop=(1<<20) if policy!=2 else min(1<<20,position+100001),schema=replace(p.schema,fraction=case%31))
        xs=[rng.randint(-S,S) for _ in ids] if case%7 else [S]*count;w,mask=oracle(p,xs);v=c.derive(p,4);assert list(v['allowed'])==mask;policies.add(policy)
        assert w['selected']==next(j for j,x,b in zip(ids,xs,mask) if b and x==w['maximum'])
        digest.update(v['raw']+json.dumps([xs,w],sort_keys=True,separators=(',',':')).encode());masked+=not all(mask);ties+=sum(b and x==w['maximum'] for x,b in zip(xs,mask))>1
        if max(w['difference'])>1<<bits:rejects('Domain',lambda:c.witness(p,xs));domain+=1;continue
        accepted+=1;actual=c.witness(p,xs);assert {k:actual[k] for k in w}==w
        pad=lambda row:row+[0]*(v['n']-count)
        assert actual['source_carry']==carries(pad(w['source']),[S]*count+[0]*(v['n']-count),v['n'])
        assert actual['difference_carry']==carries(pad([x*int(b) for x,b in zip(w['offset'],mask)]),pad(w['difference']),v['n'])
        assert actual['first_carry']==carries(pad(w['gap']),pad([int(b and j<w['selected']) for j,b in zip(ids,mask)]),v['n'])
        roots=c.expected_roots(p,xs);manual=[r.source_root(v['ranges'][name],r.witness(v['ranges'][name],actual[name] if name!='maximum' else [actual[name]%(1<<32)])[0]) for name in ('source','maximum','difference')]
        assert roots==manual[:2]+[r.root(p.selection,[w['selected']])]+manual[2:];digest.update(b''.join(roots));widths.add((v['bo'],v['bd']))
    assert accepted+domain==10000 and accepted>0 and domain>0 and masked>0 and ties>0 and policies=={0,1,2} and {b for pair in widths for b in pair}=={0,1,2},(accepted,domain,masked,ties,widths)
    p=spec(16384,identity=(1<<48)-1,repetitions=2);v=c.derive(p,8);assert v['base']+(1<<14)==(1<<63)+(1<<62)
    spans=sorted((r.derive(child,8)[4],64) for child in v['ranges'].values());assert all(v['base']+35<lo and lo+size<=v['base']+(1<<14) for lo,size in spans) and all(lo+size<=nxt for (lo,size),(nxt,_) in zip(spans,spans[1:]))
    for bad in (replace(p,identity=1<<48),replace(p,repetitions=True),replace(p,source=p.maximum),replace(p,difference=v['base']),replace(p,schema=replace(p.schema,score_max=1<<31))):rejects('Spec',lambda:c.derive(bad,4))
    rejects('Capacity',lambda:c.derive(spec(16385),4));rejects('Spec',lambda:c.derive(p,True))
    for bad in (replace(p,position=True),replace(p,position=1<<20)):rejects('Position',lambda:c.derive(bad,4))
    for bad in (replace(p,positions=(1,1)),replace(p,positions=(2,1)),replace(p,positions=(True,)),replace(p,positions=[])):rejects('Positions',lambda:c.derive(bad,4))
    for bad in (replace(p,window=True),replace(p,window=-1),replace(p,start=p.position+1),replace(p,stop=p.position)):rejects('Mask',lambda:c.derive(bad,4))
    rejects('EmptyRow',lambda:c.derive(replace(spec(),position=0,positions=(1,2,3)),4))
    for xs in ([False]*3,[1<<31]*3,[-(1<<31)]*3,[0],(0,0,0)):rejects('Input',lambda:c.witness(spec(),xs))
    assert (accepted,domain,masked,ties)==(8218,1782,8008,1178)
    assert digest.hexdigest()=='087e62b41088768faa8dc95a77805fb72b7dd5736d571c3c84c652fa0bf6f84d'
    print(json.dumps(dict(seed=2730,cases=10000,accepted=accepted,domain=domain,masked=masked,ties=ties,sha256=digest.hexdigest()),sort_keys=True),flush=True)


def account(p,out,d):
    v=c.derive(p,d);a,bo,bd=v['a'],v['bo'],v['bd'];dims=[a+3,3,a+bo+1,a+bd+1,a+bd+1]+[a+3]*3;f=lambda m:3*m*(m-1)//2+2*m
    assert out['account']==dict(identities=[((1<<m)+255,p.repetitions) for m in dims],lookup_reduction_numerator=sum(p.repetitions*(f(m)+f(8)+3*m) for m in dims),range_reduction_numerator=72*a+100+7*bo+14*bd,denominator=r.sc.P**d)
    assert len(out['claims'])==20 and len(out['children'])==8 and sum(x['numerator'] for x in out['sc'])==9*a+18
    assert out['draws']=={r.zc.WEIGHT:4*a+8,r.zc.tr.CHALLENGE:4*a+8}
    for label in (r.zc.WEIGHT,r.zc.tr.CHALLENGE):assert sum(x['draws'].get(label,0) for x in [out]+out['children'])==32*a+44+3*bo+6*bd


def honest(maximum=False):
    digest=hashlib.sha256();count=0
    for d,reps in (((4,1),) if maximum else ((4,1),(4,2),(8,1),(8,2))):
        for size,S in (((16384,(1<<31)-1),) if maximum else ((1,0),(3,127),(16,32768),(65,(1<<31)-1))):
            p=spec(size,S,identity=3410+count,repetitions=reps);xs=[min(S,(-1,0,1)[j%3]) for j in range(size)] if S else [0]*size
            if size==65:p=replace(p,window=311,start=31,stop=p.position+1)
            print('honest start',count+1,d,reps,size,flush=True);proof,state=c.prove(p,xs,d);out=c.verify(p,c.expected_roots(p,xs),proof,d);assert out['state']==state;account(p,out,d);digest.update(state);count+=1;print('honest passed',count,d,reps,size,flush=True)
    if not maximum:assert digest.hexdigest()=='e96860a9139e74686c61b5a16e1bce54ca231165236a2fda220b854ceaadbd1b'
    print(json.dumps(dict(maximum=maximum,proofs=count,sha256=digest.hexdigest()),sort_keys=True),flush=True)


def controls():
    p=spec();d=4;xs=[7,7,p.schema.score_max];v=c.derive(p,d);w=c.witness(p,xs);pairs=c.prepare(p,xs,d);proof,state=c.assemble(p,pairs,w['selected'],d);roots=c.expected_roots(p,xs);out=c.verify(p,roots,proof,d);assert out['state']==state;account(p,out,d)
    for index,name in enumerate(('Source','Maximum','Selection','Difference')):
        bad=roots.copy();bad[index]=bytes([bad[index][0]^1])+bad[index][1:];rejects(name+':CommitmentMismatch',lambda:c.verify(p,bad,proof,d))
    for name in c.AUXILIARY:
        bad=copy.deepcopy(proof);value=bad['roots'][name];bad['roots'][name]=bytes([value[0]^1])+value[1:];rejects(name.title()+':CommitmentMismatch',lambda:c.verify(p,roots,bad,d))
    for name,reason in (('offset','SourceOffset'),('difference','Difference'),('gap','FirstMaximum'),('source_carry','SourceOffset'),('difference_carry','Difference'),('first_carry','FirstMaximum')):
        values=w[name].copy();values[0]=1-values[0] if name.endswith('carry') else values[0]+1;bad,_=c.assemble(p,dict(pairs,**{name:r.prove(v['ranges'][name],values,d)}),w['selected'],d);rejects(reason+':RoundSumMismatch',lambda:c.verify(p,c.roots(p,bad),bad,d))
    bad,_=c.assemble(p,dict(pairs,maximum=r.prove(v['ranges']['maximum'],[8],d)),w['selected'],d);rejects('Attainment:RoundSumMismatch',lambda:c.verify(p,c.roots(p,bad),bad,d))
    alt=c.prepare(p,[8,7,p.schema.score_max],d);bad,_=c.assemble(p,{name:(alt[name] if name in ('source','offset','source_carry') else pairs[name]) for name in c.CHILDREN},w['selected'],d);rejects('Difference:RoundSumMismatch',lambda:c.verify(p,c.roots(p,bad),bad,d))
    for selected in (62,1,True):
        bad=dict(proof,selected=selected);expected=roots.copy();expected[2]=r.root(p.selection,[int(selected)]);rejects('Selection',lambda:c.verify(p,expected,bad,d))
    for key in ('receipt','certificate','mask','position'):rejects('ProofShape',lambda:c.verify(p,roots,dict(proof,**{key:{}}),d))
    bad=copy.deepcopy(proof);bad['zero'][0]['rounds'][0][0]=(False,0,0,0);rejects('NoncanonicalField',lambda:c.verify(p,roots,bad,d))
    print('four external/five auxiliary roots, all arithmetic roles, valid source substitutes and masked selection reject',flush=True)


def originals():
    p=spec(score_max=0,identity=3440);d=4;v=c.derive(p,d);pairs=c.prepare(p,[0]*3,d);proof,state=c.assemble(p,pairs,0,d);roots=c.expected_roots(p,[0]*3);assert c.verify(p,roots,proof,d)['state']==state;one=r.sc.scalar(1,d)
    cases=[(0,[(j,one),(3,one)]) for j in (0,1,2)]+[(0,[(4,one),(3,r.sc.scalar(-256,d))])]+[(1,[(j,one)]) for j in (0,1,4)]+[(1,[(2,one),(3,r.sc.scalar(-1,d))]),(1,[(5,one),(2,r.sc.scalar(256,d))])]+[(2,[(j,one),(3,one)]) for j in (0,1,2)]+[(2,[(4,one),(3,r.sc.scalar(-256,d))]),(3,[(0,one),(1,r.sc.scalar(-1,d))]),(4,[(0,one),(1,one)])]
    # The source and selected-offset terms in Difference share the actual mask value.
    mask=proof['zero'][1]['final'][1][0]
    cases=[case for case in cases if not(case[0]==1 and case[1][0][0] in (0,4))]+[(1,[(0,one),(2,r.sc.neg(mask))]),(1,[(4,one),(2,mask)])]
    touched=set()
    for index,changes in cases:
        bad=copy.deepcopy(proof)
        for j,delta in changes:bad['zero'][index]['final'][j][0]=r.sc.add(bad['zero'][index]['final'][j][0],delta);touched.add((index,j))
        rejects(('SourceOffset','Difference','FirstMaximum','Terminal','Attainment')[index]+':ClaimMismatch',lambda:c.verify(p,roots,bad,d))
    assert touched=={(i,j) for i,size in enumerate((5,6,5,2,2)) for j in range(size)}
    for changed in (replace(p,window=32),replace(p,position=32),replace(p,start=1,position=31),replace(p,schema=replace(p.schema,fraction=13)),replace(p,positions=(0,31,63))):
        reason='Selection' if changed.start else 'Difference:ClaimMismatch';rejects(reason,lambda:c.verify(changed,roots,proof,d))
    t=c.transcript(v,roots+[proof['roots'][name] for name in c.AUXILIARY],[pairs[name][1] for name in c.CHILDREN],d);parts=[]
    for index,(_,i,tables) in enumerate(c.parts(p,proof,d)):
        if index==1:tables[1][-1]=one
        parts.append(r.zero_prove(t,i,tables))
    rejects('Difference:ClaimMismatch',lambda:c.verify(p,roots,dict(proof,zero=parts),d))
    print('all twenty originals, masked public views and expected window/position/block/units/keys replays reject',flush=True)


def boundaries():
    p=spec(identity=3450);d=4;v=c.derive(p,d);xs=[7,7,p.schema.score_max];pairs=c.prepare(p,xs,d)
    bad,_=c.assemble(p,dict(pairs,maximum=r.prove(v['ranges']['maximum'],[7+r.sc.P],d)),0,d);rejects('Attainment:RoundSumMismatch',lambda:c.verify(p,c.roots(p,bad),bad,d))
    values=[7,7+p.schema.score_max,2*p.schema.score_max];bad,_=c.assemble(p,dict(pairs,offset=r.prove(v['ranges']['offset'],values,d)),0,d);rejects('SourceOffset:RoundSumMismatch',lambda:c.verify(p,c.roots(p,bad),bad,d))
    pairs=forged_pairs(p,[7,7,p.schema.score_max],31,[0,0,0],[r.sc.P-1,0,0]);bad,_=c.assemble(p,pairs,31,d);assert (r.sc.P-1+1)%r.sc.P==0;rejects('FirstMaximum:RoundSumMismatch',lambda:c.verify(p,c.roots(p,bad),bad,d))
    S=p.schema.score_max;xs=[S,-S,0];rejects('Domain',lambda:c.witness(p,xs));delta=2*S-r.sc.P;assert 0<=delta<=1<<31 and (2*S-delta)%r.sc.P==0
    pairs=forged_pairs(p,xs,0,[0,delta,0],[0,delta,0]);bad,_=c.assemble(p,pairs,0,d);rejects('Difference:RoundSumMismatch',lambda:c.verify(p,c.roots(p,bad),bad,d))
    p=spec(score_max=1<<30,identity=3451);v=c.derive(p,d);xs=[1<<30,-(1<<30),0];proof,state=c.prove(p,xs,d);assert c.verify(p,c.expected_roots(p,xs),proof,d)['state']==state;assert c.witness(p,xs)['difference'][1]==1<<31
    p=spec(score_max=127,bits=7,identity=3452);v=c.derive(p,d);xs=[1,0,127];pairs=c.prepare(p,xs,d);w=c.witness(p,xs)
    for name,index,value,reason in (('offset',0,255,'Offset'),('difference',1,129,'Difference'),('difference',2,1,'Difference'),('gap',2,1,'Gap')):
        child=v['ranges'][name];values=w[name].copy();values[index]=value;caps=list(child.caps);caps[index]=value;changed=r.assemble(child,*r.witness(replace(child,caps=tuple(caps)),values),d);bad,_=c.assemble(p,dict(pairs,**{name:changed}),0,d);rejects(reason+':CapRelation:RoundSumMismatch',lambda:c.verify(p,c.roots(p,bad),bad,d))
    child=v['ranges']['source'];changed=r.assemble(child,*r.witness(replace(child,caps=child.caps+(1,)),w['source']+[1]),d);bad,_=c.assemble(p,dict(pairs,source=changed),0,d);rejects('Source:CapRelation:RoundSumMismatch',lambda:c.verify(p,c.roots(p,bad),bad,d))
    print('maximum/source/difference/tie M31 aliases, inclusive domain, actual caps and source padding controls pass',flush=True)


if __name__=='__main__':
    modes={'--corpus':corpus,'--controls':controls,'--originals':originals,'--boundaries':boundaries,'--honest':honest,'--maximum':lambda:honest(True)}
    if sys.argv[1:]:
        assert all(mode in modes for mode in sys.argv[1:])
        for mode in sys.argv[1:]:modes[mode]()
    else:
        for test in modes.values():test()
