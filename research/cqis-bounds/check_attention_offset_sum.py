# /// script
# requires-python = ">=3.12"
# dependencies = ["numpy==2.3.4", "blake3==1.0.11"]
# ///
"""Draft RFC-0004 A3/A6: weighted offsets, bounded columns and actual originals."""
import copy
from dataclasses import replace
import hashlib
import json
import random
import sys
import numpy as np
import attention_offset_sum as c

r=c.r


def rejects(reason,call):
    try:call()
    except ValueError as error:assert str(error)==reason,(reason,str(error))
    else:raise AssertionError('accepted '+reason)


def spec(rows=2,width=3,exponent=14,mode='dynamic',scale=0,identity=4400,repetitions=1):
    return c.Spec(c.bounds.Spec(1<<20,width,7,exponent,mode,scale,'exact'),tuple(31*j for j in range(rows)),(True,)*rows,0,identity,1409,1423,1427,repetitions)


def oracle(p,weights,values):
    rows=len(p.positions);width=p.schema.width;nr=1<<(rows-1).bit_length();n=1<<(rows*width-1).bit_length();nc=1<<(width-1).bit_length()
    result=(np.array(weights,dtype=np.int64)@np.array(values,dtype=np.int64).reshape(rows,width)).tolist()
    def planes(xs,size,dtype):return np.frombuffer(np.array(xs+[0]*(size-len(xs)),dtype=dtype).tobytes(),dtype=np.uint8).reshape(size,-1).T.reshape(-1).tolist()
    roots=[r.root(p.probability,planes(weights,nr,'<u1' if p.schema.exponent<=7 else '<u2')),r.root(p.value_source,planes(values,n,'<u4')),r.root(p.output,planes(result,nc,'<u8'))]
    return result,roots


def carries(p,weights,values):
    width=p.schema.width;nc=1<<(width-1).bit_length();out=[[0]*nc for _ in range(16)]
    # Prefix convolution computes every carry independently of the producer recurrence.
    for channel in range(width):
        coeff=[sum((weight>>(4*i)&15)*(values[j*width+channel]>>(4*(k-i))&15) for j,weight in enumerate(weights) for i in range(4) if 0<=k-i<5) for k in range(8)]
        for k in range(1,16):out[k][channel]=sum(x<<(4*i) for i,x in enumerate(coeff[:k]))>>(4*k)
    return sum(out,[])


def corpus():
    rng=random.Random(2735);digest=hashlib.sha256();zeros=0;cells=0
    for index in range(10000):
        rows=rng.randrange(1,5);width=rng.randrange(1,18);mode='dynamic' if index%2 else 'static';scale=0 if mode=='dynamic' else rng.choice((1,2,259,65535));p=spec(rows,width,index%15,mode,scale)
        if index%3==0:p=replace(p,schema=replace(p.schema,accumulation='block1024'),positions=tuple(2048+17*j for j in range(rows)),block=2)
        allowed=tuple(bool(rng.randrange(2)) for _ in range(rows));p=replace(p,allowed=allowed);S=127*259 if mode=='dynamic' else scale*min(127,(65536+scale)//(2*scale))
        weights=[rng.randint(0,1<<p.schema.exponent)*int(bit) for bit in allowed];values=[rng.randint(0,2*S) for _ in range(rows*width)];output,roots=oracle(p,weights,values);v=c.derive(p,4);w=c.witness(p,weights,values)
        assert w['probability']==weights and w['value']==values and w['output']==output and c.expected_roots(p,weights,values)==roots
        carry=carries(p,weights,values);assert [x for name in v['ranges'] if name.startswith('carry_') for x in w[name]]==carry
        assert 2*max(v['cert']['lhs']+v['cert']['rhs'])<r.sc.P;zeros+=not any(output);cells+=len(values);digest.update(b''.join(roots))
    for rows,width in ((128,128),(16384,1),(1,16384)):
        p=spec(rows,width,14,'static',65535,(1<<44)-1,2);v=c.derive(p,8);assert v['k']==13 and v['base']+(1<<18)==(1<<63)+(1<<62)
        assert all(r.derive(child,8)[2]*r.derive(child,8)[3]<=131072 for child in v['ranges'].values())
    p=spec();v=c.derive(p,4)
    for bad in (replace(p,identity=1<<44),replace(p,repetitions=True),replace(p,probability=v['base']),replace(p,value_source=p.probability),replace(p,positions=(31,0)),replace(p,allowed=(1,True)),replace(p,block=1)):
        rejects('Spec',lambda:c.derive(bad,4))
    rejects('Capacity',lambda:c.derive(spec(2,16384),4));rejects('Input',lambda:c.witness(replace(p,allowed=(False,True)),[1,0],[0]*6))
    assert zeros>1000
    assert digest.hexdigest()=='e1ae0608e74c877ac2e15a0b543bbb527cfd8a0dd85da3c07445aa69164340bb'
    print(json.dumps(dict(seed=2735,cases=10000,cells=cells,zero_outputs=zeros,sha256=digest.hexdigest()),sort_keys=True),flush=True)


def account(p,out,d):
    v=c.derive(p,d);layouts=[r.derive(child,d) for child in v['ranges'].values()];dims=[a+b+1 for a,b,*_ in layouts];f=lambda m:3*m*(m-1)//2+2*m
    assert out['account']==dict(identities=[((1<<m)+255,p.repetitions) for m in dims],lookup_reduction_numerator=sum(p.repetitions*(f(m)+f(8)+3*m) for m in dims),range_reduction_numerator=sum(9*a+7*b for a,b,*_ in layouts),weighted_identity_numerator=v['k']-1+v['ac'],weighted_reduction_numerator=2*v['ar'],denominator=r.sc.P**d)
    assert len(out['claims'])==2 and out['draws']=={r.zc.tr.CHALLENGE:1+v['ac']+v['ar']}
    expected=sum(4*a+3*b for a,b,*_ in layouts)
    for label,extra in ((r.zc.WEIGHT,0),(r.zc.tr.CHALLENGE,1+v['ac']+v['ar'])):assert sum(x['draws'].get(label,0) for x in [out]+out['children'])==expected+extra


def honest(mode=None):
    digest=hashlib.sha256();done=0;cases=((1,1,0,'static',1),(3,1,14,'static',65535),(2,3,14,'dynamic',0),(5,13,7,'static',2))
    if mode:cases=(({'maximum':128,'keys':16384,'wide':1}[mode],{'maximum':128,'keys':1,'wide':16384}[mode],14,'static',65535),)
    for d,reps in (((4,1),) if mode else ((4,1),(4,2),(8,1),(8,2))):
        for rows,width,E,policy,scale in cases:
            p=spec(rows,width,E,policy,scale,4410+done,reps)
            if not mode and rows==1:p=replace(p,schema=replace(p.schema,length=1))
            if not mode and rows==5:p=replace(p,schema=replace(p.schema,accumulation='block1024'))
            v=c.derive(p,d);S=v['constants']['restored_max'];weights=[(0,1<<E,1)[j%3] for j in range(rows)];values=[(0,2*S,S,1)[j%4] for j in range(rows*width)]
            if rows==1:weights=[1<<E]
            print('honest start',done+1,d,reps,rows,width,flush=True);proof,state=c.prove(p,weights,values,d);out=c.verify(p,oracle(p,weights,values)[1],proof,d);assert out['state']==state;account(p,out,d);digest.update(state);done+=1;print('honest passed',done,d,reps,rows,width,flush=True)
    print(json.dumps(dict(mode=mode,proofs=done,sha256=digest.hexdigest()),sort_keys=True),flush=True)


def controls():
    p=spec();d=4;weights=[1,2];values=[1,2,3,4,5,6];v=c.derive(p,d);w=c.witness(p,weights,values);pairs=c.prepare(p,weights,values,d);proof,state=c.assemble(p,pairs,d);roots=oracle(p,weights,values)[1];out=c.verify(p,roots,proof,d);assert out['state']==state;account(p,out,d)
    for index,name in enumerate(('Probability','Value','Output')):
        bad=roots.copy();bad[index]=bytes(32);rejects(name+':CommitmentMismatch',lambda:c.verify(p,bad,proof,d))
    for changes in ((1,0,0),(1,-1,0),(r.sc.P,0,0)):
        output=[x+y for x,y in zip(w['output'],changes)];bad,_=c.assemble(p,dict(pairs,output=r.prove(v['ranges']['output'],output,d)),d);rejects('WeightedSum:RoundSumMismatch',lambda:c.verify(p,c.roots(p,bad),bad,d))
    for ws,vs,reason in (([2,1],values,'Probability'),(weights,values[3:]+values[:3],'Value')):
        bad,st=c.prove(p,ws,vs,d);assert c.verify(p,oracle(p,ws,vs)[1],bad,d)['state']==st;rejects(reason+':CommitmentMismatch',lambda:c.verify(p,roots,bad,d))
    for key in ('receipt','certificate','point','projected'):rejects('ProofShape',lambda:c.verify(p,roots,dict(proof,**{key:{}}),d))
    print('all roots, false sums, compensating channels, M31 aliases and valid source substitutions reject',flush=True)


def originals():
    p=spec(1,1);d=4
    for weights,values,index in (([1],[0],0),([0],[123],1)):
        proof,state=c.prove(p,weights,values,d);roots=oracle(p,weights,values)[1];assert c.verify(p,roots,proof,d)['state']==state
        bad=copy.deepcopy(proof);bad['sum']['final'][index]=r.sc.add(bad['sum']['final'][index],r.sc.scalar(1,d));rejects('WeightedSum:ClaimMismatch',lambda:c.verify(p,roots,bad,d))
        bad=copy.deepcopy(proof);bad['sum']['final'][index]=(r.sc.P,)+(0,)*(d-1);rejects('NoncanonicalField',lambda:c.verify(p,roots,bad,d))
    print('both zero-hidden original factors and noncanonical parent fields reject',flush=True)


def boundaries():
    p=spec(3,3);p=replace(p,allowed=(True,False,True));d=4;v=c.derive(p,d);pairs=c.prepare(p,[0]*3,[0]*9,d)
    attacks=[('probability',1),('probability',3),('value',9),('output',3)]
    for name in v['ranges']:
        if name.startswith('carry_'):
            child=v['ranges'][name]
            for index,cap in enumerate(child.caps):
                if cap==0 and index%v['nc']==0:attacks.append((name,index))
    for name,index in attacks:
        child=v['ranges'][name];caps=list(child.caps);xs=[0]*len(caps)
        if index==len(caps):caps.append(0);xs.append(0)
        caps[index]=max(1,caps[index]+1);xs[index]=caps[index];false=r.assemble(child,*r.witness(replace(child,caps=tuple(caps)),xs),d);bad,_=c.assemble(p,dict(pairs,**{name:false}),d)
        rejects(name.title()+':CapRelation:RoundSumMismatch',lambda:c.verify(p,c.roots(p,bad),bad,d))
    p=spec(1,1,0,'static',1);proof,state=c.prove(p,[1],[1],d);roots=oracle(p,[1],[1])[1];assert c.verify(p,roots,proof,d)['state']==state
    for index,source,width in ((1,p.value_source,4),(2,p.output,8)):
        words=[1]+[0]*(width-1);words[-1]=1;bad=roots.copy();bad[index]=r.root(source,words);rejects(('Value' if index==1 else 'Output')+':CommitmentMismatch',lambda:c.verify(p,bad,proof,d))
    p=replace(spec(2,3),allowed=(False,False));proof,state=c.prove(p,[0,0],[123]*6,d);out=c.verify(p,oracle(p,[0,0],[123]*6)[1],proof,d);assert out['state']==state;account(p,out,d)
    print('masked/padded sources, output padding, carry boundaries/tails and full zero extensions reject; all-masked contributions pass',flush=True)


def composition():
    import attention_values as values
    import attention_probability_sum as probability
    for index,(policy,scale,codes,scales) in enumerate((('dynamic',0,[-127,0,127],[259]),('static',2,[-127,0,127],[2]))):
        p=spec(1,3,14,policy,scale,4480+index);d=4;vp=values.Spec(p.schema,p.positions,4500+index,1451,1453,p.value_source,1);child,st=values.prove(vp,codes,scales,d);vr=values.expected_roots(vp,codes,scales);assert values.verify(vp,vr,child,d)['state']==st;us=values.witness(vp,codes,scales)['output']
        row=probability.attained.Spec(probability.attained.maximum.Spec(p.schema.length,127,7,6),0,p.positions,0,0,p.schema.length,4520+index,1459,1471,1481,1483,1);pp=probability.Spec(row,p.schema.exponent,4540+index,p.probability,1487);ws=[1<<p.schema.exponent];child,st=probability.prove(pp,ws,d);pr=probability.expected_roots(pp,ws);assert probability.verify(pp,pr,child,d)['state']==st
        assert p.allowed==probability.derive(pp,d)['allowed'];proof,state=c.prove(p,ws,us,d);expected=oracle(p,ws,us)[1];assert expected[:2]==[pr[0],vr[2]] and c.verify(p,expected,proof,d)['state']==state
        other,st=values.prove(vp,list(reversed(codes)),scales,d);other_roots=values.expected_roots(vp,list(reversed(codes)),scales);assert values.verify(vp,other_roots,other,d)['state']==st;other_values=values.witness(vp,list(reversed(codes)),scales)['output'];bad,st=c.prove(p,ws,other_values,d);assert c.verify(p,oracle(p,ws,other_values)[1],bad,d)['state']==st;rejects('Value:CommitmentMismatch',lambda:c.verify(p,expected,bad,d));print('actual probability/restored-value composition passed',policy,flush=True)


if __name__=='__main__':
    modes={'--corpus':corpus,'--controls':controls,'--originals':originals,'--boundaries':boundaries,'--composition':composition,'--honest':honest,'--maximum':lambda:honest('maximum'),'--full-keys':lambda:honest('keys'),'--full-wide':lambda:honest('wide')}
    if sys.argv[1:]:
        assert all(mode in modes for mode in sys.argv[1:])
        for mode in sys.argv[1:]:modes[mode]()
    else:
        for test in modes.values():test()
