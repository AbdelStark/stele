# /// script
# requires-python = ">=3.12"
# dependencies = ["numpy==2.3.4", "blake3==1.0.11"]
# ///
"""RFC-0004 A3/A6: restored code/scale sources and actual original consumers."""
import copy
from dataclasses import replace
import hashlib
import json
import random
import sys
import numpy as np
import attention_values as c

r=c.r


def rejects(reason,call):
    try:call()
    except ValueError as error:assert str(error)==reason,(reason,str(error))
    else:raise AssertionError('accepted '+reason)


def spec(rows=2,width=2,mode='dynamic',scale=0,identity=4100,repetitions=1):
    return c.Spec(c.bounds.Spec(1<<20,width,7,14,mode,scale,'exact'),tuple(31*j for j in range(rows)),identity,1301,1303,1307,repetitions)


def oracle(p,codes,scales):
    count=len(p.positions)*p.schema.width;n=1<<(count-1).bit_length();nr=1<<(len(p.positions)-1).bit_length()
    cap=127 if p.schema.value_mode=='dynamic' else min(127,(65536+p.schema.scale)//(2*p.schema.scale));maximum=259 if p.schema.value_mode=='dynamic' else p.schema.scale
    offsets=(cap*maximum+np.array(codes,dtype=np.int64)*np.repeat(np.array(scales,dtype=np.int64),p.schema.width)).tolist()
    raw=(np.array(codes+[0]*(n-count),dtype=np.int64)&255).astype(np.uint8).tolist()
    def planes(values,size,dtype):return np.frombuffer(np.array(values+[0]*(size-len(values)),dtype=dtype).tobytes(),dtype=np.uint8).reshape(size,-1).T.reshape(-1).tolist()
    return offsets,[r.root(p.source,raw),r.root(p.scale_source,planes(scales,nr,'<u2')),r.root(p.output,planes(offsets,n,'<u4'))]


def corpus():
    rng=random.Random(2734);digest=hashlib.sha256();widths=set();zeros=0;cells=0
    for index in range(10000):
        rows=rng.randrange(1,5);width=rng.randrange(1,18);mode='dynamic' if index%2 else 'static';scale=0 if mode=='dynamic' else rng.choice((1,2,258,259,32768,65535,rng.randrange(1,65536)));p=spec(rows,width,mode,scale)
        maximum=259 if mode=='dynamic' else scale;cap=127 if mode=='dynamic' else min(127,(65536+scale)//(2*scale));scales=[rng.choice((0,1,127,128,258,259)) if mode=='dynamic' else scale for _ in range(rows)]
        codes=[rng.randint(-cap,cap) if scales[j//width] else 0 for j in range(rows*width)];expected,roots=oracle(p,codes,scales);v=c.derive(p,4);w=c.witness(p,codes,scales)
        assert w['output']==expected and w['magnitude']==list(map(abs,codes));assert c.expected_roots(p,codes,scales)==roots and v['S']==cap*maximum;assert 2*v['bound']<r.sc.P
        if mode=='dynamic':assert w['nonzero']==[int(x!=0) for x in scales] and w['predecessor']==[max(x-1,0) for x in scales]
        widths.add(v['bo']);zeros+=scales.count(0);cells+=len(codes);digest.update(b''.join(roots))
    assert widths=={0,1,2} and zeros>0
    for mode,scale in (('dynamic',0),('static',65535)):
        p=spec(128,128,mode,scale,(1<<44)-1,2);v=c.derive(p,8);assert v['n']==16384 and v['nr']==128 and v['base']+(1<<18)==(1<<63)+(1<<62)
        assert all(r.derive(x,8)[2]*r.derive(x,8)[3]<=131072 for x in v['ranges'].values())
    p=spec();v=c.derive(p,4)
    for bad in (replace(p,identity=1<<44),replace(p,repetitions=True),replace(p,source=v['base']),replace(p,output=p.source),replace(p,positions=(31,0)),replace(p,positions=(0,0)),replace(p,positions=(True,))):rejects('Spec',lambda:c.derive(bad,4))
    rejects('Capacity',lambda:c.derive(spec(2,16384),4));rejects('Input',lambda:c.witness(p,[1,0,0,0],[0,1]))
    assert digest.hexdigest()=='e9b2d757efa88648081269849d7886ddc78ed44119c2930b1c5fc932a85a53fb'
    print(json.dumps(dict(seed=2734,cases=10000,cells=cells,zero_scales=zeros,sha256=digest.hexdigest()),sort_keys=True),flush=True)


def account(p,out,d):
    v=c.derive(p,d);a,ar,bo=v['a'],v['ar'],v['bo'];dynamic=v['dynamic'];dims=[a+1,a+1,a+2,a+1,a+bo+1]+([ar+2,ar+1,ar+2] if dynamic else []);f=lambda m:3*m*(m-1)//2+2*m
    loss=67*a+30*ar+26+7*bo if dynamic else 64*a+9+7*bo;draw=28*a+13*ar+11+3*bo if dynamic else 27*a+4+3*bo
    assert out['account']==dict(identities=[((1<<m)+255,p.repetitions) for m in dims],lookup_reduction_numerator=sum(p.repetitions*(f(m)+f(8)+3*m) for m in dims),range_reduction_numerator=loss,denominator=r.sc.P**d)
    assert len(out['claims'])==(11 if dynamic else 5)
    draws=[out['draws']]+[x['draws'] for x in out['children']]+[x['draws'] for x in out['children'][0]['ranges']]
    assert all(sum(x.get(label,0) for x in draws)==draw for label in (r.zc.WEIGHT,r.zc.tr.CHALLENGE))


def honest(mode=None):
    digest=hashlib.sha256();done=0;cases=((1,1,'dynamic',0),(1,1,'static',1),(3,1,'static',2),(2,8,'dynamic',0),(5,13,'static',65535))
    if mode:cases=((128,128,'dynamic' if mode=='maximum' else 'static',0 if mode=='maximum' else 65535),)
    for d,reps in (((4,1),) if mode else ((4,1),(4,2),(8,1),(8,2))):
        for rows,width,policy,scale in cases:
            p=spec(rows,width,policy,scale,4110+done,reps);v=c.derive(p,d);scales=[(0,259,1)[j%3] if policy=='dynamic' else scale for j in range(rows)];codes=[(-v['cap'],0,v['cap'],1)[j%4] if scales[j//width] else 0 for j in range(rows*width)]
            print('honest start',done+1,d,reps,rows,width,policy,flush=True);proof,state=c.prove(p,codes,scales,d);out=c.verify(p,oracle(p,codes,scales)[1],proof,d);assert out['state']==state;account(p,out,d);digest.update(state);done+=1;print('honest passed',done,d,reps,rows,width,policy,flush=True)
    if mode is None:assert digest.hexdigest()=='fa90ed30a01a39392a3e8844dec842a997677d3eed737ece6a194e0a6372af7f'
    print(json.dumps(dict(mode=mode,proofs=done,sha256=digest.hexdigest()),sort_keys=True),flush=True)


def controls():
    p=spec();d=4;codes=[-127,1,0,0];scales=[259,0];v=c.derive(p,d);w=c.witness(p,codes,scales);pairs=c.prepare(p,codes,scales,d);proof,state=c.assemble(p,pairs,d);roots=oracle(p,codes,scales)[1];out=c.verify(p,roots,proof,d);assert out['state']==state;account(p,out,d)
    for index,name in enumerate(('Source:Raw','Scale','Output')):
        changed=roots.copy();changed[index]=bytes(32);rejects(name+':CommitmentMismatch',lambda:c.verify(p,changed,proof,d))
    for delta in (-1,1):
        values=w['output'].copy();values[1]+=delta;bad,_=c.assemble(p,dict(pairs,output=r.prove(v['ranges']['output'],values,d)),d);rejects('Restoration:RoundSumMismatch',lambda:c.verify(p,c.roots(p,bad),bad,d))
    other=[1,-127,0,0];bad,st=c.prove(p,other,scales,d);assert c.verify(p,oracle(p,other,scales)[1],bad,d)['state']==st;rejects('Source:Raw:CommitmentMismatch',lambda:c.verify(p,roots,bad,d))
    zero=[0]*4;proof,st=c.prove(p,zero,[1,2],d);roots=oracle(p,zero,[1,2])[1];assert c.verify(p,roots,proof,d)['state']==st;bad,st=c.prove(p,zero,[2,1],d);assert c.verify(p,oracle(p,zero,[2,1])[1],bad,d)['state']==st;rejects('Scale:CommitmentMismatch',lambda:c.verify(p,roots,bad,d))
    p=spec(3,1,identity=4140);v=c.derive(p,d);scales=[0,1,1];pairs=c.prepare(p,[0]*3,scales,d);changed=dict(pairs,source=c.ss.prove(v['signed'],[1,0,0],d),magnitude=r.prove(v['ranges']['magnitude'],[1,0,0],d));bad,_=c.assemble(p,changed,d);rejects('ZeroScaleCodes:RoundSumMismatch',lambda:c.verify(p,c.roots(p,bad),bad,d))
    for flags,pred in (([0,0,1],[0,1,0]),([1,1,1],[0,0,0]),([0,1,1],[0,1,0])):
        bad,_=c.assemble(p,dict(pairs,nonzero=r.prove(v['ranges']['nonzero'],flags,d),predecessor=r.prove(v['ranges']['predecessor'],pred,d)),d);rejects('ScalePredicates:RoundSumMismatch',lambda:c.verify(p,c.roots(p,bad),bad,d))
    print('source/scale roots, fresh false offsets, valid substitutions and zero-scale predicates reject',flush=True)


def originals():
    p=spec(1,1,identity=4150);d=4;proof,state=c.prove(p,[0],[0],d);roots=oracle(p,[0],[0])[1];assert c.verify(p,roots,proof,d)['state']==state
    for index in (1,2,3):
        bad=copy.deepcopy(proof);bad['zero'][0]['final'][index][0]=r.sc.scalar(1,d);rejects('Restoration:ClaimMismatch',lambda:c.verify(p,roots,bad,d))
    rejects('ProofShape',lambda:c.verify(p,roots,dict(proof,zero=proof['zero'][:1]),d));rejects('ProofShape',lambda:c.verify(p,roots,dict(proof,certificate={}),d))
    bad=copy.deepcopy(proof);bad['zero'][0]['final'][0][0]=(r.sc.P,)+(0,)*(d-1);rejects('NoncanonicalField',lambda:c.verify(p,roots,bad,d))
    v=c.derive(p,d);pairs=c.prepare(p,[0],[0],d);pairs['output']=r.prove(v['ranges']['output'],[2*v['S']],d);bad,_=c.assemble(p,pairs,d);expected=c.roots(p,bad);t=c.transcript(v,c.bound(v,expected,bad),[pairs[name][1] for name in v['names']],d);bad['zero']=[]
    for index,(_,instance,tables) in enumerate(c.parts(p,bad,d)):
        if index==0:tables[4]=[r.sc.scalar(2,d)]
        bad['zero'].append(r.zero_prove(t,instance,tables))
    rejects('Restoration:ClaimMismatch',lambda:c.verify(p,expected,bad,d))
    print('zero-hidden scale/raw/sign originals, false real-row mask and mandatory children reject',flush=True)


def boundaries():
    p=spec(3,1,identity=4160);d=4;v=c.derive(p,d);pairs=c.prepare(p,[0]*3,[0]*3,d)
    for name,index in (('output',3),('nonzero',0),('nonzero',3),('predecessor',0),('predecessor',3)):
        child=v['ranges'][name];caps=list(child.caps);values=[0]*len(caps)
        if index==len(caps):caps.append(0);values.append(0)
        caps[index]+=1;values[index]=caps[index];false=r.assemble(child,*r.witness(replace(child,caps=tuple(caps)),values),d);bad,_=c.assemble(p,dict(pairs,**{name:false}),d);rejects(name.title()+':CapRelation:RoundSumMismatch',lambda:c.verify(p,c.roots(p,bad),bad,d))
    child=v['ranges']['magnitude'];false=r.assemble(child,*r.witness(replace(child,caps=(128,127,127)),[128,0,0]),d);bad,_=c.assemble(p,dict(pairs,source=c.ss.prove(v['signed'],[-128,0,0],d),magnitude=false),d);rejects('Magnitude:CapRelation:RoundSumMismatch',lambda:c.verify(p,c.roots(p,bad),bad,d))
    p=spec(3,1,'static',1,4161);v=c.derive(p,d);proof,st=c.prove(p,[-127,0,127],[1]*3,d);roots=oracle(p,[-127,0,127],[1]*3)[1];assert c.verify(p,roots,proof,d)['state']==st
    changed=roots.copy();changed[1]=r.root(p.scale_source,[2,1,1,0]+[0]*4);rejects('Scale:CommitmentMismatch',lambda:c.verify(p,changed,proof,d));words=c.full_output(v,proof['output']['words']);words[-1]=1;changed=roots.copy();changed[2]=r.root(p.output,words);rejects('Output:CommitmentMismatch',lambda:c.verify(p,changed,proof,d))
    print('symmetric code cap, padded output/predicates, static scale and full output extension reject',flush=True)


def edge_controls():
    d=4;p=spec(3,1,identity=4190);v=c.derive(p,d);pairs=c.prepare(p,[0]*3,[0]*3,d);values=[v['S']+r.sc.P,v['S'],v['S']];child=v['ranges']['output'];caps=(values[0],)+child.caps[1:]
    false=r.assemble(child,*r.witness(replace(child,caps=caps),values),d);bad,_=c.assemble(p,dict(pairs,output=false),d);rejects('Output:CapRelation:RoundSumMismatch',lambda:c.verify(p,c.roots(p,bad),bad,d))
    p=spec(3,1,'static',65535,4191);v=c.derive(p,d);pairs=c.prepare(p,[0]*3,[65535]*3,d);child=v['ranges']['magnitude'];false=r.assemble(child,*r.witness(replace(child,caps=(2,1,1)),[2,0,0]),d)
    bad,_=c.assemble(p,dict(pairs,source=c.ss.prove(v['signed'],[2,0,0],d),magnitude=false),d);rejects('Magnitude:CapRelation:RoundSumMismatch',lambda:c.verify(p,c.roots(p,bad),bad,d))
    p=spec(1,1,identity=4192);proof,_=c.prove(p,[0],[0],d);roots=oracle(p,[0],[0])[1]
    for part,index,name in ((0,0,'Restoration:FinalEvaluationMismatch'),(1,0,'ScalePredicates:FinalEvaluationMismatch'),(1,1,'ScalePredicates:FinalEvaluationMismatch'),(1,2,'ScalePredicates:FinalEvaluationMismatch'),(1,3,'ScalePredicates:ClaimMismatch'),(2,1,'ZeroScaleCodes:ClaimMismatch')):
        bad=copy.deepcopy(proof);old=bad['zero'][part]['final'][index][0];bad['zero'][part]['final'][index][0]=r.sc.add(old,r.sc.scalar(1,d));rejects(name,lambda:c.verify(p,roots,bad,d))
    proof,_=c.prove(p,[0],[1],d);proof['zero'][2]['final'][0][0]=r.sc.scalar(1,d);rejects('ZeroScaleCodes:ClaimMismatch',lambda:c.verify(p,oracle(p,[0],[1])[1],proof,d))
    print('M31 offset alias, tighter static cap and all remaining parent originals reject',flush=True)


def composition():
    import row_code as dynamic
    import static_row_code as static
    for index,(mode,scale,inputs) in enumerate((('dynamic',0,[-32768,0,32767]),('static',2,[-254,0,254]))):
        p=spec(1,3,mode,scale,4170+index);d=4;module=dynamic if mode=='dynamic' else static;schema=static.row.Spec('wide',3,7,mode,scale);rp=module.Spec(schema,4180+index,1319,p.scale_source,p.source,1)
        child,st=module.prove(rp,inputs,d);roots=module.roots(rp,child);assert module.verify(rp,roots,child,d)['state']==st;w=module.witness(rp,inputs);codes=w['codes'];actual=w['scale'] if mode=='dynamic' else scale
        proof,state=c.prove(p,codes,[actual],d);expected=oracle(p,codes,[actual])[1];assert expected[:2]==[roots[2],roots[1]] and c.verify(p,expected,proof,d)['state']==state
        changed=inputs[:-1]+[-inputs[-1]];other,st=module.prove(rp,changed,d);other_roots=module.roots(rp,other);assert module.verify(rp,other_roots,other,d)['state']==st
        other_codes=module.witness(rp,changed)['codes'];bad,st=c.prove(p,other_codes,[actual],d);assert c.verify(p,oracle(p,other_codes,[actual])[1],bad,d)['state']==st;rejects('Source:Raw:CommitmentMismatch',lambda:c.verify(p,expected,bad,d));print('actual prepared value composition passed',mode,flush=True)


if __name__=='__main__':
    modes={'--corpus':corpus,'--controls':controls,'--originals':originals,'--boundaries':boundaries,'--edge-controls':edge_controls,'--composition':composition,'--honest':honest,'--maximum':lambda:honest('maximum'),'--full-static':lambda:honest('static')}
    if sys.argv[1:]:
        assert all(mode in modes for mode in sys.argv[1:])
        for mode in sys.argv[1:]:modes[mode]()
    else:
        for test in modes.values():test()
