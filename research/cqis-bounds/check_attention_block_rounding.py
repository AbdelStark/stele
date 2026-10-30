# /// script
# requires-python = ">=3.12"
# dependencies = ["numpy==2.3.4", "blake3==1.0.11", "python-flint==0.9.0"]
# ///
"""Draft RFC-0004 A3/A6: actual block roots, exact rounding and strict remainder."""
import copy
from dataclasses import replace
from fractions import Fraction
import hashlib
import json
import random
import sys
import numpy as np
import attention_block_rounding as c

r=c.r


def rejects(reason,call):
    try:call()
    except ValueError as error:assert str(error)==reason,(reason,str(error))
    else:raise AssertionError('accepted '+reason)


def spec(blocks=2,width=3,identity=5100,repetitions=1):
    ids=tuple(range(blocks)) if blocks==1024 else tuple(2*j for j in range(blocks))
    return c.Spec(c.bounds.Spec(1<<20,width,7,14,'static',65535,26),ids,identity,tuple(1801+j for j in range(blocks)),4001,4003,repetitions)


def oracle(p,ms):
    width=p.schema.width;count=len(ms);n=1<<(count-1).bit_length();nc=1<<(width-1).bit_length();D=1<<p.schema.drop;h=D//2;M=np.array(ms,dtype=np.int64);qs=((M+h)//D).tolist();rs=((M+h)%D).tolist()
    def planes(xs,size,dtype):return np.frombuffer(np.array(xs+[0]*(size-len(xs)),dtype=dtype).tobytes(),dtype=np.uint8).reshape(size,-1).T.reshape(-1).tolist()
    roots=[r.root(identity,planes(ms[j*width:(j+1)*width],nc,'<u8')) for j,identity in enumerate(p.sources)]
    roots.extend((r.root(p.quotient,planes(qs,n,'<u2')),r.root(p.remainder,planes(rs,n,'<u8'))));return qs,rs,roots


def corpus():
    rng=random.Random(2738);digest=hashlib.sha256();accepted=rejected=cells=0;shifts=set();widths=set();seen=set()
    for case in range(10000):
        blocks=1+case%5;width=1+case%17;mode='dynamic' if case%2 else 'static';scale=0 if mode=='dynamic' else rng.choice((1,2,259,65535));E=case%15;drop=case%63
        if case<63:mode='static';scale=1;E=0
        p=replace(spec(blocks,width,case,1+case%2),schema=c.bounds.Spec(1<<20,width,case%31,E,mode,scale,drop));S=127*259 if mode=='dynamic' else scale*min(127,(65536+scale)//(2*scale));H=1024*(1<<E)*S;D=1<<drop;h=D//2;qmax=(H+h)//D
        if qmax>32767:rejects('BlockBound',lambda:c.derive(p,4));rejected+=1;digest.update(b'reject'+bytes([E,drop])+H.to_bytes(8,'little'));continue
        v=c.derive(p,4);count=blocks*width;ms=[rng.randrange(H+1) for _ in range(count)];ms[0]=min(H,(0,h,D-1,D,H)[case%5]);qs,rs,roots=oracle(p,ms);w=c.witness(p,ms)
        for m,q in zip(ms,qs):z=Fraction(m,D);assert q==(2*z.numerator+z.denominator)//(2*z.denominator)
        assert w['magnitude']==ms and w['quotient']==qs and w['remainder']==rs and c.expected_roots(p,ms,qs,rs)==roots
        cs=[];n=v['n'];shiftbytes=drop//8
        for k in range(1,9):
            modulus=1<<(8*k);qmod=1<<(8*max(0,k-shiftbytes));diff=[m%modulus+h%modulus-(q%qmod)*D-rem%modulus for m,q,rem in zip(ms,qs,rs)]
            assert all(x%modulus==0 and -129<=x//modulus<=2 for x in diff);seen.update(x//modulus for x in diff);cs.extend([x//modulus+129 for x in diff]+[0]*(n-count))
        assert cs[-n:]==[129]*count+[0]*(n-count) and w['carry_0']+w['carry_1']==cs
        assert H+h<1<<64 and qmax*D<1<<64 and all(0<=x<=cap for name in w for x,cap in zip(w[name],v['ranges'][name].caps))
        digest.update(v['raw']+b''.join(roots)+bytes(cs));accepted+=1;cells+=count;shifts.add(drop);widths.update(v['widths'][name] for name in ('magnitude','quotient','remainder'))
    for blocks,width in ((128,128),(1024,16),(1,16384)):
        p=spec(blocks,width,(1<<48)-1,2);v=c.derive(p,8);assert v['base']+(1<<14)==(1<<63)+(1<<62)
        spans=sorted((r.derive(child,8)[4],64) for child in v['ranges'].values());assert all(v['base']+23<lo and lo+size<=v['base']+(1<<14) for lo,size in spans) and all(lo+size<=nxt for (lo,size),(nxt,_) in zip(spans,spans[1:]))
    p=spec();v=c.derive(p,4)
    for bad in (replace(p,identity=1<<48),replace(p,repetitions=True),replace(p,blocks=()),replace(p,blocks=(2,0)),replace(p,blocks=(0,0)),replace(p,blocks=(0,1024)),replace(p,sources=(p.quotient,1802)),replace(p,sources=(v['base'],1802)),replace(p,sources=(1801,)),replace(p,schema=replace(p.schema,drop=63)),replace(p,schema=replace(p.schema,drop=True))):rejects('Spec',lambda:c.derive(bad,4))
    rejects('Capacity',lambda:c.derive(spec(2,16384),4));rejects('Spec',lambda:c.derive(p,True))
    for values in ([False]*6,[-1]*6,[v['constants']['raw_max']+1]*6,[0]):rejects('Input',lambda:c.witness(p,values))
    assert accepted+rejected==10000 and accepted>0 and rejected>0 and shifts==set(range(2,63)) and widths=={1,2,4,8} and min(seen)<0
    print(json.dumps(dict(seed=2738,cases=10000,accepted=accepted,rejected=rejected,cells=cells,carry_min=min(seen),carry_max=max(seen),sha256=digest.hexdigest()),sort_keys=True),flush=True)


def account(p,out,d):
    v=c.derive(p,d);a=v['a'];bm,bq,br=((v['widths'][name]-1).bit_length() for name in ('magnitude','quotient','remainder'));dims=[a+bm+1,a+bq+1,a+br+1,a+3,a+3];f=lambda m:3*m*(m-1)//2+2*m
    assert out['account']==dict(identities=[((1<<m)+255,p.repetitions) for m in dims],lookup_reduction_numerator=sum(p.repetitions*(f(m)+f(8)+3*m) for m in dims),range_reduction_numerator=49*a+7*(bm+bq+br)+42,denominator=r.sc.P**d)
    assert len(out['claims'])==8 and out['draws']=={r.zc.WEIGHT:2*a+3,r.zc.tr.CHALLENGE:2*a+3} and sum(x['numerator'] for x in out['sc'])==4*a+6
    assert all(sum(x['draws'].get(label,0) for x in [out]+out['children'])==22*a+19+3*(bm+bq+br) for label in (r.zc.WEIGHT,r.zc.tr.CHALLENGE))


def honest(mode=None):
    digest=hashlib.sha256();done=0;cases=((1,1,0,'static',1,2),(2,3,14,'dynamic',0,25),(3,16,8,'static',259,20),(5,13,14,'static',65535,62))
    if mode:cases=(({'maximum':128,'blocks':1024,'wide':1}[mode],{'maximum':128,'blocks':16,'wide':16384}[mode],14,'static',65535,26),)
    for d,reps in (((4,1),) if mode else ((4,1),(4,2),(8,1),(8,2))):
        for blocks,width,E,policy,scale,drop in cases:
            p=replace(spec(blocks,width,5110+done,reps),schema=c.bounds.Spec(1<<20,width,7,E,policy,scale,drop));v=c.derive(p,d);H=v['constants']['raw_max'];pattern=[min(H,x) for x in (0,v['bias'],v['divisor']-1,v['divisor'],H)];ms=(pattern*((v['count']+4)//5))[:v['count']]
            print('honest start',done+1,d,reps,blocks,width,drop,flush=True);proof,state=c.prove(p,ms,d);out=c.verify(p,oracle(p,ms)[2],proof,d);assert out['state']==state;account(p,out,d);digest.update(state);done+=1;print('honest passed',done,d,reps,blocks,width,drop,flush=True)
    print(json.dumps(dict(mode=mode,proofs=done,sha256=digest.hexdigest()),sort_keys=True),flush=True)


def controls():
    p=spec();d=4;v=c.derive(p,d);B=v['divisor'];h=v['bias'];ms=[0,h,B,B+h,1,2];w=c.witness(p,ms);pairs=c.prepare(p,ms,d);proof,state=c.assemble(p,pairs,d);roots=oracle(p,ms)[2];out=c.verify(p,roots,proof,d);assert out['state']==state;account(p,out,d)
    names=['Magnitude:'+str(block) for block in p.blocks]+['Quotient','Remainder']
    for index,name in enumerate(names):
        bad=roots.copy();bad[index]=bytes(32);rejects(name+':CommitmentMismatch',lambda:c.verify(p,bad,proof,d))
    for name in v['ranges']:
        bad=copy.deepcopy(proof);bad[name]['words'][0]^=1;rejects(name.title()+':CommitmentMismatch',lambda:c.verify(p,roots,bad,d))
    for name,index,delta in (('magnitude',0,1),('magnitude',0,r.sc.P),('quotient',0,1),('remainder',0,1)):
        values=w[name].copy();values[index]+=delta;bad,_=c.assemble(p,dict(pairs,**{name:r.prove(v['ranges'][name],values,d)}),d);rejects('RoundColumns:RoundSumMismatch',lambda:c.verify(p,c.roots(p,bad),bad,d))
    qs=w['quotient'].copy();rs=w['remainder'].copy();qs[1]=0;rs[1]=B;assert all(m+h==q*B+rem for m,q,rem in zip(ms,qs,rs));changed=dict(pairs,quotient=r.prove(v['ranges']['quotient'],qs,d));child=v['ranges']['remainder'];caps=list(child.caps);caps[1]=B;changed['remainder']=r.assemble(child,*r.witness(replace(child,caps=tuple(caps)),rs),d);cs=c.carries(p,ms,qs,rs)
    for g in range(2):changed['carry_'+str(g)]=r.prove(v['ranges']['carry_'+str(g)],cs[4*g*v['n']:4*(g+1)*v['n']],d)
    bad,_=c.assemble(p,changed,d);rejects('Remainder:CapRelation:RoundSumMismatch',lambda:c.verify(p,c.roots(p,bad),bad,d))
    bad,_=c.assemble(p,dict(pairs,quotient=r.prove(v['ranges']['quotient'],[m//B for m in ms],d),remainder=r.prove(child,[m%B for m in ms],d)),d);rejects('RoundColumns:RoundSumMismatch',lambda:c.verify(p,c.roots(p,bad),bad,d))
    for name,index,reason in (('carry_0',0,'RoundColumns:RoundSumMismatch'),('carry_1',3*v['n'],'TerminalCarry:RoundSumMismatch')):
        values=w[name].copy();values[index]+=1;bad,_=c.assemble(p,dict(pairs,**{name:r.prove(v['ranges'][name],values,d)}),d);rejects(reason,lambda:c.verify(p,roots,bad,d))
    for index,changes in ((0,((0,1),(1,1))),(1,((0,1),(3,1))),(1,((1,1),(4,1))),(1,((2,256),(5,1)))):
        bad=copy.deepcopy(proof)
        for column,delta in changes:bad['zero'][index]['final'][column][0]=r.sc.add(bad['zero'][index]['final'][column][0],r.sc.scalar(delta,d))
        rejects(('TerminalCarry','RoundColumns')[index]+':ClaimMismatch',lambda:c.verify(p,roots,bad,d))
    for changed in (replace(p,blocks=(1,2)),replace(p,schema=replace(p.schema,fraction=8))):rejects('TerminalCarry:ClaimMismatch',lambda:c.verify(changed,roots,proof,d))
    other,st=c.prove(p,ms[3:]+ms[:3],d);assert c.verify(p,oracle(p,ms[3:]+ms[:3])[2],other,d)['state']==st;rejects('Magnitude:0:CommitmentMismatch',lambda:c.verify(p,roots,other,d))
    bad=copy.deepcopy(proof);bad['zero'][1]['rounds'][0][0]=(False,0,0,0);rejects('NoncanonicalField',lambda:c.verify(p,roots,bad,d))
    for key in ('receipt','certificate','bias','mask','projected'):rejects('ProofShape',lambda:c.verify(p,roots,dict(proof,**{key:{}}),d))
    rejects('Root',lambda:c.verify(p,roots[:-1],proof,d))
    print('all block/output roots, bounded p-alias, coherent r=D, omitted bias, carries, eight originals and metadata/source substitutions reject',flush=True)


def boundaries():
    p=spec(identity=5140);d=4;v=c.derive(p,d);ms=[0]*v['count'];w=c.witness(p,ms);pairs=c.prepare(p,ms,d)
    attacks=[('magnitude',0,v['constants']['raw_max']+1),('quotient',0,v['constants']['rounded_max']+1),('carry_0',v['n']-1,1),('carry_1',v['n']-1,1)]+[(name,v['count'],1) for name in ('magnitude','quotient','remainder')]
    for name,index,value in attacks:
        child=v['ranges'][name];caps=list(child.caps);values=w[name].copy()
        if index==len(caps):caps.append(0);values.append(0)
        values[index]=caps[index]=value;pair=r.assemble(child,*r.witness(replace(child,caps=tuple(caps)),values),d);bad,_=c.assemble(p,dict(pairs,**{name:pair}),d);rejects(name.title()+':CapRelation:RoundSumMismatch',lambda:c.verify(p,c.roots(p,bad),bad,d))
    p=replace(spec(1,1,5141),schema=c.bounds.Spec(1<<20,1,0,0,'static',1,62));v=c.derive(p,d);proof,state=c.prove(p,[1],d);roots=oracle(p,[1])[2];out=c.verify(p,roots,proof,d);assert out['state']==state;account(p,out,d)
    assert v['widths']['quotient']==1 and v['widths']['remainder']==8 and v['constants']['rounded_max']==0
    for index,identity,words in ((0,p.sources[0],[1]+[0]*7),(1,p.quotient,[0,0]),(2,p.remainder,list(((1<<61)+1).to_bytes(8,'little')))):
        words[-1]^=1;bad=roots.copy();bad[index]=r.root(identity,words);rejects(('Magnitude:0','Quotient','Remainder')[index]+':CommitmentMismatch',lambda:c.verify(p,bad,proof,d))
    bad=copy.deepcopy(proof);bad['zero'][1]['final'][0][0]=r.sc.add(bad['zero'][1]['final'][0][0],r.sc.scalar(1,d));bad['zero'][1]['final'][3][0]=r.sc.add(bad['zero'][1]['final'][3][0],r.sc.scalar(1,d));rejects('RoundColumns:ClaimMismatch',lambda:c.verify(p,roots,bad,d))
    print('whole bounds, dense padding, carry tails, shift62 zero quotient, hidden original and full external planes reject',flush=True)


def composition():
    import attention_sign as sign
    p=spec(identity=5150);d=4;ms=[];source_roots=[];sources=[];schema=sign.bounds.Spec(p.schema.length,p.schema.width,p.schema.fraction,p.schema.exponent,p.schema.value_mode,p.schema.scale,'block1024');H=sign.bounds.constants(schema)['base_max']//1024
    for j in range(2):
        sp=sign.Spec(schema,5151+j,1741+10*j,1743+10*j,p.sources[j],1747+10*j,1);O=[H,H+H//(j+2),0];child,st=sign.prove(sp,O,H,d);sw=sign.witness(sp,O,H);sr=sign.expected_roots(sp,O,H,sw['magnitude'],sw['sign']);assert sign.verify(sp,sr,child,d)['state']==st;ms.extend(sw['magnitude']);source_roots.append(sr[2]);sources.append((sp,O))
    proof,state=c.prove(p,ms,d);roots=oracle(p,ms)[2];assert roots[:2]==source_roots and c.verify(p,roots,proof,d)['state']==state
    sp,O=sources[1];O[1]+=1;other,st=sign.prove(sp,O,H,d);other_roots=sign.roots(sp,other);assert sign.verify(sp,other_roots,other,d)['state']==st;bad=roots.copy();bad[1]=other_roots[2];rejects('Magnitude:2:CommitmentMismatch',lambda:c.verify(p,bad,proof,d))
    print('two complete canonical-sign block sources compose through ragged joins; valid replacement rejects its pinned root',flush=True)


if __name__=='__main__':
    modes={'--corpus':corpus,'--controls':controls,'--boundaries':boundaries,'--composition':composition,'--honest':honest,'--maximum':lambda:honest('maximum'),'--full-blocks':lambda:honest('blocks'),'--full-wide':lambda:honest('wide')}
    if sys.argv[1:]:
        assert all(mode in modes for mode in sys.argv[1:])
        for mode in sys.argv[1:]:modes[mode]()
    else:
        for test in modes.values():test()
