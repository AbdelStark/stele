# /// script
# requires-python = ">=3.12"
# dependencies = ["numpy==2.3.4", "blake3==1.0.11", "python-flint==0.9.0"]
# ///
"""Draft RFC-0004 A3/A8: exact signed residual numerator and canonical zero."""
import copy
from dataclasses import replace
import hashlib
import json
import random
import sys
import numpy as np
import residual_sign as c

r=c.r


def rejects(reason,call):
    try:call()
    except ValueError as error:assert str(error)==reason,(reason,str(error))
    else:raise AssertionError('accepted '+reason)


def spec(count=3,identity=3000,repetitions=1):
    return c.Spec(c.residual.Spec(count,0,30,0),identity,809,811,821,repetitions)


def planes(xs,width,n):
    return [x>>(8*k)&255 for k in range(width) for x in xs+[0]*(n-len(xs))]


def corpus():
    rng=random.Random(2726);digest=hashlib.sha256();cells=0;shifts=set();widths=set()
    for case in range(10000):
        count=1+case%63;fracs=tuple(rng.randrange(31) for _ in range(3))
        if case<31:fracs=(0,case,30)
        if case==31:fracs=(16,1,17)
        p=replace(spec(count,case,1+case%2),schema=c.residual.Spec(count,*fracs));v=c.derive(p,4);f=max(fracs);A=2**(f-fracs[0]);B=2**(f-fracs[1]);H=32768*(A+B);U=65535*(A+B);shifts.update((f-fracs[0],f-fracs[1]));widths.add((v['widths']['offset'],v['widths']['magnitude']))
        offsets=[rng.randrange(U+1) for _ in range(count)];offsets[0]=(0,H,U,H-1,H+1)[case%5];w=c.witness(p,offsets);total=np.array(offsets,dtype=np.int64)-H;mag=np.abs(total);sgn=(total<0).astype(np.int64)
        assert w['magnitude']==mag.tolist() and w['sign']==sgn.tolist() and w['offset']==offsets
        pred=[sum(int(x)>>(8*k)&255 for k in range(8))-int(s) for x,s in zip(mag,sgn)];assert w['predecessor']==pred
        n=v['n'];mask=(np.arange(n)<count).astype(np.int64);O=np.pad(np.array(offsets,dtype=np.int64),(0,n-count));M=np.pad(mag,(0,n-count));S=np.pad(sgn,(0,n-count));carry=np.zeros(n,dtype=np.int64);cs=[]
        for k in range(8):
            diff=((O>>(8*k))&255)+(2*S-1)*((M>>(8*k))&255)-mask*((H>>(8*k))&255)+carry
            assert not np.any(diff%256);carry=diff//256;assert np.all((-2<=carry)&(carry<=2));cs.extend(((carry+2)*mask).tolist())
        assert not carry.any()
        for g in range(2):assert w['carry_'+str(g)]==cs[4*g*n:4*(g+1)*n]
        roots=c.expected_roots(p,offsets,mag.tolist(),sgn.tolist());assert roots==[r.root(p.offset,planes(offsets,8,n)),r.root(p.magnitude,planes(mag.tolist(),8,n)),r.root(p.sign,sgn.tolist()+[0]*(n-count))]
        assert all(0<=x<=cap for name in w for x,cap in zip(w[name],v['ranges'][name].caps));digest.update(v['raw']+b''.join(roots)+bytes(cs));cells+=8*n
    p=spec(16384,(1<<48)-1,2);v=c.derive(p,8);assert v['base']+(1<<14)==(1<<63)+(1<<62)
    spans=sorted((r.derive(child,8)[4],64) for child in v['ranges'].values());assert all(v['base']+26<lo and lo+size<=v['base']+(1<<14) for lo,size in spans) and all(lo+size<=nxt for (lo,size),(nxt,_) in zip(spans,spans[1:]))
    for bad in (replace(p,identity=1<<48),replace(p,repetitions=True),replace(p,offset=p.sign),replace(p,offset=v['base']),replace(p,schema=replace(p.schema,left_fraction=True))):rejects('Spec',lambda:c.derive(bad,4))
    rejects('Capacity',lambda:c.derive(spec(16385),4));rejects('Spec',lambda:c.derive(p,True))
    for values in ([False]*3,[-1]*3,[v['constants']['offset_max']+1]*3,[0]):rejects('Input',lambda:c.witness(spec(),values))
    assert shifts==set(range(31)) and widths=={(4,4),(8,4),(8,8)}
    print(json.dumps(dict(seed=2726,cases=10000,column_cells=cells,sha256=digest.hexdigest()),sort_keys=True),flush=True)


def account(p,out,d):
    v=c.derive(p,d);a=v['a'];bo=(v['widths']['offset']-1).bit_length();bm=(v['widths']['magnitude']-1).bit_length();dims=[a+bo+1,a+bm+1,a+1,a+2,a+3,a+3];f=lambda m:3*m*(m-1)//2+2*m
    assert out['account']==dict(identities=[((1<<m)+255,p.repetitions) for m in dims],lookup_reduction_numerator=sum(p.repetitions*(f(m)+f(8)+3*m) for m in dims),range_reduction_numerator=61*a+7*(bo+bm)+52,denominator=r.sc.P**d)
    assert len(out['claims'])==12 and out['draws']=={r.zc.WEIGHT:3*a+3,r.zc.tr.CHALLENGE:3*a+3}
    assert sum(x['numerator'] for x in out['sc'])==7*a+9
    assert all(sum(x['draws'].get(label,0) for x in [out]+out['children'])==27*a+22+3*(bo+bm) for label in (r.zc.WEIGHT,r.zc.tr.CHALLENGE))


def honest(maximum=False):
    digest=hashlib.sha256();count=0;cases=((1,0,0,0),(3,16,1,17),(16,0,30,0),(65,0,0,30))
    for d,reps in (((4,1),) if maximum else ((4,1),(4,2),(8,1),(8,2))):
        for size,fl,fr,fo in (((16384,0,30,0),) if maximum else cases):
            p=replace(spec(size,3010+count,reps),schema=c.residual.Spec(size,fl,fr,fo));v=c.derive(p,d);H=v['constants']['numerator_max'];U=v['constants']['offset_max'];offsets=([0,H,U,H-1,H+1]*((size+4)//5))[:size];w=c.witness(p,offsets)
            print('honest start',count+1,d,reps,size,flush=True);proof,state=c.prove(p,offsets,d);out=c.verify(p,c.expected_roots(p,offsets,w['magnitude'],w['sign']),proof,d);assert out['state']==state;account(p,out,d);digest.update(state);count+=1;print('honest passed',count,d,reps,size,flush=True)
    print(json.dumps(dict(maximum=maximum,proofs=count,sha256=digest.hexdigest()),sort_keys=True),flush=True)


def controls():
    p=spec();d=4;v=c.derive(p,d);H=v['constants']['numerator_max'];offsets=[H,H+1,H-1];w=c.witness(p,offsets);pairs=c.prepare(p,offsets,d);proof,state=c.assemble(p,pairs,d);roots=c.expected_roots(p,offsets,w['magnitude'],w['sign']);out=c.verify(p,roots,proof,d);assert out['state']==state;account(p,out,d)
    for index,reason in enumerate(('Offset:CommitmentMismatch','Magnitude:CommitmentMismatch','Sign:CommitmentMismatch')):
        bad=roots.copy();bad[index]=bytes([bad[index][0]^1])+bad[index][1:];rejects(reason,lambda:c.verify(p,bad,proof,d))
    for name in v['ranges']:
        bad=copy.deepcopy(proof);bad[name]['words'][0]^=1;rejects(name.title()+':CommitmentMismatch',lambda:c.verify(p,roots,bad,d))
    for delta in (1,r.sc.P):
        values=w['magnitude'].copy();values[1]+=delta;bad,_=c.assemble(p,dict(pairs,magnitude=r.prove(v['ranges']['magnitude'],values,d)),d);rejects('SignColumns:RoundSumMismatch',lambda:c.verify(p,c.roots(p,bad),bad,d))
    values=w['sign'].copy();values[0]=1;bad,_=c.assemble(p,dict(pairs,sign=r.prove(v['ranges']['sign'],values,d)),d);rejects('CanonicalZero:RoundSumMismatch',lambda:c.verify(p,c.roots(p,bad),bad,d))
    for name,index,reason in (('carry_0',0,'SignColumns:RoundSumMismatch'),('carry_1',3*v['n'],'TerminalCarry:RoundSumMismatch')):
        values=w[name].copy();values[index]+=1;bad,_=c.assemble(p,dict(pairs,**{name:r.prove(v['ranges'][name],values,d)}),d);rejects(reason,lambda:c.verify(p,roots,bad,d))
    print('roots, all range words, range-valid M+p, coherent negative zero and actual carries reject',flush=True)
    zero=c.prepare(p,[H]*3,d);zp,zs=c.assemble(p,zero,d);zr=c.roots(p,zp);assert c.verify(p,zr,zp,d)['state']==zs
    attacks=((0,((0,1),(1,1))),(1,((0,1),(5,1))),(1,((3,1),(4,-1))),(1,((0,256),(6,1))),(1,((0,1),(2,1))),(1,((1,1),)),(2,((0,1),(1,1))))
    for index,changes in attacks:
        bad=copy.deepcopy(zp)
        for column,delta in changes:bad['zero'][index]['final'][column][0]=r.sc.add(bad['zero'][index]['final'][column][0],r.sc.scalar(delta,d))
        rejects(('TerminalCarry','SignColumns','CanonicalZero')[index]+':ClaimMismatch',lambda:c.verify(p,zr,bad,d))
    bad=copy.deepcopy(proof);bad['zero'][1]['rounds'][0][0]=(False,0,0,0);rejects('NoncanonicalField',lambda:c.verify(p,roots,bad,d))
    for key in ('receipt','certificate','mask'):rejects('ProofShape',lambda:c.verify(p,roots,dict(proof,**{key:{}}),d))
    print('every parent original, including zero-hidden sign and public carry views, retains its consumer',flush=True)


def boundaries():
    p=spec(3,3040);d=4;v=c.derive(p,d);H=v['constants']['numerator_max'];offsets=[H]*3;w=c.witness(p,offsets);pairs=c.prepare(p,offsets,d);roots=c.expected_roots(p,offsets,w['magnitude'],w['sign'])
    for name,index,value in (('offset',0,v['constants']['offset_max']+1),('magnitude',0,H+1),('sign',0,2),('predecessor',0,2041),('carry_0',v['n']-1,1),('carry_1',v['n']-1,1)):
        child=v['ranges'][name];values=w[name].copy();caps=list(child.caps);values[index]=caps[index]=value;badpair=r.assemble(child,*r.witness(replace(child,caps=tuple(caps)),values),d);bad,_=c.assemble(p,dict(pairs,**{name:badpair}),d);rejects(name.title()+':CapRelation:RoundSumMismatch',lambda:c.verify(p,c.roots(p,bad),bad,d))
    small=replace(spec(1,3041),schema=c.residual.Spec(1,0,0,0));sv=c.derive(small,d);H=sv['constants']['numerator_max'];proof,_=c.prove(small,[H],d)
    for index in (0,1):
        br=c.expected_roots(small,[H],[0],[0]);br[index]=r.root((small.offset,small.magnitude)[index],[0]*7+[1]);rejects(('Offset','Magnitude')[index]+':CommitmentMismatch',lambda:c.verify(small,br,proof,d))
    print('whole bounds, nonboolean sign, predecessor overflow, padded carries and high planes reject',flush=True)


def composition():
    import residual_aligned as aligned
    p=spec(3,3050);ap=aligned.Spec(p.schema,3051,823,827,p.offset,1);xs=[1,0,-1];ys=[-1,0,1];proof,state=aligned.prove(ap,xs,ys,4);O=aligned.witness(ap,xs,ys)['output'];ar=aligned.expected_roots(ap,xs,ys,O);assert aligned.verify(ap,ar,proof,4)['state']==state
    proof,state=c.prove(p,O,4);w=c.witness(p,O);roots=c.expected_roots(p,O,w['magnitude'],w['sign']);assert roots[0]==ar[2] and c.verify(p,roots,proof,4)['state']==state
    alt,ast=aligned.prove(ap,[-1,0,-1],ys,4);ar=aligned.roots(ap,alt);assert aligned.verify(ap,ar,alt,4)['state']==ast;roots[0]=ar[2];rejects('Offset:CommitmentMismatch',lambda:c.verify(p,roots,proof,4))
    print('actual aligned offset composes; independently valid replacement rejects at the same root',flush=True)


if __name__=='__main__':
    modes={'--corpus':corpus,'--controls':controls,'--boundaries':boundaries,'--composition':composition,'--honest':honest,'--maximum':lambda:honest(True)}
    if sys.argv[1:]:
        assert all(mode in modes for mode in sys.argv[1:])
        for mode in sys.argv[1:]:modes[mode]()
    else:
        for test in modes.values():test()
