# /// script
# requires-python = ">=3.12"
# dependencies = ["numpy==2.3.4", "blake3==1.0.11", "python-flint==0.9.0"]
# ///
"""Draft RFC-0004 A3/A8: complete single-round signed residual consumers."""
import copy
from dataclasses import replace
from fractions import Fraction
import hashlib
import json
import random
import sys
import numpy as np
import residual_composition as c

r=c.r


def rejects(reason,call):
    try:call()
    except ValueError as error:assert str(error)==reason,(reason,str(error))
    else:raise AssertionError('accepted '+reason)


def spec(count=3,identity=3200,repetitions=1):
    return c.Spec(c.residual.Spec(count,0,1,0),identity,907,911,919,929,937,941,947,953,repetitions)


def oracle(p,xs,ys):
    s=p.schema;f=max(s.left_fraction,s.right_fraction,s.output_fraction);A=2**(f-s.left_fraction);B=2**(f-s.right_fraction);D=2**(f-s.output_fraction)
    X=np.array(xs,dtype=np.int64);Y=np.array(ys,dtype=np.int64);T=X*A+Y*B;M=np.abs(T);Q=(M+D//2)//D;R=M+D//2-Q*D;Z=np.where(T<0,-Q,Q)
    return dict(offset=(T+32768*(A+B)).tolist(),magnitude=M.tolist(),sign=(T<0).astype(np.int64).tolist(),quotient=Q.tolist(),remainder=R.tolist(),output=Z.tolist())


def corpus():
    rng=random.Random(2728);digest=hashlib.sha256();accepted=overflow=0;shifts=set();groups=set();widths=set();negative_zero=False
    for case in range(10000):
        count=1+case%31;fracs=(0,case,0) if case<31 else tuple(rng.randrange(31) for _ in range(3));p=replace(spec(count,case,1+case%2),schema=c.residual.Spec(count,*fracs));v=c.derive(p,4)
        xs=[rng.randrange(-32768,32768) for _ in range(count)];ys=[rng.randrange(-32768,32768) for _ in range(count)]
        if case%11==0:xs=[0]*count;ys=[-1]*count
        w=oracle(p,xs,ys)
        if case%4:
            while any(not -32768<=z<=32767 for z in w['output']):
                xs=[(1 if x>=0 else -1)*(abs(x)//2) for x in xs];ys=[(1 if y>=0 else -1)*(abs(y)//2) for y in ys];w=oracle(p,xs,ys)
        for x,y,z in zip(xs,ys,w['output']):
            q=(Fraction(x,2**fracs[0])+Fraction(y,2**fracs[1]))*2**fracs[2];m=abs(q);nearest=(2*m.numerator+m.denominator)//(2*m.denominator);assert z==(-nearest if q<0 else nearest)
        digest.update(v['raw']+json.dumps([xs,ys,w],sort_keys=True,separators=(',',':')).encode());shifts.add(max(fracs)-fracs[2])
        if any(not -32768<=z<=32767 for z in w['output']):rejects('OutputRange',lambda:c.witness(p,xs,ys));overflow+=1;continue
        accepted+=1;assert c.witness(p,xs,ys)==w;av=c.aligned.derive(v['aligned'],4);rv=c.rounding.derive(v['rounding'],4);sv=c.sign.derive(v['sign'],4);groups.add(len(av['ranges'])-1);widths.add((av['width'],sv['widths']['magnitude'],rv['widths']['remainder']))
        roots=c.expected_roots(p,xs,ys);n=1<<(count-1).bit_length();rows=([x%65536 for x in xs],[y%65536 for y in ys],w['offset'],w['magnitude'],w['sign'],w['quotient'],w['remainder'],[z%65536 for z in w['output']]);manual=[]
        for name,values,width in zip(c.NAMES,rows,(2,2,8,8,1,2,4,2)):
            words=[x>>(8*k)&255 for k in range(width) for x in values+[0]*(n-count)];manual.append(r.root(getattr(p,name),words))
        assert roots==manual;digest.update(b''.join(roots));negative_zero|=any(s==1 and q==0 for s,q in zip(w['sign'],w['quotient']))
    assert accepted+overflow==10000 and accepted>0 and overflow>0 and shifts==set(range(31)) and groups=={0,1,2} and negative_zero
    p=spec(16384,(1<<42)-1,2);v=c.derive(p,8);spans=sorted((module.derive(v[name],8)['base'],span) for (name,module,_),span in zip(c.MODULES,(1<<18,1<<14,1<<14,512)))
    assert v['base']+(1<<20)==(1<<63)+(1<<62) and all(v['base']+18<lo and lo+size<=v['base']+(1<<20) for lo,size in spans) and all(lo+size<=nxt for (lo,size),(nxt,_) in zip(spans,spans[1:]))
    for bad in (replace(p,identity=1<<42),replace(p,repetitions=True),replace(p,left=p.output),replace(p,remainder=v['base']),replace(p,schema=replace(p.schema,left_fraction=True))):rejects('Spec',lambda:c.derive(bad,4))
    rejects('Capacity',lambda:c.derive(spec(16385),4));rejects('Spec',lambda:c.derive(p,True))
    for xs,ys in (([False]*3,[0]*3),([32768]*3,[0]*3),([0],[0]*3),((0,0,0),[0]*3)):rejects('Input',lambda:c.witness(spec(),xs,ys))
    for xs,ys in (([32767]*3,[1]*3),([-32768]*3,[-1]*3)):
        p=replace(spec(),schema=c.residual.Spec(3,0,0,0));rejects('OutputRange',lambda:c.witness(p,xs,ys))
    assert (accepted,overflow)==(8552,1448) and widths=={(4,4,1),(4,4,2),(4,4,4),(8,4,1),(8,8,1),(8,8,2),(8,8,4)}
    assert digest.hexdigest()=='867f8ea8bdf678c51b9c8ef984f6d5eaffecaa3077c75b5d4d9f3b2fb8e2295a'
    print(json.dumps(dict(seed=2728,cases=10000,accepted=accepted,overflow=overflow,widths=sorted(widths),sha256=digest.hexdigest()),sort_keys=True),flush=True)


def account(p,out,d):
    v=c.derive(p,d);av=c.aligned.derive(v['aligned'],d);sv=c.sign.derive(v['sign'],d);rv=c.rounding.derive(v['rounding'],d);a=v['a'];g=len(av['ranges'])-1;bo=(av['width']-1).bit_length();bm=(sv['widths']['magnitude']-1).bit_length();br=(rv['widths']['remainder']-1).bit_length()
    dims=[a+2]*6+[a+bo+1]+[a+3]*g+[a+bo+1,a+bm+1,a+1,a+2,a+3,a+3]+[a+bm+1,a+2,a+br+1,a+3,a+3]+[a+2]*3;f=lambda m:3*m*(m-1)//2+2*m
    assert out['account']==dict(identities=[((1<<m)+255,p.repetitions) for m in dims],lookup_reduction_numerator=sum(p.repetitions*(f(m)+f(8)+3*m) for m in dims),range_reduction_numerator=(253+9*g)*a+212+14*(bo+bm)+7*br+18*g,denominator=r.sc.P**d)
    assert len(out['children'])==4 and len(out['claims'])==3 and sum(x['numerator'] for x in out['sc'])==3*a and out['draws']==({r.zc.WEIGHT:a,r.zc.tr.CHALLENGE:a} if a else {})
    def draws(node,label):return node['draws'].get(label,0)+sum(draws(x,label) for key in ('children','ranges') for x in node.get(key,[]))
    assert all(draws(out,label)==(109+4*g)*a+89+6*(bo+bm)+3*br+8*g for label in (r.zc.WEIGHT,r.zc.tr.CHALLENGE))


def honest(maximum=False):
    digest=hashlib.sha256();count=0;cases=((1,0,0,0),(3,0,2,0),(16,0,16,0),(65,0,30,0))
    for d,reps in (((4,1),) if maximum else ((4,1),(4,2),(8,1),(8,2))):
        for size,fl,fr,fo in (((16384,0,30,0),) if maximum else cases):
            p=replace(spec(size,3210+count,reps),schema=c.residual.Spec(size,fl,fr,fo));xs=([0,1,-1,123,-123]*((size+4)//5))[:size];ys=([-1,1,-1,32767,-32768]*((size+4)//5))[:size]
            if size==1:xs=[-32768];ys=[0]
            print('honest start',count+1,d,reps,size,flush=True);proof,state=c.prove(p,xs,ys,d);out=c.verify(p,c.expected_roots(p,xs,ys),proof,d);assert out['state']==state;account(p,out,d);digest.update(state);count+=1;print('honest passed',count,d,reps,size,flush=True)
    print(json.dumps(dict(maximum=maximum,proofs=count,sha256=digest.hexdigest()),sort_keys=True),flush=True)


def controls():
    p=spec();d=4;xs=[0,1,-1];ys=[-1,-1,0];v=c.derive(p,d);w=c.witness(p,xs,ys);pairs=c.prepare(p,xs,ys,d);proof,state=c.assemble(p,pairs,d);roots=c.expected_roots(p,xs,ys);out=c.verify(p,roots,proof,d);assert out['state']==state;account(p,out,d)
    reasons=('Aligned:Left:Raw','Aligned:Right:Raw','Aligned:Output','NumeratorSign:Magnitude','NumeratorSign:Sign','Rounding:Quotient','Rounding:Remainder','Output:Raw')
    for index,reason in enumerate(reasons):
        bad=roots.copy();bad[index]=bytes([bad[index][0]^1])+bad[index][1:];rejects(reason+':CommitmentMismatch',lambda:c.verify(p,bad,proof,d))
    alt=c.aligned.prove(v['aligned'],[1,1,-1],[-3,-1,0],d);ar=c.aligned.roots(v['aligned'],alt[0]);assert ar[2]==roots[2] and c.aligned.verify(v['aligned'],ar,alt[0],d)['state']==alt[1];bad,_=c.assemble(p,dict(pairs,aligned=alt),d);rejects('Aligned:Left:Raw:CommitmentMismatch',lambda:c.verify(p,roots,bad,d))
    offsets=w['offset'].copy();offsets[0]+=1;alt=c.sign.prove(v['sign'],offsets,d);ar=c.sign.roots(v['sign'],alt[0]);assert c.sign.verify(v['sign'],ar,alt[0],d)['state']==alt[1];bad,_=c.assemble(p,dict(pairs,sign=alt),d);rejects('NumeratorSign:Offset:CommitmentMismatch',lambda:c.verify(p,roots,bad,d))
    ms=w['magnitude'].copy();ms[0]+=1;alt=c.rounding.prove(v['rounding'],ms,d);ar=c.rounding.roots(v['rounding'],alt[0]);assert c.rounding.verify(v['rounding'],ar,alt[0],d)['state']==alt[1];bad,_=c.assemble(p,dict(pairs,rounding=alt),d);rejects('Rounding:Magnitude:CommitmentMismatch',lambda:c.verify(p,roots,bad,d))
    alt=c.signed.prove(v['output'],[-z for z in w['output']],d);ar=[r.root(p.output,alt[0]['ranges'][0]['words']),roots[5]];assert c.signed.verify(v['output'],ar,alt[0],d)['state']==alt[1];bad,_=c.assemble(p,dict(pairs,output=alt),d);rejects('SignedOutput:RoundSumMismatch',lambda:c.verify(p,c.roots(p,bad),bad,d))
    bad=copy.deepcopy(proof)
    for index in (1,2):bad['zero']['final'][index][0]=r.sc.add(bad['zero']['final'][index][0],r.sc.scalar(1,d))
    rejects('SignedOutput:ClaimMismatch',lambda:c.verify(p,roots,bad,d))
    bad=copy.deepcopy(proof);bad['zero']['rounds'][0][0]=(False,0,0,0);rejects('NoncanonicalField',lambda:c.verify(p,roots,bad,d))
    for key in ('receipt','certificate','output_values','selector'):rejects('ProofShape',lambda:c.verify(p,roots,dict(proof,**{key:{}}),d))
    print('all eight roots, four valid replacement children, wrong output sign and preserving originals reject',flush=True)


def zeros():
    p=replace(spec(1,3240),schema=c.residual.Spec(1,0,2,0));proof,state=c.prove(p,[0],[-1],4);roots=c.expected_roots(p,[0],[-1]);w=c.witness(p,[0],[-1]);assert w['sign']==[1] and w['quotient']==w['output']==[0] and c.verify(p,roots,proof,4)['state']==state
    for changes in (((1,1),),((2,1),),((0,1),(2,1))):
        bad=copy.deepcopy(proof)
        for index,delta in changes:bad['zero']['final'][index][0]=r.sc.add(bad['zero']['final'][index][0],r.sc.scalar(delta,4))
        rejects('SignedOutput:ClaimMismatch',lambda:c.verify(p,roots,bad,4))
    print('negative numerator rounds to canonical zero; all three zero-hidden originals remain consumed',flush=True)


def boundaries():
    p=replace(spec(3,3250),schema=c.residual.Spec(3,0,0,0));d=4;v=c.derive(p,d);xs=[32767]*3;ys=[1]*3;offsets=c.aligned.witness(v['aligned'],xs,ys)['output'];w=c.sign.witness(v['sign'],offsets)
    pairs=dict(aligned=c.aligned.prove(v['aligned'],xs,ys,d),sign=c.sign.prove(v['sign'],offsets,d),rounding=c.rounding.prove(v['rounding'],w['magnitude'],d),output=c.signed.prove(v['output'],[-32768]*3,d));proof,_=c.assemble(p,pairs,d);roots=c.roots(p,proof)
    for (name,module,_),indices in zip(c.MODULES,c.ROUTES):assert module.verify(v[name],[roots[i] for i in indices],pairs[name][0],d)['state']==pairs[name][1]
    rejects('SignedOutput:RoundSumMismatch',lambda:c.verify(p,roots,proof,d))
    p=replace(spec(3,3251),schema=c.residual.Spec(3,1,1,0));v=c.derive(p,d);pairs=c.prepare(p,[1]*3,[1]*3,d);rp=c.rounding.prepare(v['rounding'],[2]*3,d);rv=c.rounding.derive(v['rounding'],d);rp['quotient']=r.prove(rv['ranges']['quotient'],[2]*3,d);pairs['rounding']=c.rounding.assemble(v['rounding'],rp,d);pairs['output']=c.signed.prove(v['output'],[2]*3,d);proof,_=c.assemble(p,pairs,d);rejects('Rounding:RoundColumns:RoundSumMismatch',lambda:c.verify(p,c.roots(p,proof),proof,d))
    p=spec(3,3252);v=c.derive(p,d);pairs=c.prepare(p,[0]*3,[0]*3,d);sp,carry=c.signed.ranges(v['output'],[0]*3,d);sv=c.signed.derive(v['output'],d);child=sv['ranges'][0];loose=replace(child,caps=child.caps+(1,));sp[0]=r.assemble(child,*r.witness(loose,[0,0,0,1]),d);proof,_=c.assemble(p,dict(pairs,output=c.signed.assemble(v['output'],sp,carry,d)),d);rejects('Output:Raw:CapRelation:RoundSumMismatch',lambda:c.verify(p,c.roots(p,proof),proof,d))
    print('genuine negative32768 cannot represent positive32768; separate input rounding and output padding reject',flush=True)


if __name__=='__main__':
    modes={'--corpus':corpus,'--controls':controls,'--zeros':zeros,'--boundaries':boundaries,'--honest':honest,'--maximum':lambda:honest(True)}
    if sys.argv[1:]:
        assert all(mode in modes for mode in sys.argv[1:])
        for mode in sys.argv[1:]:modes[mode]()
    else:
        for test in modes.values():test()
