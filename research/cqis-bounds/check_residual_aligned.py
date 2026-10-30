# /// script
# requires-python = ">=3.12"
# dependencies = ["numpy==2.3.4", "blake3==1.0.11", "python-flint==0.9.0"]
# ///
"""Draft RFC-0004 A3/A8: actual aligned sources before one-round residual."""
import copy
from dataclasses import replace
import hashlib
import json
import random
import sys
import numpy as np
import residual_aligned as c

r=c.r


def rejects(reason,call):
    try:call()
    except ValueError as error:assert str(error)==reason,(reason,str(error))
    else:raise AssertionError('accepted '+reason)


def spec(count=3,identity=2900,repetitions=1):
    return c.Spec(c.residual.Spec(count,0,30,0),identity,751,757,761,repetitions)


def planes(xs,width,n):
    return [x>>(8*k)&255 for k in range(width) for x in xs+[0]*(n-len(xs))]


def oracle(p,xs,ys):
    s=p.schema;f=max(s.left_fraction,s.right_fraction,s.output_fraction);A=2**(f-s.left_fraction);B=2**(f-s.right_fraction)
    return ((np.array(xs,dtype=np.int64)+32768)*A+(np.array(ys,dtype=np.int64)+32768)*B).tolist()


def corpus():
    rng=random.Random(2725);digest=hashlib.sha256();shifts=set();widths=set();cells=0
    for case in range(10000):
        count=1+case%63;s=c.residual.Spec(count,*(rng.randrange(31) for _ in range(3)))
        if case<62:s=c.residual.Spec(count,0,case%31,30) if case<31 else c.residual.Spec(count,case%31,0,30)
        p=replace(spec(count,case,1+case%2),schema=s);v=c.derive(p,4);n=v['n'];xs=[rng.randrange(-32768,32768) for _ in range(count)];ys=[rng.randrange(-32768,32768) for _ in range(count)]
        xs[0],ys[0]=((-32768,-32768),(-32768,32767),(32767,32767),(-1,1),(0,0))[case%5]
        expected=oracle(p,xs,ys);w=c.witness(p,xs,ys);assert w['output']==expected
        f=max(s.left_fraction,s.right_fraction,s.output_fraction);sa=f-s.left_fraction;sb=f-s.right_fraction;shifts.update((sa,sb));widths.add(v['width'])
        inputs=[np.pad(np.array(z,dtype=np.int64)+32768,(0,n-count)) for z in (xs,ys)];parts=[]
        for values,shift in zip(inputs,(sa,sb)):
            parts.append(np.stack([((values>>(8*(k-shift//8)))&255)*2**(shift%8) if shift//8<=k<shift//8+2 else np.zeros(n,dtype=np.int64) for k in range(8)]))
        carry=np.zeros(n,dtype=np.int64);cs=[];out=[];caps=[];cap=0
        for k in range(8):
            total=parts[0][k]+parts[1][k]+carry;out.extend((total%256).tolist());carry=total//256;cs.extend(carry.tolist())
            maximum=sum(255*2**(shift%8) for shift in (sa,sb) if shift//8<=k<shift//8+2);cap=(maximum+cap)//256;caps.append(cap)
        assert not carry.any() and max(caps)<=255 and caps[-1]==0 and tuple(caps)==v['carry_caps']
        assert out==planes(expected,8,n)
        for g in range(2):
            name='carry_'+str(g);values=cs[4*g*n:4*(g+1)*n]
            if name in v['ranges']:assert w[name]==values and all(x<=cap for x,cap in zip(values,v['ranges'][name].caps))
            else:assert not any(values)
        roots=c.expected_roots(p,xs,ys,expected);assert roots==[r.root(p.left,planes([x%65536 for x in xs],2,n)),r.root(p.right,planes([y%65536 for y in ys],2,n)),r.root(p.output,out)]
        digest.update(v['raw']+b''.join(roots)+bytes(cs));cells+=8*n
    p=spec(16384,(1<<44)-1,2);v=c.derive(p,8);assert v['base']+(1<<18)==(1<<63)+(1<<62)
    spans=[(c.ss.derive(v[name],8)['base'],512) for name in ('left','right')]+[(r.derive(child,8)[4],64) for child in v['ranges'].values()];spans.sort()
    assert all(v['base']+21<lo and lo+size<=v['base']+(1<<18) for lo,size in spans) and all(lo+size<=nxt for (lo,size),(nxt,_) in zip(spans,spans[1:]))
    assert all(r.derive(child,8)[2]*r.derive(child,8)[3]<=131072 for child in v['ranges'].values()) and {'carry_0','carry_1'}<=v['ranges'].keys()
    for bad in (replace(p,identity=1<<44),replace(p,repetitions=True),replace(p,left=p.right),replace(p,output=v['base']),replace(p,schema=replace(p.schema,left_fraction=True))):rejects('Spec',lambda:c.derive(bad,4))
    rejects('Capacity',lambda:c.derive(spec(16385),4));rejects('Spec',lambda:c.derive(p,True))
    for xs,ys in (([False]*3,[0]*3),([32768]*3,[0]*3),([0],[0]*3)):rejects('Input',lambda:c.witness(spec(),xs,ys))
    assert shifts==set(range(31)) and widths=={4,8}
    assert cells==3383720 and digest.hexdigest()=='aa7a6fa5bcb9a5011b9efeb4c3ad021f3d1dd6f39f9daf24b23b0ecb584edbb9'
    print(json.dumps(dict(seed=2725,cases=10000,column_cells=cells,sha256=digest.hexdigest()),sort_keys=True),flush=True)


def account(p,out,d):
    v=c.derive(p,d);a=v['a'];b=(v['width']-1).bit_length();g=len(v['ranges'])-1;dims=[a+2]*6+[a+b+1]+[a+3]*g;f=lambda m:3*m*(m-1)//2+2*m
    assert out['account']==dict(identities=[((1<<m)+255,p.repetitions) for m in dims],lookup_reduction_numerator=sum(p.repetitions*(f(m)+f(8)+3*m) for m in dims),range_reduction_numerator=(97+9*g)*a+76+7*b+18*g,denominator=r.sc.P**d)
    assert len(out['claims'])==5 and out['draws']=={r.zc.WEIGHT:a+3,r.zc.tr.CHALLENGE:a+3}
    draws=[out['draws']]+[x['draws'] for x in out['children']]+[part['draws'] for child in out['children'][:2] for part in child['ranges']]
    assert all(sum(row.get(label,0) for row in draws)==(41+4*g)*a+31+3*b+8*g for label in (r.zc.WEIGHT,r.zc.tr.CHALLENGE))


def honest(maximum=False):
    digest=hashlib.sha256();count=0;cases=((1,0,0,0),(3,1,2,0),(16,0,30,0),(65,0,0,30))
    for d,reps in (((4,1),) if maximum else ((4,1),(4,2),(8,1),(8,2))):
        for size,fl,fr,fo in (((16384,0,30,0),) if maximum else cases):
            p=replace(spec(size,2910+count,reps),schema=c.residual.Spec(size,fl,fr,fo));xs=([-32768,32767,-1,0,255]*((size+4)//5))[:size];ys=([-32768,-1,1,32767,-255]*((size+4)//5))[:size]
            print('honest start',count+1,d,reps,size,fl,fr,fo,flush=True);proof,state=c.prove(p,xs,ys,d);out=c.verify(p,c.expected_roots(p,xs,ys,oracle(p,xs,ys)),proof,d);assert out['state']==state;account(p,out,d);digest.update(state);count+=1;print('honest passed',count,d,reps,size,flush=True)
    if not maximum:assert count==16 and digest.hexdigest()=='255254bd0f9be1fb7dc6c7813cce742f06268dc2b2aeeb2c30ac4079cd791b3c'
    print(json.dumps(dict(maximum=maximum,proofs=count,sha256=digest.hexdigest()),sort_keys=True),flush=True)


def no_carry():
    digest=hashlib.sha256()
    for d,reps in ((4,1),(4,2),(8,1),(8,2)):
        p=replace(spec(3,2930,reps),schema=c.residual.Spec(3,0,24,0));v=c.derive(p,d);assert list(v['ranges'])==['output'] and not any(v['carry_caps'])
        xs=[-32768,32767,-1];ys=[32767,-32768,0];proof,state=c.prove(p,xs,ys,d);out=c.verify(p,c.expected_roots(p,xs,ys,oracle(p,xs,ys)),proof,d);assert out['state']==state;account(p,out,d);digest.update(state)
        for changes in (((2,1),(3,1)),((3,256),(4,-1))):
            bad=copy.deepcopy(proof)
            for index,delta in changes:bad['zero']['final'][index][0]=r.sc.add(bad['zero']['final'][index][0],r.sc.scalar(delta,d))
            rejects('AlignedColumns:ClaimMismatch',lambda:c.verify(p,c.roots(p,proof),bad,d))
        rejects('ProofShape',lambda:c.verify(p,c.roots(p,proof),dict(proof,carry_0={}),d));print('no-carry passed',d,reps,flush=True)
    print(json.dumps(dict(mode='no-carry',proofs=4,sha256=digest.hexdigest()),sort_keys=True),flush=True)


def controls():
    p=spec();d=4;xs=[1,0,-1];ys=[-1,0,1];v=c.derive(p,d);w=c.witness(p,xs,ys);pairs=c.prepare(p,xs,ys,d);proof,state=c.assemble(p,pairs,d);roots=c.expected_roots(p,xs,ys,w['output']);out=c.verify(p,roots,proof,d);assert out['state']==state;account(p,out,d)
    for index,reason in enumerate(('Left:Raw:CommitmentMismatch','Right:Raw:CommitmentMismatch','Output:CommitmentMismatch')):
        bad=roots.copy();bad[index]=bytes([bad[index][0]^1])+bad[index][1:];rejects(reason,lambda:c.verify(p,bad,proof,d))
    for name in ('left','right'):
        changed=([ -1,0,-1] if name=='left' else [1,0,1]);bad,_=c.assemble(p,dict(pairs,**{name:c.ss.prove(v[name],changed,d)}),d)
        rejects(name.title()+':Raw:CommitmentMismatch',lambda:c.verify(p,roots,bad,d));rejects('AlignedColumns:RoundSumMismatch',lambda:c.verify(p,c.roots(p,bad),bad,d))
    for delta in (1,r.sc.P):
        wrong=w['output'].copy();wrong[0]+=delta;bad,_=c.assemble(p,dict(pairs,output=r.prove(v['ranges']['output'],wrong,d)),d)
        rejects('AlignedColumns:RoundSumMismatch',lambda:c.verify(p,c.expected_roots(p,xs,ys,wrong),bad,d))
    for name in (name for name in v['ranges'] if name.startswith('carry_')):
        values=w[name].copy();index=next(i for i,cap in enumerate(v['ranges'][name].caps) if cap);values[index]^=1;bad,_=c.assemble(p,dict(pairs,**{name:r.prove(v['ranges'][name],values,d)}),d)
        rejects('AlignedColumns:RoundSumMismatch',lambda:c.verify(p,roots,bad,d))
    bad=copy.deepcopy(proof);bad['zero']['final'][0][0]=r.sc.add(bad['zero']['final'][0][0],r.sc.scalar(1,d));bad['zero']['final'][1][0]=r.sc.add(bad['zero']['final'][1][0],r.sc.scalar(-1,d));rejects('AlignedColumns:ClaimMismatch',lambda:c.verify(p,roots,bad,d))
    bad=copy.deepcopy(proof);bad['zero']['rounds'][0][0]=(False,0,0,0);rejects('NoncanonicalField',lambda:c.verify(p,roots,bad,d))
    for key in ('receipt','certificate','mask'):rejects('ProofShape',lambda:c.verify(p,roots,dict(proof,**{key:{}}),d))
    rejects('Root',lambda:c.verify(p,[False]*3,proof,d))
    print('three roots, valid same-magnitude source substitutions, in-range p-alias, carries and original finals reject',flush=True)


def boundaries():
    p=spec(3,2940);d=4;xs=ys=[-32768]*3;v=c.derive(p,d);w=c.witness(p,xs,ys);pairs=c.prepare(p,xs,ys,d);roots=c.expected_roots(p,xs,ys,w['output'])
    for name,index in (('carry_0',v['n']-1),('carry_1',3*v['n'])):
        child=v['ranges'][name];caps=list(child.caps);values=w[name].copy();assert caps[index]==0;caps[index]=values[index]=1;badpair=r.assemble(child,*r.witness(replace(child,caps=tuple(caps)),values),d);bad,_=c.assemble(p,dict(pairs,**{name:badpair}),d)
        rejects(name.title()+':CapRelation:RoundSumMismatch',lambda:c.verify(p,roots,bad,d))
    child=v['ranges']['output'];loose=replace(child,caps=child.caps+(v['constants']['numerator_max'],));badpair=r.assemble(child,*r.witness(loose,[0]*3+[v['constants']['numerator_max']]),d);bad,_=c.assemble(p,dict(pairs,output=badpair),d)
    rejects('Output:CapRelation:RoundSumMismatch',lambda:c.verify(p,c.roots(p,bad),bad,d))
    small=replace(spec(1,2941),schema=c.residual.Spec(1,0,0,0));proof,_=c.prove(small,[0],[0],d);br=c.expected_roots(small,[0],[0],[65536+(1<<56)])
    rejects('Output:CommitmentMismatch',lambda:c.verify(small,br,proof,d))
    print('terminal and padded carries, offset padding and high output planes reject',flush=True)


if __name__=='__main__':
    modes={'--corpus':corpus,'--controls':controls,'--boundaries':boundaries,'--honest':honest,'--maximum':lambda:honest(True),'--no-carry':no_carry}
    if sys.argv[1:]:
        assert all(mode in modes for mode in sys.argv[1:])
        for mode in sys.argv[1:]:modes[mode]()
    else:
        for test in modes.values():test()
