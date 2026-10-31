# /// script
# requires-python = "==3.12.*"
# dependencies = ["numpy==2.3.4", "blake3==1.0.11", "python-flint==0.9.0"]
# ///
"""Draft RFC-0004 A3/A6: complete block sources, no native proof credit."""
import copy
from dataclasses import replace
import hashlib
import json
import random
import struct
import sys
import tempfile
import numpy as np
import attention_block_offset as c

r=c.r


def rejects(reason,call):
    try:call()
    except ValueError as error:assert str(error)==reason,(reason,str(error))
    else:raise AssertionError('accepted '+reason)


def spec(rows=3,width=3,identity=8200,repetitions=1):
    return c.Spec(c.bounds.Spec(rows,width,7,14,'static',65535,'exact'),0,(True,)*rows,identity,101,103,107,repetitions)


class Capture:
    def __init__(self,source):self.source=iter(source);self.state=None
    def __iter__(self):return self
    def __next__(self):
        try:return next(self.source)
        except StopIteration as end:self.state=end.value;raise


def groups(v,values):
    at=0
    for size in v['sizes']:yield values[at:at+size];at+=size
    assert at==len(values)


def oracle(p,weights,values):
    rows=len(weights);width=p.schema.width;output=(np.array(weights,dtype=np.int64)@np.array(values,dtype=np.int64).reshape(rows,width)).tolist()
    def planes(xs,size,dtype):return np.frombuffer(np.array(xs+[0]*(size-len(xs)),dtype=dtype).tobytes(),dtype=np.uint8).reshape(size,-1).T.reshape(-1).tolist()
    sizes=(1<<(rows-1).bit_length(),1<<(rows*width-1).bit_length(),1<<(width-1).bit_length())
    roots=[r.root(identity,planes(xs,n,dtype)) for identity,xs,n,dtype in zip((p.probability,p.value_source,p.output),(weights,values,output),sizes,('<u1' if p.schema.exponent<=7 else '<u2','<u4','<u8'))]
    return output,roots


def corpus():
    rng=random.Random(2759);digest=hashlib.sha256();cells=zeros=0
    for case in range(10000):
        rows=rng.randrange(1,5);width=rng.randrange(1,18);p=spec(rows,width)
        policy='dynamic' if case%2 else 'static';scale=0 if policy=='dynamic' else rng.choice((1,2,259,65535))
        p=replace(p,schema=replace(p.schema,length=1024+rows if case%3==0 else rows,exponent=case%15,value_mode=policy,scale=scale,accumulation='block1024' if case%3==0 else 'exact'),block=1 if case%3==0 else 0,allowed=tuple(bool(rng.randrange(2)) for _ in range(rows)))
        v=c.derive(p,4);S=127*259 if policy=='dynamic' else scale*min(127,(65536+scale)//(2*scale));weights=[rng.randint(0,1<<p.schema.exponent)*bit for bit in p.allowed];values=[rng.randint(0,2*S) for _ in range(rows*width)]
        partial=c.columns(v)
        for g,xs in enumerate(groups(v,values)):c.accumulate(v,partial,weights[g*v['group_rows']:g*v['group_rows']+len(xs)//width],xs)
        output,carry=c.finish_columns(v,partial);expected,roots=oracle(p,weights,values);assert output==expected
        for channel in range(width):
            coefficients=[sum((w>>(4*i)&15)*(values[j*width+channel]>>(4*(k-i))&15) for j,w in enumerate(weights) for i in range(v['la']) if 0<=k-i<v['lb']) for k in range(v['k'])]
            assert all(carry[k*v['nc']+channel]==sum(x<<(4*i) for i,x in enumerate(coefficients[:k]))>>(4*k) for k in range(16))
        with tempfile.TemporaryFile() as spool:
            for xs in groups(v,values):spool.write(struct.pack('<'+'I'*len(xs),*xs))
            assert c.value_root(p,v,spool)==roots[1]
        assert not any(carry[k*v['nc']+j] for k in range(16) for j in range(width,v['nc']))
        cells+=len(values);zeros+=not any(output);digest.update(v['raw']+b''.join(roots))
    print(json.dumps(dict(seed=2759,cases=10000,cells=cells,zero_outputs=zeros,sha256=digest.hexdigest()),sort_keys=True),flush=True)


def shapes():
    done=0
    for d in (4,8):
        for rows,width in ((1024,16384),(1023,16383),(1,16384),(1024,1),(3,10923)):
            p=spec(rows,width,(1<<42)-1,2);p=replace(p,schema=replace(p.schema,length=1023*1024+rows),block=1023);v=c.derive(p,d)
            assert v['rows']==rows and sum(v['sizes'])==rows*width and max(v['sizes'])<=32768 and v['groups']<=512
            assert v['n']==1<<(rows*width-1).bit_length() and v['base']+(1<<20)==(1<<63)+(1<<62)
            indices=sorted(set((0,1,v['groups'],*range(v['groups']+1,v['children']))));spans=[]
            for index in indices:
                child=c.range_spec(p,v,index);a,b,n,w,base,_=r.derive(child,d);assert n*w<=131072;assert v['base']<=base<base+64<=v['base']+(1<<18);assert v['base']+(1<<18)<child.source<v['base']+(1<<19);spans.append((base,base+64))
            assert all(hi<=lo for (_,hi),(lo,_) in zip(spans,spans[1:]));assert 2*max(v['cert']['lhs']+v['cert']['rhs'])<r.sc.P;done+=1
    p=spec();v=c.derive(p,4)
    for bad in (replace(p,identity=1<<42),replace(p,repetitions=True),replace(p,block=True),replace(p,block=1),replace(p,allowed=(True,)),replace(p,allowed=(True,1,True)),replace(p,output=v['base']),replace(p,value_source=p.output)):
        rejects('Spec',lambda:c.derive(bad,4))
    rejects('Spec',lambda:c.derive(p,True));print('full shape and namespace cases passed',done,flush=True)


def account(p,out,d):
    v=c.derive(p,d);layouts=[r.derive(c.range_spec(p,v,i),d) for i in range(v['children'])];f=lambda m:3*m*(m-1)//2+2*m;dims=[a+b+1 for a,b,*_ in layouts]
    assert out['account']==dict(identities=[((1<<m)+255,p.repetitions) for m in dims],lookup_reduction_numerator=sum(p.repetitions*(f(m)+f(8)+3*m) for m in dims),range_reduction_numerator=sum(9*a+7*b for a,b,*_ in layouts),weighted_identity_numerator=v['ac']+v['k']-1,weighted_reduction_numerator=2*v['ar'],denominator=r.sc.P**d)
    assert out['draws']=={r.zc.tr.CHALLENGE:1+v['ac']+v['ar']} and len(out['claims'])==2
    child=sum(4*a+3*b for a,b,*_ in layouts);assert out['child_draws']=={r.zc.WEIGHT:child,r.zc.tr.CHALLENGE:child}


def run(p,weights,values,d):
    source=Capture(c.prove(p,weights,groups(c.derive(p,d),values),d));out=c.verify(p,oracle(p,weights,values)[1],source,d);assert out['state']==source.state;account(p,out,d);return out


def honest():
    digest=hashlib.sha256();done=0
    for d,reps in ((4,1),(4,2),(8,1),(8,2)):
        for rows,width,E,mode in ((1,1,0,'exact'),(3,3,14,'exact'),(2,5,8,'block1024'),(3,1,7,'block1024')):
            p=spec(rows,width,8210+done,reps);p=replace(p,schema=replace(p.schema,exponent=E,accumulation=mode));v=c.derive(p,d);weights=[(0,1<<E,1)[j%3] for j in range(rows)];values=[(0,2*v['constants']['restored_max'],1)[j%3] for j in range(rows*width)]
            print('block offset start',done+1,d,reps,rows,width,flush=True);out=run(p,weights,values,d);digest.update(out['state']);done+=1;print('block offset passed',done,d,reps,flush=True)
    print(json.dumps(dict(proofs=done,sha256=digest.hexdigest()),sort_keys=True),flush=True)


def controls():
    p=spec(2,3);d=4;v=c.derive(p,d);weights=[1,2];values=[1,2,3,4,5,6];source=Capture(c.prove(p,weights,groups(v,values),d));proof=list(source);roots=oracle(p,weights,values)[1];out=c.verify(p,roots,iter(proof),d);assert out['state']==source.state;account(p,out,d)
    for index,name in enumerate(('Probability','Value','Output')):
        bad=roots.copy();bad[index]=bytes(32);rejects(name+':CommitmentMismatch',lambda:c.verify(p,bad,iter(proof),d))
    for bad in (proof[:-1],proof+[{}],proof[1:],list(reversed(proof)),[dict(proof[0],range=False)]+proof[1:],[dict(proof[0],receipt={})]+proof[1:]):rejects('StreamShape',lambda:c.verify(p,roots,iter(bad),d))
    for ws,vs,name in (([2,1],values,'Probability'),(weights,values[3:]+values[:3],'Value')):
        other=list(c.prove(p,ws,groups(v,vs),d));c.verify(p,oracle(p,ws,vs)[1],iter(other),d);rejects(name+':CommitmentMismatch',lambda:c.verify(p,roots,iter(other),d))
    for ws,vs,index in (([1],[0],0),([0],[123],1)):
        one=spec(1,1);pr=list(c.prove(one,ws,[vs],d));rr=oracle(one,ws,vs)[1];c.verify(one,rr,iter(pr),d);bad=copy.deepcopy(pr);bad[-1]['sum']['final'][index]=r.sc.add(bad[-1]['sum']['final'][index],r.sc.scalar(1,d));rejects('WeightedSum:ClaimMismatch',lambda:c.verify(one,rr,iter(bad),d))
        bad=copy.deepcopy(pr);bad[-1]['sum']['final'][index]=(r.sc.P,)+(0,)*(d-1);rejects('NoncanonicalField',lambda:c.verify(one,rr,iter(bad),d))
    p=replace(p,allowed=(False,False));run(p,[0,0],values,d)
    print('all source roots, exact stream roster, valid replacements and both zero-hidden originals reject; all-masked sources consumed',flush=True)


def boundaries():
    p=spec(3,3);p=replace(p,allowed=(True,False,True));d=4;v=c.derive(p,d);weights=[16384,0,16384];values=[100000]*v['count'];proof=list(c.prove(p,weights,groups(v,values),d));expected=oracle(p,weights,values)[1]
    pairs=[]
    for i,record in enumerate(proof[:-1]):
        plan=c.range_spec(p,v,i);child=record['proof'];pairs.append((child,r.verify(plan,r.source_root(plan,child['words']),child,d)['state']))
    def assemble(changed):
        roots=[];states=[];local={'carry':[]};records=[]
        with tempfile.TemporaryFile() as spool:
            for i,(child,state) in enumerate(changed):
                roots.append(r.source_root(c.range_spec(p,v,i),child['words']));states.append(state);c.retain(p,v,i,child['words'],spool,local);records.append(dict(range=i,proof=child))
            external=[r.root(p.probability,c.planes(local['probability'],v['nr'],2)),c.value_root(p,v,spool),r.root(p.output,c.planes(local['output'],v['nc'],8))]
            t,instance,tables=c.parent(p,v,external,roots,states,local,spool,d);records.append(dict(sum=r.sc.prove(t,instance,tables)[0]));return records,external
    output=oracle(p,weights,values)[0];index=v['groups']+1;plan=c.range_spec(p,v,index)
    for delta in ((1,0,0),(1,-1,0),(r.sc.P,0,0),(-r.sc.P,0,0)):
        xs=[x+y for x,y in zip(output,delta)];assert all(0<=x<=cap for x,cap in zip(xs,plan.caps));changed=pairs.copy();changed[index]=r.prove(plan,xs,d);bad,roots=assemble(changed);rejects('WeightedSum:RoundSumMismatch',lambda:c.verify(p,roots,iter(bad),d))
    for i,at in ((0,1),(0,3),(1,9),(index,3),(index+1,0),(v['children']-1,-1)):
        plan=c.range_spec(p,v,i);caps=list(plan.caps);xs=c.unpack(plan,pairs[i][0]['words'])[:len(caps)]
        if at==len(caps):caps.append(0);xs.append(0)
        caps[at]+=1;xs[at]=caps[at];changed=pairs.copy();changed[i]=r.assemble(plan,*r.witness(replace(plan,caps=tuple(caps)),xs),d);bad,roots=assemble(changed);rejects('Range:'+str(i)+':CapRelation:RoundSumMismatch',lambda:c.verify(p,roots,iter(bad),d))
    wrong=np.pad(np.array(values,dtype=np.uint32).reshape(3,3),((0,1),(0,1))).reshape(-1).tolist();bad=expected.copy();bad[1]=r.root(p.value_source,c.planes(wrong,v['n'],4));rejects('Value:CommitmentMismatch',lambda:c.verify(p,bad,iter(proof),d))
    for index,identity,size,width,xs in ((1,p.value_source,v['n'],4,values),(2,p.output,v['nc'],8,output)):
        words=c.planes(xs,size,width);words[-1]=1;bad=expected.copy();bad[index]=r.root(identity,words);rejects(('Value' if index==1 else 'Output')+':CommitmentMismatch',lambda:c.verify(p,bad,iter(proof),d))
    print('genuine ranged false sums, compensated channels, plus/minus p, mask/padding/carry boundaries, flat layout and high planes reject',flush=True)


def composition():
    import attention_values as values
    import attention_probability_sum as probability
    for index,(policy,scale) in enumerate((('static',2),('dynamic',0))):
        p=spec(1,3,8250+index);p=replace(p,schema=replace(p.schema,value_mode=policy,scale=scale));positions=(0,);codes=[-127,0,127];scales=[259 if policy=='dynamic' else scale]
        vp=values.Spec(p.schema,positions,8400+index,109,113,p.value_source,1);child,st=values.prove(vp,codes,scales,4);vr=values.expected_roots(vp,codes,scales);assert values.verify(vp,vr,child,4)['state']==st;us=values.witness(vp,codes,scales)['output']
        row=probability.attained.Spec(probability.attained.maximum.Spec(1,127,7,6),0,positions,0,0,1,8500+index,127,131,137,139,1);pp=probability.Spec(row,14,8600+index,p.probability,149);ws=[16384];child,st=probability.prove(pp,ws,4);pr=probability.expected_roots(pp,ws);assert probability.verify(pp,pr,child,4)['state']==st and probability.derive(pp,4)['allowed']==p.allowed
        assert oracle(p,ws,us)[1][:2]==[pr[0],vr[2]];run(p,ws,us,4)
        other,st=values.prove(vp,list(reversed(codes)),scales,4);rr=values.expected_roots(vp,list(reversed(codes)),scales);assert values.verify(vp,rr,other,4)['state']==st;proof=list(c.prove(p,ws,[us],4));roots=oracle(p,ws,us)[1];rejects('Value:CommitmentMismatch',lambda:c.verify(p,[roots[0],rr[2],roots[2]],iter(proof),4));print('complete source composition passed',policy,flush=True)


def maximum(mode):
    rows,width={'maximum':(1024,16384),'full-ragged':(1023,16383),'full-tail':(1,16384)}[mode];p=spec(rows,width,8290);p=replace(p,schema=replace(p.schema,length=1023*1024+rows),block=1023);v=c.derive(p,4);S=v['constants']['restored_max'];weights=[(0,16384,1,16383)[j%4] for j in range(rows)]
    if rows==1:weights=[16384]
    def sources():
        at=0
        for size in v['sizes']:
            xs=[(17*i+31*(i//width))%(2*S+1) for i in range(at,at+size)];at+=size;yield xs
    output=np.zeros(width,dtype=np.int64);at=0
    for xs in sources():
        count=len(xs)//width;output+=np.array(weights[at:at+count],dtype=np.int64)@np.array(xs,dtype=np.int64).reshape(count,width);at+=count
    def payloads():
        for k in range(4):
            for xs in sources():
                for x in xs:yield struct.pack('<I',x>>(8*k)&255)
            for _ in range(v['n']-v['count']):yield bytes(4)
    merkle=r.lu.merkle;uroot=merkle.root(merkle.Tree(0,p.value_source,4*v['n'],4),payloads())
    planes=lambda xs,n,b:[x>>(8*k)&255 for k in range(b) for x in xs+[0]*(n-len(xs))]
    roots=[r.root(p.probability,planes(weights,v['nr'],2)),uroot,r.root(p.output,planes(output.tolist(),v['nc'],8))]
    print('full block offset start',mode,rows,width,v['groups'],flush=True);source=Capture(c.prove(p,weights,sources(),4));out=c.verify(p,roots,source,4);assert out['state']==source.state;account(p,out,4);print('full block offset passed',mode,out['state'].hex(),flush=True)


if __name__=='__main__':
    modes={'--corpus':corpus,'--shapes':shapes,'--controls':controls,'--boundaries':boundaries,'--composition':composition,'--honest':honest,'--maximum':lambda:maximum('maximum'),'--full-ragged':lambda:maximum('full-ragged'),'--full-tail':lambda:maximum('full-tail')}
    assert all(mode in modes for mode in sys.argv[1:])
    for mode in sys.argv[1:] or modes:modes[mode]()
