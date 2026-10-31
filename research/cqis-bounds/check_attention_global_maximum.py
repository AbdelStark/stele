# /// script
# requires-python = "==3.12.*"
# dependencies = ["numpy==2.3.4", "blake3==1.0.11", "python-flint==0.9.0"]
# ///
"""Draft RFC-0004 A3/A6: complete global maximum, no native proof credit."""
import copy
from dataclasses import replace
import hashlib
import json
import random
import struct
import sys
import tempfile
import numpy as np
import attention_global_maximum as c

r=c.r


def rejects(reason,call):
    try:call()
    except ValueError as error:assert str(error)==reason,(reason,str(error))
    else:raise AssertionError('accepted '+reason)


def spec(count=3,S=(1<<31)-1,bits=31,identity=8900,repetitions=1):
    return c.Spec(c.maximum.Spec(count,S,bits,12),count-1,0,0,count,identity,101,103,107,109,repetitions)


class Capture:
    def __init__(self,source):self.source=iter(source);self.state=None
    def __iter__(self):return self
    def __next__(self):
        try:return next(self.source)
        except StopIteration as end:self.state=end.value;raise


def groups(v,xs):
    at=0
    for size in v['sizes']:yield xs[at:at+size];at+=size
    assert at==len(xs)


def oracle(p,xs):
    ids=np.arange(p.schema.length,dtype=np.int64);X=np.array(xs,dtype=np.int64);mask=(ids>=p.start)&(ids<p.stop)&(ids<=p.position)
    if p.window:mask&=p.position-ids<p.window
    selected=int(np.argmax(np.where(mask,X,np.iinfo(np.int64).min)));M=int(X[selected]);D=np.where(mask,M-X,0);G=D-(mask&(ids<selected));n=1<<(len(xs)-1).bit_length()
    planes=lambda values:np.frombuffer(np.array(values+[0]*(n-len(values)),dtype='<u4').tobytes(),dtype=np.uint8).reshape(n,4).T.reshape(-1).tolist()
    roots=[r.root(p.source,planes([x%(1<<32) for x in xs])),r.root(p.maximum,list((M%(1<<32)).to_bytes(4,'little'))),r.root(p.selection,[selected]),r.root(p.difference,planes(D.tolist()))]
    return dict(selected=selected,maximum=M,source=[x%(1<<32) for x in xs],offset=(X+p.schema.score_max).tolist(),difference=D.tolist(),gap=G.tolist(),mask=mask.tolist(),roots=roots)


def carries(left,right,n):
    return [((x&((1<<(8*k))-1))+(y&((1<<(8*k))-1)))>>(8*k) for k in range(1,5) for x,y in zip(left,right)]


def forged_values(p,g,xs,selected,difference,gap):
    size=len(xs);n=1<<(size-1).bit_length();raw=[x%(1<<32) for x in xs];offset=[x+p.schema.score_max for x in xs];mask=[c.allowed(p,16384*g+j) for j in range(size)];pad=lambda a:a+[0]*(n-size);prefix=[int(bit and 16384*g+j<selected) for j,bit in enumerate(mask)]
    return [raw,offset,difference,gap,carries(pad(raw),[p.schema.score_max]*size+[0]*(n-size),n),carries(pad([x*bit for x,bit in zip(offset,mask)]),pad(difference),n),carries(pad(gap),pad(prefix),n)]


def corpus():
    rng=random.Random(2762);digest=hashlib.sha256();accepted=domain=ties=masked=0
    for case in range(10000):
        size=(1,3,5,16,17,65)[case%6];S=(0,1,127,128,32767,32768,(1<<23)-1,1<<23,1<<30,(1<<31)-1)[case%10];p=spec(size,S,(7,15,31)[case%3],case,1+case%2);q=rng.randrange(size);p=replace(p,position=q,window=(0,1,7,size)[case%4],start=rng.randint(0,q),stop=rng.randint(q+1,size));v=c.derive(p,4);xs=[rng.randint(-S,S) for _ in range(size)] if case%7 else [S]*size;w=oracle(p,xs)
        digest.update(v['raw']+json.dumps([xs,w['selected'],w['difference']],separators=(',',':')).encode());ties+=sum(bit and x==w['maximum'] for bit,x in zip(w['mask'],xs))>1;masked+=not all(w['mask'])
        with tempfile.TemporaryFile() as spool:
            selected,maximum=c.prefill(p,v,groups(v,xs),spool);assert (selected,maximum)==(w['selected'],w['maximum']%(1<<32))
            if max(w['difference'])>v['bounds']['delta_max']:
                rejects('Domain',lambda:c.group_values(p,v,0,w['source'],maximum,selected));domain+=1;continue
            values=c.group_values(p,v,0,w['source'],maximum,selected);assert values==forged_values(p,0,xs,selected,w['difference'],w['gap']);c.write_group(v,0,values,spool);assert c.external_roots(p,v,selected,list(maximum.to_bytes(4,'little')),spool)==w['roots'];digest.update(b''.join(w['roots']));accepted+=1
    assert accepted+domain==10000 and accepted and domain and masked and ties
    print(json.dumps(dict(seed=2762,cases=10000,accepted=accepted,domain=domain,masked=masked,ties=ties,sha256=digest.hexdigest()),sort_keys=True),flush=True)


def shapes():
    cases=0
    for d in (4,8):
        for size in (1,16384,16385,(1<<20)-1,1<<20):
            p=spec(size,identity=(1<<39)-1,repetitions=2);v=c.derive(p,d);spans=[];instances=set();sources=[]
            assert sum(v['sizes'])==size and v['groups']<=64 and max(v['sizes'])<=16384
            for i in range(v['children']):
                plan=c.range_spec(p,v,i);a,b,n,width,base,_=r.derive(plan,d);assert n*width<=131072;spans.append((base,base+64));sources.append(plan.source)
                for j in range(4):assert 4*plan.identity+j not in instances;instances.add(4*plan.identity+j)
            assert 524288*p.identity+262144+64 not in instances;spans.sort();assert all(a[1]<=b[0] for a,b in zip(spans,spans[1:]));assert all(not lo<=source<hi for source in sources for lo,hi in spans);assert spans[-1][1]<v['base']+(1<<23)<1<<64;cases+=1
    p=spec();v=c.derive(p,4)
    for bad in (replace(p,identity=1<<39),replace(p,repetitions=True),replace(p,source=v['base']),replace(p,maximum=p.source),replace(p,schema=replace(p.schema,length=(1<<20)+1))):rejects('Spec',lambda:c.derive(bad,4))
    for bad in (replace(p,position=True),replace(p,position=3)):rejects('Position',lambda:c.derive(bad,4))
    for bad in (replace(p,window=True),replace(p,window=-1),replace(p,start=3),replace(p,stop=2)):rejects('Mask',lambda:c.derive(bad,4))
    print('full global maximum shape and namespace cases passed',cases,flush=True)


def account(p,out,d):
    v=c.derive(p,d);layouts=[r.derive(c.range_spec(p,v,i),d) for i in range(v['children'])];dims=[a+b+1 for a,b,*_ in layouts];f=lambda m:3*m*(m-1)//2+2*m
    assert out['account']==dict(identities=[((1<<m)+255,p.repetitions) for m in dims],lookup_reduction_numerator=sum(p.repetitions*(f(m)+f(8)+3*m) for m in dims),range_reduction_numerator=sum(9*a+7*b for a,b,*_ in layouts),maximum_identity_numerator=v['a']+5,maximum_reduction_numerator=4,denominator=r.sc.P**d)
    assert out['draws']=={r.zc.tr.CHALLENGE:v['a']+4} and len(out['claims'])==16;draw=sum(4*a+3*b for a,b,*_ in layouts);assert out['child_draws']=={r.zc.WEIGHT:draw,r.zc.tr.CHALLENGE:draw}


def run(p,xs,d):
    source=Capture(c.prove(p,groups(c.derive(p,d),xs),d));out=c.verify(p,oracle(p,xs)['roots'],source,d);assert out['state']==source.state;account(p,out,d);return out


def assemble(p,selected,pairs,d):
    """Producer-only attack construction; verify always consumes every child."""
    v=c.derive(p,d);roots=[];states=[];local={};records=[dict(selected=selected)]
    with tempfile.TemporaryFile() as spool:
        for i,(proof,state) in enumerate(pairs):
            plan=c.range_spec(p,v,i);roots.append(r.source_root(plan,proof['words']));states.append(state);c.retain(p,v,i,proof['words'],local,spool);records.append(dict(range=i,proof=proof))
        expected=c.external_roots(p,v,selected,local['maximum'],spool);t=c.context(v,expected,roots,states,d);instance,tables=c.parent(p,v,t,roots,selected,local['maximum'],spool,d);records.append(dict(sum=r.sc.prove(t,instance,tables)[0]));return records,expected


def prepared(p,xs,d,selected=None,difference=None,gap=None):
    v=c.derive(p,d);w=oracle(p,xs);selected=w['selected'] if selected is None else selected;difference=w['difference'] if difference is None else difference;gap=w['gap'] if gap is None else gap;result=[r.prove(c.range_spec(p,v,0),[xs[selected]%(1<<32)],d)];at=0
    for g,ys in enumerate(groups(v,xs)):
        vs=forged_values(p,g,ys,selected,difference[at:at+len(ys)],gap[at:at+len(ys)]);at+=len(ys)
        for j,values in enumerate(vs):result.append(r.prove(c.range_spec(p,v,1+7*g+j),values,d))
    return result


def controls():
    p=spec(3,127,7);xs=[5,-5,10];proof=list(c.prove(p,[xs],4));roots=oracle(p,xs)['roots'];account(p,c.verify(p,roots,iter(proof),4),4)
    for i,reason in enumerate(('Source:CommitmentMismatch','Range:0:CommitmentMismatch','Selection:CommitmentMismatch','Difference:CommitmentMismatch')):
        bad=roots.copy();bad[i]=bytes(32);rejects(reason,lambda:c.verify(p,bad,iter(proof),4))
    for bad in (proof[:-1],proof+[{}],proof[1:],list(reversed(proof)),[proof[0],dict(proof[1],range=False)]+proof[2:],[dict(proof[0],receipt={})]+proof[1:]):rejects('StreamShape',lambda:c.verify(p,roots,iter(bad),4))
    changed=[4,-5,10];other=list(c.prove(p,[changed],4));c.verify(p,oracle(p,changed)['roots'],iter(other),4);rejects('Source:CommitmentMismatch',lambda:c.verify(p,roots,iter(other),4))
    p=spec(1,0);proof=list(c.prove(p,[[0]],4));roots=oracle(p,[0])['roots']
    for i in range(16):
        bad=copy.deepcopy(proof);bad[-1]['sum']['final'][i]=r.sc.add(bad[-1]['sum']['final'][i],r.sc.scalar(1,4));rejects('Maximum:'+('ClaimMismatch' if i==15 else 'FinalEvaluationMismatch'),lambda:c.verify(p,roots,iter(bad),4))
    bad=copy.deepcopy(proof);bad[-1]['sum']['final'][0]=(r.sc.P,0,0,0);rejects('NoncanonicalField',lambda:c.verify(p,roots,iter(bad),4))
    print('all global roots, strict roster, valid replacement and sixteen originals reject',flush=True)


def boundaries():
    p=spec(2);v=c.derive(p,4);S=p.schema.score_max;xs=[-1,S];ps=prepared(p,xs,4,selected=0,difference=[0,1<<31],gap=[0,1<<31]);bad,roots=assemble(p,0,ps,4);rejects('Maximum:RoundSumMismatch',lambda:c.verify(p,roots,iter(bad),4))
    ps=prepared(p,[0,0],4,selected=1,difference=[0,0],gap=[0,0]);bad,roots=assemble(p,1,ps,4);rejects('Maximum:RoundSumMismatch',lambda:c.verify(p,roots,iter(bad),4))
    p=spec(3);v=c.derive(p,4);xs=[S,-1,0];ps=prepared(p,xs,4);baseline,roots=assemble(p,0,ps,4)
    for index,values in ((2,[2*S,r.sc.P+S-1,S]),(3,[0,1,S])):
        changed=ps.copy();changed[index]=r.prove(c.range_spec(p,v,index),values,4);bad,rr=assemble(p,0,changed,4);rejects('Maximum:RoundSumMismatch',lambda:c.verify(p,rr,iter(bad),4))
    false,state=r.prove(c.range_spec(p,v,0),[S-r.sc.P],4);bad=baseline.copy();bad[1]=dict(range=0,proof=false);rr=roots.copy();rr[1]=r.source_root(c.range_spec(p,v,0),false['words']);rejects('Attainment',lambda:c.verify(p,rr,iter(bad),4))
    for index,at in ((1,3),(2,3),(3,3),(4,3),(5,3),(6,3),(7,3),(6,12),(7,12)):
        plan=c.range_spec(p,v,index);values=c.unpack(plan,ps[index][0]['words']);caps=list(plan.caps)+[0]*(len(values)-len(plan.caps));caps[at]=max(caps[at],1);values[at]=1;false=r.assemble(plan,*r.witness(replace(plan,caps=tuple(caps)),values),4)[0];bad=baseline.copy();bad[index+1]=dict(range=index,proof=false)
        rejects('Range:'+str(index)+':CapRelation:RoundSumMismatch' if at==3 else 'Maximum:RoundSumMismatch',lambda:c.verify(p,roots,iter(bad),4))
    p=replace(spec(3,127,7),position=1);xs=[0,1,127];run(p,xs,4);proof=list(c.prove(p,[xs],4));roots=oracle(p,xs)['roots'];bad=proof.copy();bad[0]=dict(selected=2);rr=roots.copy();rr[2]=r.root(p.selection,[2]);rejects('Selection',lambda:c.verify(p,rr,iter(bad),4))
    print('isolated terminal wrap, later tie, signed aliases, all padding/carry roles and masked selection reject',flush=True)


def honest():
    digest=hashlib.sha256();done=0
    for d,reps in ((4,1),(4,2),(8,1),(8,2)):
        for size,S,bits in ((1,0,7),(3,127,7),(5,32768,15),(3,(1<<31)-1,31)):
            p=spec(size,S,bits,8910+done,reps);xs=[0]*size if not S else ([S,-1,S] if S==(1<<31)-1 else [(0,1,-1)[j%3] for j in range(size)])
            if size==5:p=replace(p,position=3,window=2,start=1,stop=4);xs[0]=S;xs[-1]=S
            print('global maximum start',done+1,d,reps,size,flush=True);out=run(p,xs,d);digest.update(out['state']);done+=1;print('global maximum passed',done,d,reps,flush=True)
    print(json.dumps(dict(proofs=done,sha256=digest.hexdigest()),sort_keys=True),flush=True)


if __name__=='__main__':
    modes={'--corpus':corpus,'--shapes':shapes,'--controls':controls,'--boundaries':boundaries,'--honest':honest};assert set(sys.argv[1:])<=set(modes)
    for mode in sys.argv[1:] or modes:modes[mode]()
