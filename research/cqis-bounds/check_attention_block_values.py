# /// script
# requires-python = "==3.12.*"
# dependencies = ["numpy==2.3.4", "blake3==1.0.11", "python-flint==0.9.0"]
# ///
"""Draft RFC-0004 A3/A6: full restored blocks, no native proof credit."""
import copy
from dataclasses import replace
import hashlib
import json
import random
import struct
import sys
import tempfile
import numpy as np
import attention_block_values as c

r=c.r


def rejects(reason,call):
    try:call()
    except ValueError as error:assert str(error)==reason,(reason,str(error))
    else:raise AssertionError('accepted '+reason)


def spec(rows=3,width=3,mode='dynamic',scale=0,identity=8700,repetitions=1):
    return c.Spec(c.bounds.Spec(rows,width,7,14,mode,scale,'exact'),0,identity,101,103,107,repetitions)


class Capture:
    def __init__(self,source):self.source=iter(source);self.state=None
    def __iter__(self):return self
    def __next__(self):
        try:return next(self.source)
        except StopIteration as end:self.state=end.value;raise


def groups(v,codes):
    at=0
    for size in v['sizes']:yield codes[at:at+size];at+=size
    assert at==len(codes)


def oracle(p,codes,scales):
    count=len(codes);n=1<<(count-1).bit_length();nr=1<<(len(scales)-1).bit_length();s=p.schema.scale
    cap=127 if p.schema.value_mode=='dynamic' else min(127,(65536+s)//(2*s));S=cap*(259 if p.schema.value_mode=='dynamic' else s)
    us=(S+np.array(codes,dtype=np.int64)*np.repeat(np.array(scales,dtype=np.int64),p.schema.width)).tolist()
    def planes(xs,n,dtype):return np.frombuffer(np.array(xs+[0]*(n-len(xs)),dtype=dtype).tobytes(),dtype=np.uint8).reshape(n,-1).T.reshape(-1).tolist()
    return us,[r.root(p.source,[x%256 for x in codes]+[0]*(n-count)),r.root(p.scale_source,planes(scales,nr,'<u2')),r.root(p.output,planes(us,n,'<u4'))]


def account(p,out,d):
    v=c.derive(p,d);ar=v['ar'];dynamic=v['dynamic'];dims=[ar+2,ar+1,ar+2] if dynamic else [];loss=(30*ar+17)*dynamic;draw=(13*ar+7)*dynamic
    for g in range(v['groups']):
        signed,mag,output=c.group_specs(p,v,g);ag=(signed.count-1).bit_length();bg=r.derive(output,d)[1]
        dims.extend((ag+1,ag+1,ag+2,ag+1,ag+bg+1));loss+=61*ag+9+7*bg;draw+=26*ag+4+3*bg
    f=lambda m:3*m*(m-1)//2+2*m
    assert out['account']==dict(identities=[((1<<m)+255,p.repetitions) for m in dims],lookup_reduction_numerator=sum(p.repetitions*(f(m)+f(8)+3*m) for m in dims),range_reduction_numerator=loss,restoration_identity_numerator=v['a']+dynamic,restoration_reduction_numerator=2*ar,denominator=r.sc.P**d)
    assert len(out['claims'])==(4 if dynamic else 2) and len(out['predicate_claims'])==4*dynamic
    for label in (r.zc.WEIGHT,r.zc.tr.CHALLENGE):
        assert out['child_draws'].get(label,0)+out['draws'].get(label,0)==draw+(v['a']+dynamic+ar if label==r.zc.tr.CHALLENGE else 0)


def run(p,codes,scales,d):
    source=Capture(c.prove(p,scales,groups(c.derive(p,d),codes),d));out=c.verify(p,oracle(p,codes,scales)[1],source,d);assert out['state']==source.state;account(p,out,d);return out


def shapes():
    done=0
    for d in (4,8):
        for rows,width in ((1024,16384),(1023,16383),(1,16384),(1024,1),(3,10923)):
            p=spec(rows,width,identity=(1<<37)-1,repetitions=2);p=replace(p,schema=replace(p.schema,length=1023*1024+rows),block=1023);v=c.derive(p,d)
            assert sum(v['sizes'])==rows*width and max(v['sizes'])<=16384 and v['groups']<=1024 and 2*v['bound']<r.sc.P
            spans=[];instances=set();sources=set()
            for g in range(v['groups']):
                signed,mag,output=c.group_specs(p,v,g);sv=c.ss.derive(signed,d);spans.append((sv['base'],sv['base']+512));sources.update((signed.source,signed.magnitude,output.source))
                for index in range(6):assert 32*signed.identity+24+index not in instances;instances.add(32*signed.identity+24+index)
                for plan in sv['ranges']+[mag,output]:
                    for index in range(4):assert 4*plan.identity+index not in instances;instances.add(4*plan.identity+index)
                for plan in (mag,output):base=r.derive(plan,d)[4];spans.append((base,base+64))
            for plan in c.common_specs(p,v):
                base=r.derive(plan,d)[4];spans.append((base,base+64));sources.add(plan.source)
                for index in range(4):assert 4*plan.identity+index not in instances;instances.add(4*plan.identity+index)
            for identity in (2097152*p.identity+1048576+64,2097152*p.identity+1048576+65):assert identity not in instances
            spans.sort();assert all(a[1]<=b[0] for a,b in zip(spans,spans[1:]));assert all(not lo<=source<hi for source in sources for lo,hi in spans)
            assert spans[-1][1]<v['base']+(1<<25)<1<<64;done+=1
    p=spec();v=c.derive(p,4)
    for bad in (replace(p,identity=1<<37),replace(p,identity=True),replace(p,block=1),replace(p,block=True),replace(p,repetitions=True),replace(p,source=v['base']),replace(p,output=p.source)):
        rejects('Spec',lambda:c.derive(bad,4))
    print('full shape and namespace cases passed',done,flush=True)


def corpus():
    rng=random.Random(2761);digest=hashlib.sha256();cells=zeros=0
    for case in range(10000):
        rows=rng.randint(1,4);width=rng.randint(1,17);mode='dynamic' if case%2 else 'static';scale=0 if mode=='dynamic' else rng.choice((1,2,259,32768,65535));p=spec(rows,width,mode,scale);v=c.derive(p,4)
        scales=[rng.choice((0,1,258,259)) if mode=='dynamic' else scale for _ in range(rows)];codes=[rng.randint(-v['cap'],v['cap']) if scales[i//width] else 0 for i in range(v['count'])];us,roots=oracle(p,codes,scales)
        assert c.values(p,v,0,codes,scales)==us
        with tempfile.TemporaryFile() as spool:
            c.write_group(spool,[x%256 for x in codes],us);assert c.external_roots(p,v,scales,spool)==roots
        cells+=len(codes);zeros+=scales.count(0);digest.update(b''.join(roots))
    print(json.dumps(dict(seed=2761,cases=10000,cells=cells,zero_scales=zeros,sha256=digest.hexdigest()),sort_keys=True),flush=True)


def assemble(p,pairs,d):
    """Producer-only attack construction; verification always consumes children."""
    v=c.derive(p,d);roots=[];states=[];local=c.initial(p,v);records=[]
    with tempfile.TemporaryFile() as spool:
        for index,(proof,state) in enumerate(pairs):
            part=c.child_roots(p,v,index,proof,d);c.retain(p,v,index,proof,part,local,spool);roots.extend(part);states.append(state);records.append(dict(child=index,proof=proof))
        expected=c.external_roots(p,v,local['scale'],spool);t=c.context(v,expected,roots,states,d);predicate=None
        if v['dynamic']:
            instance,tables=c.predicates(p,v,local,d);predicate=r.zero_prove(t,instance,tables)
        instance,tables=c.parent(p,v,t,roots,local,spool,d);records.append(dict(predicates=predicate,sum=r.sc.prove(t,instance,tables)[0]));return records,expected


def pairs(p,codes,scales,d):
    v=c.derive(p,d);out=[]
    for index in range(v['children']):
        role,g,plan=c.child_spec(p,v,index)
        if g is None:xs={'scale':scales,'nonzero':[int(s!=0) for s in scales],'predecessor':[max(s-1,0) for s in scales]}[role]
        else:
            start=g*v['group_rows']*v['width'];xs=codes[start:start+v['sizes'][g]]
            if role=='magnitude':xs=list(map(abs,xs))
            if role=='output':xs=c.values(p,v,g,xs,scales)
        out.append(c.ss.prove(plan,xs,d) if role=='source' else r.prove(plan,xs,d))
    return out


def controls():
    p=spec(2,3);d=4;codes=[0,0,0,-127,1,127];scales=[0,259];proof=list(c.prove(p,scales,[codes],d));roots=oracle(p,codes,scales)[1];account(p,c.verify(p,roots,iter(proof),d),d)
    for index,name in enumerate(('Source','Scale','Output')):
        bad=roots.copy();bad[index]=bytes(32);rejects(name+':CommitmentMismatch',lambda:c.verify(p,bad,iter(proof),d))
    for bad in (proof[:-1],proof+[{}],proof[1:],list(reversed(proof)),[dict(proof[0],child=False)]+proof[1:],[dict(proof[0],receipt={})]+proof[1:]):rejects('StreamShape',lambda:c.verify(p,roots,iter(bad),d))
    for changed,ss,name in (([0,0,0,127,1,-127],scales,'Source'),(codes,[0,258],'Scale')):
        other=list(c.prove(p,ss,[changed],d));c.verify(p,oracle(p,changed,ss)[1],iter(other),d);rejects(name+':CommitmentMismatch',lambda:c.verify(p,roots,iter(other),d))
    for scale,index in ((0,0),(0,1),(0,2),(1,3)):
        one=spec(1,1);pr=list(c.prove(one,[scale],[[0]],d));rr=oracle(one,[0],[scale])[1];bad=copy.deepcopy(pr);bad[-1]['sum']['final'][index]=r.sc.add(bad[-1]['sum']['final'][index],r.sc.scalar(1,d));rejects('Restoration:ClaimMismatch',lambda:c.verify(one,rr,iter(bad),d))
        bad=copy.deepcopy(pr);bad[-1]['sum']['final'][index]=(r.sc.P,)+(0,)*(d-1);rejects('NoncanonicalField',lambda:c.verify(one,rr,iter(bad),d))
    print('roots, strict stream, valid replacements and all zero-hidden originals reject',flush=True)


def boundaries():
    d=4;p=spec(3,1);v=c.derive(p,d);ps=pairs(p,[0,0,0],[0,1,259],d);index=v['children']-1;plan=c.child_spec(p,v,index)[2]
    for values in ([v['S']+1,v['S'],v['S']],[v['S']+1,v['S']-1,v['S']]):
        changed=ps.copy();changed[index]=r.prove(plan,values,d);bad,roots=assemble(p,changed,d);rejects('Restoration:RoundSumMismatch',lambda:c.verify(p,roots,iter(bad),d))
    changed=ps.copy();signed,mag,_=c.group_specs(p,v,0);changed[3]=c.ss.prove(signed,[1,0,0],d);changed[4]=r.prove(mag,[1,0,0],d);bad,roots=assemble(p,changed,d);rejects('Restoration:RoundSumMismatch',lambda:c.verify(p,roots,iter(bad),d))
    honest,expected=assemble(p,ps,d)
    for index,at in ((0,3),(1,3),(2,3),(4,3),(5,3)):
        plan=c.child_spec(p,v,index)[2];xs=c.unpack(plan,ps[index][0]['words']);caps=list(plan.caps)+[0]*(len(xs)-len(plan.caps));caps[at]=1;xs[at]=1
        bad=honest.copy();bad[index]=dict(child=index,proof=r.assemble(plan,*r.witness(replace(plan,caps=tuple(caps)),xs),d)[0]);role,g,_=c.child_spec(p,v,index);prefix=role.title()+(':'+str(g) if g is not None else '')
        rejects(prefix+':CapRelation:RoundSumMismatch',lambda:c.verify(p,expected,iter(bad),d))
    for policy,scale,code in (('dynamic',0,-128),('static',65535,2)):
        p=spec(1,1,policy,scale);v=c.derive(p,d);scales=[1 if policy=='dynamic' else scale];ps=pairs(p,[0],scales,d);at=3 if v['dynamic'] else 0;signed,mag,_=c.group_specs(p,v,0);ps[at]=c.ss.prove(signed,[code],d);false=r.assemble(mag,*r.witness(replace(mag,caps=(abs(code),)),[abs(code)]),d);ps[at+1]=false
        bad,roots=assemble(p,ps,d);rejects('Magnitude:0:CapRelation:FinalEvaluationMismatch',lambda:c.verify(p,roots,iter(bad),d))
    print('false and compensated U, zero-scale nonzero code, padding and tighter cap controls reject',flush=True)


def honest():
    digest=hashlib.sha256();done=0
    for d,reps in ((4,1),(4,2),(8,1),(8,2)):
        for rows,width,mode,scale,acc in ((1,1,'dynamic',0,'exact'),(1,1,'static',1,'block1024'),(3,3,'dynamic',0,'block1024'),(3,5,'static',65535,'exact')):
            p=spec(rows,width,mode,scale,8710+done,reps);p=replace(p,schema=replace(p.schema,accumulation=acc));v=c.derive(p,d);scales=[(0,259,1)[j%3] if mode=='dynamic' else scale for j in range(rows)];codes=[(-v['cap'],0,v['cap'])[i%3] if scales[i//width] else 0 for i in range(v['count'])]
            print('block values start',done+1,d,reps,rows,width,mode,flush=True);out=run(p,codes,scales,d);digest.update(out['state']);done+=1;print('block values passed',done,d,reps,flush=True)
    print(json.dumps(dict(proofs=done,sha256=digest.hexdigest()),sort_keys=True),flush=True)


def originals():
    p=spec(1,1);d=4;proof=list(c.prove(p,[0],[[0]],d));roots=oracle(p,[0],[0])[1]
    for index in range(4):
        bad=copy.deepcopy(proof);bad[-1]['predicates']['final'][index][0]=r.sc.scalar(1,d)
        rejects('ScalePredicates:'+('ClaimMismatch' if index==3 else 'FinalEvaluationMismatch'),lambda:c.verify(p,roots,iter(bad),d))
    p=spec(1,1,'static',1);proof=list(c.prove(p,[1],[[0]],d));roots=oracle(p,[0],[1])[1]
    for index in range(2):
        bad=copy.deepcopy(proof);bad[-1]['sum']['final'][index]=r.sc.add(bad[-1]['sum']['final'][index],r.sc.scalar(1,d))
        rejects('Restoration:'+('ClaimMismatch' if index==0 else 'FinalEvaluationMismatch'),lambda:c.verify(p,roots,iter(bad),d))
    p=spec(3,3);v=c.derive(p,d);codes=[0]*9;scales=[0,1,259];proof=list(c.prove(p,scales,[codes],d));us,roots=oracle(p,codes,scales)
    words=c.planes(us,v['n'],4);words[-1]=1;changed=roots.copy();changed[2]=r.root(p.output,words);rejects('Output:CommitmentMismatch',lambda:c.verify(p,changed,iter(proof),d))
    wrong=np.pad(np.array(us,dtype=np.uint32).reshape(3,3),((0,1),(0,1))).reshape(-1).tolist();changed[2]=r.root(p.output,c.planes(wrong,v['n'],4));rejects('Output:CommitmentMismatch',lambda:c.verify(p,changed,iter(proof),d))
    ps=pairs(p,codes,scales,d);plan=c.child_spec(p,v,5)[2];xs=[v['S']+r.sc.P]+[v['S']]*8;ps[5]=r.assemble(plan,*r.witness(replace(plan,caps=(xs[0],)+plan.caps[1:]),xs),d);bad,rr=assemble(p,ps,d);rejects('Output:0:CapRelation:RoundSumMismatch',lambda:c.verify(p,rr,iter(bad),d))
    print('scale-predicate/static originals, high planes, flat layout and M31 alias reject',flush=True)


def predicates_controls():
    p=spec(1,1);d=4;v=c.derive(p,d)
    for scales,index,xs in (([0],1,[1]),([0],2,[1]),([1],1,[0])):
        ps=pairs(p,[0],scales,d);plan=c.child_spec(p,v,index)[2];ps[index]=r.prove(plan,xs,d);bad,roots=assemble(p,ps,d)
        rejects('ScalePredicates:RoundSumMismatch',lambda:c.verify(p,roots,iter(bad),d))
    p=spec(1,1,'static',1);proof=list(c.prove(p,[1],[[0]],d));roots=oracle(p,[0],[1])[1];roots[1]=r.root(p.scale_source,[2,0]);rejects('Scale:CommitmentMismatch',lambda:c.verify(p,roots,iter(proof),d))
    print('valid changed scale predicates and static scale source reject',flush=True)


def zero_predicate():
    p=spec(1,1);d=4;v=c.derive(p,d);ps=pairs(p,[0],[1],d)
    # s=k+n holds exactly; only the second scale predicate is false.
    for index,xs in ((1,[0]),(2,[1])):ps[index]=r.prove(c.child_spec(p,v,index)[2],xs,d)
    bad,roots=assemble(p,ps,d);rejects('ScalePredicates:RoundSumMismatch',lambda:c.verify(p,roots,iter(bad),d))
    print('isolated scale nonzero predicate rejects',flush=True)


def projections():
    # Arithmetic only: synthetic child states never authorize verify.
    for d in (4,8):
        p=spec(3,10923);v=c.derive(p,d);scales=[0,259,1];codes=[(i%255)-127 if scales[i//v['width']] else 0 for i in range(v['count'])];us,expected=oracle(p,codes,scales);roots=[];local=dict(scale=scales+[0],nonzero=[0,1,1,0],predecessor=[0,258,0,0])
        for plan,name in zip(c.common_specs(p,v),('scale','nonzero','predecessor')):
            _,_,n,width,*_=r.derive(plan,d);roots.append(r.source_root(plan,c.planes(local[name],n,width)))
        with tempfile.TemporaryFile() as spool:
            for g,xs in enumerate(groups(v,codes)):
                signed,mag,up=c.group_specs(p,v,g);n=1<<(len(xs)-1).bit_length();raw=[x%256 for x in xs];uv=c.values(p,v,g,xs,scales);mr=r.root(mag.source,c.planes(list(map(abs,xs)),n,1));roots.extend((r.root(signed.source,c.planes(raw,n,1)),mr,mr,r.source_root(up,c.planes(uv,n,r.derive(up,d)[3]))));c.write_group(spool,raw,uv)
            assert c.external_roots(p,v,scales,spool)==expected;states=[bytes(32)]*v['children'];t=c.context(v,expected,roots,states,d);reference=c.context(v,expected,roots,states,d);point=[r.sc.challenge(reference) for _ in range(v['a'])];r.sc.challenge(reference);weights=r.scalar.eq_weights(point,d)
            instance,tables=c.parent(p,v,t,roots,local,spool,d);assert t.state==reference.state
            for j in range(v['rows']):
                lo=j*v['width'];hi=lo+v['width'];project=lambda xs:tuple(sum(x*weight[k] for x,weight in zip(xs,weights[lo:hi]))%r.sc.P for k in range(d))
                assert tables[1][j]==project([-x for x in codes[lo:hi]]) and tables[3][j]==project(list(map(abs,codes[lo:hi])))
            assert instance['sum']==tuple(sum((v['S']-u)*weight[k] for u,weight in zip(us,weights))%r.sc.P for k in range(d))
            for at in (0,5*v['sizes'][0],5*(v['count']-1)+4):
                spool.seek(at);old=spool.read(1);spool.seek(at);spool.write(bytes([old[0]^1]));g=at//(5*v['group_rows']*v['width']);rejects('Replay:'+str(g)+':CommitmentMismatch',lambda:c.parent(p,v,c.context(v,expected,roots,states,d),roots,local,spool,d));spool.seek(at);spool.write(old)
        print('ragged value projection and replay arithmetic passed',d,v['sizes'],flush=True)


def composition():
    import row_code as dynamic
    import static_row_code as static
    import check_attention_block_offset as weighted
    for index,(mode,scale,inputs) in enumerate((('dynamic',0,[-32768,0,32767]),('static',2,[-254,0,254]))):
        p=spec(1,3,mode,scale,8770+index);module=dynamic if mode=='dynamic' else static;schema=static.row.Spec('wide',3,7,mode,scale);rp=module.Spec(schema,8780+index,109,p.scale_source,p.source,1)
        proof,state=module.prove(rp,inputs,4);rr=module.roots(rp,proof);assert module.verify(rp,rr,proof,4)['state']==state;w=module.witness(rp,inputs);codes=w['codes'];scales=[w['scale'] if mode=='dynamic' else scale];us,roots=oracle(p,codes,scales);assert roots[:2]==[rr[2],rr[1]];run(p,codes,scales,4)
        wp=weighted.c.Spec(p.schema,0,(True,),8790+index,113,p.output,127,1);assert weighted.oracle(wp,[16384],us)[1][1]==roots[2];weighted.run(wp,[16384],us,4)
        other=list(c.prove(p,scales,[list(reversed(codes))],4));c.verify(p,oracle(p,list(reversed(codes)),scales)[1],iter(other),4);rejects('Source:CommitmentMismatch',lambda:c.verify(p,roots,iter(other),4));print('prepared row through restored block to weighted sum passed',mode,flush=True)


def maximum(mode):
    rows,width={'maximum':(1024,16384),'full-static':(1024,16384),'full-ragged':(1023,16383),'full-tail':(1,16384)}[mode];policy='static' if mode=='full-static' else 'dynamic';scale=65535 if policy=='static' else 0;p=spec(rows,width,policy,scale,8799);p=replace(p,schema=replace(p.schema,length=1023*1024+rows),block=1023);v=c.derive(p,4);scales=[scale if policy=='static' else (0,259,1)[j%3] for j in range(rows)]
    if rows==1:scales=[259]
    print('full block values start',mode,rows,width,v['groups'],flush=True)
    def sources():
        at=0
        for size in v['sizes']:
            yield [(i*17+31*(i//width))%(2*v['cap']+1)-v['cap'] if scales[i//width] else 0 for i in range(at,at+size)];at+=size
    def payloads(output):
        for k in range(4 if output else 1):
            at=0
            for xs in sources():
                values=(v['S']+np.array(xs,dtype=np.int64)*np.repeat(np.array(scales[at:at+len(xs)//width],dtype=np.int64),width)).tolist() if output else [x%256 for x in xs];at+=len(xs)//width
                for x in values:yield struct.pack('<I',x>>(8*k)&255)
            for _ in range(v['n']-v['count']):yield bytes(4)
    merkle=r.lu.merkle;roots=[merkle.root(merkle.Tree(0,p.source,v['n'],4),payloads(False)),r.root(p.scale_source,c.planes(scales,v['nr'],2)),merkle.root(merkle.Tree(0,p.output,4*v['n'],4),payloads(True))];source=Capture(c.prove(p,scales,sources(),4))
    def observed():
        for record in source:
            yield record
            if 'child' in record:print('full block value children verified',mode,record['child']+1,v['children'],flush=True)
    out=c.verify(p,roots,observed(),4);assert out['state']==source.state;account(p,out,4);print('full block values passed',mode,out['state'].hex(),flush=True)


if __name__=='__main__':
    modes={'--shapes':shapes,'--corpus':corpus,'--controls':controls,'--boundaries':boundaries,'--honest':honest,'--originals':originals,'--predicates':predicates_controls,'--zero-predicate':zero_predicate,'--projections':projections,'--composition':composition,'--maximum':lambda:maximum('maximum'),'--full-static':lambda:maximum('full-static'),'--full-ragged':lambda:maximum('full-ragged'),'--full-tail':lambda:maximum('full-tail')};assert set(sys.argv[1:])<=set(modes)
    for flag in sys.argv[1:] or modes:
        modes[flag]()
