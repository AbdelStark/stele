# /// script
# requires-python = ">=3.12"
# dependencies = ["numpy==2.3.4", "blake3==1.0.11", "python-flint==0.9.0"]
# ///
"""Draft RFC-0004 A3/A6/A8: actual normalized heads and one complete row conversion."""
import copy
from dataclasses import replace
import hashlib
import json
import random
import sys
import numpy as np
import attention_output_conversion as c
import check_attention_normalization as normal_check
import check_row_conversion_capacity as row_check

r=c.r


def rejects(reason,call):
    try:call()
    except ValueError as error:assert str(error)==reason,(reason,str(error))
    else:raise AssertionError('accepted '+reason)


def spec(mode='exact',policy='dynamic',heads=2,width=3,identity=2851,repetitions=1):
    schema=c.norm.bounds.Spec(4096,width,0,0,0,'static',65535,mode,0 if mode=='exact' else 12)
    sources=tuple(tuple(0 if mode=='block1024' and k==1 else 21001+13*j+k for k in range(13)) for j in range(heads))
    return c.Spec(schema,heads,1,policy,0 if policy=='dynamic' else 3,identity,sources,25001,25003,repetitions)


def oracle(p,zs,totals):
    head_values=[];roots=[]
    for j,(z,ts) in enumerate(zip(zs,totals)):
        child=c.norm.Spec(p.schema,256*p.identity+j,*p.sources[j],p.repetitions)
        values,bound=normal_check.oracle(child,z,ts);head_values.append(values);roots.append(bound)
    wide=sum((x['output'] for x in head_values),[]);xs=np.array(wide,dtype=object)
    scale=(int(np.max(np.abs(xs)))+126)//127 if p.output_mode=='dynamic' else p.output_scale
    mag=(2*np.abs(xs)+scale)//(2*scale) if scale else np.zeros(len(xs),dtype=object)
    if any(x>127 for x in mag):raise ValueError('OutputRange')
    codes=[int(x) for x in np.where(xs<0,-mag,mag)];n=1<<(len(wide)-1).bit_length()
    return dict(heads=head_values,wide=wide,scale=scale,codes=codes),dict(heads=roots,scale=r.root(p.scale,list(scale.to_bytes(2,'little'))),output=r.root(p.output,[x%256 for x in codes]+[0]*(n-len(codes))))


def corpus():
    rng=random.Random(2753);digest=hashlib.sha256();accepted=rejected=cells=zeros=0
    def check(p,zs,totals):
        nonlocal accepted,rejected,cells,zeros
        try:w,roots=oracle(p,zs,totals)
        except ValueError:
            rejects('OutputRange',lambda:c.witness(p,zs,totals));rejected+=1;digest.update(b'reject'+c.derive(p,4)['raw']);return
        assert c.witness(p,zs,totals)==w and c.expected_roots(p,zs,totals)==roots
        digest.update(c.derive(p,4)['raw']+b''.join(sum(roots['heads'],[])+[roots['scale'],roots['output']]))
        accepted+=1;cells+=len(w['wide']);zeros+=sum(x<0 and y==0 for x,y in zip(w['wide'],w['codes']))
    for case in range(10000):
        mode='exact' if case%2 else 'block1024';policy='dynamic' if case%4<2 else 'static';h=(1,2,3,4)[case%4];width=(1,3,5)[case%3]
        p=spec(mode,policy,h,width,case,1+case%2);L=rng.choice((65,1025,4096,1<<20));fv=case%31;fo=(case//31)%31;E=case%15;Q=1<<E
        vm='dynamic' if case%3 else 'static';vs=0 if vm=='dynamic' else rng.choice((1,259,65535));S=127*259 if vm=='dynamic' else vs*min(127,(65536+vs)//(2*vs));raw=1024*Q*S
        drop=0 if mode=='exact' else next(k for k in range(63) if (raw+(1<<k)//2)//(1<<k)<=32767)
        p=replace(p,schema=c.norm.bounds.Spec(L,width,fv,fo,E,vm,vs,mode,drop),groups=h if case%3 else 1,output_scale=0 if policy=='dynamic' else rng.choice((1,2,259,65535)))
        shift=fo-fv+drop;A=1<<max(shift,0);B=1<<max(-shift,0);G=L*Q*S if mode=='exact' else ((L+1023)//1024)*((raw+(1<<drop)//2)//(1<<drop))
        zs=[rng.randint(Q,L*Q) for _ in range(h)];totals=[]
        for z in zs:
            cap=min(G,z*S if mode=='exact' else G,(33000*z*B)//A);totals.append([rng.choice((0,-min(cap,1),-cap,cap,rng.randint(-cap,cap))) for _ in range(width)])
        check(p,zs,totals)
    for mode,policy,h,width in (('exact','dynamic',128,128),('block1024','static',128,128),('exact','static',127,129),('block1024','dynamic',1,16384)):
        p=spec(mode,policy,h,width,20000);p=replace(p,schema=replace(p.schema,length=1<<20),output_scale=0 if policy=='dynamic' else 259);zs,totals=full_inputs(p);check(p,zs,totals)
    p=spec('exact','dynamic',3,2731,20001);check(p,[4096]*3,[[0]*2731 for _ in range(3)])
    assert accepted>1000 and rejected>100 and zeros>0
    assert digest.hexdigest()=='b5fbec3f9e22d85e71634844d77a468255be026177abbe7dc0e244366aca270b'
    print(json.dumps(dict(seed=2753,cases=10000,capacity_cases=4,zero_cases=1,accepted=accepted,rejected=rejected,cells=cells,negative_zero_codes=zeros,sha256=digest.hexdigest()),sort_keys=True),flush=True)


def account(p,out,d):
    v=c.derive(p,d)
    for child,part in zip(v['head_specs'],out['heads']):normal_check.account(child,part,d)
    row_check.account(v['module'],v['conversion'],out['conversion'],d);heads=[x['account'] for x in out['heads']];row=out['conversion']['account'];all_parts=heads+[row]
    assert out['draws']=={} and out['account']==dict(identities=sum((x['identities'] for x in all_parts),[]),lookup_reduction_numerator=sum(x['lookup_reduction_numerator'] for x in all_parts),range_reduction_numerator=sum(x['range_reduction_numerator'] for x in all_parts),product_identity_numerators=sum((x['product_identity_numerators'] for x in heads),[]),product_reduction_numerator=sum(x['product_reduction_numerator'] for x in heads),selection_reduction_numerator=row.get('selection_reduction_numerator',0),denominator=r.sc.P**d)


def controls():
    for mode,policy in (('exact','dynamic'),('exact','static'),('block1024','dynamic'),('block1024','static')):
        p=spec(mode,policy);d=4;v=c.derive(p,d);zs=[4095,4096];ys=[[-1,0,1],[381,-1,1]];totals=[[x*z if mode=='exact' else x for x in xs] for z,xs in zip(zs,ys)]
        proof,state=c.prove(p,zs,totals,d);w,roots=oracle(p,zs,totals);out=c.verify(p,roots,proof,d);assert out['state']==state;account(p,out,d)
        reasons={'offset':'Sign:Offset:CommitmentMismatch','base_source':'GlobalBase:Base:CommitmentMismatch','probability':('GlobalBase' if mode=='exact' else 'Denominator')+':WeightSum:CommitmentMismatch','magnitude':'Sign:Magnitude:CommitmentMismatch','sign':'Sign:Sign:CommitmentMismatch','numerator':'Numerator:Numerator:CommitmentMismatch','denominator':'Denominator:Denominator:CommitmentMismatch','quotient':'Division:QuotientProduct:Quotient:CommitmentMismatch','product':'Division:QuotientProduct:Product:CommitmentMismatch','biased':'Division:Bias:Biased:CommitmentMismatch','doubled':'Division:Double:Doubled:CommitmentMismatch','remainder':'Division:Remainder:CommitmentMismatch','output':'SignedOutput:Output:Raw:CommitmentMismatch'}
        for j in range(p.heads):
            for k,role in enumerate(v['roles']):
                bad=copy.deepcopy(roots);bad['heads'][j][k]=bytes(32);rejects('Head'+str(j)+':'+reasons[role],lambda:c.verify(p,bad,proof,d))
        for role,reason in (('scale','Scale:Scale:CommitmentMismatch' if policy=='dynamic' else 'Scale:CommitmentMismatch'),('output','Output:Raw:CommitmentMismatch')):
            bad=dict(roots);bad[role]=bytes(32);rejects('Conversion:'+reason,lambda:c.verify(p,bad,proof,d))
        for heads in (proof['heads'][:-1],proof['heads']+proof['heads'][:1]):rejects('ProofShape',lambda:c.verify(p,roots,dict(proof,heads=heads),d))
        rejects('ProofShape',lambda:c.verify(p,roots,dict(proof,extra=proof['conversion']),d))
        swapped=dict(proof,heads=list(reversed(proof['heads'])));rejects('Head0:'+('GlobalBase:Product:Input:WholeWord:CommitmentMismatch' if mode=='exact' else 'Sign:Offset:CommitmentMismatch'),lambda:c.verify(p,roots,swapped,d))
        bad=copy.deepcopy(proof);bad['heads'][0]['output']['output']['ranges'][0]['words'][p.schema.width]=1
        rejects('Head0:SignedOutput:Output:Raw:CommitmentMismatch',lambda:c.verify(p,roots,bad,d))
        changed=totals[0].copy();changed[0]=0;other,_=c.norm.prove(v['head_specs'][0],zs[0],changed,d);bad=dict(proof,heads=[other,proof['heads'][1]])
        rejects('Head0:Sign:Offset:CommitmentMismatch',lambda:c.verify(p,roots,bad,d));rejects('SourceJoin',lambda:c.roots(p,bad))
        wide=w['wide'].copy();wide[0]=0;other,st=v['module'].prove(v['conversion'],wide,d);rr=v['module'].roots(v['conversion'],other)
        assert rr[1:]==[roots['scale'],roots['output']] and v['module'].verify(v['conversion'],rr,other,d)['state']==st
        bad=dict(proof,conversion=other);rejects('SourceJoin',lambda:c.roots(p,bad));reason='Scale:Maximum:Input:Raw:CommitmentMismatch' if policy=='dynamic' else 'Input:Raw:CommitmentMismatch'
        rejects('Conversion:'+reason,lambda:c.verify(p,roots,bad,d))
        if mode=='exact' and policy=='dynamic':
            local=[];codes=[]
            for j,xs in enumerate(ys):
                lp=replace(v['conversion'],schema=replace(v['conversion'].schema,dimension=3),identity=30000+j,source=p.sources[j][-1],scale=31001+2*j,output=31002+2*j)
                part,st=c.dynamic.prove(lp,xs,d);rr=c.dynamic.roots(lp,part);rr[0]=roots['heads'][j][-1];assert c.dynamic.verify(lp,rr,part,d)['state']==st
                local.append(part);codes.extend(c.dynamic.witness(lp,xs)['codes'])
            assert codes!=w['codes'];rejects('Conversion:ProofShape',lambda:c.verify(p,roots,dict(proof,conversion=local),d))
        print('all head/row roots, omission/order/padding, valid replacements and zero-hidden conversion sources reject',mode,policy,flush=True)


def boundaries():
    context()
    for mode in ('exact','block1024'):
        for policy in ('dynamic','static'):
            for h,width in ((128,128),(1,16384)):
                p=spec(mode,policy,h,width,(1<<24)-1,2)
                for d in (4,8):
                    v=c.derive(p,d);spans=[(c.norm.derive(child,d)['base'],1<<30) for child in v['head_specs']]+[(v['module'].derive(v['conversion'],d)['base'],1<<(26 if policy=='dynamic' else 18)),(v['assembled'],1)]
                    assert all(v['base']<=lo and lo+size<=v['base']+(1<<38) for lo,size in spans) and all(lo+size<=nxt for (lo,size),(nxt,_) in zip(spans,spans[1:]))
            p=spec(mode,policy);v=c.derive(p,4);roots=dict(heads=[[hashlib.sha256(str((j,k)).encode()).digest() for k in v['roles']] for j in range(p.heads)],scale=bytes(32),output=bytes([1])*32);assembled=bytes([2])*32;states=[hashlib.sha256(bytes([j])).digest() for j in range(p.heads+1)];t=c.transcript(v,roots,assembled,states,4);assert not t.draws
            for j in range(len(states)):
                other=states.copy();other[j]=bytes([states[j][0]^1])+states[j][1:];assert c.transcript(v,roots,assembled,other,4).state!=t.state
            for other in (replace(p,groups=2),replace(p,output=25005),replace(p,schema=replace(p.schema,fraction=1,output_fraction=1)),replace(p,output_scale=1) if policy=='static' else replace(p,output_mode='static',output_scale=3)):
                assert c.transcript(c.derive(other,4),roots,assembled,states,4).state!=t.state
            rejects('Root',lambda:c.transcript(v,roots,assembled,states[:-1],4));rejects('Root',lambda:c.transcript(v,dict(roots,extra=assembled),assembled,states,4))
            for other in (replace(p,heads=True),replace(p,heads=129),replace(p,groups=3),replace(p,identity=1<<24),replace(p,scale=p.output),replace(p,output=v['base']),replace(p,sources=p.sources[:-1]),replace(p,repetitions=True)):
                rejects('Spec',lambda:c.derive(other,4))
            rejects('Capacity',lambda:c.derive(replace(spec(mode,policy,2,8193)),4))
    print('full namespaces, metadata context, canonical roles and shape limits pass',flush=True)


def context():
    for mode in ('exact','block1024'):
        for policy in ('dynamic','static'):
            for d,reps in ((4,1),(4,2),(8,1),(8,2)):
                p=spec(mode,policy,3,1,2853,reps);v=c.derive(p,d);roots=dict(heads=[[hashlib.sha256(str((j,role)).encode()).digest() for role in v['roles']] for j in range(3)],scale=bytes(32),output=bytes([1])*32);assembled=bytes([2])*32;states=[hashlib.sha256(bytes([j])).digest() for j in range(4)];t=c.transcript(v,roots,assembled,states,d);assert not t.draws
                for j in range(4):
                    other=states.copy();other[j]=bytes([states[j][0]^1])+states[j][1:];assert c.transcript(v,roots,assembled,other,d).state!=t.state
                for j in range(3):
                    for k in range(len(v['roles'])):
                        other=copy.deepcopy(roots);value=other['heads'][j][k];other['heads'][j][k]=bytes([value[0]^1])+value[1:];assert c.transcript(v,other,assembled,states,d).state!=t.state
                assert c.transcript(v,roots,bytes([3])+assembled[1:],states,d).state!=t.state
                ids=(tuple([40001]+list(p.sources[0][1:])),)+p.sources[1:]
                for other in (replace(p,groups=3),replace(p,sources=ids),replace(p,output=25005),replace(p,schema=replace(p.schema,fraction=1,output_fraction=1))):assert c.transcript(c.derive(other,d),roots,assembled,states,d).state!=t.state
    print('all fields/repetitions bind every head root, child state, assembled root and expected metadata',flush=True)


def full_inputs(p):
    z=p.schema.length;A=1<<p.schema.drop;zs=[z]*p.heads;totals=[]
    for j in range(p.heads):
        bound=min(32768,(j+1)*256);ys=[(-bound,bound-1,-1,0,1)[i%5] for i in range(p.schema.width)];totals.append([y*z//A for y in ys])
    return zs,totals


def honest(mode='matrix'):
    digest=hashlib.sha256();done=0
    for d,reps in (((4,1),) if mode!='matrix' else ((4,1),(4,2),(8,1),(8,2))):
        for acc,policy in ((('exact','dynamic'),) if mode=='maximum' else (('block1024','static'),) if mode=='full-block' else (('exact','dynamic'),('exact','static'),('block1024','dynamic'),('block1024','static'))):
            full=mode!='matrix';p=spec(acc,policy,128 if full else 3,128 if full else 1,2852+done,reps);p=replace(p,schema=replace(p.schema,length=1<<20 if full else 4096),output_scale=0 if policy=='dynamic' else 259)
            zs,totals=full_inputs(p);print('output conversion start',mode,done+1,d,reps,acc,policy,flush=True)
            proof,state=c.prove(p,zs,totals,d);w,roots=oracle(p,zs,totals);out=c.verify(p,roots,proof,d);assert out['state']==state and c.roots(p,proof)==roots;account(p,out,d)
            v=c.derive(p,d);words=[x>>(8*k)&255 for k in range(2) for x in w['wide']+[0]*(v['n']-len(w['wide']))];assert c.assembled_words(p,v,proof)==words
            digest.update(state);done+=1;print('output conversion passed',mode,done,d,reps,acc,policy,flush=True)
    print(json.dumps(dict(mode=mode,proofs=done,sha256=digest.hexdigest()),sort_keys=True),flush=True)


if __name__=='__main__':
    modes={'--corpus':corpus,'--controls':controls,'--boundaries':boundaries,'--honest':honest,'--maximum':lambda:honest('maximum'),'--full-block':lambda:honest('full-block')}
    selected=sys.argv[1:] or ['--corpus','--controls','--boundaries','--honest'];assert all(mode in modes for mode in selected)
    for mode in selected:modes[mode]()
