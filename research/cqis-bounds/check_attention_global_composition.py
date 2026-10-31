# /// script
# requires-python = ">=3.12"
# dependencies = ["numpy==2.3.4", "blake3==1.0.11", "python-flint==0.9.0"]
# ///
"""Draft RFC-0004 A3/A6/A8: actual global sources through complete output."""
import copy
from dataclasses import replace
import hashlib
import json
import random
import sys
import numpy as np
import attention_global_composition as c
import check_attention_output_conversion as output_check
import check_attention_global_probability_sum as probability_check
import check_attention_global_offset as offset_check

r=c.r


def rejects(reason,call):
    try:call()
    except ValueError as error:assert str(error)==reason,(reason,str(error))
    else:raise AssertionError('accepted '+reason)


def spec(mode='exact',policy='dynamic',heads=2,width=1,length=1025,identity=2951,repetitions=1):
    row=output_check.spec(mode,policy,heads,width,2*identity,repetitions);row=replace(row,schema=replace(row.schema,length=length),output_scale=0 if policy=='dynamic' else 259);B=(length+1023)//1024
    return c.Spec(row,identity,tuple(tuple(40000+2*B*j+b for b in range(B)) for j in range(heads)),tuple(tuple(40000+2*B*j+B+b for b in range(B)) for j in range(heads)))


def oracle(p,inputs):
    s=p.row.schema;Q=1<<s.exponent;S=127*259 if s.value_mode=='dynamic' else s.scale*min(127,(65536+s.scale)//(2*s.scale));B=(s.length+1023)//1024;R=(1024*Q*S+(1<<s.drop)//2)//(1<<s.drop);n=1<<(s.width-1).bit_length();zs=[];totals=[];offsets=[];probabilities=[]
    for j,(weights,blocks) in enumerate(inputs):
        Z=int(np.array(weights,dtype=object).sum());O=[int(x) for x in np.array(blocks,dtype=object).sum(axis=0)];zs.append(Z);totals.append([x-(S*Z if s.accumulation=='exact' else B*R) for x in O])
        probabilities.append([r.root(identity,list(z.to_bytes(4,'little'))) for identity,z in zip(p.probabilities[j],weights)])
        offsets.append([r.root(identity,[x>>(8*k)&255 for k in range(8) for x in row+[0]*(n-s.width)]) for identity,row in zip(p.offsets[j],blocks)])
    w,output=output_check.oracle(p.row,zs,totals);return (zs,totals),w,dict(probabilities=probabilities,offsets=offsets,output=output)


def small_inputs(p):
    v=c.derive(p,4);s=p.row.schema;S=c.out.norm.bounds.constants(s)['restored_max'];R=c.out.norm.bounds.constants(s)['rounded_block_max'];inputs=[]
    for j in range(p.row.heads):
        zs=[1023,1] if v['B']==2 else [min(1024,s.length-1024*b) for b in range(v['B'])]
        inputs.append((zs,[[S*z if s.accumulation=='exact' else R for _ in range(s.width)] for z in zs]))
    return inputs


def make(p,inputs,d):
    states=[];proof=list(offset_check.capture(c.prove(p,iter(inputs),d),states));assert len(states)==1;return proof,states[0]


def account(p,out,d):
    v=c.derive(p,d)
    for child,part in zip(v['probability'],out['probability']):probability_check.account(child,part,d)
    for child,part in zip(v['offset'],out['offset']):offset_check.account(child,part,d)
    output_check.account(p.row,out['output'],d);a=out['output']['account'];up=[child['account'] for pair in zip(out['probability'],out['offset']) for child in pair];all_parts=up+[a]
    assert out['draws']=={} and out['account']==dict(identities=[x for part in all_parts for x in part['identities']],lookup_reduction_numerator=sum(x['lookup_reduction_numerator'] for x in all_parts),range_reduction_numerator=sum(x['range_reduction_numerator'] for x in all_parts),product_identity_numerators=[x['account']['product_identity_numerator'] for x in out['probability']]+a['product_identity_numerators'],product_reduction_numerator=sum(x['account']['product_reduction_numerator'] for x in out['probability'])+a['product_reduction_numerator'],projection_identity_numerators=[x['account']['projection_identity_numerator'] for x in out['offset']],sum_reduction_numerator=sum(x['account']['sum_reduction_numerator'] for x in out['offset']),selection_reduction_numerator=a['selection_reduction_numerator'],denominator=r.sc.P**d)


def corpus():
    rng=random.Random(2756);digest=hashlib.sha256();accepted=rejected=cells=0
    for case in range(10000):
        mode='exact' if case%2 else 'block1024';policy='dynamic' if case%4<2 else 'static';p=spec(mode,policy,1+case%3,(1,3)[case%2],rng.choice((1,65,1025,2049)),case);p=replace(p,row=replace(p.row,output_scale=0 if policy=='dynamic' else rng.choice((1,259))))
        s=p.row.schema;B=(s.length+1023)//1024;S=65535;R=(1024*S+2048)//4096;inputs=[];os=[];zss=[];expected_z=[];expected_t=[]
        for j in range(p.row.heads):
            weights=[rng.randint(0,min(1024,s.length-1024*b)) for b in range(B)];weights[0]=max(1,weights[0]);blocks=[]
            for z in weights:blocks.append([S*z+rng.randint(-40000,40000)*z if mode=='exact' else R+rng.randint(-8,8) for _ in range(s.width)])
            O=[int(x) for x in np.array(blocks,dtype=object).sum(axis=0)];Z=sum(weights);inputs.append((weights,blocks));zss.append(weights);os.append(O);expected_z.append(Z);expected_t.append([x-(S*Z if mode=='exact' else B*R) for x in O])
        assert c.normalize(p,zss,os)==(expected_z,expected_t)
        try:_,w,roots=oracle(p,inputs)
        except ValueError:
            rejects('OutputRange',lambda:c.out.witness(p.row,expected_z,expected_t));rejected+=1;digest.update(b'reject'+c.derive(p,4)['raw']);continue
        assert c.out.witness(p.row,expected_z,expected_t)==w;digest.update(b''.join(c.flatten(c.derive(p,4),roots)));accepted+=1;cells+=B*p.row.heads*s.width
    assert (accepted,rejected,cells)==(5698,4302,32034)
    assert digest.hexdigest()=='198089949cd75620fc52d65cf1e3e1dfa344b29a6fda2c9d858e09fa2aea7fe1'
    print(json.dumps(dict(seed=2756,cases=10000,accepted=accepted,rejected=rejected,source_cells=cells,sha256=digest.hexdigest()),sort_keys=True),flush=True)


def adapters():
    checks=0
    for E in range(15):
        for vm,scale in (('dynamic',0),('static',1),('static',259),('static',65535)):
            p=spec('exact','static',1,1,1);p=replace(p,row=replace(p.row,schema=replace(p.row.schema,exponent=E,value_mode=vm,scale=scale)))
            S=127*259 if vm=='dynamic' else scale*min(127,(65536+scale)//(2*scale));raw=1024*(1<<E)*S;k=next(j for j in range(63) if (raw+(1<<j)//2)//(1<<j)<=32767)
            for d in (4,8):
                v=c.derive(p,d);zp=v['probability'][0];assert zp.schema.drop==k and c.prob.derive(zp,d)['caps']==(1<<E,) and c.prob.derive(zp,d)['zmax']==1<<E;checks+=1
    assert checks==120;print('all 120 exact probability adapter configurations preserve canonical shifts and L/Q caps',flush=True)


def boundaries():
    adapters()
    for mode in ('exact','block1024'):
        for policy in ('dynamic','static'):
            for h,w in ((128,128),(1,16384)):
                p=spec(mode,policy,h,w,1<<20,(1<<23)-1,2)
                for d in (4,8):
                    v=c.derive(p,d);spans=[(v['row']['base'],1<<38)]
                    for op,zp in zip(v['offset'],v['probability']):
                        ov,zv=c.off.derive(op,d),c.prob.derive(zp,d);spans.extend(((ov['base'],1<<20),(zv['base'],1<<18)));assert zp.blocks==tuple(range(1024))
                    assert all(v['base']<=lo and lo+size<=v['base']+(1<<39) for lo,size in spans) and all(lo+size<=nxt for (lo,size),(nxt,_) in zip(spans,spans[1:]))
            p=spec(mode,policy);v=c.derive(p,4);_,_,roots=oracle(p,small_inputs(p));states=[hashlib.sha256(bytes([j])).digest() for j in range(2*p.row.heads+1)];t=c.transcript(v,roots,states,4);assert not t.draws
            for j in range(len(states)):
                other=states.copy();other[j]=bytes([other[j][0]^1])+other[j][1:];assert c.transcript(v,roots,other,4).state!=t.state
            for family in ('offsets','probabilities'):
                for j in range(p.row.heads):
                    for b in range(v['B']):
                        other=copy.deepcopy(roots);other[family][j][b]=bytes(32);assert c.transcript(v,other,states,4).state!=t.state
            for other in (replace(p,row=replace(p.row,groups=2)),replace(p,row=replace(p.row,schema=replace(p.row.schema,fraction=1,output_fraction=1)))):assert c.transcript(c.derive(other,4),roots,states,4).state!=t.state
            for other in (replace(p,identity=True),replace(p,identity=1<<23),replace(p,row=replace(p.row,identity=p.row.identity+1)),replace(p,offsets=p.offsets[:-1]),replace(p,probabilities=p.offsets),replace(p,offsets=((v['base'],)+p.offsets[0][1:],)+p.offsets[1:])):rejects('Spec',lambda:c.derive(other,4))
            if mode=='exact':
                zp=v['probability'][0];raw=1024*65535;drop=zp.schema.drop;assert (raw+(1<<drop)//2)//(1<<drop)<=32767 and (raw+(1<<(drop-1))//2)//(1<<(drop-1))>32767
    print('full source rosters, nested namespaces, exact probability adapters and all root/state contexts passed',flush=True)


def controls():
    for mode in ('exact','block1024'):
        p=spec(mode,'static');v=c.derive(p,4);inputs=small_inputs(p);proof,state=make(p,inputs,4);(zs,ts),w,roots=oracle(p,inputs);out=c.verify(p,roots,iter(proof),4);assert out['state']==state;account(p,out,4);stride=v['B']+2
        for family,label in (('probabilities','Probability'),('offsets','Offset')):
            for j in range(p.row.heads):
                for b in range(v['B']):
                    bad=copy.deepcopy(roots);bad[family][j][b]=bytes(32);rejects('Head'+str(j)+':'+label+':Block:'+str(b)+':CommitmentMismatch',lambda:c.verify(p,bad,iter(proof),4))
        for role,label in (('offset','Offset'),('probability','Probability')):
            bad=copy.deepcopy(roots);bad['output']['heads'][0][v['row']['roles'].index(role)]=bytes(32);rejects('Head0:'+label+':Output:CommitmentMismatch',lambda:c.verify(p,bad,iter(proof),4))
        for bad in (proof[:-1],proof+[proof[-1]],proof[stride:]+proof[:stride],proof[:stride]+proof[:stride]+proof[stride:]):rejects('StreamShape',lambda:c.verify(p,roots,iter(bad),4))
        for index in (True,-1,1):
            bad=copy.deepcopy(proof);bad[0]['head']=index;rejects('StreamShape',lambda:c.verify(p,roots,iter(bad),4))
        bad=copy.deepcopy(proof);bad[1]['block']=1;rejects('Head0:Offset:StreamShape',lambda:c.verify(p,roots,iter(bad),4))
        bad=proof[:-1]+[dict(proof[-1],receipt=bytes(32))];rejects('StreamShape',lambda:c.verify(p,roots,iter(bad),4))
        weights=inputs[0][0].copy();weights[0]+=1;weights[1]-=1;child,st=c.prob.prove(v['probability'][0],weights,4);rr=c.prob.expected_roots(v['probability'][0],weights);assert rr[-1]==roots['output']['heads'][0][v['row']['roles'].index('probability')] and c.prob.verify(v['probability'][0],rr,child,4)['state']==st
        bad=proof.copy();bad[0]=dict(head=0,probability=child);rejects('Head0:Probability:Block:0:CommitmentMismatch',lambda:c.verify(p,roots,iter(bad),4))
        blocks=copy.deepcopy(inputs[0][1]);blocks[0][0]+=1;blocks[1][0]-=1;parts,st=offset_check.make(v['offset'][0],blocks,4);rr=offset_check.oracle(v['offset'][0],blocks)[2];assert rr[-1]==roots['output']['heads'][0][0] and c.off.verify(v['offset'][0],rr,iter(parts),4)['state']==st
        bad=proof[:1]+parts+proof[stride:];rejects('Head0:Offset:Block:0:CommitmentMismatch',lambda:c.verify(p,roots,iter(bad),4))
        changed=copy.deepcopy(ts);changed[0][0]=zs[0] if mode=='exact' else 1;alternate,st=c.out.prove(p.row,zs,changed,4);ar=c.out.roots(p.row,alternate);assert c.out.verify(p.row,ar,alternate,4)['state']==st and ar['scale']==roots['output']['scale'] and ar['output']==roots['output']['output']
        bad=proof[:-1]+[dict(output=alternate)];rejects('Output:Head0:Sign:Offset:CommitmentMismatch',lambda:c.verify(p,roots,iter(bad),4))
        changed_roots=dict(roots,output=ar);rejects('Head0:Offset:Output:CommitmentMismatch',lambda:c.verify(p,changed_roots,iter(bad),4))
        print('all global source families, O/Z joins, strict streams and valid same-total/same-code substitutions reject',mode,flush=True)


def edges():
    for mode in ('exact','block1024'):
        for d in (4,8):
            p=spec(mode,'static',1,1,1,2959);p=replace(p,row=replace(p.row,schema=replace(p.row.schema,scale=1,drop=0 if mode=='exact' else 62)));v=c.derive(p,d);inputs=[([1],[[0]])];proof,state=make(p,inputs,d);_,w,roots=oracle(p,inputs);out=c.verify(p,roots,iter(proof),d);assert out['state']==state and w['codes']==[0];account(p,out,d)
            child,st=c.prob.prove(v['probability'][0],[0],d);rr=c.prob.expected_roots(v['probability'][0],[0]);assert c.prob.verify(v['probability'][0],rr,child,d)['state']==st
            bad=proof.copy();bad[0]=dict(head=0,probability=child);changed=copy.deepcopy(roots);changed['probabilities'][0]=rr[:-1];rejects('Head0:Probability:Output:CommitmentMismatch',lambda:c.verify(p,changed,iter(bad),d))
            changed['output']['heads'][0][v['row']['roles'].index('probability')]=rr[-1]
            rejects('Output:Head0:'+('GlobalBase' if mode=='exact' else 'Denominator')+':WeightSum:CommitmentMismatch',lambda:c.verify(p,changed,iter(bad),d))
            print('zero offsets retain complete sources and a valid zero aggregate cannot replace positive normalization',mode,d,flush=True)


def full_inputs(p):
    s=p.row.schema;B=(s.length+1023)//1024;S=65535;R=16384
    for j in range(p.row.heads):
        bound=min(32768,(j+1)*256);ys=[(-bound,bound-1,-1,0,1)[k%5] for k in range(s.width)]
        def blocks(ys=ys):
            for b in range(B):yield [(S+y)*1024 if s.accumulation=='exact' else R+(y*256)//B+int(b<(y*256)%B) for y in ys]
        yield ([1024]*B,blocks())


def full_roots(p):
    s=p.row.schema;n=1<<(s.width-1).bit_length();offsets=[];probabilities=[];zs=[];totals=[];S=65535;R=16384;B=(s.length+1023)//1024
    for j,(weights,blocks) in enumerate(full_inputs(p)):
        summed=[0]*s.width;bound=[]
        for identity,row in zip(p.offsets[j],blocks):summed=[x+y for x,y in zip(summed,row)];bound.append(r.root(identity,[x>>(8*k)&255 for k in range(8) for x in row+[0]*(n-s.width)]))
        Z=sum(weights);zs.append(Z);totals.append([x-(S*Z if s.accumulation=='exact' else B*R) for x in summed]);offsets.append(bound);probabilities.append([r.root(identity,list(z.to_bytes(4,'little'))) for identity,z in zip(p.probabilities[j],weights)])
    return dict(offsets=offsets,probabilities=probabilities,output=output_check.oracle(p.row,zs,totals)[1])


def honest(mode='matrix'):
    digest=hashlib.sha256();done=0
    for d,reps in (((4,1),) if mode!='matrix' else ((4,1),(4,2),(8,1),(8,2))):
        for acc,policy in ((('exact','dynamic'),) if mode in ('maximum','full-wide-exact') else (('block1024','static'),) if mode in ('full-block','full-wide-block') else (('exact','dynamic'),('exact','static'),('block1024','dynamic'),('block1024','static'))):
            full=mode!='matrix';wide=mode.startswith('full-wide');p=spec(acc,policy,(1 if wide else 128) if full else 1,(16384 if wide else 128) if full else 1,1<<20 if full else 1025,2952+done,reps);states=[]
            inputs=None if full else small_inputs(p)
            if not full:inputs[0][1][-1][0]+=sum(inputs[0][0]) if acc=='exact' else 1
            roots=full_roots(p) if full else oracle(p,inputs)[2]
            print('global composition start',mode,done+1,d,reps,acc,policy,flush=True);out=c.verify(p,roots,offset_check.capture(c.prove(p,full_inputs(p) if full else iter(inputs),d),states),d);assert states==[out['state']];account(p,out,d);digest.update(out['state']);done+=1;print('global composition passed',mode,done,d,reps,acc,policy,flush=True)
    if mode=='matrix':assert done==16 and digest.hexdigest()=='0aa3ce0205e993437cb97d3bfe6508816e7a1d8cadb9b986fb627ceb2aab6c7c'
    print(json.dumps(dict(mode=mode,proofs=done,sha256=digest.hexdigest()),sort_keys=True),flush=True)


if __name__=='__main__':
    modes={'--corpus':corpus,'--controls':controls,'--boundaries':boundaries,'--edges':edges,'--honest':honest,'--maximum':lambda:honest('maximum'),'--full-block':lambda:honest('full-block'),'--full-wide-exact':lambda:honest('full-wide-exact'),'--full-wide-block':lambda:honest('full-wide-block')}
    selected=sys.argv[1:] or ['--corpus','--controls','--boundaries','--edges','--honest'];assert all(mode in modes for mode in selected)
    for mode in selected:modes[mode]()
