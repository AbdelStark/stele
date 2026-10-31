# /// script
# requires-python = ">=3.12"
# dependencies = ["numpy==2.3.4", "blake3==1.0.11", "python-flint==0.9.0"]
# ///
"""Draft RFC-0004 A3/A6: complete streamed global byte-column controls."""
import copy
from dataclasses import replace
import hashlib
import json
import random
import sys
from unittest.mock import patch
import numpy as np
import attention_global_offset as c

r=c.r


def rejects(reason,call):
    try:call()
    except ValueError as error:assert str(error)==reason,(reason,str(error))
    else:raise AssertionError('accepted '+reason)


def spec(mode='exact',length=1025,width=3,identity=2901,repetitions=1):
    s=c.bounds.Spec(length,width,0,0,14,'static',65535,mode,0 if mode=='exact' else 26)
    return c.Spec(s,identity,tuple(33001+j for j in range((length+1023)//1024)),35001,repetitions)


def oracle(p,blocks):
    s=p.schema;B=(s.length+1023)//1024;n=1<<(s.width-1).bit_length();Q=1<<s.exponent;S=s.scale*min(127,(65536+s.scale)//(2*s.scale)) if s.value_mode=='static' else 127*259
    R=(1024*Q*S+(1<<s.drop)//2)//(1<<s.drop)
    caps=[2*min(1024,s.length-1024*b)*Q*S if s.accumulation=='exact' else 2*R for b in range(B)]
    xs=np.array(blocks,dtype=object);assert xs.shape==(B,s.width) and all(0<=x<=cap for row,cap in zip(xs,caps) for x in row)
    output=[int(x) for x in xs.sum(axis=0)];columns=np.zeros((8,n),dtype=object)
    for k in range(8):columns[k,:s.width]=((xs>>(8*k))&255).sum(axis=0)
    carries=[];incoming=np.zeros(n,dtype=object)
    for k in range(8):incoming=(columns[k]+incoming)//256;carries.extend(map(int,incoming))
    words=lambda row:[int(x)>>(8*k)&255 for k in range(8) for x in list(row)+[0]*(n-s.width)]
    expected=[r.root(i,words(row)) for i,row in zip(p.sources,blocks)]+[r.root(p.output,words(output))]
    return output,[carries[:4*n],carries[4*n:]],expected,[int(x) for x in columns.flat],caps


def capture(generator,states):
    states.append((yield from generator))


def make(p,blocks,d):
    states=[];proof=list(capture(c.prove(p,iter(blocks),d),states));assert len(states)==1;return proof,states[0]


def account(p,out,d):
    v=c.derive(p,d);a=v['a'];B=v['B'];parts=[r.derive(c.range_spec(p,v,j),d) for j in range(B+3)];bs=[x[1] for x in parts];dims=[x[0]+x[1]+1 for x in parts];F=lambda m:3*m*(m-1)//2+2*m
    assert out['account']==dict(identities=[((1<<m)+255,p.repetitions) for m in dims],lookup_reduction_numerator=p.repetitions*sum(F(m)+F(8)+3*m for m in dims),range_reduction_numerator=9*a*(B+3)+36+7*sum(bs),projection_identity_numerator=a+3,sum_reduction_numerator=v['bb'],denominator=r.sc.P**d)
    draws=4*a*(B+3)+16+3*sum(bs);sc_label=r.zc.tr.CHALLENGE;zw_label=r.zc.WEIGHT
    assert out['child_draws']=={sc_label:draws,zw_label:draws} and out['draws']=={sc_label:a+3+v['bb']}
    assert out['sc']['numerator']==v['bb'] and [x[0] for x in out['claims']]==[v['base']+(1<<19)+1]


def corpus():
    rng=random.Random(2754);digest=hashlib.sha256();cells=0
    for case in range(10000):
        p=spec('exact' if case%2 else 'block1024',rng.choice((1,1024,1025,2049)),(1,3,5)[case%3],case);v=c.derive(p,4)
        blocks=[[rng.choice((0,cap,rng.randrange(cap+1))) for _ in range(p.schema.width)] for cap in v['caps']]
        output,carries,roots,columns,caps=oracle(p,blocks);assert caps==v['caps'];assert c.final_values(p,v,columns)==(output,carries)
        assert all(x<=v['carry_caps'][k] for k in range(8) for x in carries[k//4][(k%4)*v['n']:(k%4+1)*v['n']]) and not any(carries[-1][-v['n']:])
        digest.update(b''.join(roots));cells+=v['B']*p.schema.width
    for mode in ('exact','block1024'):
        p=spec(mode,1048576,1,20000);v=c.derive(p,4);blocks=[[cap-(b%257)] for b,cap in enumerate(v['caps'])];out,carry,roots,cols,_=oracle(p,blocks);assert c.final_values(p,v,cols)==(out,carry);digest.update(b''.join(roots))
        p=spec(mode,1,16384,20001);v=c.derive(p,4);blocks=[[i%257 for i in range(16384)]];out,carry,roots,cols,_=oracle(p,blocks);assert c.final_values(p,v,cols)==(out,carry);digest.update(b''.join(roots))
    assert digest.hexdigest()=='372bdec714302fa688f851576060ab956eb050cc6522af6f86c7ac63998efb9c'
    print(json.dumps(dict(seed=2754,cases=10000,capacity_cases=4,cells=cells,sha256=digest.hexdigest()),sort_keys=True),flush=True)


def projection():
    rng=random.Random(2755)
    for case in range(10000):
        d=4 if case%2 else 8;n=1<<(case%7);words=[rng.randint(-262143,262143) for _ in range(n)];weights=[[rng.randrange(r.sc.P) for _ in range(d)] for _ in range(n)]
        matrix=c.nmod_mat(n,d,[x for row in weights for x in row],r.sc.P)
        expected=tuple(sum(x*row[j] for x,row in zip(words,weights))%r.sc.P for j in range(d));assert c.project(words,matrix,d)==expected
    print('10000 exact signed coefficient projections match independent integer dot products',flush=True)


def boundaries():
    projection()
    for mode in ('exact','block1024'):
        for d in (4,8):
            p=spec(mode,1048576,16384,(1<<42)-1,2);v=c.derive(p,d);assert v['B']==1024 and v['n']==16384 and v['bb']==10 and v['carry_caps'][-1]==0
            for j in (0,1023,1024,1025,1026):r.derive(c.range_spec(p,v,j),d)
            roots=[hashlib.sha256(str(j).encode()).digest() for j in range(1025)];internal=roots+[bytes(32)]*2;states=internal.copy();t=c.transcript(v,roots,internal,states,d);assert not t.draws
            for values,k in ((roots,500),(internal,1026),(states,1024)):
                prior=values[k];values[k]=bytes([prior[0]^1])+prior[1:];assert c.transcript(v,roots,internal,states,d).state!=t.state;values[k]=prior
            for other in (replace(p,identity=True),replace(p,identity=1<<42),replace(p,sources=p.sources[:-1]),replace(p,output=p.sources[0]),replace(p,output=v['base']),replace(p,repetitions=True)):
                rejects('Spec',lambda:c.derive(other,d))
    print('full configured geometry, static carry bounds, namespaces and context passed',flush=True)


def controls():
    for mode in ('exact','block1024'):
        p=spec(mode);v=c.derive(p,4);blocks=[[1000,0,700],[1000,1,900]];proof,state=make(p,blocks,4);expected=oracle(p,blocks)[2];out=c.verify(p,expected,iter(proof),4);assert out['state']==state;account(p,out,4)
        for j in range(v['B']+1):
            roots=expected.copy();roots[j]=bytes(32);rejects(('Block:'+str(j) if j<v['B'] else 'Output')+':CommitmentMismatch',lambda:c.verify(p,roots,iter(proof),4))
        for bad in (proof[:-1],proof+[proof[-1]],proof[1:],list(reversed(proof))):rejects('StreamShape',lambda:c.verify(p,expected,iter(bad),4))
        for value in (True,-1,1):
            bad=copy.deepcopy(proof);bad[0]['block']=value;rejects('StreamShape',lambda:c.verify(p,expected,iter(bad),4))
        bad=copy.deepcopy(proof);bad[0]['range']['words'][p.schema.width]=1;rejects('Block:0:Range:SourceCopy:ClaimMismatch',lambda:c.verify(p,expected,iter(bad),4))
        changed=copy.deepcopy(blocks);changed[0][0]+=1;changed[1][0]-=1;alternate,st=make(p,changed,4);rr=oracle(p,changed)[2];assert rr[-1]==expected[-1] and c.verify(p,rr,iter(alternate),4)['state']==st
        rejects('Block:0:CommitmentMismatch',lambda:c.verify(p,expected,iter(alternate),4))
        original=c.replay
        for operation,reason in (('change','Block:0:CommitmentMismatch'),('short','SpoolShape'),('extra','SpoolShape')):
            def altered(p,v,roots,spool,weights,d):
                spool.seek(0,2);size=spool.tell()
                if operation=='short':spool.truncate(size-1)
                elif operation=='extra':spool.write(b'\x00')
                else:spool.seek(0);value=spool.read(1);spool.seek(0);spool.write(bytes([value[0]^1]))
                return original(p,v,roots,spool,weights,d)
            with patch.object(c,'replay',altered):rejects(reason,lambda:c.verify(p,expected,iter(proof),4))
        original_prove=r.sc.prove
        def forged(t,i,tables):
            if i['id']==65536*p.identity+8192:
                tables=copy.deepcopy(tables);tables[0][0]=r.sc.add(tables[0][0],r.sc.scalar(1,4));tables[0][1]=r.sc.add(tables[0][1],r.sc.scalar(-1,4))
                before=copy.deepcopy(t);result,point=original_prove(t,i,tables);assert r.sc.verify_reduction(before,i,result)['point']==point;return result,point
            return original_prove(t,i,tables)
        with patch.object(r.sc,'prove',forged):bad,_=make(p,blocks,4)
        rejects('Sum:ClaimMismatch',lambda:c.verify(p,expected,iter(bad),4))
        # Fresh valid ranges retain nonzero static caps even for zero sources.
        zero=[[0]*3 for _ in range(v['B'])];original_final=c.final_values
        def false_carry(p,v,columns):
            output,carry=original_final(p,v,columns);carry[0][0]=1;return output,carry
        with patch.object(c,'final_values',false_carry):bad,_=make(p,zero,4)
        rejects('Sum:RoundSumMismatch',lambda:c.verify(p,oracle(p,zero)[2],iter(bad),4))
        if mode=='exact':
            high=[[r.sc.P+100,0,0],[200,0,0]];expected_alias=oracle(p,high)[2];false_words=[300,0,0];n=v['n'];expected_alias[-1]=r.root(p.output,[x>>(8*k)&255 for k in range(8) for x in false_words+[0]*(n-3)])
            def false_output(p,v,columns):
                output,carry=original_final(p,v,columns);output[0]-=r.sc.P;return output,carry
            with patch.object(c,'final_values',false_output):bad,_=make(p,high,4)
            rejects('Sum:RoundSumMismatch',lambda:c.verify(p,expected_alias,iter(bad),4))
        print('all streamed roots/order/padding, valid replacements, spool attacks, forged originals and fresh false ranges reject',mode,flush=True)


def honest(mode='matrix'):
    digest=hashlib.sha256();done=0
    for d,reps in (((4,1),) if mode!='matrix' else ((4,1),(4,2),(8,1),(8,2))):
        for acc in (('exact',) if mode=='maximum' else ('block1024',) if mode=='full-block' else ('exact','block1024')):
            for L,w in (((1048576,16384),) if mode!='matrix' else ((1,1),(2049,3))):
                p=spec(acc,L,w,2902+done,reps);v=c.derive(p,d)
                def blocks():
                    for b,cap in enumerate(v['caps']):yield [cap if j%5==0 else (b*31+j*17)%(cap+1) for j in range(w)]
                # Expected roots are independently built before starting either proof stream.
                output=[0]*w;roots=[]
                for identity,row in zip(p.sources,blocks()):
                    output=[x+y for x,y in zip(output,row)];roots.append(r.root(identity,[x>>(8*k)&255 for k in range(8) for x in row+[0]*(v['n']-w)]))
                roots.append(r.root(p.output,[x>>(8*k)&255 for k in range(8) for x in output+[0]*(v['n']-w)]));states=[]
                print('global offset start',mode,done+1,d,reps,acc,L,w,flush=True)
                out=c.verify(p,roots,capture(c.prove(p,blocks(),d),states),d);assert states==[out['state']];account(p,out,d);digest.update(out['state']);done+=1
                print('global offset passed',mode,done,d,reps,acc,L,w,flush=True)
    print(json.dumps(dict(mode=mode,proofs=done,sha256=digest.hexdigest()),sort_keys=True),flush=True)


if __name__=='__main__':
    modes={'--corpus':corpus,'--controls':controls,'--boundaries':boundaries,'--honest':honest,'--maximum':lambda:honest('maximum'),'--full-block':lambda:honest('full-block')}
    selected=sys.argv[1:] or ['--corpus','--controls','--boundaries','--honest'];assert all(mode in modes for mode in selected)
    for mode in selected:modes[mode]()
