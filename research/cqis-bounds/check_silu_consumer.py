# /// script
# requires-python = ">=3.12"
# dependencies = ["numpy==2.3.4", "blake3==1.0.11", "python-flint==0.9.0"]
# ///
"""Complete canonical SiLU membership and actual signed-source controls."""
import copy
from collections import Counter
from dataclasses import replace
import hashlib
import json
from pathlib import Path
import random
import struct
import sys
import numpy as np
import silu_consumer as c

r=c.r


def rejects(reason,call):
    try: call()
    except ValueError as error: assert str(error)==reason,(reason,str(error))
    else: raise AssertionError('accepted '+reason)


def spec(f,e,count,identity=940,repetitions=1):
    rep=c.fn.Representation(c.fn.Function('silu_q',1,bytes([f,e])),0,b'')
    return c.Spec(rep,count,identity,61,67,repetitions)


def codec(value,decode=False):
    # Ephemeral synthetic test fixtures; decoding constructs data, never executable objects.
    if decode:
        if type(value) is dict and set(value)=={'tuple'}: return tuple(codec(x,True) for x in value['tuple'])
        if type(value) is dict and set(value)=={'bytes'}: return bytes.fromhex(value['bytes'])
    elif type(value) is tuple: return {'tuple':[codec(x) for x in value]}
    elif type(value) is bytes: return {'bytes':value.hex()}
    if type(value) is list: return [codec(x,decode) for x in value]
    if type(value) is dict: return {k:codec(v,decode) for k,v in value.items()}
    return value


def corpus():
    rng=random.Random(2679); digest=hashlib.sha256(); valid=overflow=0
    for f in range(31):
        for e in range(15):
            p=spec(f,e,1)
            if e>f:
                assert f<=13 and 32767>1<<f and 4*32767>3*32768
                rejects('Table:Overflow',lambda:c.metadata(p,4)); rejects('Overflow',lambda:c.fn.table.act.certify(c.fn.table.act.Parameters('silu',f,e),32767)); overflow+=1
            else:
                assert (32767<<e)<=(32767<<f) and (16384<<e)<=(16384<<f); c.metadata(p,4); valid+=1
    assert (valid,overflow)==(360,105)
    for first in range(-32768,32768,1024):
        xs=list(range(first,first+1024)); raw=[x%65536&255 for x in xs]+[x%65536>>8 for x in xs]
        signs=[int(x<0) for x in xs]+[x%65536>>8&127 for x in xs]; fields=c.lift(raw,signs,1024)
        packed=b''.join(bytes((raw[i],raw[1024+i])) for i in range(1024)); expected=np.frombuffer(packed,dtype='<i2').tolist()
        assert fields==[x%r.sc.P for x in expected] and expected==xs
        digest.update(b''.join(struct.pack('<I',x) for x in fields))
    for case in range(10000):
        f=rng.randrange(31); e=rng.randrange(min(14,f)+1); p=spec(f,e,1+case%9,case,1+case%2); v=c.metadata(p,(4,8)[case%2]); digest.update(v['raw'])
    other=c.fn.Representation(c.fn.Function('sigmoid_q',1,bytes([0,0])),0,b'')
    for bad in (replace(p,identity=1<<44),replace(p,source=c.metadata(p,4)['base']),replace(p,source=p.output),replace(p,repetitions=True),replace(p,count=0),
                replace(p,count=True),replace(p,source=True),replace(p,representation=None),replace(p,representation=other)):
        rejects('Spec',lambda:c.metadata(bad,4))
    rejects('Spec',lambda:c.metadata(p,True))
    rejects('Capacity',lambda:c.witness(replace(p,count=2049),None)); rejects('Table:Overflow',lambda:c.witness(spec(0,14,1),[0]))
    edge=c.metadata(spec(30,14,2048,(1<<44)-1,2),8); assert edge['base']+(1<<18)==(1<<63)+(1<<62)
    assert digest.hexdigest()=='06ead64872b0749f414678a17f3a4a9443e29002f1fe4d4b6d67a637131c3f3a'
    print(json.dumps(dict(seed=2679,signed_lifts=65536,metadata=10000,total=valid,overflow=overflow,sha256=digest.hexdigest()),sort_keys=True),flush=True)


def check_account(p,proof,out,d):
    a=c.metadata(p,d)['a']; reps=p.repetitions; f=lambda m:3*m*(m-1)//2+2*m
    assert out['account']==dict(identities=[((1<<(a+2))+255,reps)]*6+[((1<<a)+131071,reps)],
        lookup_reduction_numerator=6*reps*(f(a+2)+f(8)+3*(a+2))+reps*(f(a)+f(16)+3*a),range_reduction_numerator=86*a+70,denominator=r.sc.P**d)
    signed=out['children']; draws=[x['draws'] for x in signed]+[x['draws'] for child in signed for x in child['ranges']]
    assert out['draws']=={}
    for label in (r.zc.WEIGHT,r.zc.tr.CHALLENGE): assert sum(x.get(label,0) for x in draws)==36*a+28
    lookup=out['lookup']; counts=Counter(label for tag,label in lookup['events'] if tag==1)
    assert counts==Counter({r.lu.UNIT:0,r.lu.BETA:reps,r.lu.ALPHA:reps,r.lu.ft.GAMMA:reps*(a+16),
        r.lu.ft.FOLD:reps*(a+16),r.lu.ft.tr.CHALLENGE:reps*(a*(a-1)//2+120+a)})
    assert len(lookup['claims'])==3*reps and len(proof['lookup']['mus'])==reps and all(len(mu)==65536 for mu in proof['lookup']['mus'])


def controls(p,proof,expected,out,d):
    for name in ('input','output'):
        for index,label in ((0,'Raw'),(1,'Magnitude'),(2,'Sign')):
            bad=copy.deepcopy(proof); bad[name]['ranges'][index]['words'][0]+=1
            rejects(name.title()+':'+label+':CommitmentMismatch',lambda:c.verify(p,expected,bad,d))
    for column in range(2):
        bad=copy.deepcopy(proof); bad['lookup']['sources'][column][0]+=1
        rejects('Lookup:SourceJoin',lambda:c.verify(p,expected,bad,d))
    bad=copy.deepcopy(proof); bad['lookup']['sources'][0][0]=False
    rejects('Lookup:NoncanonicalField',lambda:c.verify(p,expected,bad,d))
    bad=copy.deepcopy(proof); bad['lookup']['rounds'].pop(); rejects('Lookup:ProofShape',lambda:c.verify(p,expected,bad,d))
    beta=out['lookup']['pairs'][0][0]; assert beta!=r.sc.scalar(0,d)
    bad=copy.deepcopy(proof); fs=bad['lookup']['rounds'][0]['leaf']['final']; fs[2]=r.sc.add(fs[2],beta); fs[3]=r.sc.add(fs[3],r.sc.scalar(-1,d))
    rejects('Lookup:OpeningMismatch',lambda:c.verify(p,expected,bad,d))
    for slot,reason in ((0,'CoefficientMismatch'),(1,'SelectorMismatch')):
        bad=copy.deepcopy(proof); bad['lookup']['rounds'][0]['leaf']['final'][slot]=r.sc.scalar(0,d)
        rejects('Lookup:'+reason,lambda:c.verify(p,expected,bad,d))
    bad=copy.deepcopy(proof); mu=bad['lookup']['mus'][0]; mu[0]=r.sc.add(mu[0],r.sc.scalar(1,d))
    rejects('Lookup:CommitmentMismatch',lambda:c.verify(p,expected,bad,d))
    print('SiLU original claims, compression-preserving finals and multiplicity controls passed',flush=True)


CASES=((4,1,0,0,[0]),(4,2,8,8,[-256,0,256]),(8,1,14,14,[-32768,-1,32767]),(8,2,30,14,[-32768,0,32767]))


def full(index,resume=False):
    d,reps,f,e,xs=CASES[index]; p=spec(f,e,len(xs),941+index,reps); print('full-table case start',index,d,reps,f,e,flush=True)
    v=c.derive(p,d); assert len(v['rows'])==65536 and len(v['lookup']['table'])==65536
    if (f,e)==(0,0): assert v['rows']==tuple((x,max(x,0)) for x in range(-32768,32768))
    if (f,e)==(30,14): assert all(y==0 for _,y in v['rows'])
    rng=random.Random(2680+index); table=np.array(v['rows'],dtype=np.int64); digest=hashlib.sha256()
    for _ in range(2500):
        x=rng.randrange(-32768,32768); assert c.witness(replace(p,count=1),[x])==[int(table[x+32768,1])]; digest.update(struct.pack('<hi',x,int(table[x+32768,1])))
    fixture=Path('/tmp/stele-silu-case-'+str(index)+'.json')
    if resume: proof,state=codec(json.loads(fixture.read_text()),True)
    else:
        proof,state=c.prove(p,xs,d); fixture.write_text(json.dumps(codec((proof,state)))); print('full-table produced',index,flush=True)
    expected=c.expected_roots(p,xs,c.witness(p,xs)); out=c.verify(p,expected,proof,d); assert out['state']==state
    check_account(p,proof,out,d); print(json.dumps(dict(case=index,state=state.hex(),gathers=2500,gather_sha256=digest.hexdigest()),sort_keys=True),flush=True)
    if index==0: controls(p,proof,expected,out,d)
    else:
        bad=copy.deepcopy(proof); bad['lookup']['sources'][0][-1]=1
        rejects('Lookup:SourceJoin',lambda:c.verify(p,expected,bad,d))
    if index==1: compose(p,xs,expected,d)


def compose(p,xs,expected,d):
    import gated_consumer as gate
    import row_code as row
    ys=c.witness(p,xs); up=[-32768,127,32767]; gp=gate.Spec(gate.g.Spec(3,30,p.representation.function.params[1]),950,73,p.output,79,p.repetitions)
    proof,state=gate.prove(gp,up,ys,d); roots=gate.roots(gp,proof); roots[1]=expected[1]
    assert gate.verify(gp,roots,proof,d)['state']==state
    false,_=gate.prove(gp,up,[ys[0]+1]+ys[1:],d); rejects('Right:Raw:CommitmentMismatch',lambda:gate.verify(gp,roots,false,d))
    rp=row.Spec(row.ds.am.row.Spec('gated',3,30+p.representation.function.params[1],'dynamic',0),951,gp.output,83,89,p.repetitions)
    converted,cs=row.prove(rp,[x*y for x,y in zip(up,ys)],d); rr=row.roots(rp,converted); rr[0]=roots[2]
    assert row.verify(rp,rr,converted,d)['state']==cs
    print('actual SiLU-to-gated-product-to-row composition passed',flush=True)


def corrupted():
    d=4; p=spec(0,0,1,945); v=c.derive(p,d); pairs=dict(input=c.ss.prove(v['input'],[0],d),output=c.ss.prove(v['output'],[1],d))
    fake=dict(v['lookup']); rows=list(fake['table']); assert rows[32768]==(0,0); rows[32768]=(0,1); fake['table']=tuple(rows)
    print('corrupted full-table proof start',flush=True); part,receipt=r.lu.prove(fake,[[0],[1]],d); pairs['lookup']=(part,receipt['state'])
    proof,_=c.assemble(p,pairs,d); Path('/tmp/stele-silu-corrupted.json').write_text(json.dumps(codec(proof)))
    rejects('Lookup:RoundSumMismatch',lambda:c.verify(p,c.expected_roots(p,[0],[1]),proof,d))
    print('one-entry-corrupted whole table rejected',flush=True)


def partial():
    p=spec(0,0,1,946); v=c.derive(p,4)
    pairs={name:c.ss.prove(v[name],[0],4) for name in ('input','output')}
    fake=dict(v['lookup'],table=((0,0),)); part,receipt=r.lu.prove(fake,[[0],[0]],4); pairs['lookup']=(part,receipt['state'])
    proof,_=c.assemble(p,pairs,4); expected=c.expected_roots(p,[0],[0])
    rejects('Lookup:TreeShape',lambda:c.verify(p,expected,proof,4))
    for key,value in (('table',fake['table']),('function_id',c.fn.function_id(p.representation.function))):
        rejects('ProofShape',lambda:c.verify(p,expected,dict(proof,**{key:value}),4))
    for slot,name in enumerate(('Input','Output')):
        wrong=list(expected); wrong[slot]=bytes(32)
        rejects(name+':Raw:CommitmentMismatch',lambda:c.verify(p,wrong,proof,4))
    rejects('Root',lambda:c.verify(p,[False,expected[1]],proof,4))
    print('partial table, supplied authority, and expected-root controls passed',flush=True)


if __name__=='__main__':
    modes={'--corpus':corpus,'--zero':lambda:full(0),'--nonlinear':lambda:full(1),'--field8':lambda:(full(2),full(3)),
           '--zero-resume':lambda:full(0,True),'--nonlinear-resume':lambda:full(1,True),'--corrupted':corrupted,'--partial':partial}
    if sys.argv[1:]:
        assert all(x in modes for x in sys.argv[1:])
        for mode in sys.argv[1:]: modes[mode]()
    else:
        corpus()
        for index in range(4): full(index)
        corrupted()
        partial()
