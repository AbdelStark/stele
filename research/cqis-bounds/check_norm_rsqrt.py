# /// script
# requires-python = ">=3.12"
# dependencies = ["numpy==2.3.4", "blake3==1.0.11", "python-flint==0.9.0"]
# ///
"""Full valid reciprocal tuples, padded-row exclusion and actual M/J claims."""
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
import norm_rsqrt as c

r=c.r


def rejects(reason,call):
    try:call()
    except ValueError as error:assert str(error)==reason,(reason,str(error))
    else:raise AssertionError('accepted '+reason)


def spec(identity=1500,repetitions=1):
    return c.Spec(c.norm.Spec(1,0,30,14,1,3),identity,101,109,repetitions)


def codec(value,decode=False):
    if decode:
        if type(value) is dict and set(value)=={'tuple'}:return tuple(codec(x,True) for x in value['tuple'])
        if type(value) is dict and set(value)=={'bytes'}:return bytes.fromhex(value['bytes'])
    elif type(value) is tuple:return {'tuple':[codec(x) for x in value]}
    elif type(value) is bytes:return {'bytes':value.hex()}
    if type(value) is list:return [codec(x,decode) for x in value]
    if type(value) is dict:return {k:codec(v,decode) for k,v in value.items()}
    return value


def corpus():
    full,valid=c.table();assert len(full)==65536 and len(valid)==49152 and full[49152:]==((0,0),)*16384
    values=np.array(valid,dtype=np.int64);m,j=values[:,0],values[:,1]
    assert np.array_equal(m,np.arange(16384,65536,dtype=np.int64)) and np.all((8192<=j)&(j<=16384))
    assert np.all(m*(2*j-1)**2<=1<<44) and np.all((1<<44)<m*(2*j+1)**2)
    raw=c.fn.table.encode_data(c.TABLE);assert c.fn.table.decode_data(c.TABLE,raw)==full
    offset=len(c.fn.table.DATA)+32+9
    for index,reason in ((4,'Entry'),(49152*8,'Padding')):
        changed=bytearray(raw);changed[offset+index]^=1;rejects(reason,lambda:c.fn.table.decode_data(c.TABLE,bytes(changed)))
    rng=random.Random(2706);digest=hashlib.sha256()
    for case in range(10000):
        x=rng.randrange(16384,65536);p=spec(case,1+case%2);actual=c.witness(p,x);assert actual==int(values[x-16384,1]);digest.update(struct.pack('<II',x,actual)+c.metadata(p,(4,8)[case%2])['raw'])
    p=spec((1<<50)-1,2);v=c.metadata(p,8);assert v['base']+4096==(1<<63)+(1<<62)
    for bad in (replace(p,identity=1<<50),replace(p,repetitions=True),replace(p,mantissa=p.output),replace(p,mantissa=v['base']),replace(p,schema=replace(p.schema,F=True))):
        rejects('Spec',lambda:c.metadata(bad,4))
    rejects('Spec',lambda:c.metadata(p,True))
    for x in (False,0,16383,65536):rejects('Mantissa',lambda:c.witness(p,x))
    plan=c.derive(p,4)['lookup'];assert len(plan['table'])==49152 and (0,0) not in plan['table']
    assert digest.hexdigest()=='16c228bea17668aeb196385fbf8b014792a95d3e61cbe93c7c83d99eeaef5e23'
    assert hashlib.sha256(raw).hexdigest()=='f0eaa630008fca89f36722acc8bdc7e737cfe2f6a6da396ddd66acc975a767a8'
    print(json.dumps(dict(valid_rows=49152,padded_rows=16384,gathers=10000,sha256=digest.hexdigest(),table_sha256=hashlib.sha256(raw).hexdigest()),sort_keys=True),flush=True)


def account(p,proof,out,d):
    reps=p.repetitions;lookup=out['lookup'];assert out['draws']=={} and out['account']==dict(identity_numerator=98304,identity_power=reps,reduction_numerator=392*reps,denominator=r.sc.P**d)
    counts=Counter(label for tag,label in lookup['events'] if tag==1)
    assert counts==Counter({r.lu.ALPHA:reps,r.lu.BETA:reps,r.lu.ft.GAMMA:16*reps,r.lu.ft.FOLD:16*reps,r.lu.ft.tr.CHALLENGE:120*reps})
    assert len(lookup['claims'])==3*reps and all(len(x)==49152 for x in proof['lookup']['mus'])


def controls(p,proof,expected,out,d):
    for column in (0,1):
        bad=copy.deepcopy(proof);bad['lookup']['sources'][column][0]+=1;rejects('Lookup:CommitmentMismatch',lambda:c.verify(p,expected,bad,d))
    bad=copy.deepcopy(proof);bad['lookup']['sources'][0][0]=False;rejects('Lookup:NoncanonicalField',lambda:c.verify(p,expected,bad,d))
    beta=out['lookup']['pairs'][0][0];assert beta!=r.sc.scalar(0,d)
    bad=copy.deepcopy(proof);final=bad['lookup']['rounds'][0]['leaf']['final'];final[2]=r.sc.add(final[2],beta);final[3]=r.sc.add(final[3],r.sc.scalar(-1,d))
    rejects('Lookup:OpeningMismatch',lambda:c.verify(p,expected,bad,d))
    # At scalar dimension0 the final composition rejects before constant consumers.
    for index,reason in ((0,'FinalEvaluationMismatch'),(1,'FinalEvaluationMismatch')):
        bad=copy.deepcopy(proof);bad['lookup']['rounds'][0]['leaf']['final'][index]=r.sc.scalar(0,d);rejects('Lookup:'+reason,lambda:c.verify(p,expected,bad,d))
    bad=copy.deepcopy(proof);bad['lookup']['mus'][0][0]=r.sc.add(bad['lookup']['mus'][0][0],r.sc.scalar(1,d));rejects('Lookup:CommitmentMismatch',lambda:c.verify(p,expected,bad,d))
    rejects('ProofShape',lambda:c.verify(p,expected,dict(proof,table=()),d));rejects('Root',lambda:c.verify(p,[False]*2,proof,d))
    print('actual reciprocal originals, compression-preserving finals and multiplicity controls passed',flush=True)


def constants(p,proof,expected,d):
    # Preserve the scalar final composition while isolating each constant consumer.
    half=r.sc.scalar((r.sc.P+1)//2,d)
    for index,reason in ((0,'CoefficientMismatch'),(1,'SelectorMismatch')):
        bad=copy.deepcopy(proof);final=bad['lookup']['rounds'][0]['leaf']['final'];final[index]=r.sc.scalar(2,d)
        final[2]=r.sc.mul(final[2],half);final[3]=r.sc.mul(final[3],half)
        rejects('Lookup:'+reason,lambda:c.verify(p,expected,bad,d))
    print('composition-preserving scalar coefficient and selector controls rejected by their own consumers',flush=True)


def saved_constants():
    proof,_=codec(json.loads(Path('/tmp/stele-norm-rsqrt-case-0.json').read_text()),True);p=spec(1501,1)
    constants(p,proof,c.expected_roots(p,16384,c.witness(p,16384)),4)


CASES=((4,1,16384),(4,2,65535),(8,1,21845),(8,2,32767))
STATES=(
    '33568ff079775615fa61024258195f498b9bf50ae08dc2911a8bf61959571dc1',
    '4152e51f6e11f298c0217dd633d1178b6b507589a9810ea346e8eb6bafb78ae4',
    'd1f24806428f480203bb5d6408cc63491992a9173b6a0aae4c7f466be9d85711',
    'd4c03e1324045cfedd364bd7c85501e04694a51d8ee0381bc09454d4acd1a21f',
)


def full(index,resume=False):
    d,reps,m=CASES[index];p=spec(1501+index,reps);fixture=Path('/tmp/stele-norm-rsqrt-case-'+str(index)+'.json')
    print('full table start',index,d,reps,m,flush=True)
    if resume:proof,state=codec(json.loads(fixture.read_text()),True)
    else:proof,state=c.prove(p,m,d);fixture.write_text(json.dumps(codec((proof,state))));print('full table produced',index,flush=True)
    expected=c.expected_roots(p,m,c.witness(p,m));out=c.verify(p,expected,proof,d);assert out['state']==state;account(p,proof,out,d)
    assert state.hex()==STATES[index]
    print(json.dumps(dict(case=index,state=state.hex()),sort_keys=True),flush=True)
    if index==0:controls(p,proof,expected,out,d);constants(p,proof,expected,d)
    if index==2:
        import norm_mantissa_product as mp
        pp=mp.Spec(p.schema,1510,p.mantissa,97,103,reps);product,ps=mp.prove(pp,m,3,d);roots=mp.expected_roots(pp,m,3,m*3);roots[0]=expected[0]
        assert mp.verify(pp,roots,product,d)['state']==ps
        false,_=mp.prove(pp,m+1,3,d);rejects('Mantissa:CommitmentMismatch',lambda:mp.verify(pp,roots,false,d))
        print('actual reciprocal M source composes with the bounded MD consumer',flush=True)


def alternate(kind,resume=False):
    p=spec(1511+int(kind=='padding'));v=c.derive(p,4);fake=dict(v['lookup']);m,j=16384,16385
    if kind=='corrupted':rows=list(fake['table']);rows[0]=(m,j);fake['table']=tuple(rows)
    else:m=j=0;fake['table']=fake['table']+((0,0),)
    fixture=Path('/tmp/stele-norm-rsqrt-'+kind+'.json');print('alternate full table start',kind,flush=True)
    if resume:proof=codec(json.loads(fixture.read_text()),True)
    else:
        part,out=r.lu.prove(fake,[[m],[j]],4);proof,_=c.assemble(p,(part,out['state']),4);fixture.write_text(json.dumps(codec(proof)))
    rejects('Lookup:RoundSumMismatch',lambda:c.verify(p,c.expected_roots(p,m,j),proof,4));print(kind,'table rejected',flush=True)


def partial():
    p=spec(1513);fake=dict(c.derive(p,4)['lookup'],table=((0,0),));part,out=r.lu.prove(fake,[[0],[0]],4);proof,_=c.assemble(p,(part,out['state']),4)
    rejects('Lookup:TreeShape',lambda:c.verify(p,c.expected_roots(p,0,0),proof,4))
    print('partial tuple table rejected by complete expected shape',flush=True)


if __name__=='__main__':
    modes={'--corpus':corpus,'--partial':partial,'--constants':saved_constants,'--corrupted':lambda:alternate('corrupted'),'--padding':lambda:alternate('padding')}
    modes.update({'--full'+str(i):lambda i=i:full(i) for i in range(4)})
    modes.update({'--resume'+str(i):lambda i=i:full(i,True) for i in range(4)})
    modes.update({'--resume-corrupted':lambda:alternate('corrupted',True),'--resume-padding':lambda:alternate('padding',True)})
    if sys.argv[1:]:
        assert all(mode in modes for mode in sys.argv[1:])
        for mode in sys.argv[1:]:modes[mode]()
    else:
        corpus();partial()
        for i in range(4):full(i)
        alternate('corrupted');alternate('padding')
