# /// script
# requires-python = ">=3.12"
# dependencies = ["numpy==2.3.4", "blake3==1.0.11"]
# ///
"""RFC-0021 §2.1 / Draft A3: complete exponential membership and arithmetic."""
import copy
from collections import Counter
from dataclasses import replace
from fractions import Fraction
from functools import lru_cache
import hashlib
import json
import random
import sys
import numpy as np
import attention_exp as c
from check_exp import reference

r=c.r


def rejects(reason,call):
    try:call()
    except ValueError as error:assert str(error)==reason,(reason,str(error))
    else:raise AssertionError('accepted '+reason)


def spec(count=3,mode=2,B=7,F=6,E=8,k=3,S=127,identity=3700,repetitions=1):
    schema=c.index.attained.maximum.Spec(1<<20,S,B,F);ids=tuple(31*j for j in range(count));row=c.index.attained.Spec(schema,ids[max(0,count-2)],ids,0,0,1<<20,3600,1201,1213,1217,1223,repetitions)
    f=c.fn.Function('exp_q/product' if mode==1 else 'exp_q/nearest',1,bytes([B,F,E])+(bytes([k]) if mode==1 else b''));rep=c.fn.Representation(f,mode,bytes([k]) if mode==2 else b'')
    return c.Spec(row,rep,identity,1249)


@lru_cache(maxsize=65536)
def rounded(u,F,E):
    return reference(Fraction(u,1<<F),1<<E)


def oracle(p,us):
    B,F,E=p.representation.function.params[:3];mode=p.representation.mode;n=1<<(len(us)-1).bit_length();mask=np.array(c.index.attained.derive(p.row,4)['allowed'],dtype=np.int64);U=np.array(us,dtype=np.int64)
    out=dict(difference=us.copy());direct=np.array([rounded(u,F,E) for u in us],dtype=np.int64)*mask
    if mode==0:out['output']=direct.tolist();return out
    k=p.representation.function.params[3] if mode==1 else p.representation.params[0];H,L=np.divmod(U,1<<k)
    HV=np.array([rounded(int(h)<<k,F,E) for h in H],dtype=np.int64)*mask;LV=np.array([rounded(int(l),F,E) for l in L],dtype=np.int64)*mask;Q,R=np.divmod(HV*LV,1<<E)
    out.update(high_index=H.tolist(),low_index=L.tolist(),high_value=HV.tolist(),low_value=LV.tolist(),remainder=R.tolist(),output=(Q if mode==1 else direct).tolist())
    if mode==2:out.update(quotient=Q.tolist(),correction=(direct-Q+mask).tolist())
    assert all(len(values)<=n for values in out.values());return out


def corpus():
    rng=random.Random(2732);digest=hashlib.sha256();corrections=set();widths=set();modes=set()
    configs=((0,7,0,0,1),(1,7,6,7,1),(2,7,6,8,3),(0,15,0,14,7),(1,31,0,14,16),(2,14,10,12,7),(1,15,30,8,15),(2,15,30,14,15),(0,7,30,7,1),(1,7,0,0,7))
    for group,(mode,B,F,E,k) in enumerate(configs):
        for offset in range(1000):
            case=group*1000+offset;count=(1,3,5,16,17)[case%5];S=(0,127,(1<<31)-1)[case%3];p=spec(count,mode,B,F,E,k,S,50000+case,1+case%2);v=c.derive(p,4);us=[rng.randint(0,v['cap']) if bit else 0 for bit in v['allowed']]
            if case%11==0:us[v['allowed'].index(True)]=v['cap']
            expected=oracle(p,us);assert c.witness(p,us)==expected;roots=c.expected_roots(p,us);assert len(roots)==2
            if mode==2:corrections.update(x-int(bit) for x,bit in zip(expected['correction'],v['allowed']))
            widths.add(r.derive(v['ranges']['output'],4)[1]);modes.add(mode);digest.update(v['raw']+json.dumps(expected,sort_keys=True,separators=(',',':')).encode()+b''.join(roots))
        for name,plan in v['lookups'].items():
            desc=c.fn.dependencies(p.representation)[list(v['lookups']).index(name)];assert len(plan['table'])==c.fn.table.shape(desc)[0]
            if name!='correction':assert (0,0) not in plan['table']
    assert modes=={0,1,2} and widths=={0,1} and {-1,0,1}<=corrections,(modes,widths,corrections)
    p=replace(spec(16384,1,31,0,14,16,(1<<31)-1),identity=(1<<42)-1);v=c.derive(p,8);assert v['base']+(1<<20)==(1<<63)+(1<<62)
    spans=sorted([(r.derive(child,8)[4],64) for child in v['ranges'].values()]+[(c.index.derive(v['index'],8)['base'],4096)])
    assert all(v['base']+40<lo and lo+size<=v['base']+(1<<20) for lo,size in spans) and all(lo+size<=nxt for (lo,size),(nxt,_) in zip(spans,spans[1:]))
    for bad in (replace(p,identity=1<<42),replace(p,output=p.row.source),replace(p,output=v['base']),replace(p,identity=p.row.identity//64),replace(p,row=replace(p.row,repetitions=True))):rejects('Spec',lambda:c.derive(bad,4))
    rejects('Capacity',lambda:c.derive(spec(16385),4));rejects('Spec',lambda:c.derive(p,True));rejects('FunctionScope',lambda:c.derive(replace(p,row=replace(p.row,schema=replace(p.row.schema,fraction=1))),4))
    for us in ([False]*3,[-1,0,0],[0,0,1],[129,0,0],[0],(0,0,0)):rejects('Input',lambda:c.witness(spec(),us))
    print(json.dumps(dict(seed=2732,cases=10000,corrections=sorted(corrections),sha256=digest.hexdigest()),sort_keys=True),flush=True)


def account(p,proof,out,d):
    v=c.derive(p,d);a=v['a'];mode=p.representation.mode;f=lambda m:3*m*(m-1)//2+2*m;dims=[];states=[];bp=r.derive(v['ranges']['output'],d)[1]
    if mode:
        iv=c.index.derive(v['index'],d);bs=iv['bu']+iv['bh']+iv['bl'];dims=[a+iv[key]+1 for key in ('bu','bh','bl')]+[a+3];states=[out['index']]+out['index']['children']
    dims += [r.derive(child,d)[0]+r.derive(child,d)[1]+1 for child in v['ranges'].values()];states += out['ranges']+[out]
    tables=[len(plan['table']) for plan in v['lookups'].values()];identities=[((1<<m)+255,p.row.repetitions) for m in dims]+[(v['n']+2*T-1,p.row.repetitions) for T in tables]
    reduction=p.row.repetitions*(sum(f(m)+f(8)+3*m for m in dims)+sum(f(a)+f((T-1).bit_length())+3*a for T in tables))
    if mode==0:bu=r.derive(v['ranges']['difference'],d)[1];total=18*a+7*(bu+bp);draws=8*a+3*(bu+bp)
    else:
        br=r.derive(v['ranges']['remainder'],d)[1];total=(77 if mode==1 else 97)*a+22+7*bs+(21 if mode==1 else 28)*bp+7*br;draws=(34 if mode==1 else 43)*a+10+3*bs+(9 if mode==1 else 12)*bp+3*br
    assert out['account']==dict(identities=identities,lookup_reduction_numerator=reduction,range_reduction_numerator=total,denominator=r.sc.P**d)
    assert len(out['claims'])==4*mode and sum(item['numerator'] for item in out['sc'])==(0,3*a,5*a)[mode]
    assert out['draws']==({} if mode==0 else {r.zc.WEIGHT:mode*a,r.zc.tr.CHALLENGE:mode*a})
    for label in (r.zc.WEIGHT,r.zc.tr.CHALLENGE):assert sum(x['draws'].get(label,0) for x in states)==draws
    for T,lookup in zip(tables,out['lookups']):
        t=(T-1).bit_length();reps=p.row.repetitions;counts=Counter(label for tag,label in lookup['events'] if tag==1)
        assert counts==Counter({r.lu.UNIT:0,r.lu.BETA:reps,r.lu.ALPHA:reps,r.lu.ft.GAMMA:reps*(a+t),r.lu.ft.FOLD:reps*(a+t),r.lu.ft.tr.CHALLENGE:reps*(a*(a-1)//2+t*(t-1)//2+a)})


def honest(full=None):
    digest=hashlib.sha256();done=0;cases=((1,0,7,0,0,1),(3,1,7,6,7,3),(16,2,7,6,8,3),(65,1,31,0,14,16))
    if full is not None:cases=((16384,full,31 if full==1 else 15,0,14,16 if full==1 else 15),)
    for d,reps in (((4,1),) if full is not None else ((4,1),(4,2),(8,1),(8,2))):
        for size,mode,B,F,E,k in cases:
            p=spec(size,mode,B,F,E,k,(1<<31)-1,3710+done,reps);v=c.derive(p,d);vals=(0,v['cap'],min(9,v['cap']),min(17,v['cap']));us=[vals[j%4] if bit else 0 for j,bit in enumerate(v['allowed'])]
            print('honest start',done+1,d,reps,size,mode,flush=True);proof,state=c.prove(p,us,d);out=c.verify(p,c.expected_roots(p,us),proof,d);assert out['state']==state;account(p,proof,out,d);digest.update(state);done+=1;print('honest passed',done,d,reps,size,mode,flush=True)
    print(json.dumps(dict(full=full,proofs=done,sha256=digest.hexdigest()),sort_keys=True),flush=True)


def controls():
    p=spec();d=4;us=[0,9,0];v=c.derive(p,d);pairs=c.prepare(p,us,d);proof,state=c.assemble(p,pairs,d);roots=c.expected_roots(p,us);out=c.verify(p,roots,proof,d);assert out['state']==state;account(p,proof,out,d)
    for j,name in enumerate(('Index:Difference','Output')):
        bad=roots.copy();bad[j]=bytes(32);rejects(name+':CommitmentMismatch',lambda:c.verify(p,bad,proof,d))
    for name in v['aux']:
        bad=copy.deepcopy(proof);bad['roots'][name]=bytes(32);prefix='Index:'+name.removesuffix('_index').title() if name.endswith('_index') else name.title();rejects(prefix+':CommitmentMismatch',lambda:c.verify(p,roots,bad,d))
    for name,receipt in zip(v['lookups'],out['lookups']):
        for column in range(2):
            bad=copy.deepcopy(proof);bad['lookups'][name]['sources'][column][0]+=1;rejects(name.title()+'Lookup:SourceJoin',lambda:c.verify(p,roots,bad,d))
        bad=copy.deepcopy(proof);fs=bad['lookups'][name]['rounds'][0]['leaf']['final'];fs[2]=r.sc.add(fs[2],receipt['pairs'][0][0]);fs[3]=r.sc.add(fs[3],r.sc.scalar(-1,d));rejects(name.title()+'Lookup:OpeningMismatch',lambda:c.verify(p,roots,bad,d))
        bad=copy.deepcopy(proof);mu=bad['lookups'][name]['mus'][0];mu[0]=r.sc.add(mu[0],r.sc.scalar(1,d));rejects(name.title()+'Lookup:CommitmentMismatch',lambda:c.verify(p,roots,bad,d))
    for key in ('receipt','certificate','mask','table','representation'):rejects('ProofShape',lambda:c.verify(p,roots,dict(proof,**{key:{}}),d))
    for changed in (replace(p,row=replace(p.row,window=32)),replace(p,representation=replace(p.representation,function=replace(p.representation.function,params=bytes([7,6,7]))))):
        rejects('Index:Index:ClaimMismatch',lambda:c.verify(changed,roots,proof,d))
    bad=copy.deepcopy(proof);bad['zero'][0]['rounds'][0][0]=(False,0,0,0);rejects('NoncanonicalField',lambda:c.verify(p,roots,bad,d))
    print('all external/auxiliary roots, lookup sources/finals/multiplicities and authority/metadata controls passed',flush=True)


def originals():
    p=spec(identity=3740);d=4;us=[1,9,0];pairs=c.prepare(p,us,d);proof,_=c.assemble(p,pairs,d);roots=c.expected_roots(p,us);c.verify(p,roots,proof,d)
    for j in range(2):
        for slot in range(4):
            bad=copy.deepcopy(proof);fs=bad['zero'][j]['final'];one=r.sc.scalar(1,d);old=[x[0] for x in fs];fs[slot][0]=r.sc.add(fs[slot][0],one)
            if j==0:
                companion=2 if slot==3 else 3;delta=old[1] if slot==0 else old[0] if slot==1 else r.sc.scalar(-(1<<8),d) if slot==2 else r.sc.scalar(pow(-(1<<8),-1,r.sc.P),d)
            else:companion=0 if slot==3 else 3;delta=r.sc.scalar(-1 if slot==2 else 1,d)
            fs[companion][0]=r.sc.add(fs[companion][0],delta);rejects(('Product' if j==0 else 'Correction')+':ClaimMismatch',lambda:c.verify(p,roots,bad,d))
    print('all eight parent original claims reject equation-preserving substitutions',flush=True)


def boundaries():
    p=spec(mode=1,identity=3750);d=4;us=[0,9,0];v=c.derive(p,d);w=c.witness(p,us);pairs=c.prepare(p,us,d)
    for name,pos,value in (('output',2,1),('high_value',2,1),('low_value',3,1)):
        child=v['ranges'][name];values=w[name]+([0] if pos==3 else []);values[pos]=value;caps=list(child.caps)+([0] if pos==3 else []);caps[pos]=value;changed=r.assemble(child,*r.witness(replace(child,caps=tuple(caps)),values),d)
        badpairs=dict(pairs,ranges=dict(pairs['ranges'],**{name:changed}));bad,_=c.assemble(p,badpairs,d);rejects(name.title()+':CapRelation:RoundSumMismatch',lambda:c.verify(p,c.roots(p,bad),bad,d))
    child=v['ranges']['remainder'];values=w['remainder'].copy();values[0]=1<<8;caps=list(child.caps);caps[0]=1<<8;badpairs=dict(pairs,ranges=dict(pairs['ranges'],output=r.prove(v['ranges']['output'],[255,w['output'][1],0],d),remainder=r.assemble(child,*r.witness(replace(child,caps=tuple(caps)),values),d)))
    bad,_=c.assemble(p,badpairs,d);rejects('Remainder:CapRelation:RoundSumMismatch',lambda:c.verify(p,c.roots(p,bad),bad,d))
    p=spec(identity=3751);v=c.derive(p,d);pairs=c.prepare(p,us,d);w=c.witness(p,us);values=w['correction'].copy();values[1]=(values[1]+1)%4;changed=r.prove(v['ranges']['correction'],values,d);bad,_=c.assemble(p,dict(pairs,ranges=dict(pairs['ranges'],correction=changed)),d);rejects('CorrectionLookup:SourceJoin',lambda:c.verify(p,c.roots(p,bad),bad,d))
    print('strict remainder, masked/padded outputs and correction-source substitutions reject',flush=True)


def tables():
    for attack in ('corrupted','padded','partial'):
        p=spec(1,1,7,0,0,7,127,3760);d=4;v=c.derive(p,d);pairs=c.prepare(p,[0],d);plan=dict(v['lookups']['high']);rows=list(plan['table']);ys=[0] if attack!='partial' else [1]
        if attack=='corrupted':rows[0]=(0,0)
        elif attack=='padded':rows.append((0,0))
        else:rows=rows[:1]
        plan['table']=tuple(rows);changed=r.lu.prove(plan,[[0],ys],d);newranges=dict(pairs['ranges'],high_value=r.prove(v['ranges']['high_value'],ys,d),output=r.prove(v['ranges']['output'],ys,d));bad,_=c.assemble(p,dict(pairs,ranges=newranges,lookups=dict(pairs['lookups'],high=(changed[0],changed[1]['state']))),d)
        rejects('HighLookup:'+('TreeShape' if attack in ('padded','partial') else 'RoundSumMismatch'),lambda:c.verify(p,c.roots(p,bad),bad,d))
    print('genuine corrupted full table, invalid padding tuple and partial-table proofs reject',flush=True)


def composition():
    p=spec(identity=3770);d=4;xs=[0,-9,100];source,state=c.index.attained.prove(p.row,xs,d);expected=c.index.attained.expected_roots(p.row,xs);assert c.index.attained.verify(p.row,expected,source,d)['state']==state
    us=c.index.attained.witness(p.row,xs)['difference'];assert us==[0,9,0];proof,state=c.prove(p,us,d);roots=c.roots(p,proof);assert roots[0]==expected[3];assert c.verify(p,[expected[3],roots[1]],proof,d)['state']==state
    alternate,other=c.index.attained.prove(p.row,[0,-8,100],d);wrong=c.index.attained.expected_roots(p.row,[0,-8,100]);assert c.index.attained.verify(p.row,wrong,alternate,d)['state']==other
    rejects('Index:Difference:CommitmentMismatch',lambda:c.verify(p,[wrong[3],roots[1]],proof,d))
    print('actual maximum difference composes through indices and canonical exponentials; alternate valid source rejects',flush=True)


if __name__=='__main__':
    modes={'--corpus':corpus,'--controls':controls,'--originals':originals,'--boundaries':boundaries,'--tables':tables,'--composition':composition,'--honest':honest,'--maximum':lambda:honest(1),'--full-direct':lambda:honest(0),'--full-corrected':lambda:honest(2)}
    if sys.argv[1:]:
        assert all(mode in modes for mode in sys.argv[1:])
        for mode in sys.argv[1:]:modes[mode]()
    else:
        for mode in list(modes)[:7]:modes[mode]()
