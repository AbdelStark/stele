# /// script
# requires-python = ">=3.12"
# dependencies = ["numpy==2.3.4", "blake3==1.0.11", "python-flint==0.9.0"]
# ///
"""Complete RFC-0022 RMSNorm arithmetic, source joins and actual full lookup."""
import copy
from dataclasses import replace
import hashlib
import json
import random
import sys
import numpy as np
import norm_composition as c
from check_rmsnorm import reference
from check_norm_bounds import numpy_output
from check_norm_configured_output import account as configured_account
from check_norm_statistic_full import account as statistic_account
from check_norm_numerator import account as numerator_account
from check_norm_mantissa_product import account as mantissa_account
from check_norm_sum import account as sum_account
from check_norm_remainder import account as remainder_account
from check_norm_rsqrt import account as reciprocal_account

r=c.r


def rejects(reason,call):
    try:call()
    except ValueError as error:assert str(error)==reason,(reason,str(error))
    else:raise AssertionError('accepted '+reason)


def spec(count=3,identity=2800,repetitions=1):
    return c.Spec(c.norm.Spec(count,8,14,8,1,100000),identity,*range(701,720),repetitions)


def corpus():
    rng=random.Random(2724);digest=hashlib.sha256();accepted=rejected=0;exponents=set();branches=set();widths=set()
    for case in range(10000):
        count=1+case%31;en,ed=((1,100000),(1,(1<<32)-1),((1<<32)-1,1),((1<<32)-1,(1<<32)-2))[case%4]
        schema=c.norm.Spec(count,rng.randrange(31),rng.randrange(31),rng.randrange(15),en,ed);xs=[rng.randrange(-32768,32768) for _ in range(count)];hs=[rng.randrange(-32768,32768) for _ in xs]
        if case%5==0:hs=[0]*count
        if case==0:schema=c.norm.Spec(1,0,0,14,1,(1<<32)-1);xs=[0];hs=[32767]
        if case==1:schema=c.norm.Spec(1,0,30,0,(1<<32)-1,1);xs=[-32768];hs=[32767]
        if case==2:schema=c.norm.Spec(4,0,0,14,1,(1<<32)-1);xs=[-1,0,0,0];hs=[1]*4
        p=replace(spec(schema.d,case,1+case%2),schema=schema);v=c.derive(p,4);params=c.canonical.Parameters(schema.d,schema.F,schema.G,schema.E,en=schema.en,ed=schema.ed)
        a,m,j,ys,ratio=reference(params,xs,hs);shift=schema.F+schema.G+21+a-schema.E;assert ys==numpy_output(xs,hs,j,shift)
        digest.update(v['raw']+json.dumps([xs,hs,ys],separators=(',',':')).encode());exponents.add(a)
        if any(not -32768<=y<=32767 for y in ys):rejects('Overflow',lambda:c.witness(p,xs,hs));rejected+=1
        else:
            w=c.witness(p,xs,hs);stat=int(np.sum(np.array(xs,dtype=np.int64)**2));unit=schema.d*2**(2*schema.F);n=schema.ed*stat+schema.en*unit;den=schema.ed*unit;A=n*4**max(-a,0);D=den*4**max(a,0)
            expected=dict(S=stat,N=n,P=den,a=a,M=m,R=A-m*D,J=j,A=A,D=D,MD=m*D,output=ys);assert w==expected and n>0 and 0<=w['R']<D and 16384*D<=A<65536*D and ratio.numerator*den==n*ratio.denominator
            roots=c.expected_roots(p,xs,hs);children=[c.statistic.expected_roots(v['statistic'],xs,stat),c.numerator.expected_roots(v['numerator'],stat,n),c.mantissa.expected_roots(v['mantissa_product'],m,D,m*D),c.summation.expected_roots(v['normal_sum'],m*D,w['R'],A),c.remainder.expected_roots(v['normal_remainder'],D,w['R']),c.rsqrt.expected_roots(v['reciprocal'],m,j)]
            for indices,actual in zip(((5,15),(15,0),(16,3,17),(17,18,2),(3,18),(16,11)),children):assert [roots[i] for i in indices]==actual
            cv=c.configured.derive(v['configured'],4);fv=c.configured.factors.derive(cv['factors'],4);dv=c.configured.factors.dv.derive(fv['paired'],4);sv=c.configured.factors.dv.s.derive(dv['scaled'],4);nv=c.numerator.derive(v['numerator'],4);mv=c.mantissa.derive(v['mantissa_product'],4);sumv=c.summation.derive(v['normal_sum'],4)
            assert nv['layout']['s']==sv['nslots'] and sv['layout']['s']==sumv['a_slots'] and mv['layout']['s']==sumv['md_slots'];widths.add((sv['nslots'],sumv['a_slots'],sumv['md_slots']))
            digest.update(b''.join(roots));accepted+=1;branches.add(shift<0)
        if case%1000==999:print('corpus',case+1,accepted,rejected,flush=True)
    p=spec(16384,(1<<24)-1,2);v=c.derive(p,8);assert v['base']+(1<<38)==(1<<63)+(1<<62)
    spans=[(c.configured.derive(v['configured'],8)['base'],1<<34)]+[(module.derive(v[name],8)['base'],1<<18) for name,module in (('statistic',c.statistic),('numerator',c.numerator),('mantissa_product',c.mantissa),('normal_sum',c.summation))]+[(c.remainder.derive(v['normal_remainder'],8)['base'],4096),(c.rsqrt.metadata(v['reciprocal'],8)['base'],4096)]
    spans.sort();assert all(v['base']<=lo and lo+size<=v['base']+(1<<38) for lo,size in spans) and all(lo+size<=nxt for (lo,size),(nxt,_) in zip(spans,spans[1:]))
    for bad in (replace(p,identity=1<<24),replace(p,repetitions=True),replace(p,statistic=p.source),replace(p,mantissa=v['base']),replace(p,schema=replace(p.schema,en=0))):rejects('Spec',lambda:c.derive(bad,4))
    rejects('Spec',lambda:c.derive(spec(16385),4));rejects('Spec',lambda:c.derive(p,True))
    assert accepted+rejected==10000 and accepted>0 and rejected>0 and branches=={False,True} and {-23,9}<=exponents
    print(json.dumps(dict(seed=2724,cases=10000,accepted=accepted,overflow=rejected,widths=sorted(widths),sha256=digest.hexdigest()),sort_keys=True),flush=True)


def account(p,proof,out,d):
    v=c.derive(p,d);children=out['children']
    for name,part,check in zip(('configured','statistic','numerator','mantissa_product','normal_sum','normal_remainder'),children,(configured_account,statistic_account,numerator_account,mantissa_account,sum_account,remainder_account)):check(v[name],part,d)
    reciprocal_account(v['reciprocal'],proof['reciprocal'],children[6],d);accounts=[x['account'] for x in children[:6]];products=[accounts[i] for i in (0,2,3,4)];lookup=children[6]['account']
    expected=dict(identities=sum((x['identities'] for x in accounts),[])+[(98304,p.repetitions)],lookup_reduction_numerator=sum(x['lookup_reduction_numerator'] for x in accounts)+392*p.repetitions,range_reduction_numerator=sum(x['range_reduction_numerator'] for x in accounts),statistic_reduction_numerator=accounts[1]['statistic_reduction_numerator'],selection_reduction_numerator=6,product_identities=[x['product_identity_numerator'] for x in products],product_reduction_numerator=sum(x['product_reduction_numerator'] for x in products),denominator=r.sc.P**d)
    assert lookup['identity_numerator']==98304 and out['draws']=={} and out['account']==expected


def inputs(case,size=None):
    if case=='zero':return c.norm.Spec(1,0,0,14,1,(1<<32)-1),[0],[32767]
    if case=='left':
        size=4 if size is None else size;xs=[-1]*(size//4)+[0]*(size-size//4);hs=[1]+[0]*(size-1)
        return c.norm.Spec(size,0,0,14,1,(1<<32)-1),xs,hs
    if case=='right':
        size=3 if size is None else size;xs=([-32768,256,1]*((size+2)//3))[:size];hs=([-32768,16384,0]*((size+2)//3))[:size]
        return c.norm.Spec(size,8,14,8,1,100000),xs,hs
    size=5 if size is None else size;return c.norm.Spec(size,30,30,0,(1<<32)-1,(1<<32)-2),[-32768]*size,([-32768,32767]*((size+1)//2))[:size]


def honest(d=4,reps=1,maximum=None):
    digest=hashlib.sha256();count=0
    for case in (('zero','left','right','wide') if maximum is None else (maximum,)):
        schema,xs,hs=inputs(case,None if maximum is None else 16384);p=replace(spec(schema.d,2810+count,reps),schema=schema)
        print('honest start',case,d,reps,schema.d,flush=True);proof,state=c.prove(p,xs,hs,d);out=c.verify(p,c.expected_roots(p,xs,hs),proof,d);assert out['state']==state;account(p,proof,out,d);digest.update(state);count+=1
        assert out['children'][0]['branch']==('left' if case in ('zero','left') else 'division');print('honest passed',case,d,reps,schema.d,flush=True)
    print(json.dumps(dict(field=d,repetitions=reps,maximum=maximum,proofs=count,sha256=digest.hexdigest()),sort_keys=True),flush=True)


def controls():
    p=spec();d=4;xs=[256,256,1];hs=[16384]*3;v=c.derive(p,d);w=c.witness(p,xs,hs);roots=c.expected_roots(p,xs,hs);print('controls baseline start',flush=True);pairs=c.prepare(p,xs,hs,d);proof,state=c.assemble(p,pairs,roots,d);out=c.verify(p,roots,proof,d);assert out['state']==state;account(p,proof,out,d);print('controls baseline passed',flush=True)
    reasons=['Factors:Paired:Scaled:Numerator:CommitmentMismatch','Factors:Paired:Scaled:Exponent:Offset:CommitmentMismatch','Factors:Paired:Scaled:Product:Output:CommitmentMismatch','Factors:Paired:Divisor:CommitmentMismatch','Factors:Factors:CommitmentMismatch','Signed:ProductSign:XY:Left:Raw:CommitmentMismatch','Signed:ProductSign:XY:Right:Raw:CommitmentMismatch','Signed:ProductSign:XY:Output:CommitmentMismatch','Signed:ProductSign:Sign:CommitmentMismatch','Signed:Output:Raw:CommitmentMismatch','Signed:Output:Magnitude:CommitmentMismatch','Product:Reciprocal:CommitmentMismatch','Product:Output:CommitmentMismatch','Division:QuotientProduct:Output:CommitmentMismatch','Division:Remainder:CommitmentMismatch']
    reasons=['Configured:'+reason for reason in reasons]+['Statistic:Output:CommitmentMismatch','MantissaProduct:Mantissa:CommitmentMismatch','MantissaProduct:Product:Output:CommitmentMismatch','NormalSum:Remainder:CommitmentMismatch']
    for index,reason in enumerate(reasons):
        bad=roots.copy();bad[index]=bytes([bad[index][0]^1])+bad[index][1:];rejects(reason,lambda:c.verify(p,bad,proof,d));print('root rejected',index,reason,flush=True)
    for key in ('receipt','normalization','table'):rejects('ProofShape',lambda:c.verify(p,roots,dict(proof,**{key:{}}),d))
    changed=dict(pairs,statistic=c.statistic.prove(v['statistic'],[-256,256,1],d));bad,_=c.assemble(p,changed,roots,d);rejects('Statistic:Source:Raw:CommitmentMismatch',lambda:c.verify(p,roots,bad,d))
    cv=c.configured.derive(v['configured'],d);cp=proof['configured'];co=out['children'][0];names=('factors','signed','product',co['branch']);child_pairs={key:(cp[name],part['state']) for key,name,part in zip(('factors','signed','product','round'),names,co['children'])}
    child_pairs['factors']=c.configured.factors.prove(cv['factors'],w['N']+1,w['a'],d);changed=dict(pairs,configured=c.configured.assemble(v['configured'],child_pairs,d));br=roots.copy();br[:15]=c.configured.roots(v['configured'],changed['configured'][0]);bad,_=c.assemble(p,changed,br,d)
    rejects('Numerator:Product:Output:CommitmentMismatch',lambda:c.verify(p,br,bad,d));print('same-S statistic substitution and coherent changed-N factors reject',flush=True)
    alternative=w['M']+1 if w['M']<65535 else w['M']-1;print('lookup substitution producer start',flush=True);other=c.rsqrt.prove(v['reciprocal'],alternative,d);other_roots=c.rsqrt.expected_roots(v['reciprocal'],alternative,c.rsqrt.witness(v['reciprocal'],alternative));assert c.rsqrt.verify(v['reciprocal'],other_roots,other[0],d)['state']==other[1]
    bad,_=c.assemble(p,dict(pairs,reciprocal=other),roots,d);rejects('Reciprocal:Lookup:CommitmentMismatch',lambda:c.verify(p,roots,bad,d));print('genuine complete-table lookup with substituted M rejects',flush=True)


if __name__=='__main__':
    modes={'--corpus':corpus,'--controls':controls,**{'--honest'+str(d)+'r'+str(reps):(lambda d=d,reps=reps:honest(d,reps)) for d in (4,8) for reps in (1,2)},'--maximum':lambda:honest(maximum='wide'),'--full-left':lambda:honest(maximum='left'),'--full-right':lambda:honest(maximum='right')}
    if sys.argv[1:]:
        assert all(mode in modes for mode in sys.argv[1:])
        for mode in sys.argv[1:]:modes[mode]()
    else:
        for test in modes.values():test()
