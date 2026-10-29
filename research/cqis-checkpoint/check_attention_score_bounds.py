"""Q26 / Draft RFC-0004 A3/A6: scaled QK score arithmetic and M31 alias controls."""
from dataclasses import asdict, replace
from fractions import Fraction as Q
from pathlib import Path
import copy
import hashlib
import json
import random
import struct
import sys
import numpy as np
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'cqis-bounds'))
import attention_score_bounds as r
import limbs
from check_limbs import oracle, numpy_columns, rejects
from check_attention import rounded
import model_attention_score_bounds as model_bounds
from check_causal_model import make, reference as model_reference
from check_decoder_block import reference as block_reference
from check_projected_attention import rotation, convert, config as attention_config

NAMES=('q_code_max','k_code_max','q_scale_min','q_scale_max','k_scale_min','k_scale_max','dot_max','sign_side_max',
       'query_scaled_max','key_scaled_max','product_max','left_factor','divisor','bias','numerator_max','biased_max',
       'score_max','scaled_quotient_max','remainder_max','output_offset_max')


def certificate(p):
    def policy(mode,s): return (127,0,259) if mode=='dynamic' else (min(127,(65536+s)//(2*s)),s,s)
    cq,ql,qh=policy(p.q_mode,p.q_scale); ck,kl,kh=policy(p.k_mode,p.k_scale)
    dot=p.width*cq*ck; query=dot*qh; key=query*kh; product=key*p.score_m
    e=p.score_e-p.fq-p.fk+p.f; a=2**max(e,0); d=2**max(-e,0); bias=d//2; n=product*a
    score=rounded(Q(product)*Q(2)**e)
    specs=dict(query_scale=limbs.Spec(1,dot,qh,8),key_scale=limbs.Spec(1,query,kh,8),
               score_multiplier=limbs.Spec(1,key,p.score_m,8),left=limbs.Spec(1,product,a,8),
               bias=limbs.Spec(2,max(n,bias),1,8),quotient_product=limbs.Spec(1,score,d,8),
               division=limbs.Spec(2,max(score*d,d-1),1,8),output_lhs=limbs.Spec(2,2*score,2,8),
               output_rhs=limbs.Spec(2,score,1,8))
    return dict(asdict(p),prime=2**31-1,q_code_max=cq,k_code_max=ck,q_scale_min=ql,q_scale_max=qh,
                k_scale_min=kl,k_scale_max=kh,dot_max=dot,sign_side_max=dot+1,query_scaled_max=query,
                key_scaled_max=key,product_max=product,left_factor=a,divisor=d,bias=bias,numerator_max=n,
                biased_max=n+bias,score_max=score,scaled_quotient_max=score*d,remainder_max=d-1,
                output_offset_max=2*score,columns={name:oracle(s) for name,s in specs.items()})


def frame(p,c):
    raw=b'stele/research/q26/attention-score-bounds/v1\0'
    raw+=struct.pack('<HBBBBHBHHb',p.width,p.fq,p.fk,p.f,('dynamic','static').index(p.q_mode),p.q_scale,
                     ('dynamic','static').index(p.k_mode),p.k_scale,p.score_m,p.score_e)
    raw+=struct.pack('<IBB',2**31-1,8,len(NAMES))+b''.join(c[k].to_bytes(20,'little') for k in NAMES)
    raw+=bytes([len(c['columns'])])
    for i,rec in enumerate(c['columns'].values(),1):
        raw+=struct.pack('<BI',i,rec['count'])+b''.join(rec[k].to_bytes(20,'little') for k in ('left_max','right_max','result_max'))
        raw+=bytes(len(rec[k]) for k in ('left_caps','right_caps','result_caps'))
        raw+=b''.join(bytes(rec[k]) for k in ('left_caps','right_caps','result_caps'))
        raw+=b''.join(struct.pack('<I',v) for k in ('carry_caps','lhs','rhs') for v in rec[k])
    return raw


def reference(p,q,k,qs,ks):
    dot=int(np.asarray(q,dtype=np.int64)@np.asarray(k,dtype=np.int64))
    assert dot==sum(x*y for x,y in zip(q,k))
    return rounded(Q(dot*qs*ks*p.score_m)*Q(2)**(p.score_e-p.fq-p.fk+p.f))


def controls():
    p=r.Spec(1,0,0,0,'static',65535,'static',32767,1,0); args=((-1,),(1,),65535,32767)
    c=r.derive(p); w=r.witness(p,*args); check=lambda v:r.check_relations(p,c,*args,v)
    assert check(w)==-2147385345 and reference(p,*args)==check(w)
    # Both signed outputs are legal, differ by exactly p, and alias in a direct M31 equation.
    bad=copy.deepcopy(w); bad['output']=98302
    assert (bad['output']-(1-2*bad['sign'])*bad['quotient'])%r.P==0
    rejects('IntegerRelation',lambda:check(r.attach(p,args[2],args[3],bad)))
    shifted=replace(p,score_e=-31); sc=r.derive(shifted); sw=r.witness(shifted,*args)
    sw.update(quotient=0,scaled_quotient=0,remainder=sw['numerator']+sc['bias']-r.P,output=0)
    rejects('IntegerRelation',lambda:r.check_relations(shifted,sc,*args,r.attach(shifted,args[2],args[3],sw)))
    large=replace(p,width=4,k_scale=65535,score_e=-4); aa=((-1,)*4,(-1,)*4,65535,65535)
    lc=r.derive(large); lw=r.witness(large,*aa)
    for key in ('key_scaled','product','numerator'): lw[key]-=r.P
    quotient,remainder=divmod(lw['numerator']+lc['bias'],lc['divisor'])
    lw.update(quotient=quotient,scaled_quotient=quotient*lc['divisor'],remainder=remainder,output=quotient)
    rejects('IntegerRelation',lambda:r.check_relations(large,lc,*aa,r.attach(large,aa[2],aa[3],lw)))
    for field in ('dot','sign','magnitude','sign_gap'):
        bad=copy.deepcopy(w); bad[field]=0 if w[field] else 1
        rejects('DotRelation' if field=='dot' else 'SignRelation',lambda:check(bad))
    for field in ('query_scaled','key_scaled','product','numerator','quotient','scaled_quotient','remainder'):
        bad=copy.deepcopy(w); bad[field]=0 if w[field] else 1
        rejects('Range' if field=='remainder' else 'IntegerRelation',lambda:check(r.attach(p,args[2],args[3],bad)))
    rejects('DotRelation',lambda:r.check_relations(p,c,(1,),args[1],*args[2:],w))
    rejects('DotRelation',lambda:r.check_relations(p,c,args[0],(-1,),*args[2:],w))
    rejects('Input',lambda:r.check_relations(p,c,args[0],args[1],65534,32767,w))
    dynamic=r.Spec(2,8,8,7,'dynamic',0,'dynamic',0,1,0); dc=r.derive(dynamic); da=((1,-1),(2,3),7,9)
    dw=r.witness(dynamic,*da)
    rejects('SourceDigits',lambda:r.check_relations(dynamic,dc,da[0],da[1],8,9,dw))
    rejects('SourceDigits',lambda:r.check_relations(dynamic,dc,da[0],da[1],7,10,dw))
    rejects('Input',lambda:r.witness(dynamic,(1,-1),(0,0),0,0))
    rejects('Input',lambda:r.witness(dynamic,(0,0),(1,-1),0,0))
    zero=((0,0),(0,0),0,0); zw=r.witness(dynamic,*zero); zw['sign']=1
    rejects('SignRelation',lambda:r.check_relations(dynamic,dc,*zero,zw))
    rejects('ScoreBound',lambda:r.witness(replace(dynamic,score_e=30),*zero))
    for aa in (((True,0),(0,0),0,0),((0,),(0,0),0,0),((128,0),(0,0),1,1),((0,0),(0,0),260,1)):
        rejects('Input',lambda:r.witness(dynamic,*aa))
    for key,value in c.items():
        if key=='columns':
            for role,record in value.items():
                for field,v in record.items():
                    bad=copy.deepcopy(c); bad[key][role][field]=(v[0]+1,)+v[1:] if type(v) is tuple else v+1
                    rejects('Certificate',lambda:r.validate(p,bad))
        else:
            bad=copy.deepcopy(c); bad[key]=value+'x' if type(value) is str else value+1
            rejects('Certificate',lambda:r.validate(p,bad))
    for role in w['columns']:
        bad=copy.deepcopy(w); col=bad['columns'][role]; col['carry']=col['carry'][:-1]+(1,)
        rejects('Boundary',lambda:check(bad))
        bad=copy.deepcopy(w); col=bad['columns'][role]; col['result']=(col['result'][0]+r.P,)+col['result'][1:]
        rejects('Range',lambda:check(bad))
        caps=c['columns'][role]['carry_caps']
        if any(caps[1:-1]):
            i=next(i for i in range(1,len(caps)-1) if caps[i]); bad=copy.deepcopy(w); col=bad['columns'][role]
            carry=list(col['carry']); carry[i]=carry[i]-1 if carry[i] else 1; col['carry']=tuple(carry)
            rejects('Relation',lambda:check(bad))
    bad=copy.deepcopy(w); bad['output']=c['score_max']+1; rejects('Range',lambda:check(bad))
    bad=copy.deepcopy(w); bad['dot']=True; rejects('Witness',lambda:check(bad))
    bad=copy.deepcopy(w); del bad['columns']['left']; rejects('Witness',lambda:check(bad))
    for field,value in (('width',0),('width',16385),('fq',31),('fk',-1),('f',31),('q_mode','other'),
                        ('q_scale',0),('k_scale',65536),('score_m',0),('score_e',31),('score_e',-63),('width',True)):
        rejects('Spec',lambda:r.derive(replace(p,**{field:value})))
    rejects('Spec',lambda:r.derive(replace(dynamic,q_scale=1)))
    for exponent in (-62,-1,0,30):
        edge=r.Spec(1,30,30,0,'static',1,'static',1,1,exponent)
        for x in (-127,-1,0,1,127):
            aa=((x,),(127,),1,1); assert r.check_relations(edge,r.derive(edge),*aa,r.witness(edge,*aa))==reference(edge,*aa)
    half=r.Spec(1,0,0,0,'static',1,'static',1,1,-1)
    for x in (-3,-1,0,1,3):
        aa=((x,),(1,),1,1); assert r.check_relations(half,r.derive(half),*aa,r.witness(half,*aa))==reference(half,*aa)
    extreme=replace(edge,score_e=-62); assert r.derive(extreme)['divisor']==2**122
    left=replace(half,score_e=17); maximum=replace(half,width=16384,score_e=0)
    for spec in (extreme,left,maximum):
        for sign in (-1,1):
            aa=((sign*127,)*spec.width,(127,)*spec.width,1,1)
            assert r.check_relations(spec,r.derive(spec),*aa,r.witness(spec,*aa))==reference(spec,*aa)
    for spec in (p,dynamic,extreme,left):
        data=r.encode(spec); assert data==frame(spec,certificate(spec)) and len(data)<=4096
        for end in range(len(data)): rejects('Encoding',lambda:r.validate_bytes(spec,data[:end]))
        for i in range(len(data)): rejects('Encoding',lambda:r.validate_bytes(spec,data[:i]+bytes([data[i]^1])+data[i+1:]))
        rejects('Encoding',lambda:r.validate_bytes(spec,data+b'\0'))


def model_row(p,position,q,positions,keys):
    # Rotation/conversion use complete projections before any head/group slice.
    qs,qc=convert(rotation(p,position,q,p.heads),p.q_mode,p.q_scale)
    ks=[convert(rotation(p,j,k,p.groups),p.k_mode,p.k_scale) for j,k in zip(positions,keys)]
    spec=model_bounds.spec(p); cert=r.derive(spec); result=[]
    assert cert['score_max']==model_bounds.m.b.pa.bounds(p)['score_abs_max']
    for h in range(p.heads):
        group=h//(p.heads//p.groups); query=tuple(qc[h*p.width:(h+1)*p.width]); scores=[]
        for scale,key in ks:
            args=(query,tuple(key[group*p.width:(group+1)*p.width]),qs,scale)
            score=r.check_relations(spec,cert,*args,r.witness(spec,*args)); assert score==reference(spec,*args)
            scores.append(score)
        result.append(scores)
    return result


def model_rows(model,expected,positions):
    for i,b in enumerate(model.blocks):
        cells=block_reference(b,expected['cuts'][i],positions); keys=[v['k'] for v in cells]
        for j,cell in zip(positions,cells):
            scores=model_row(b.attention,j,cell['q'],positions,keys)
            for row,head in zip(scores,cell['attention']['heads']):
                assert max(s for k,s in zip(positions,row) if k<=j)==head['maximum']


def models():
    rng=random.Random(2650); accepted=0
    for case in range(30):
        model=make(rng,case); rows=model_bounds.records(model); assert len(rows)==len(model.blocks)
        weight=model.embedding; zero=replace(weight,codes=tuple((0,)*len(row) for row in weight.codes),mantissas=(1,)*len(weight.codes))
        assert model_bounds.records(replace(model,embedding=zero))==rows
        try: expected=model_reference(model,[0,1,2])
        except ValueError as error:
            assert str(error)=='Overflow'
            continue
        model_rows(model,expected,[0,1,2]); accepted+=1
    p=attention_config(4,2,n=2050); keys=[[127,0,254,0],[-127,0,-254,0]]; q=[127,0,254,0,127,0,254,0]
    scores=model_row(p,2048,q,[1023,2048],keys)
    assert scores==[[32,-32],[64,-64],[64,-64],[126,-126]]
    assert accepted==28
    return accepted


def check():
    rng=random.Random(2649); digest=hashlib.sha256(); accepted=0
    for case in range(10000):
        qm='dynamic' if case%3 else 'static'; km='dynamic' if case%4 else 'static'
        p=r.Spec(rng.randrange(1,16385),rng.randrange(31),rng.randrange(31),rng.randrange(31),
                 qm,0 if qm=='dynamic' else rng.randrange(1,65536),km,0 if km=='dynamic' else rng.randrange(1,65536),
                 rng.randrange(1,65536),rng.randrange(-62,31))
        c=certificate(p)
        if c['score_max']>=2**31:
            rejects('ScoreBound',lambda:r.witness(p,(),(),0,0)); digest.update(b'bound'); continue
        assert r.derive(p)==c; data=r.encode(p); assert data==frame(p,c); r.validate_bytes(p,data)
        qs=rng.randrange(c['q_scale_min'],c['q_scale_max']+1); ks=rng.randrange(c['k_scale_min'],c['k_scale_max']+1)
        # Full width exercises dot bounds; limb checks remain constant-size per score.
        q=tuple(rng.randrange(-c['q_code_max'],c['q_code_max']+1) if qs else 0 for _ in range(p.width))
        k=tuple(rng.randrange(-c['k_code_max'],c['k_code_max']+1) if ks else 0 for _ in range(p.width))
        args=(q,k,qs,ks); w=r.witness(p,*args); expected=reference(p,*args)
        assert r.check_relations(p,c,*args,w)==expected
        values=r.column_inputs(p,qs,ks,w)
        for name,col in w['columns'].items(): assert numpy_columns(*values[name],8)==sum(v*256**i for i,v in enumerate(col['result']))
        digest.update(data+json.dumps([args,expected],separators=(',',':')).encode()); accepted+=1
    assert accepted==5499 and digest.hexdigest()=='6ebb42692249177177927c0b55d754ce0d9084cf9e989b5adf01a259cacc330b'
    model_count=models(); controls()
    print(json.dumps(dict(seed=2649,cases=10000,accepted=accepted,rejected=10000-accepted,model_seed=2650,
                          models_accepted=model_count,sha256=digest.hexdigest()),sort_keys=True))
