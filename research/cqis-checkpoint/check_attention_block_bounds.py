"""Q26 / Draft RFC-0004 A3/A6, RFC-0009 A2: block rounding and aggregation attacks."""
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
import attention_block_bounds as r
import limbs
from check_limbs import oracle, numpy_columns, rejects
from check_attention import rounded
import model_attention_block_bounds as model_bounds
import model_attention_normalization_bounds as normalization
from check_attention_sum_bounds import model_row as raw_model_row
from check_causal_model import make, reference as model_reference
from check_decoder_block import reference as block_reference
from check_projected_attention import config as attention_config, oracle as attention_reference


NAMES=('probability_max','restored_max','block_count_max','block_id_max','raw_max','source_offset_max',
       'divisor','bias','rounded_max','scaled_quotient_max','remainder_max','total_max','sum_side_max',
       'block_z_max','z_max','entry_capacity')


def certificate(p):
    s=127*259 if p.value_mode=='dynamic' else p.scale*min(127,(65536+p.scale)//(2*p.scale))
    probability=2**p.exponent; blocks=(p.length+1023)//1024; h=1024*probability*s; d=2**p.drop
    q=rounded(Q(h,d)); total=blocks*q
    shared=dict(probability_sum=limbs.Spec(blocks,1024*probability,1,8))
    entries=dict(sign_lhs=limbs.Spec(2,2*h,2,8),sign_rhs=limbs.Spec(2,h,1,8),sign_gap=limbs.Spec(2,h,1,8),
                 bias=limbs.Spec(2,max(h,d//2),1,8),quotient_product=limbs.Spec(1,q,d,8),
                 division=limbs.Spec(2,max(q*d,d-1),1,8))
    return dict(asdict(p),prime=2**31-1,probability_max=probability,restored_max=s,block_count_max=blocks,
                block_id_max=blocks-1,raw_max=h,source_offset_max=2*h,divisor=d,bias=d//2,rounded_max=q,
                scaled_quotient_max=q*d,remainder_max=d-1,total_max=total,sum_side_max=total,
                block_z_max=1024*probability,z_max=p.length*probability,entry_capacity=1<<20,
                shared_columns={name:oracle(s) for name,s in shared.items()},entry_columns={name:oracle(s) for name,s in entries.items()})


def frame(p,c):
    raw=b'stele/research/q26/attention-block-bounds/v1\0'
    raw+=struct.pack('<IHBBBHB',p.length,p.width,p.fraction,p.exponent,('dynamic','static').index(p.value_mode),p.scale,p.drop)
    raw+=struct.pack('<IBB',2**31-1,8,len(NAMES))+b''.join(c[k].to_bytes(20,'little') for k in NAMES)
    for group in ('shared_columns','entry_columns'):
        raw+=bytes([len(c[group])])
        for i,rec in enumerate(c[group].values(),1):
            raw+=struct.pack('<BI',i,rec['count'])+b''.join(rec[k].to_bytes(20,'little') for k in ('left_max','right_max','result_max'))
            raw+=bytes(len(rec[k]) for k in ('left_caps','right_caps','result_caps'))
            raw+=b''.join(bytes(rec[k]) for k in ('left_caps','right_caps','result_caps'))
            raw+=b''.join(struct.pack('<I',v) for k in ('carry_caps','lhs','rhs') for v in rec[k])
    return raw


def reference(p,zs,raw):
    values=np.asarray(raw,dtype=np.int64); d=2**p.drop
    small=np.sign(values)*((np.abs(values)+d//2)//d)
    exact=tuple(tuple(rounded(Q(t,d)) for t in row) for row in raw)
    assert tuple(tuple(int(v) for v in row) for row in small)==exact
    return int(np.asarray(zs,dtype=np.int64).sum()),tuple(int(v) for v in small.sum(axis=0,dtype=np.int64))


def controls():
    p=r.Spec(1<<20,1,0,14,'static',65535,26); c=r.derive(p); ids=(0,2); zs=(16384,0); raw=((0,),(0,))
    w=r.witness(p,ids,zs,raw); check=lambda v:r.check_relations(p,c,ids,zs,raw,v)
    assert check(w)==(16384,(0,))
    # Wrong nearest result at raw zero; the biased division sides differ by exactly p.
    bad=copy.deepcopy(w); d=c['divisor']; bad['entries'][0][0].update(quotient=32,scaled_quotient=32*d,remainder=d//2-1,output=32)
    bad['totals']=(32,); assert 32*d-1==r.P
    rejects('IntegerRelation',lambda:check(r.attach(p,ids,zs,raw,bad)))
    # Two canonical static codes -1 with weights 16384 give this negative sum.
    source=-2*16384*65535; az=(32768,0); aa=((source,),(0,)); bad=r.witness(p,ids,az,aa)
    assert (source-32767)%r.P==0 and r.check_relations(p,c,ids,az,aa,bad)==(32768,(-32,))
    bad['entries'][0][0].update(sign=0,magnitude=32767,sign_gap=32767,quotient=0,scaled_quotient=0,remainder=d//2+32767,output=0)
    bad['totals']=(0,)
    rejects('IntegerRelation',lambda:r.check_relations(p,c,ids,az,aa,r.attach(p,ids,az,aa,bad)))
    bad=copy.deepcopy(w); bad['weight_sum']+=r.P; rejects('IntegerRelation',lambda:check(bad))
    bad=copy.deepcopy(w); bad['totals']=(1,); rejects('SumRelation',lambda:check(bad))
    bad=copy.deepcopy(w); bad['totals']=(r.P,); rejects('Range',lambda:check(bad))
    bad=copy.deepcopy(w); bad['block_ids']=(0,1); rejects('Blocks',lambda:check(bad))
    bad=copy.deepcopy(w); bad['entries']=bad['entries'][:1]; rejects('Witness',lambda:check(bad))
    bad=copy.deepcopy(w); bad['entries'][0][0]['sign']=1; rejects('IntegerRelation',lambda:check(r.attach(p,ids,zs,raw,bad)))
    bad=copy.deepcopy(w); bad['entries'][0][0]['sign']=True; rejects('Witness',lambda:check(bad))
    rejects('SourceDigits',lambda:check(r.witness(p,ids,(16385,0),raw)))
    rejects('SourceDigits',lambda:check(r.witness(p,ids,zs,((1,),(0,)))))
    for field in ('magnitude','sign_gap','quotient','scaled_quotient','remainder'):
        bad=copy.deepcopy(w); bad['entries'][0][0][field]+=1
        rejects('IntegerRelation',lambda:check(r.attach(p,ids,zs,raw,bad)))
    bad=copy.deepcopy(w); bad['entries'][0][0]['output']=1; rejects('OutputRelation',lambda:check(bad))
    for key,value in c.items():
        if key.endswith('_columns'):
            for role,record in value.items():
                for field,v in record.items():
                    bad=copy.deepcopy(c); bad[key][role][field]=(v[0]+1,)+v[1:] if type(v) is tuple else v+1
                    rejects('Certificate',lambda:r.validate(p,bad))
        else:
            bad=copy.deepcopy(c); bad[key]=value+'x' if type(value) is str else value+1
            rejects('Certificate',lambda:r.validate(p,bad))
    for group,cols in (('shared_columns',w['columns']),('entry_columns',w['entries'][0][0]['columns'])):
        for role in cols:
            bad=copy.deepcopy(w); col=bad['columns'][role] if group=='shared_columns' else bad['entries'][0][0]['columns'][role]
            col['carry']=col['carry'][:-1]+(1,); rejects('Boundary',lambda:check(bad))
            bad=copy.deepcopy(w); col=bad['columns'][role] if group=='shared_columns' else bad['entries'][0][0]['columns'][role]
            col['result']=(col['result'][0]+r.P,)+col['result'][1:]; rejects('Range',lambda:check(bad))
            bad=copy.deepcopy(w); col=bad['columns'][role] if group=='shared_columns' else bad['entries'][0][0]['columns'][role]
            carry=col['carry']; changed=carry[1]-1 if carry[1] else 1
            assert changed<=c[group][role]['carry_caps'][1]
            col['carry']=(carry[0],changed)+carry[2:]; rejects('Relation',lambda:check(bad))
    bad=copy.deepcopy(w); col=bad['columns']['probability_sum']; col['left']=col['left'][:1]
    rejects('Witness',lambda:check(bad))
    for badids in ((),(0,0),(2,0),(0,1024),(False,2)): rejects('Blocks',lambda:r.witness(p,badids,zs,raw))
    rejects('Blocks',lambda:r.witness(replace(p,width=16384),tuple(range(65)),(),()))
    rejects('Weights',lambda:r.witness(p,ids,(0,True),raw))
    rejects('Weights',lambda:r.witness(p,ids,(0,c['block_z_max']+1),raw))
    rejects('Input',lambda:r.witness(p,ids,zs,((c['raw_max']+1,),(0,))))
    rejects('DivisorRange',lambda:r.witness(replace(p,length=1),(0,),(16385,),((0,),)))
    rejects('BlockBound',lambda:r.witness(replace(p,drop=25),ids,zs,raw))
    for field,value in (('length',0),('width',16385),('fraction',31),('exponent',15),('scale',0),('drop',63),('drop',True)):
        rejects('Spec',lambda:r.derive(replace(p,**{field:value})))
    for t in (-d-1,-d//2-1,-d//2,-1,0,1,d//2,d//2+1,d+1):
        aa=((t,),); assert r.check_relations(p,c,(1023,),(16384,),aa,r.witness(p,(1023,),(16384,),aa))==reference(p,(16384,),aa)
    maximum=replace(p,scale=32767,drop=24); mc=r.derive(maximum)
    mi=tuple(range(1024)); mz=(1<<24,)*1024; mr=((mc['raw_max'],),)*1024
    mw=r.witness(maximum,mi,mz,mr)
    assert r.check_relations(maximum,mc,mi,mz,mr,mw)==(1<<34,(33553408,))
    sparse=r.witness(maximum,(1023,),(0,),((0,),)); assert len(sparse['columns']['probability_sum']['left'])==1
    zero=replace(p,drop=62); zr=((-c['raw_max'],),)
    assert r.check_relations(zero,r.derive(zero),(0,),(16384,),zr,r.witness(zero,(0,),(16384,),zr))==(16384,(0,))
    for spec in (p,replace(p,length=1),zero):
        data=r.encode(spec); assert data==frame(spec,certificate(spec)) and len(data)<=2048
        for end in range(len(data)): rejects('Encoding',lambda:r.validate_bytes(spec,data[:end]))
        for i in range(len(data)): rejects('Encoding',lambda:r.validate_bytes(spec,data[:i]+bytes([data[i]^1])+data[i+1:]))
        rejects('Encoding',lambda:r.validate_bytes(spec,data+b'\0'))


def model_row(p,position,q,positions,keys,values,allowed,expected):
    partials=raw_model_row(p,position,q,positions,keys,values,allowed,expected)
    spec=model_bounds.spec(p); cert=r.derive(spec); ns=normalization.spec(p)
    for groups,head in zip(partials,expected['heads']):
        ids=tuple(block for block,_ in groups); zs=tuple(a[0] for _,a in groups); raw=tuple(a[1] for _,a in groups)
        z,total=r.check_relations(spec,cert,ids,zs,raw,r.witness(spec,ids,zs,raw))
        assert (z,total)==(head['z'],tuple(head['total']))
        assert normalization.r.check_relations(ns,normalization.r.derive(ns),z,total,normalization.r.witness(ns,z,total))==tuple(head['wide'])


def model_rows(model,expected,positions):
    for i,b in enumerate(model.blocks):
        if b.attention.attention.accumulation!='block1024': continue
        cells=block_reference(b,expected['cuts'][i],positions); keys=[v['k'] for v in cells]; values=[v['v'] for v in cells]
        for j,cell in zip(positions,cells):
            model_row(b.attention,j,cell['q'],positions,keys,values,[k<=j for k in positions],cell['attention'])


def block_variant(model):
    blocks=[]
    for b in model.blocks:
        a=b.attention; policy=replace(a.attention,accumulation='block1024',drop=model_bounds.m.b.pa.a.minimum_drop(a.attention))
        blocks.append(replace(b,attention=replace(a,attention=policy)))
    return replace(model,blocks=tuple(blocks))


def check_variant(model,tokens):
    model=block_variant(model); expected=model_reference(model,tokens); actual=model_bounds.m.full(model,tokens)
    assert {k:actual[k] for k in expected}==expected
    state=None
    for j,t in enumerate(tokens):
        row,state=model_bounds.m.step(model,t,state)
        assert row==dict(cuts=[c[j] for c in expected['cuts']],head=expected['heads'][j])
    assert state==actual['cache']; model_rows(model,expected,list(range(len(tokens))))
    from check_gated_product_bounds import model_rows as gated_rows
    gated_rows(model,expected,list(range(len(tokens))))
    return dict(model_bounds.evidence(model),drops=[b.attention.attention.drop for b in model.blocks],tokens=list(tokens),
                logits_sha256=hashlib.sha256(b''.join(struct.pack('<h',v) for h in expected['heads'] for v in h['logits'])).hexdigest())


def models():
    rng=random.Random(2648); accepted=0
    for case in range(30):
        model=make(rng,case); blocks=[]
        for b in model.blocks:
            p=b.attention; mode='static' if case%3==0 else 'dynamic'; scale=(65535 if case%6==0 else 256) if mode=='static' else 0
            a=replace(p.attention,fv=5+case%7,fo=6+(case//7)%5,value_mode=mode,value_scale=scale,accumulation='exact',drop=0)
            if case%4: a=replace(a,accumulation='block1024',drop=model_bounds.m.b.pa.a.minimum_drop(a)+case%3)
            blocks.append(replace(b,attention=replace(p,attention=a)))
        model=replace(model,blocks=tuple(blocks)); rows=model_bounds.records(model)
        assert len(rows)==(len(blocks) if case%4 else 0)
        weight=model.embedding; zero=replace(weight,codes=tuple((0,)*len(row) for row in weight.codes),mantissas=(1,)*len(weight.codes))
        assert model_bounds.records(replace(model,embedding=zero))==rows
        try: expected=model_reference(model,[0,1,2])
        except ValueError as error:
            assert str(error)=='Overflow'
            continue
        model_rows(model,expected,[0,1,2]); accepted+=1
    assert accepted==28
    p=attention_config(n=2050); a=replace(p.attention,accumulation='block1024',drop=model_bounds.m.b.pa.a.minimum_drop(p.attention))
    p=replace(p,attention=a); positions=[1023,1024,2048]; keys=[[1,2],[-1,3],[4,-2]]; values=[[1024,-1024],[100,2],[1024,-1024]]
    q=[1,2,3,4]; allowed=[True,False,True]; expected=attention_reference(p,2048,q,positions,keys,values,allowed)
    assert expected['heads'][0]['total']==[2,-2]
    model_row(p,2048,q,positions,keys,values,allowed,expected)
    return accepted


def check():
    rng=random.Random(2647); digest=hashlib.sha256()
    for case in range(10000):
        mode='dynamic' if case%3 else 'static'
        p=r.Spec(rng.randrange(1,(1<<20)+1),rng.randrange(1,5),rng.randrange(31),rng.randrange(15),
                 mode,0 if mode=='dynamic' else rng.randrange(1,65536),0)
        h=certificate(p)['raw_max']; minimum=next(k for k in range(63) if rounded(Q(h,2**k))<=32767)
        p=replace(p,drop=rng.randrange(minimum,63)); c=r.derive(p); assert c==certificate(p)
        data=r.encode(p); assert data==frame(p,c); r.validate_bytes(p,data)
        count=rng.randrange(1,min(8,c['block_count_max'])+1); ids=tuple(sorted(rng.sample(range(c['block_count_max']),count)))
        zs=tuple(rng.randrange(min(1024,p.length-1024*i)*c['probability_max']+1) for i in ids)
        raw=tuple(tuple(rng.randrange(-h,h+1) for _ in range(p.width)) for _ in ids)
        w=r.witness(p,ids,zs,raw); expected=reference(p,zs,raw); assert r.check_relations(p,c,ids,zs,raw,w)==expected
        assert numpy_columns(zs,(1,)*count,8)==expected[0]
        values=r.column_inputs(p,raw,w)
        for row,entries in zip(w['entries'],values):
            for e,vs in zip(row,entries):
                for name,col in e['columns'].items(): assert numpy_columns(*vs[name],8)==sum(v*256**i for i,v in enumerate(col['result']))
        digest.update(data+json.dumps([ids,zs,raw,expected],separators=(',',':')).encode())
    assert digest.hexdigest()=='c55dd0056ebf2ec462131547b4010307bc2296335d1f8dea73e484face206ec4'
    accepted=models(); controls()
    print(json.dumps(dict(seed=2647,cases=10000,model_seed=2648,models_accepted=accepted,sha256=digest.hexdigest()),sort_keys=True))
