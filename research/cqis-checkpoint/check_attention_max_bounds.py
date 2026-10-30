"""Q26 / RFC-0009 A1, Draft RFC-0004 A3/A6: masked maximum and difference attacks."""
from dataclasses import asdict, replace
from pathlib import Path
import copy
import hashlib
import json
import random
import struct
import sys
import numpy as np
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'cqis-bounds'))
import attention_max_bounds as r
import limbs
from check_limbs import oracle, numpy_columns, rejects
import model_attention_max_bounds as model_bounds
from check_attention_score_bounds import model_row as score_row
from check_causal_model import make, reference as model_reference
from check_decoder_block import reference as block_reference
from check_projected_attention import config as attention_config

NAMES=('position_max','score_offset_max','domain_max','delta_max','gap_max','prefix_max','entry_capacity')


def certificate(p):
    offset=2*p.score_max; domain=2**p.domain_bits; delta=min(offset,domain)
    shared=dict(maximum=limbs.Spec(1,offset,1,8))
    entries=dict(difference=limbs.Spec(2,offset,1,8),first_maximum=limbs.Spec(2,max(delta,1),1,8))
    return dict(asdict(p),prime=2**31-1,position_max=p.length-1,score_offset_max=offset,domain_max=domain,
                delta_max=delta,gap_max=delta,prefix_max=1,entry_capacity=2**20,
                shared_columns={name:oracle(s) for name,s in shared.items()},entry_columns={name:oracle(s) for name,s in entries.items()})


def frame(p,c):
    raw=b'stele/research/q26/attention-max-bounds/v1\0'+struct.pack('<IIBB',p.length,p.score_max,p.domain_bits,p.fraction)
    raw+=struct.pack('<IBB',2**31-1,8,len(NAMES))+b''.join(struct.pack('<Q',c[k]) for k in NAMES)
    for group in ('shared_columns','entry_columns'):
        raw+=bytes([len(c[group])])
        for i,rec in enumerate(c[group].values(),1):
            raw+=struct.pack('<BIQQQ',i,rec['count'],rec['left_max'],rec['right_max'],rec['result_max'])
            raw+=bytes(len(rec[k]) for k in ('left_caps','right_caps','result_caps'))
            raw+=b''.join(bytes(rec[k]) for k in ('left_caps','right_caps','result_caps'))
            raw+=b''.join(struct.pack('<I',v) for k in ('carry_caps','lhs','rhs') for v in rec[k])
    return raw


def reference(p,ids,scores,allowed):
    xs=np.asarray(scores,dtype=np.int64); mask=np.asarray(allowed,dtype=np.bool_); maximum=int(xs[mask].max())
    selected=ids[int(np.flatnonzero(mask & (xs==maximum))[0])]
    deltas=tuple(int(v) for v in np.where(mask,maximum-xs,0))
    exact=max(v for v,b in zip(scores,allowed) if b)
    assert maximum==exact and selected==min(j for j,v,b in zip(ids,scores,allowed) if b and v==exact)
    assert deltas==tuple(exact-v if b else 0 for v,b in zip(scores,allowed))
    if any(d>2**p.domain_bits for d in deltas): raise ValueError('Domain')
    return maximum,selected,deltas


def controls():
    p=r.Spec(1<<20,2147385345,31,0); ids=(1024,); scores=(-p.score_max,); mask=(True,); c=r.derive(p)
    w=r.witness(p,2048,ids,scores,mask); bad=copy.deepcopy(w); bad['maximum']=98302
    assert (bad['maximum']-scores[0])%r.P==0
    rejects('IntegerRelation',lambda:r.check_relations(p,c,2048,ids,scores,mask,1024,r.attach(p,ids,scores,mask,bad)))
    # The true difference exceeds the inclusive domain; subtracting p would conceal that.
    ids=(0,2048); scores=(p.score_max,-p.score_max); mask=(True,True)
    rejects('Domain',lambda:r.witness(p,2048,ids,scores,mask))
    bad=r.witness(p,2048,ids,(p.score_max,p.score_max),mask); delta=2*p.score_max-r.P
    bad['entries'][1].update(delta=delta,gap=delta); assert 0<=delta<=2**31
    rejects('IntegerRelation',lambda:r.check_relations(p,c,2048,ids,scores,mask,0,r.attach(p,ids,scores,mask,bad)))
    # Coherent later-tie selection wraps the strict prefix relation by exactly p.
    p=replace(p,score_max=r.P); c=r.derive(p); ids=(0,1024,2048); scores=(0,0,r.P); mask=(True,True,False)
    w=r.witness(p,2048,ids,scores,mask); check=lambda v:r.check_relations(p,c,2048,ids,scores,mask,0,v)
    assert check(w)==(0,0,(0,0,0))
    bad=copy.deepcopy(w); bad['selected']=1024; bad['entries'][0]['gap']=r.P-1
    rejects('IntegerRelation',lambda:r.check_relations(p,c,2048,ids,scores,mask,1024,r.attach(p,ids,scores,mask,bad)))
    bad=copy.deepcopy(w); bad['entries'][2]['delta']=1; rejects('Masked',lambda:check(bad))
    bad=copy.deepcopy(w); bad['entries'][2]['gap']=1; rejects('Masked',lambda:check(bad))
    bad=copy.deepcopy(w); bad['entries'][1]['delta']=1; rejects('IntegerRelation',lambda:check(r.attach(p,ids,scores,mask,bad)))
    bad=copy.deepcopy(w); bad['entries'][1]['gap']=1; rejects('IntegerRelation',lambda:check(r.attach(p,ids,scores,mask,bad)))
    bad=copy.deepcopy(w); bad['maximum']=1; rejects('IntegerRelation',lambda:check(r.attach(p,ids,scores,mask,bad)))
    bad=copy.deepcopy(w); bad['position']=2047; rejects('Position',lambda:check(bad))
    bad=copy.deepcopy(w); bad['positions']=(0,1024,2047); rejects('Positions',lambda:check(bad))
    bad=copy.deepcopy(w); bad['selected']=1024; rejects('Selected',lambda:check(bad))
    bad=copy.deepcopy(w); bad['entries']=bad['entries'][:-1]; rejects('Witness',lambda:check(bad))
    bad=copy.deepcopy(w); bad['maximum']=True; rejects('Witness',lambda:check(bad))
    bad=copy.deepcopy(w); bad['maximum']=p.score_max+1; rejects('Range',lambda:check(bad))
    changed=(0,-1,r.P); rejects('SourceDigits',lambda:r.check_relations(p,c,2048,ids,changed,mask,0,w))
    changed_mask=(True,True,True); rejects('SourceDigits',lambda:r.check_relations(p,c,2048,ids,scores,changed_mask,0,w))
    for selected in (2048,100,True): rejects('Selection',lambda:r.check_relations(p,c,2048,ids,scores,mask,selected,w))
    for badids in ((),(0,0),(1,0),(0,1<<20),(False,1024,2048)):
        rejects('Positions',lambda:r.witness(p,2048,badids,scores,mask))
    rejects('Position',lambda:r.witness(p,1<<20,ids,scores,mask))
    rejects('Input',lambda:r.witness(p,2048,ids,(0,0,p.score_max+1),mask))
    rejects('Input',lambda:r.witness(p,2048,ids,(0,True,0),mask))
    rejects('Mask',lambda:r.witness(p,2048,ids,scores,(True,1,False)))
    rejects('EmptyRow',lambda:r.witness(p,2048,ids,scores,(False,False,False)))
    for key,value in c.items():
        if key.endswith('_columns'):
            for role,rec in value.items():
                for field,v in rec.items():
                    bad=copy.deepcopy(c); bad[key][role][field]=(v[0]+1,)+v[1:] if type(v) is tuple else v+1
                    rejects('Certificate',lambda:r.validate(p,bad))
        else:
            bad=copy.deepcopy(c); bad[key]=value+1; rejects('Certificate',lambda:r.validate(p,bad))
    for group,roles in (('shared_columns',w['columns']),('entry_columns',w['entries'][0]['columns'])):
        for role in roles:
            bad=copy.deepcopy(w); col=bad['columns'][role] if group=='shared_columns' else bad['entries'][0]['columns'][role]
            col['carry']=col['carry'][:-1]+(1,); rejects('Boundary',lambda:check(bad))
            bad=copy.deepcopy(w); col=bad['columns'][role] if group=='shared_columns' else bad['entries'][0]['columns'][role]
            col['result']=(col['result'][0]+r.P,)+col['result'][1:]; rejects('Range',lambda:check(bad))
            caps=c[group][role]['carry_caps']
            if any(caps[1:-1]):
                i=next(i for i in range(1,len(caps)-1) if caps[i]); bad=copy.deepcopy(w)
                col=bad['columns'][role] if group=='shared_columns' else bad['entries'][0]['columns'][role]
                carry=list(col['carry']); carry[i]=carry[i]-1 if carry[i] else 1; col['carry']=tuple(carry)
                rejects('Relation',lambda:check(bad))
    for field,value in (('length',0),('length',2**20+1),('score_max',-1),('score_max',2**31),
                        ('domain_bits',6),('domain_bits',32),('fraction',31),('length',True)):
        rejects('Spec',lambda:r.derive(replace(p,**{field:value})))
    for spec,ss,mm in ((p,(r.P,-1),(True,True)),(replace(p,score_max=0),(0,0),(False,True)),
                       (replace(p,domain_bits=7),(128,0),(True,True)),(p,(-r.P,r.P),(True,False))):
        ii=(0,(1<<20)-1); ww=r.witness(spec,0,ii,ss,mm)
        assert r.check_relations(spec,r.derive(spec),0,ii,ss,mm,ww['selected'],ww)==reference(spec,ii,ss,mm)
        assert len(ww['entries'])==2  # Static span does not allocate a padded tail.
        data=r.encode(spec); assert data==frame(spec,certificate(spec)) and len(data)<=512
        for end in range(len(data)): rejects('Encoding',lambda:r.validate_bytes(spec,data[:end]))
        for i in range(len(data)): rejects('Encoding',lambda:r.validate_bytes(spec,data[:i]+bytes([data[i]^1])+data[i+1:]))
        rejects('Encoding',lambda:r.validate_bytes(spec,data+b'\0'))
    rejects('Domain',lambda:r.witness(replace(p,domain_bits=7),0,(0,1),(129,0),(True,True)))


def model_row(p,position,positions,scores,allowed,heads):
    spec=model_bounds.spec(p); cert=r.derive(spec); ids=tuple(positions); mask=tuple(allowed); result=[]
    assert len(scores)==len(heads)==p.heads
    for row,head in zip(scores,heads):
        xs=tuple(row); w=r.witness(spec,position,ids,xs,mask)
        answer=r.check_relations(spec,cert,position,ids,xs,mask,head['selected'],w)
        assert answer==reference(spec,ids,xs,mask) and answer[0]==head['maximum']; result.append(answer)
    assert len(result)==p.heads
    return result


def models():
    rng=random.Random(2652); accepted=0
    for case in range(30):
        model=make(rng,case); records=model_bounds.records(model); assert len(records)==len(model.blocks)
        weight=model.embedding; zero=replace(weight,codes=tuple((0,)*len(row) for row in weight.codes),mantissas=(1,)*len(weight.codes))
        assert model_bounds.records(replace(model,embedding=zero))==records
        try: expected=model_reference(model,[0,1,2])
        except ValueError as error:
            assert str(error)=='Overflow'
            continue
        for i,b in enumerate(model.blocks):
            cells=block_reference(b,expected['cuts'][i],[0,1,2]); keys=[v['k'] for v in cells]
            for j,cell in enumerate(cells):
                scores=score_row(b.attention,j,cell['q'],[0,1,2],keys)
                model_row(b.attention,j,[0,1,2],scores,[k<=j for k in range(3)],cell['attention']['heads'])
        accepted+=1
    p=attention_config(n=2050); heads=[dict(maximum=10,selected=1023),dict(maximum=5,selected=1024)]
    assert model_row(p,2048,[1023,1024,2048],[[10,10,30],[-2,5,100]],[True,True,False],heads)==[
        (10,1023,(0,0,0)),(5,1024,(7,0,0))]
    assert accepted==28
    return accepted


def check():
    rng=random.Random(2651); digest=hashlib.sha256(); accepted=0
    for case in range(10000):
        p=r.Spec(rng.randrange(1,2**20+1),rng.randrange(2**31),rng.randrange(7,32),rng.randrange(31)); c=r.derive(p)
        assert c==certificate(p); data=r.encode(p); assert data==frame(p,c); r.validate_bytes(p,data)
        count=rng.randrange(1,min(p.length,17)+1); ids=tuple(sorted(rng.sample(range(p.length),count))); position=rng.randrange(p.length)
        mask=tuple(bool(rng.randrange(2)) or i==case%count for i in range(count))
        peak=rng.randrange(-p.score_max,p.score_max+1); low=max(-p.score_max,peak-min(2*p.score_max,2**p.domain_bits))
        scores=tuple(rng.randrange(low,peak+1) if case%2 else rng.randrange(-p.score_max,p.score_max+1) for _ in ids)
        try: expected=reference(p,ids,scores,mask)
        except ValueError as error:
            assert str(error)=='Domain'; rejects('Domain',lambda:r.witness(p,position,ids,scores,mask)); digest.update(b'domain'); continue
        w=r.witness(p,position,ids,scores,mask)
        assert r.check_relations(p,c,position,ids,scores,mask,expected[1],w)==expected
        shared,entries=r.column_inputs(p,ids,scores,mask,w)
        for role,col in w['columns'].items(): assert numpy_columns(*shared[role],8)==sum(v*256**i for i,v in enumerate(col['result']))
        for e,vs in zip(w['entries'],entries):
            for role,col in e['columns'].items(): assert numpy_columns(*vs[role],8)==sum(v*256**i for i,v in enumerate(col['result']))
        digest.update(data+json.dumps([position,ids,scores,mask,expected],separators=(',',':')).encode()); accepted+=1
    assert accepted==5874 and digest.hexdigest()=='69618915e68d73e044eed4f5148e0cfd788170fe23cd38221101522b4f158999'
    model_count=models(); controls()
    print(json.dumps(dict(seed=2651,cases=10000,accepted=accepted,rejected=10000-accepted,model_seed=2652,
                          models_accepted=model_count,sha256=digest.hexdigest()),sort_keys=True))
