"""Q26 / Draft RFC-0004 A3/A6, RFC-0009 A2: variable-divisor arithmetic and attacks."""
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
import attention_normalization_bounds as r
import limbs
from check_limbs import oracle, numpy_columns, rejects
from check_attention import rounded
import model_attention_normalization_bounds as model_bounds
from check_causal_model import make, reference as model_reference
from check_decoder_block import reference as block_reference
from check_projected_attention import config as attention_config, oracle as attention_reference


NAMES=('probability_max','restored_max','block_raw_max','rounded_block_max','block_count_max','total_max',
       'z_min','z_max','left_factor','right_factor','numerator_max','denominator_max','double_denominator_max',
       'biased_max','quotient_max','scaled_quotient_max','remainder_max','output_max','source_offset_max','source_gap_max')


def certificate(p):
    scale=259 if p.value_mode=='dynamic' else p.scale
    code=127 if p.value_mode=='dynamic' else min(127,(65536+p.scale)//(2*p.scale))
    s=scale*code; probability=2**p.exponent; raw=1024*probability*s
    small=0 if p.accumulation=='exact' else rounded(Q(raw,2**p.drop))
    blocks=0 if p.accumulation=='exact' else (p.length+1023)//1024
    t=p.length*probability*s if p.accumulation=='exact' else blocks*small
    z=p.length*probability; exponent=p.output_fraction-p.fraction+p.drop
    a=2**max(exponent,0); b=2**max(-exponent,0); u=t*a; d=z*b
    shared=dict(denominator=limbs.Spec(1,z,b,8),doubled_denominator=limbs.Spec(1,d,2,8))
    entries=dict(sign_lhs=limbs.Spec(2,2*t,2,8),sign_rhs=limbs.Spec(2,t,1,8),
                 sign_gap=limbs.Spec(2,max(t,1),1,8),numerator=limbs.Spec(1,t,a,8),
                 biased=limbs.Spec(2,max(u,d),2,8),quotient_product=limbs.Spec(1,32768,d,8),
                 division=limbs.Spec(2,max(32768*d,2*d-1),2,8),remainder_gap=limbs.Spec(3,2*d-1,1,8))
    return dict(asdict(p),prime=2**31-1,probability_max=probability,restored_max=s,block_raw_max=raw,
                rounded_block_max=small,block_count_max=blocks,total_max=t,z_min=probability,z_max=z,
                left_factor=a,right_factor=b,numerator_max=u,denominator_max=d,double_denominator_max=2*d,
                biased_max=2*u+d,quotient_max=32768,scaled_quotient_max=32768*d,remainder_max=2*d-1,
                output_max=32768,source_offset_max=2*t,source_gap_max=t,
                shared_columns={k:oracle(s) for k,s in shared.items()},entry_columns={k:oracle(s) for k,s in entries.items()})


def frame(p,c):
    raw=b'stele/research/q26/attention-normalization-bounds/v1\0'
    raw+=struct.pack('<IHBBBBHBB',p.length,p.width,p.fraction,p.output_fraction,p.exponent,
                     ('dynamic','static').index(p.value_mode),p.scale,('exact','block1024').index(p.accumulation),p.drop)
    raw+=struct.pack('<IBB',2**31-1,8,len(NAMES))+b''.join(c[k].to_bytes(20,'little') for k in NAMES)
    for group in ('shared_columns','entry_columns'):
        raw+=bytes([len(c[group])])
        for i,rec in enumerate(c[group].values(),1):
            raw+=struct.pack('<BI',i,rec['count'])+b''.join(rec[k].to_bytes(20,'little') for k in ('left_max','right_max','result_max'))
            raw+=bytes(len(rec[k]) for k in ('left_caps','right_caps','result_caps'))
            raw+=b''.join(bytes(rec[k]) for k in ('left_caps','right_caps','result_caps'))
            raw+=b''.join(struct.pack('<I',v) for k in ('carry_caps','lhs','rhs') for v in rec[k])
    return raw


def reference(p,z,totals):
    return tuple(rounded(Q(t,z)*Q(2)**(p.output_fraction-p.fraction+p.drop)) for t in totals)


def controls():
    p=r.Spec(1<<20,1,0,0,14,'static',65535,'exact',0); c=r.derive(p); prime=2**31-1
    w=r.witness(p,prime,(prime,)); assert r.check_relations(p,c,prime,(prime,),w)==(1,)
    # Coherent wrong quotient: each local field equality holds, but biased/division differ by 2p.
    bad=copy.deepcopy(w); bad['entries'][0].update(quotient=0,scaled_quotient=0,remainder=prime,remainder_gap=prime-1,output=0)
    rejects('IntegerRelation',lambda:r.check_relations(p,c,prime,(prime,),r.attach(p,prime,(prime,),bad)))
    # Source-sign alias yields zero for a true negative normalized value.
    bad=r.witness(p,prime,(-prime,)); bad['entries'][0].update(sign=0,magnitude=0,sign_gap=0,numerator=0,
                    quotient=0,scaled_quotient=0,remainder=prime,remainder_gap=prime-1,output=0)
    rejects('IntegerRelation',lambda:r.check_relations(p,c,prime,(-prime,),r.attach(p,prime,(-prime,),bad)))
    # A coherent changed divisor would change the answer from two to one.
    bad=r.witness(p,prime,(2*prime,)); bad['denominator']=2*prime
    bad['entries'][0].update(quotient=1,scaled_quotient=2*prime,remainder=2*prime,remainder_gap=2*prime-1,output=1)
    rejects('IntegerRelation',lambda:r.check_relations(p,c,prime,(2*prime,),r.attach(p,prime,(2*prime,),bad)))
    # Preserve the integer division but wrap its strict remainder comparison by p.
    bad=r.witness(p,16384,(32768,)); bad['entries'][0].update(quotient=1,scaled_quotient=16384,
                    remainder=49152,remainder_gap=prime-16385,output=1)
    rejects('IntegerRelation',lambda:r.check_relations(p,c,16384,(32768,),r.attach(p,16384,(32768,),bad)))
    check=lambda v:r.check_relations(p,c,prime,(prime,),v)
    for field in ('magnitude','sign_gap','numerator','quotient','scaled_quotient','remainder','remainder_gap'):
        bad=copy.deepcopy(w); bad['entries'][0][field]+=1
        rejects('IntegerRelation',lambda:check(r.attach(p,prime,(prime,),bad)))
    bad=copy.deepcopy(w); bad['entries'][0]['output']=2; rejects('OutputRelation',lambda:check(bad))
    bad=copy.deepcopy(w); bad['entries'][0]['sign']=True; rejects('Witness',lambda:check(bad))
    zero=r.witness(p,prime,(0,)); zero['entries'][0]['sign']=1
    rejects('IntegerRelation',lambda:r.check_relations(p,c,prime,(0,),r.attach(p,prime,(0,),zero)))
    rejects('SourceDigits',lambda:check(r.witness(p,prime+1,(prime,))))
    rejects('SourceDigits',lambda:check(r.witness(p,prime,(prime+1,))))
    for key,value in c.items():
        if key.endswith('_columns'):
            for role,record in value.items():
                for field,v in record.items():
                    bad=copy.deepcopy(c); bad[key][role][field]=(v[0]+1,)+v[1:] if type(v) is tuple else v+1
                    rejects('Certificate',lambda:r.validate(p,bad))
        else:
            bad=copy.deepcopy(c); bad[key]=value+'x' if type(value) is str else value+1
            rejects('Certificate',lambda:r.validate(p,bad))
    for group,cols in (('shared_columns',w['columns']),('entry_columns',w['entries'][0]['columns'])):
        for role in cols:
            bad=copy.deepcopy(w); col=bad['columns'][role] if group=='shared_columns' else bad['entries'][0]['columns'][role]
            col['carry']=col['carry'][:-1]+(1,); rejects('Boundary',lambda:check(bad))
            bad=copy.deepcopy(w); col=bad['columns'][role] if group=='shared_columns' else bad['entries'][0]['columns'][role]
            col['result']=(col['result'][0]+prime,)+col['result'][1:]; rejects('Range',lambda:check(bad))
    for z in (0,16383,c['z_max']+1,True): rejects('Divisor',lambda:r.witness(p,z,(0,)))
    for xs in ((True,),(c['total_max']+1,),()): rejects('Input',lambda:r.witness(p,prime,xs))
    for field,value in (('drop',1),('output_fraction',31),('fraction',-1),('exponent',15),('width',True)):
        rejects('Spec',lambda:r.derive(replace(p,**{field:value})))
    rejects('BlockBound',lambda:r.derive(replace(p,accumulation='block1024')))
    small=replace(p,length=4,exponent=0)
    for x in (-3,-1,0,1,3,-65536,65534):
        assert r.check_relations(small,r.derive(small),2,(x,),r.witness(small,2,(x,)))==reference(small,2,(x,))
    rejects('OutputRange',lambda:r.witness(small,2,(65536,)))
    flat=replace(p,accumulation='block1024',drop=62,output_fraction=30)
    assert r.derive(flat)['total_max']==0
    assert r.check_relations(flat,r.derive(flat),16384,(0,),r.witness(flat,16384,(0,)))==(0,)
    wide=replace(p,fraction=30); wc=r.derive(wide); wz=wc['z_max']; wt=(wc['total_max'],)
    ww=r.witness(wide,wz,wt); assert ww['denominator']==2**64
    assert r.check_relations(wide,wc,wz,wt,ww)==reference(wide,wz,wt)==(0,)
    for spec in (p,small,flat,replace(p,fraction=30)):
        raw=r.encode(spec); assert raw==frame(spec,certificate(spec)) and len(raw)<=4096
        for end in range(len(raw)): rejects('Encoding',lambda:r.validate_bytes(spec,raw[:end]))
        for i in range(len(raw)): rejects('Encoding',lambda:r.validate_bytes(spec,raw[:i]+bytes([raw[i]^1])+raw[i+1:]))
        rejects('Encoding',lambda:r.validate_bytes(spec,raw+b'\0'))


def model_heads(p,expected):
    spec=model_bounds.spec(p); cert=r.derive(spec)
    for head in expected['heads']:
        z=head['z']; totals=tuple(head['total'])
        assert r.check_relations(spec,cert,z,totals,r.witness(spec,z,totals))==tuple(head['wide'])


def model_rows(model,expected,positions):
    for i,b in enumerate(model.blocks):
        for cell in block_reference(b,expected['cuts'][i],positions): model_heads(b.attention,cell['attention'])


def models():
    rng=random.Random(2646); accepted=0
    for case in range(30):
        model=make(rng,case); blocks=[]
        for b in model.blocks:
            p=b.attention; mode='static' if case%3==0 else 'dynamic'; scale=(65535 if case%6==0 else 256) if mode=='static' else 0
            a=replace(p.attention,fv=5+case%7,fo=6+(case//7)%5,value_mode=mode,value_scale=scale,accumulation='exact',drop=0)
            if p.attention.accumulation=='block1024': a=replace(a,accumulation='block1024',drop=model_bounds.m.b.pa.a.minimum_drop(a)+case%3)
            blocks.append(replace(b,attention=replace(p,attention=a)))
        model=replace(model,blocks=tuple(blocks)); rows=model_bounds.records(model); assert len(rows)==len(blocks)
        weight=model.embedding; zero=replace(weight,codes=tuple((0,)*len(row) for row in weight.codes),mantissas=(1,)*len(weight.codes))
        assert model_bounds.records(replace(model,embedding=zero))==rows
        try: expected=model_reference(model,[0,1,2])
        except ValueError as error:
            assert str(error)=='Overflow'
            continue
        model_rows(model,expected,[0,1,2]); accepted+=1
    assert accepted==28
    p=attention_config(n=2050); a=replace(p.attention,accumulation='block1024',drop=model_bounds.m.b.pa.a.minimum_drop(p.attention))
    p=replace(p,attention=a)
    expected=attention_reference(p,2048,[1,2,3,4],[1023,1024,2048],[[1,2],[-1,3],[4,-2]],
                                 [[1024,-1024],[100,2],[1024,-1024]],[True,False,True])
    model_heads(p,expected)
    return accepted


def check():
    rng=random.Random(2645); digest=hashlib.sha256(); accepted=rejected=small_cases=0
    for case in range(10000):
        mode='dynamic' if case%3 else 'static'; accumulation='exact' if case%2 else 'block1024'
        p=r.Spec(rng.randrange(1,(1<<20)+1),rng.randrange(1,5),rng.randrange(31),rng.randrange(31),rng.randrange(15),
                 mode,0 if mode=='dynamic' else rng.randrange(1,65536),accumulation,0)
        if accumulation=='block1024':
            c=certificate(p); drop=next(k for k in range(63) if rounded(Q(c['block_raw_max'],2**k))<=32767)
            p=replace(p,drop=rng.randrange(drop,63))
        c=r.derive(p); assert c==certificate(p); raw=r.encode(p); assert raw==frame(p,c); r.validate_bytes(p,raw)
        z=rng.randrange(c['z_min'],c['z_max']+1)
        total=tuple(rng.randrange(-c['total_max'],c['total_max']+1) for _ in range(p.width))
        if case%7==0: total=(0,)*p.width
        expected=reference(p,z,total)
        digest.update(raw+json.dumps([z,total,expected],separators=(',',':')).encode())
        if any(not -32768<=v<=32767 for v in expected):
            rejects('OutputRange',lambda:r.witness(p,z,total)); rejected+=1; continue
        w=r.witness(p,z,total); assert r.check_relations(p,c,z,total,w)==expected; accepted+=1
        shared,entries=r.column_inputs(p,z,total,w)
        for name,col in w['columns'].items(): assert numpy_columns(*shared[name],8)==sum(v*256**i for i,v in enumerate(col['result']))
        for e,values in zip(w['entries'],entries):
            for name,col in e['columns'].items(): assert numpy_columns(*values[name],8)==sum(v*256**i for i,v in enumerate(col['result']))
        numerators=[abs(t)*c['left_factor'] for t in total]; denominator=z*c['right_factor']
        if max(2*v+denominator for v in numerators)<2**63 and 2*denominator<2**63:
            answers=(2*np.asarray(numerators,dtype=np.int64)+denominator)//(2*denominator)
            assert tuple((-1 if t<0 else 1)*int(v) for t,v in zip(total,answers))==expected
            small_cases+=1
    assert (accepted,rejected,small_cases)==(6935,3065,6935)
    assert digest.hexdigest()=='4058a256af22725c1a630307b54ef2e0f59bd278ab64b01def36b8b83ce1c476'
    model_cases=models(); controls()
    print(json.dumps(dict(seed=2645,accepted=accepted,rejected=rejected,numpy_divisions=small_cases,model_seed=2646,models_accepted=model_cases,
                          sha256=digest.hexdigest()),sort_keys=True))
