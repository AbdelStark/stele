"""Q26 / Draft RFC-0004 A3/A6, RFC-0009 A2: signed attention sum arithmetic and attacks."""
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
import attention_sum_bounds as r
import bounded_columns as bounded
import limbs
from check_limbs import oracle, numpy_columns, rejects
import model_attention_sum_bounds as model_bounds
from check_causal_model import make, reference as model_reference
from check_decoder_block import reference as block_reference
from check_projected_attention import rotation, convert, rounded, probability, oracle as attention_reference, config as attention_config


def certificate(p):
    count=p.length if p.accumulation=='exact' else min(1024,p.length)
    code=127 if p.value_mode=='dynamic' else min(127,(65536+p.scale)//(2*p.scale))
    scale=259 if p.value_mode=='dynamic' else p.scale; s=code*scale; probability=2**p.exponent
    z=count*probability; h=z*s
    shared=dict(weight_sum=limbs.Spec(count,probability,1,4),base=limbs.Spec(1,z,s,4))
    entries=dict(offset_sum=limbs.Spec(count,probability,2*s,4),sign_lhs=limbs.Spec(2,2*h,2,4),
                 sign_rhs=limbs.Spec(2,h,1,4),sign_gap=limbs.Spec(2,h,1,4))
    return dict(asdict(p),prime=2**31-1,term_cap=count,probability_max=probability,code_max=code,
                scale_min=0 if p.value_mode=='dynamic' else scale,scale_max=scale,restored_max=s,
                value_offset_max=2*s,weight_sum_max=z,base_max=h,offset_sum_max=2*h,magnitude_max=h,
                source_rhs_max=2*s,entry_capacity=1<<20,block_max=(p.length-1)//1024 if p.accumulation=='block1024' else 0,
                shared_columns={name:oracle(s) for name,s in shared.items()},
                entry_columns={name:oracle(s) for name,s in entries.items()})


def frame(p,c):
    raw=b'stele/research/q26/attention-sum-bounds/v1\0'
    raw+=struct.pack('<IHBBBHB',p.length,p.width,p.fraction,p.exponent,('dynamic','static').index(p.value_mode),
                     p.scale,('exact','block1024').index(p.accumulation))
    names=('term_cap','probability_max','code_max','scale_min','scale_max','restored_max','value_offset_max',
           'weight_sum_max','base_max','offset_sum_max','magnitude_max','source_rhs_max','entry_capacity','block_max')
    raw+=struct.pack('<IBB',2**31-1,4,len(names))+b''.join(c[k].to_bytes(20,'little') for k in names)
    for group in ('shared_columns','entry_columns'):
        raw+=bytes([len(c[group])])
        for i,rec in enumerate(c[group].values(),1):
            raw+=struct.pack('<BI',i,rec['count'])
            raw+=b''.join(rec[k].to_bytes(20,'little') for k in ('left_max','right_max','result_max'))
            raw+=bytes(len(rec[k]) for k in ('left_caps','right_caps','result_caps'))
            raw+=b''.join(bytes(rec[k]) for k in ('left_caps','right_caps','result_caps'))
            raw+=b''.join(struct.pack('<I',v) for k in ('carry_caps','lhs','rhs') for v in rec[k])
    return raw


def reference(weights,codes,scales):
    restored=np.asarray(codes,dtype=np.int64)*np.asarray(scales,dtype=np.int64)[:,None]
    total=np.asarray(weights,dtype=np.int64)@restored
    expected=tuple(sum(w*s*row[j] for w,s,row in zip(weights,scales,codes)) for j in range(len(codes[0])))
    assert tuple(int(v) for v in total)==expected
    return int(np.asarray(weights,dtype=np.int64).sum()),expected


def controls():
    p=r.Spec(4096,2,12,14,'dynamic',0,'exact'); pos=(0,1024,3072); weights=(2,0,3)
    codes=((-3,4),(0,0),(5,-6)); scales=(7,0,9); allowed=(True,False,True)
    args=(pos,0,weights,codes,scales,allowed); c=r.derive(p); w=r.witness(p,*args)
    check=lambda v:r.check_relations(p,c,*args,v)
    assert check(w)==reference(weights,codes,scales)
    other=(codes[0][0]+1,codes[0][1])
    rejects('SourceValue',lambda:check(r.witness(p,pos,0,weights,(other,)+codes[1:],scales,allowed)))
    rejects('SourceValue',lambda:check(r.witness(p,pos,0,weights,codes,(8,)+scales[1:],allowed)))
    rejects('SourceDigits',lambda:check(r.witness(p,pos,0,(3,0,3),codes,scales,allowed)))
    for key,value in c.items():
        if key.endswith('_columns'):
            for role,rec in value.items():
                for field,v in rec.items():
                    bad=copy.deepcopy(c); bad[key][role][field]=(v[0]+1,)+v[1:] if type(v) is tuple else v+1
                    rejects('Certificate',lambda:r.validate(p,bad))
        else:
            bad=copy.deepcopy(c); bad[key]=value+'x' if type(value) is str else value+1
            rejects('Certificate',lambda:r.validate(p,bad))
    bad=copy.deepcopy(w); bad['positions']=(0,1024,3071); rejects('Positions',lambda:check(bad))
    bad=copy.deepcopy(w); bad['block']=1; rejects('Block',lambda:check(bad))
    bad=copy.deepcopy(w); offsets=list(bad['offsets']); offsets[0]=(offsets[0][0]+1,offsets[0][1]); bad['offsets']=tuple(offsets)
    rejects('SourceValue',lambda:check(r.attach(p,*args,bad)))
    for field in ('weight_sum','base'):
        bad=copy.deepcopy(w); bad[field]+=1; rejects('IntegerRelation',lambda:check(r.attach(p,*args,bad)))
    for field in ('offset_sum','magnitude','gap'):
        bad=copy.deepcopy(w); bad['entries'][0][field]+=1
        rejects('IntegerRelation',lambda:check(r.attach(p,*args,bad)))
    bad=copy.deepcopy(w); bad['entries'][0]['sign']=1; rejects('IntegerRelation',lambda:check(r.attach(p,*args,bad)))
    bad=copy.deepcopy(w); bad['entries'][0]['sign']=True; rejects('Witness',lambda:check(bad))
    bad=copy.deepcopy(w); bad['columns']['weight_sum']['left']=bad['columns']['weight_sum']['left'][:-1]
    rejects('Witness',lambda:check(bad))
    for group,columns in (('shared_columns',w['columns']),('entry_columns',w['entries'][0]['columns'])):
        for role in columns:
            bad=copy.deepcopy(w); cols=bad['columns'] if group=='shared_columns' else bad['entries'][0]['columns']
            col=cols[role]; col['carry']=col['carry'][:-1]+(1,); rejects('Boundary',lambda:check(bad))
            bad=copy.deepcopy(w); cols=bad['columns'] if group=='shared_columns' else bad['entries'][0]['columns']
            col=cols[role]; col['result']=(col['result'][0]+r.P,)+col['result'][1:]; rejects('Range',lambda:check(bad))
            bad=copy.deepcopy(w); cols=bad['columns'] if group=='shared_columns' else bad['entries'][0]['columns']
            col=cols[role]; carry=col['carry']; changed=carry[1]-1 if carry[1] else 1
            assert changed<=c[group][role]['carry_caps'][1]
            col['carry']=(carry[0],changed)+carry[2:]; rejects('Relation',lambda:check(bad))
    # Source-domain checks remain active even when the offending probability is zero.
    rejects('MaskWeight',lambda:r.witness(p,pos,0,(2,1,3),codes,scales,allowed))
    rejects('ZeroScale',lambda:r.witness(p,pos,0,weights,(codes[0],(1,0),codes[2]),scales,allowed))
    rejects('Scale',lambda:r.witness(p,pos,0,weights,codes,(7,260,9),allowed))
    rejects('Codes',lambda:r.witness(p,pos,0,weights,(codes[0],(128,0),codes[2]),scales,allowed))
    rejects('Weights',lambda:r.witness(p,pos,0,(True,0,3),codes,scales,allowed))
    rejects('Positions',lambda:r.witness(p,(0,0,3072),0,weights,codes,scales,allowed))
    rejects('Positions',lambda:r.witness(p,(0,1024,4096),0,weights,codes,scales,allowed))
    rejects('Positions',lambda:r.witness(replace(p,width=16384),tuple(range(65)),0,(),(),(),()))
    cancellation=((0,1),0,(16384,16384),((-127,127),(127,-127)),(259,259),(True,True))
    assert r.check_relations(p,c,*cancellation,r.witness(p,*cancellation))==(32768,(0,0))
    block=replace(p,accumulation='block1024')
    rejects('Block',lambda:r.witness(block,*args))
    zeroargs=((1024,),1,(0,),((0,0),),(0,),(False,)); zero=r.witness(block,*zeroargs)
    assert r.check_relations(block,r.derive(block),*zeroargs,zero)==(0,(0,0))
    zero['entries'][0]['sign']=1
    rejects('IntegerRelation',lambda:r.check_relations(block,r.derive(block),*zeroargs,r.attach(block,*zeroargs,zero)))
    # An honest canonical negative static conversion gives the forged sign equality exactly p.
    alias=r.Spec(1<<20,1,0,14,'static',65535,'exact'); aa=((0,1),0,(16384,16384),((-1,),(-1,)),(65535,65535),(True,True))
    good=r.witness(alias,*aa); actual=-(2**31-32768); forged=32767
    assert (actual-forged)%r.P==0 and r.check_relations(alias,r.derive(alias),*aa,good)==(32768,(actual,))
    bad=copy.deepcopy(good); bad['entries'][0].update(sign=0,magnitude=forged,gap=forged)
    rejects('IntegerRelation',lambda:r.check_relations(alias,r.derive(alias),*aa,r.attach(alias,*aa,bad)))
    bad=copy.deepcopy(good); bad['weight_sum']+=r.P; bad['base']=bad['weight_sum']*65535
    rejects('IntegerRelation',lambda:r.check_relations(alias,r.derive(alias),*aa,r.attach(alias,*aa,bad)))
    maximum=limbs.Spec(1<<20,1<<14,2*65535,4); cert=limbs.derive(maximum)
    assert max(cert['lhs']+cert['rhs'])==816840975
    rejects('FieldBound',lambda:limbs.derive(replace(maximum,radix_bits=8)))
    rejects('FieldBound',lambda:bounded.witness(replace(maximum,radix_bits=8),(0,),(0,)))
    rejects('InputRange',lambda:bounded.witness(maximum,(0,),(131071,)))
    # Fixed capacity does not allocate an unneeded zero tail; extra supplied source rows reject.
    tiny=bounded.witness(maximum,(16384,),(131070,)); assert len(tiny['left'])==len(tiny['right'])==1
    assert bounded.check_relations(maximum,cert,(16384,),(131070,),tiny)==16384*131070
    bad=copy.deepcopy(tiny); bad['left']+=bad['left']; rejects('Witness',lambda:bounded.check_relations(maximum,cert,(16384,),(131070,),bad))
    for field,value in (('length',0),('length',2**20+1),('width',16385),('fraction',31),('exponent',15),
                        ('value_mode','other'),('scale',1),('accumulation','other'),('width',True)):
        rejects('Spec',lambda:r.derive(replace(p,**{field:value})))
    for t in (p,alias,replace(alias,accumulation='block1024')):
        raw=r.encode(t); assert len(raw)<=2048
        for end in range(len(raw)): rejects('Encoding',lambda:r.validate_bytes(t,raw[:end]))
        for i in range(len(raw)): rejects('Encoding',lambda:r.validate_bytes(t,raw[:i]+bytes([raw[i]^1])+raw[i+1:]))
        rejects('Encoding',lambda:r.validate_bytes(t,raw+b'\0'))


def model_row(p,position,q,positions,keys,values,allowed,expected):
    # Convert the whole K/V/Q projections before slicing head/group views.
    ks=[convert(rotation(p,j,k,p.groups),p.k_mode,p.k_scale) for j,k in zip(positions,keys)]
    vs=[convert(v,p.attention.value_mode,p.attention.value_scale) for v in values]
    qs,qc=convert(rotation(p,position,q,p.heads),p.q_mode,p.q_scale); spec=model_bounds.spec(p)
    for head in range(p.heads):
        group=head//(p.heads//p.groups); lo=group*p.width; hi=lo+p.width
        scores=[rounded(Q(sum(x*y for x,y in zip(qc[head*p.width:(head+1)*p.width],k[lo:hi]))*qs*s*p.score_m)*
                        Q(2)**(p.score_e-p.fq-p.fk+p.attention.function.params[1])) for s,k in ks]
        maximum=max(v for v,bit in zip(scores,allowed) if bit)
        weights=[probability(p,maximum-v) if bit else 0 for v,bit in zip(scores,allowed)]
        groups={}
        for i,j in enumerate(positions): groups.setdefault(j//1024 if p.attention.accumulation=='block1024' else 0,[]).append(i)
        total=[0]*p.width; z=0
        for block,indices in groups.items():
            args=(tuple(positions[i] for i in indices),block,tuple(weights[i] for i in indices),
                  tuple(tuple(vs[i][1][lo:hi]) for i in indices),tuple(vs[i][0] for i in indices),tuple(allowed[i] for i in indices))
            answer=r.check_relations(spec,r.derive(spec),*args,r.witness(spec,*args)); z+=answer[0]
            assert answer==reference(args[2],args[3],args[4])
            total=[x+rounded(Q(v,1<<p.attention.drop)) for x,v in zip(total,answer[1])]
        assert (z,total)==(expected['heads'][head]['z'],expected['heads'][head]['total'])


def models():
    rng=random.Random(2644); accepted=0
    for case in range(30):
        model=make(rng,case); blocks=[]
        for b in model.blocks:
            p=b.attention; mode='static' if case%3==0 else 'dynamic'; scale=(65535 if case%6==0 else 256) if mode=='static' else 0
            a=replace(p.attention,value_mode=mode,value_scale=scale,accumulation='exact',drop=0)
            if p.attention.accumulation=='block1024': a=replace(a,accumulation='block1024',drop=model_bounds.m.b.pa.a.minimum_drop(a))
            blocks.append(replace(b,attention=replace(p,attention=a)))
        model=replace(model,blocks=tuple(blocks)); rows=model_bounds.records(model); assert len(rows)==len(blocks)
        weight=model.embedding; zero=replace(weight,codes=tuple((0,)*len(row) for row in weight.codes),mantissas=(1,)*len(weight.codes))
        assert model_bounds.records(replace(model,embedding=zero))==rows
        try: expected=model_reference(model,[0,1,2])
        except ValueError as error:
            assert str(error)=='Overflow'
            continue
        for i,b in enumerate(blocks):
            cells=block_reference(b,expected['cuts'][i],[0,1,2]); keys=[v['k'] for v in cells]; values=[v['v'] for v in cells]
            for j,cell in enumerate(cells): model_row(b.attention,j,cell['q'],[0,1,2],keys,values,[k<=j for k in range(3)],cell['attention'])
        accepted+=1
    assert accepted==28
    p=attention_config(n=2050); a=replace(p.attention,accumulation='block1024',drop=model_bounds.m.b.pa.a.minimum_drop(p.attention))
    p=replace(p,attention=a); positions=[1023,1024,2048]; keys=[[1,2],[-1,3],[4,-2]]; values=[[1024,-1024],[100,2],[1024,-1024]]
    q=[1,2,3,4]; allowed=[True,False,True]
    expected=attention_reference(p,2048,q,positions,keys,values,allowed)
    assert expected['heads'][0]['total']==[2,-2]  # Compacting keys into one block would give [1,-1].
    model_row(p,2048,q,positions,keys,values,allowed,expected)
    return accepted


def model_rows(model,expected,positions):
    for i,b in enumerate(model.blocks):
        cells=block_reference(b,expected['cuts'][i],positions); keys=[v['k'] for v in cells]; values=[v['v'] for v in cells]
        for j,cell in zip(positions,cells):
            model_row(b.attention,j,cell['q'],positions,keys,values,[k<=j for k in positions],cell['attention'])


def check():
    rng=random.Random(2643); digest=hashlib.sha256()
    for case in range(10000):
        mode='dynamic' if case%3 else 'static'
        p=r.Spec(rng.randrange(1,(1<<20)+1),rng.randrange(1,5),rng.randrange(31),rng.randrange(15),
                 mode,0 if mode=='dynamic' else rng.randrange(1,65536),'exact' if case%2 else 'block1024')
        c=r.derive(p); assert c==certificate(p); raw=r.encode(p); assert raw==frame(p,c); r.validate_bytes(p,raw)
        block=0 if p.accumulation=='exact' else rng.randrange(c['block_max']+1)
        lo,hi=(0,p.length) if p.accumulation=='exact' else (block*1024,min(p.length,(block+1)*1024))
        n=rng.randrange(1,min(8,hi-lo)+1); pos=tuple(sorted(rng.sample(range(lo,hi),n)))
        scales=tuple(rng.randrange(260) if mode=='dynamic' else p.scale for _ in pos)
        codes=tuple(tuple(rng.randrange(-c['code_max'],c['code_max']+1) if s else 0 for _ in range(p.width)) for s in scales)
        allowed=tuple(bool(rng.randrange(2)) for _ in pos)
        weights=tuple(rng.randrange(c['probability_max']+1) if bit else 0 for bit in allowed)
        args=(pos,block,weights,codes,scales,allowed); w=r.witness(p,*args); expected=reference(weights,codes,scales)
        assert r.check_relations(p,c,*args,w)==expected
        shared,entries=r.column_inputs(p,weights,w)
        for name,col in w['columns'].items(): assert numpy_columns(*shared[name],4)==sum(v*16**i for i,v in enumerate(col['result']))
        for e,values in zip(w['entries'],entries):
            for name,col in e['columns'].items(): assert numpy_columns(*values[name],4)==sum(v*16**i for i,v in enumerate(col['result']))
        digest.update(raw+json.dumps([args,expected],separators=(',',':')).encode())
    accepted=models()
    controls()
    assert digest.hexdigest()=='008219d51e2d96bc9fa90c5508243b09f7917c022cab2e58701f84ede055f55e'
    print(json.dumps(dict(seed=2643,cases=10000,model_seed=2644,models_accepted=accepted,sha256=digest.hexdigest()),sort_keys=True))
