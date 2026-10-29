"""Q26 / Draft RFC-0004 A3/A8: exact gated products and coherent M31 alias controls."""
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
import gated_product_bounds as r
import limbs
import row_bounds
import model_gated_product_bounds as model_bounds
import model_scaled_bounds as scaled
from check_limbs import oracle, numpy_columns, rejects
from check_causal_model import make, reference as model_reference
from check_decoder_block import reference as block_reference

NAMES=('product_fraction','source_max','source_high','source_offset_max','output_max','output_offset_max',
       'offset_product_max','offset_bias','restoration_factor','entry_capacity')


def certificate(p):
    specs=dict(product=limbs.Spec(1,65535,65535,8),lhs=limbs.Spec(2,65535**2,1,8),rhs=limbs.Spec(3,2**31,32768,8))
    return dict(asdict(p),prime=2**31-1,product_fraction=p.up_fraction+p.silu_fraction,source_max=32768,source_high=32767,
                source_offset_max=65535,output_max=2**30,output_offset_max=2**31,offset_product_max=65535**2,
                offset_bias=2**31,restoration_factor=32768,entry_capacity=16384,
                columns={name:oracle(s) for name,s in specs.items()})


def frame(p,c):
    raw=b'stele/research/q26/gated-product-bounds/v1\0'+struct.pack('<IBB',p.dimension,p.up_fraction,p.silu_fraction)
    raw+=struct.pack('<IBB',2**31-1,8,len(NAMES))+b''.join(struct.pack('<Q',c[k]) for k in NAMES)+bytes([len(c['columns'])])
    for i,rec in enumerate(c['columns'].values(),1):
        raw+=struct.pack('<BIQQQ',i,rec['count'],rec['left_max'],rec['right_max'],rec['result_max'])
        raw+=bytes(len(rec[k]) for k in ('left_caps','right_caps','result_caps'))
        raw+=b''.join(bytes(rec[k]) for k in ('left_caps','right_caps','result_caps'))
        raw+=b''.join(struct.pack('<I',v) for k in ('carry_caps','lhs','rhs') for v in rec[k])
    return raw


def reference(xs,ys):
    result=tuple(int(v) for v in np.asarray(xs,dtype=np.int64)*np.asarray(ys,dtype=np.int64))
    assert result==tuple(x*y for x,y in zip(xs,ys))
    return result


def controls():
    p=r.Spec(1,30,14); c=r.derive(p); xs=ys=(-32768,); w=r.witness(p,xs,ys)
    check=lambda v:r.check_relations(p,c,xs,ys,v)
    assert check(w)==(2**30,)
    bad=copy.deepcopy(w); bad['entries'][0]['output']=-(2**30)+1
    assert (bad['entries'][0]['output']-2**30)%r.P==0
    rejects('IntegerRelation',lambda:check(r.attach(p,xs,ys,bad)))
    # Alter the offset product by p, preserving both wide field equalities.
    zero=(0,); zw=r.witness(p,zero,zero); zw['entries'][0]['offset_product']+=r.P
    rejects('IntegerRelation',lambda:r.check_relations(p,c,zero,zero,r.attach(p,zero,zero,zw)))
    zcheck=lambda v:r.check_relations(p,c,zero,zero,v); base=r.witness(p,zero,zero)
    for key in ('offset_product','output'):
        bad=copy.deepcopy(base); bad['entries'][0][key]+=1
        rejects('IntegerRelation',lambda:zcheck(r.attach(p,zero,zero,bad)))
    rejects('SourceDigits',lambda:r.check_relations(p,c,(-32767,),ys,w))
    rejects('SourceDigits',lambda:r.check_relations(p,c,xs,(-32767,),w))
    bad=copy.deepcopy(w); bad['entries'][0]['output']=2**30+1; rejects('Range',lambda:check(bad))
    bad=copy.deepcopy(w); bad['entries'][0]['offset_product']=65535**2+1; rejects('Range',lambda:check(bad))
    bad=copy.deepcopy(w); bad['entries'][0]['output']=True; rejects('Witness',lambda:check(bad))
    bad=copy.deepcopy(w); bad['entries']=(); rejects('Witness',lambda:check(bad))
    bad=copy.deepcopy(w); bad['entries']+=bad['entries']; rejects('Witness',lambda:check(bad))
    bad=copy.deepcopy(w); del bad['entries'][0]['columns']['rhs']; rejects('Witness',lambda:check(bad))
    for a,b in (((),ys),(xs,()),([0],ys),((True,),ys),((32768,),ys),(xs,(-32769,))):
        rejects('Input',lambda:r.witness(p,a,b))
    for key,value in c.items():
        if key=='columns':
            for role,rec in value.items():
                for field,v in rec.items():
                    bad=copy.deepcopy(c); bad[key][role][field]=(v[0]+1,)+v[1:] if type(v) is tuple else v+1
                    rejects('Certificate',lambda:r.validate(p,bad))
        else:
            bad=copy.deepcopy(c); bad[key]=value+1; rejects('Certificate',lambda:r.validate(p,bad))
    for role in w['entries'][0]['columns']:
        bad=copy.deepcopy(w); col=bad['entries'][0]['columns'][role]; col['carry']=col['carry'][:-1]+(1,)
        rejects('Boundary',lambda:check(bad))
        bad=copy.deepcopy(w); col=bad['entries'][0]['columns'][role]; col['result']=(col['result'][0]+r.P,)+col['result'][1:]
        rejects('Range',lambda:check(bad))
        caps=c['columns'][role]['carry_caps']; i=next(i for i in range(1,len(caps)-1) if caps[i])
        bad=copy.deepcopy(w); col=bad['entries'][0]['columns'][role]; carry=list(col['carry'])
        carry[i]=carry[i]-1 if carry[i] else 1; col['carry']=tuple(carry); rejects('Relation',lambda:check(bad))
    for field,value in (('dimension',0),('dimension',16385),('up_fraction',31),('silu_fraction',15),('up_fraction',-1),('dimension',True)):
        rejects('Spec',lambda:r.derive(replace(p,**{field:value})))
    pair=replace(p,dimension=2); a=(1,2); b=(3,4); wrong=r.witness(pair,a,b); wrong['entries']=wrong['entries'][::-1]
    rejects('SourceDigits',lambda:r.check_relations(pair,r.derive(pair),a,b,wrong))
    for x in (-32768,-32767,-1,0,1,32767):
        for y in (-32768,-32767,-1,0,1,32767):
            assert r.check_relations(p,c,(x,),(y,),r.witness(p,(x,),(y,)))==reference((x,),(y,))
    large=replace(p,dimension=16384); aa=(-32768,32767,0,-1)*4096; bb=(-32768,-32768,32767,1)*4096
    assert r.check_relations(large,r.derive(large),aa,bb,r.witness(large,aa,bb))==reference(aa,bb)
    for spec in (p,large,replace(p,up_fraction=0,silu_fraction=0)):
        raw=r.encode(spec); assert raw==frame(spec,certificate(spec)) and len(raw)<=512
        for end in range(len(raw)): rejects('Encoding',lambda:r.validate_bytes(spec,raw[:end]))
        for i in range(len(raw)): rejects('Encoding',lambda:r.validate_bytes(spec,raw[:i]+bytes([raw[i]^1])+raw[i+1:]))
        rejects('Encoding',lambda:r.validate_bytes(spec,raw+b'\0'))


def model_cell(b,cell):
    p=model_bounds.spec(b); xs=tuple(cell['up']); ys=tuple(cell['silu'])
    products=r.check_relations(p,r.derive(p),xs,ys,r.witness(p,xs,ys))
    assert products==tuple(cell['product'])==reference(xs,ys)
    rp=row_bounds.Spec('gated',p.dimension,p.up_fraction+p.silu_fraction,*b.gated)
    scale,codes=row_bounds.check_relations(rp,row_bounds.derive(rp),products,row_bounds.witness(rp,products))
    assert (scale,codes,rp.fraction)==(cell['h'].scale,cell['h'].codes,cell['h'].fraction)
    wd=b.weights[6]; sp=scaled.s.Spec('gated',p.dimension,wd.bits,wd.exponent,rp.fraction,b.fd,*b.gated)
    cert=scaled.s.derive(sp); dots=np.asarray(wd.codes,dtype=np.int64)@np.asarray(codes,dtype=np.int64)
    result=tuple(scaled.s.check_relations(sp,cert,int(dot),m,scale,scaled.s.witness(sp,int(dot),m,scale))
                 for dot,m in zip(dots,wd.mantissas))
    assert result==tuple(cell['down'])
    return products


def model_rows(model,expected,positions):
    for i,b in enumerate(model.blocks):
        for cell in block_reference(b,expected['cuts'][i],positions): model_cell(b,cell)


def models():
    rng=random.Random(2654); accepted=0
    for case in range(30):
        model=make(rng,case); blocks=[]
        for b in model.blocks:
            silu=replace(b.silu,params=bytes([b.silu.params[0],6+(case//5)%3]))
            blocks.append(replace(b,fu=6+case%5,silu=silu,gated=('static',257+case) if case%4==0 else ('dynamic',0)))
        model=replace(model,blocks=tuple(blocks)); records=model_bounds.records(model); assert len(records)==len(blocks)
        weight=model.embedding; zero=replace(weight,codes=tuple((0,)*len(row) for row in weight.codes),mantissas=(1,)*len(weight.codes))
        assert model_bounds.records(replace(model,embedding=zero))==records
        try: expected=model_reference(model,[0,1,2])
        except ValueError as error:
            assert str(error)=='Overflow'
            rejects('Overflow',lambda:model_bounds.m.full(model,[0,1,2]))
            continue
        actual=model_bounds.m.full(model,[0,1,2]); assert {k:actual[k] for k in expected}==expected
        model_rows(model,expected,[0,1,2]); accepted+=1
    assert accepted==28
    return accepted


def check():
    rng=random.Random(2653); digest=hashlib.sha256()
    for case in range(10000):
        p=r.Spec(rng.randrange(1,10),rng.randrange(31),rng.randrange(15)); c=r.derive(p)
        assert c==certificate(p); raw=r.encode(p); assert raw==frame(p,c); r.validate_bytes(p,raw)
        wide=replace(p,dimension=rng.randrange(1,16385)); assert r.derive(wide)==certificate(wide) and r.encode(wide)==frame(wide,certificate(wide))
        xs=tuple(rng.randrange(-32768,32768) for _ in range(p.dimension)); ys=tuple(rng.randrange(-32768,32768) for _ in xs)
        w=r.witness(p,xs,ys); expected=reference(xs,ys); assert r.check_relations(p,c,xs,ys,w)==expected
        for e,vs in zip(w['entries'],r.column_inputs(p,xs,ys,w)):
            for role,col in e['columns'].items(): assert numpy_columns(*vs[role],8)==sum(v*256**i for i,v in enumerate(col['result']))
        digest.update(raw+r.encode(wide)+json.dumps([xs,ys,expected],separators=(',',':')).encode())
    assert digest.hexdigest()=='23d27d03d47fb95ddee8addd66d2e729f5f0b6573bcd97694e988b038b6d8924'
    model_count=models(); controls()
    print(json.dumps(dict(seed=2653,cases=10000,static_dimensions=10000,model_seed=2654,models_accepted=model_count,
                          sha256=digest.hexdigest()),sort_keys=True))
