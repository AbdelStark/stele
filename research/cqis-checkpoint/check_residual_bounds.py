"""Q26 / Draft RFC-0004 A3/A8: independent residual arithmetic and coherent attacks."""
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
import residual_bounds as r
import limbs
from check_limbs import oracle, numpy_columns, rejects
import model_residual_bounds as model_bounds
from check_causal_model import make, reference as model_reference
from check_decoder_block import reference as block_reference


def reference(p,xs,ys):
    common=max(p.left_fraction,p.right_fraction,p.output_fraction)
    values=(np.asarray(xs,dtype=np.int64)*(1<<(common-p.left_fraction))+
            np.asarray(ys,dtype=np.int64)*(1<<(common-p.right_fraction)))
    divisor=1<<(common-p.output_fraction)
    result=np.sign(values)*((np.abs(values)+divisor//2)//divisor)
    for x,y,z in zip(xs,ys,result):
        exact=(Q(x,1<<p.left_fraction)+Q(y,1<<p.right_fraction))*(1<<p.output_fraction)
        a=abs(exact); whole,rem=divmod(a.numerator,a.denominator)
        assert int(z)==(-1 if exact<0 else 1)*(whole+int(2*rem>=a.denominator))
    return tuple(int(v) for v in result)


def certificate(p):
    c=max(p.left_fraction,p.right_fraction,p.output_fraction)
    a=2**(c-p.left_fraction); b=2**(c-p.right_fraction); d=2**(c-p.output_fraction)
    n=32768*(a+b); offset=65535*(a+b)
    specs=dict(aligned=limbs.Spec(2,65535,max(a,b),8),sign_lhs=limbs.Spec(2,offset,2,8),
               sign_rhs=limbs.Spec(2,n,1,8),sign_gap=limbs.Spec(2,n,1,8),
               bias=limbs.Spec(2,max(n,d//2),1,8),quotient_product=limbs.Spec(1,32768,d,8),
               division=limbs.Spec(2,max(32768*d,d-1),1,8))
    return dict(asdict(p),prime=2**31-1,source_max=32768,source_high=32767,left_factor=a,right_factor=b,
                divisor=d,bias=d//2,numerator_max=n,offset_max=offset,quotient_max=32768,
                scaled_quotient_max=32768*d,remainder_max=d-1,output_max=32768,
                columns={name:oracle(s) for name,s in specs.items()})


def frame(p,c):
    raw=b'stele/research/q26/residual-bounds/v1\0'
    raw+=struct.pack('<IBBB',p.dimension,p.left_fraction,p.right_fraction,p.output_fraction)
    names=('source_max','source_high','left_factor','right_factor','divisor','bias','numerator_max',
           'offset_max','quotient_max','scaled_quotient_max','remainder_max','output_max')
    raw+=struct.pack('<IBB',2**31-1,8,len(names))+b''.join(c[k].to_bytes(20,'little') for k in names)
    raw+=bytes([7])
    for i,name in enumerate(('aligned','sign_lhs','sign_rhs','sign_gap','bias','quotient_product','division'),1):
        rec=c['columns'][name]; raw+=struct.pack('<BI',i,rec['count'])
        raw+=b''.join(rec[k].to_bytes(20,'little') for k in ('left_max','right_max','result_max'))
        raw+=bytes(len(rec[k]) for k in ('left_caps','right_caps','result_caps'))
        raw+=b''.join(bytes(rec[k]) for k in ('left_caps','right_caps','result_caps'))
        raw+=b''.join(struct.pack('<I',v) for k in ('carry_caps','lhs','rhs') for v in rec[k])
    return raw


def controls():
    p=r.Spec(3,1,2,0); xs=(1,-1,127); ys=(-1,1,-16); c=r.derive(p); w=r.witness(p,xs,ys)
    check=lambda value:r.check_relations(p,c,xs,ys,value)
    assert check(w)==(0,0,60)
    # Round once: R(1/2-1/4)=0, unlike R(1/2)+R(-1/4)=1.
    bad=copy.deepcopy(w); bad['entries'][0]['output']=1; rejects('OutputRelation',lambda:check(bad))
    for key,value in c.items():
        if key=='columns':
            for role,record in value.items():
                for field,v in record.items():
                    bad=copy.deepcopy(c); bad[key][role][field]=(v[0]+1,)+v[1:] if type(v) is tuple else v+1
                    rejects('Certificate',lambda:r.validate(p,bad))
        else:
            bad=copy.deepcopy(c); bad[key]=value+1; rejects('Certificate',lambda:r.validate(p,bad))
    for field in ('offset','magnitude','sign_gap','scaled_quotient','remainder'):
        bad=copy.deepcopy(w); bad['entries'][2][field]+=1
        rejects('SourceDigits',lambda:check(bad))
        rejects('IntegerRelation',lambda:check(r.attach(p,xs,ys,bad)))
    bad=copy.deepcopy(w); bad['entries'][0]['quotient']+=1
    rejects('IntegerRelation',lambda:check(r.attach(p,xs,ys,bad)))
    bad=copy.deepcopy(w); bad['entries'][0]['sign']=True; rejects('Witness',lambda:check(bad))
    rejects('SourceDigits',lambda:check(r.witness(p,(2,)+xs[1:],ys)))
    rejects('IntegerRelation',lambda:check(r.attach(p,xs,ys,r.witness(p,(2,)+xs[1:],ys))))
    different=replace(p,left_fraction=2,right_fraction=1)
    rejects('IntegerRelation',lambda:check(r.attach(p,xs,ys,r.witness(different,xs,ys))))
    for role in c['columns']:
        bad=copy.deepcopy(w); col=bad['entries'][0]['columns'][role]; col['carry']=col['carry'][:-1]+(1,)
        rejects('Boundary',lambda:check(bad))
        bad=copy.deepcopy(w); col=bad['entries'][0]['columns'][role]; col['result']=(col['result'][0]+r.P,)+col['result'][1:]
        rejects('Range',lambda:check(bad))
    # A field-only signed sum can change the correctly rounded output from +1 to -1.
    p=r.Spec(1,0,30,0); xs=(1,); ys=(-1,); c=r.derive(p); w=r.witness(p,xs,ys)
    numerator=(1<<30)-1; alias=-(1<<30); assert (numerator-alias)%r.P==0
    assert reference(p,xs,ys)==(1,)
    bad=copy.deepcopy(w); bad['entries'][0].update(sign=1,magnitude=-alias,sign_gap=-alias-1,
                                                  quotient=1,scaled_quotient=1<<30,remainder=1<<29,output=-1)
    rejects('IntegerRelation',lambda:r.check_relations(p,c,xs,ys,r.attach(p,xs,ys,bad)))
    zero=r.witness(p,(0,),(0,)); zero['entries'][0]['sign']=1
    rejects('IntegerRelation',lambda:r.check_relations(p,c,(0,),(0,),r.attach(p,(0,),(0,),zero)))
    bad=copy.deepcopy(w); bad['entries'][0]['remainder']=1<<30
    rejects('Range',lambda:r.check_relations(p,c,xs,ys,bad))
    for f in range(31):
        same=r.Spec(1,f,f,f)
        for x,y in ((-32768,0),(32767,0),(32767,-32768),(1,-1)):
            assert r.check_relations(same,r.derive(same),(x,),(y,),r.witness(same,(x,),(y,)))==(x+y,)
        for x in (-32768,32767): rejects('OutputRange',lambda:r.witness(same,(x,),(x,)))
    for x in (-1,1): assert r.witness(r.Spec(1,1,1,0),(x,),(0,))['entries'][0]['output']==x
    for field,value in (('dimension',0),('dimension',2**20+1),('dimension',True),
                        ('left_fraction',-1),('right_fraction',31),('output_fraction',True)):
        rejects('Spec',lambda:r.derive(replace(p,**{field:value})))
    rejects('Input',lambda:r.witness(p,(True,),ys))
    rejects('Input',lambda:r.witness(p,(1+r.P,),ys))
    for t in (p,r.Spec(2**20,30,0,30),r.Spec(1,0,0,30)):
        raw=r.encode(t); assert len(raw)<=2048
        for end in range(len(raw)): rejects('Encoding',lambda:r.validate_bytes(t,raw[:end]))
        for i in range(len(raw)): rejects('Encoding',lambda:r.validate_bytes(t,raw[:i]+bytes([raw[i]^1])+raw[i+1:]))
        rejects('Encoding',lambda:r.validate_bytes(t,raw+b'\0'))


def models():
    rng=random.Random(2640); accepted=0
    for case in range(30):
        model=make(rng,case)
        blocks=tuple(replace(b,norm2=replace(b.norm2,F=6+case%7),fo=5+case%8,fd=6+case%6) for b in model.blocks)
        model=replace(model,blocks=blocks); rows=model_bounds.records(model)
        assert len(rows)==2*len(blocks)
        for _,s,raw in rows: r.validate_bytes(s,raw)
        weight=model.embedding; zero=replace(weight,codes=tuple((0,)*len(row) for row in weight.codes),mantissas=(1,)*len(weight.codes))
        assert model_bounds.records(replace(model,embedding=zero))==rows
        try: expected=model_reference(model,[0,1])
        except ValueError as error:
            assert str(error)=='Overflow'
            continue
        for i,b in enumerate(blocks):
            cells=block_reference(b,expected['cuts'][i],[0,1])
            for row,cell in zip(expected['cuts'][i],cells):
                for attention,xs,ys,output in ((True,row,cell['o'],cell['mid']),
                                               (False,cell['mid'],cell['down'],cell['output'])):
                    s=model_bounds.spec(b,attention); xs,ys=tuple(xs),tuple(ys)
                    assert r.check_relations(s,r.derive(s),xs,ys,r.witness(s,xs,ys))==tuple(output)
                    assert (s.left_fraction,s.right_fraction,s.output_fraction)==(
                        (b.norm1.F,b.fo,b.norm2.F) if attention else (b.norm2.F,b.fd,b.fout))
        accepted+=1
    assert accepted>0


def check():
    rng=random.Random(2639); digest=hashlib.sha256(); accepted=rejected=0
    for case in range(10000):
        p=r.Spec(rng.randrange(1,9),rng.randrange(31),rng.randrange(31),rng.randrange(31))
        xs=tuple(rng.randrange(-32768,32768) for _ in range(p.dimension))
        ys=tuple(rng.randrange(-32768,32768) for _ in range(p.dimension))
        if case%19==0: xs=(-32768,)*p.dimension; ys=(32767,)*p.dimension
        c=r.derive(p); assert c==certificate(p); raw=r.encode(p); assert raw==frame(p,c); r.validate_bytes(p,raw)
        expected=reference(p,xs,ys); good=all(-32768<=v<=32767 for v in expected)
        if good:
            w=r.witness(p,xs,ys); assert r.check_relations(p,c,xs,ys,w)==expected; accepted+=1
            for x,y,e in zip(xs,ys,w['entries']):
                values=r.column_inputs(p,x,y,e)
                for role,col in e['columns'].items():
                    assert numpy_columns(*values[role],8)==sum(v*256**i for i,v in enumerate(col['result']))
        else: rejects('OutputRange',lambda:r.witness(p,xs,ys)); rejected+=1
        digest.update(raw+json.dumps([xs,ys,expected,good],separators=(',',':')).encode())
    assert (accepted,rejected)==(3540,6460)
    assert digest.hexdigest()=='626a52677a666e48ce0ec7b83e0a4a1dc4e5984b6570dbd238e87db0e395e1d1'
    models()
    controls()
    print(json.dumps(dict(seed=2639,cases=10000,accepted=accepted,rejected=rejected,sha256=digest.hexdigest()),sort_keys=True))
