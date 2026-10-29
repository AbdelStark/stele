"""Q26 row constraints: independent arithmetic/columns and coherent attacks."""
from dataclasses import replace
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
import row_bounds as r
from check_limbs import oracle, numpy_columns, rejects
import model_row_bounds as c
from check_causal_model import make, reference as model_reference
from check_decoder_block import reference as block_reference, norm, quantized
from check_projected_attention import rotation as rotation_reference


def reference(p,xs):
    scale=(max(map(abs,xs))+126)//127 if p.mode=='dynamic' else p.scale
    values=np.asarray(xs,dtype=np.int64); magnitude=np.abs(values)
    codes=np.sign(values)*((2*magnitude+scale)//(2*scale)) if scale else np.zeros_like(values)
    for x,code in zip(xs,codes):
        q=abs(Q(x,scale)) if scale else Q(0)
        assert int(code)==(-1 if x<0 else 1)*((2*q.numerator+q.denominator)//(2*q.denominator))
    return scale,tuple(int(v) for v in codes)


def frame(p,c):
    raw=b'stele/research/q26/row-bounds/v1\0'
    raw+=struct.pack('<BIBBH',('wide','gated').index(p.kind),p.dimension,p.fraction,
                     ('dynamic','static').index(p.mode),p.scale)
    names=('source_max','source_high','offset_max','scale_min','scale_max','predecessor_max',
           'maximum_max','selected_max','slack_max','gap_max','quotient_max','scaled_quotient_max',
           'remainder_max','scale_bound','remainder_lhs_bound','remainder_rhs_bound',
           'zero_lhs_bound','zero_rhs_bound','output_bound')
    raw+=struct.pack('<IBB',2**31-1,8,len(names))+b''.join(c[k].to_bytes(20,'little') for k in names)
    for group in ('row_columns','entry_columns'):
        raw+=bytes([len(c[group])])
        for i,record in enumerate(c[group].values(),1):
            raw+=struct.pack('<BI',i,record['count'])
            raw+=b''.join(record[k].to_bytes(20,'little') for k in ('left_max','right_max','result_max'))
            raw+=bytes(len(record[k]) for k in ('left_caps','right_caps','result_caps'))
            raw+=b''.join(bytes(record[k]) for k in ('left_caps','right_caps','result_caps'))
            raw+=b''.join(struct.pack('<I',v) for k in ('carry_caps','lhs','rhs') for v in record[k])
    return raw


def controls():
    p=r.Spec('wide',4,12,'dynamic',0); xs=(-17,256,0,-256)
    c=r.derive(p); w=r.witness(p,xs)
    check=lambda w:r.check_relations(p,c,xs,w)
    assert check(w)==(3,(-6,85,0,-85))
    tied=copy.deepcopy(w); tied['selected']=3; assert check(tied)==check(w)
    for key,value in c.items():
        if key in ('row_columns','entry_columns'):
            for role,record in value.items():
                for field,v in record.items():
                    bad=copy.deepcopy(c); bad[key][role][field]=(v[0]+1,)+v[1:] if type(v) is tuple else v+1
                    rejects('Certificate',lambda:r.validate(p,bad))
        else:
            bad=copy.deepcopy(c); bad[key]=value+'x' if type(value) is str else value+1
            rejects('Certificate',lambda:r.validate(p,bad))
    for field,value,reason in (('nonzero',0,'ScaleRelation'),('nonzero',True,'Witness'),
                              ('predecessor',3,'ScaleRelation'),('slack',126,'SourceDigits'),
                              ('selected',0,'Attainment')):
        bad=copy.deepcopy(w); bad[field]=value; rejects(reason,lambda:check(bad))
    bad=copy.deepcopy(w); bad['maximum']+=1; bad['slack']-=1
    for e in bad['entries']: e['gap']+=1
    rejects('Attainment',lambda:check(r.attach(p,xs,bad)))
    for scale in (2,4):
        bad=copy.deepcopy(w); bad.update(scale=scale,predecessor=scale-1,slack=0)
        rejects('IntegerRelation',lambda:check(r.attach(p,xs,bad)))
    for field,value,reason in (('sign',0,'SourceDigits'),('magnitude',18,'SourceDigits'),
                              ('gap',240,'SourceDigits'),('scaled_quotient',37,'SourceDigits'),
                              ('remainder',2,'Remainder'),('code',-5,'OutputRelation'),
                              ('zero_gap',122,'ZeroCode')):
        bad=copy.deepcopy(w); bad['entries'][0][field]=value; rejects(reason,lambda:check(bad))
    for field in ('sign','gap','scaled_quotient'):
        bad=copy.deepcopy(w); bad['entries'][0][field]+=1 if field!='sign' else -1
        rejects('IntegerRelation',lambda:check(r.attach(p,xs,bad)))
    bad=copy.deepcopy(w); e=bad['entries'][0]; e['remainder']+=1; e['remainder_gap']-=1
    rejects('IntegerRelation',lambda:check(r.attach(p,xs,bad)))
    for group in ('row_columns','entry_columns'):
        for role in c[group]:
            bad=copy.deepcopy(w); target=bad if group=='row_columns' else bad['entries'][0]
            values=target['columns'][role]['result']; target['columns'][role]['result']=(values[0]+r.P,)+values[1:]
            rejects('Range',lambda:check(bad))
            bad=copy.deepcopy(w); target=bad if group=='row_columns' else bad['entries'][0]
            values=target['columns'][role]['carry']; target['columns'][role]['carry']=values[:-1]+(1,)
            rejects('Boundary',lambda:check(bad))
    zero=r.witness(p,(0,)*4)
    for field,value,reason in (('predecessor',1,'ScaleCanonical'),('nonzero',1,'ScaleRelation')):
        bad=copy.deepcopy(zero); bad[field]=value
        rejects(reason,lambda:r.check_relations(p,c,(0,)*4,bad))
    bad=copy.deepcopy(zero); bad['entries'][0].update(quotient=1,code=1)
    rejects('ZeroCode',lambda:r.check_relations(p,c,(0,)*4,bad))
    bad=copy.deepcopy(zero); bad['entries'][0]['sign']=1
    rejects('Sign',lambda:r.check_relations(p,c,(0,)*4,bad))
    # Two allowed gated source integers are the same M31 residue.
    gated=r.Spec('gated',1,44,'dynamic',0); x=-(1<<30); alias=(1<<30)-1
    assert (x-alias)%r.P==0
    bad=r.witness(gated,(alias,))
    rejects('SourceDigits',lambda:r.check_relations(gated,r.derive(gated),(x,),bad))
    bad=r.witness(gated,(x,)); bad['entries'][0].update(sign=0,magnitude=alias,gap=1,code=127)
    rejects('IntegerRelation',lambda:r.check_relations(gated,r.derive(gated),(x,),r.attach(gated,(x,),bad)))
    for scale in (1,2,3,65535):
        t=r.Spec('wide',1,0,'static',scale)
        for x in (-32768,-255,-3,-1,0,1,3,255,32767):
            expected=reference(t,(x,))
            if abs(expected[1][0])<=127: assert r.check_relations(t,r.derive(t),(x,),r.witness(t,(x,)))==expected
            else: rejects('OutputRange',lambda:r.witness(t,(x,)))
    for field,value in (('kind','other'),('dimension',0),('dimension',True),('dimension',(1<<20)+1),
                        ('fraction',31),('mode','other'),('scale',1)):
        rejects('Spec',lambda:r.derive(replace(p,**{field:value})))
    rejects('Input',lambda:r.witness(p,(0,0,0,32768)))
    rejects('Input',lambda:r.witness(p,(True,0,0,0)))
    largest=replace(gated,dimension=1<<20)
    assert r.derive(largest)['selected_max']==(1<<20)-1 and len(r.encode(largest))<=2048
    t=replace(gated,dimension=16384); zeros=(0,)*t.dimension
    assert r.check_relations(t,r.derive(t),zeros,r.witness(t,zeros))==(0,zeros)
    static=replace(p,mode='static',scale=3); wrong=r.witness(static,xs); wrong['maximum']=1
    rejects('Range',lambda:r.check_relations(static,r.derive(static),xs,wrong))
    for t in (p,gated,replace(p,mode='static',scale=65535)):
        raw=r.encode(t)
        for end in range(len(raw)): rejects('Encoding',lambda:r.validate_bytes(t,raw[:end]))
        for i in range(len(raw)): rejects('Encoding',lambda:r.validate_bytes(t,raw[:i]+bytes([raw[i]^1])+raw[i+1:]))
        rejects('Encoding',lambda:r.validate_bytes(t,raw+b'\0'))


def model_relations(model):
    records=c.records(model); assert len(records)==1+7*len(model.blocks)
    for _,spec,raw in records: r.validate_bytes(spec,raw)
    # Bounds use metadata, not observed learned values.
    w=model.embedding; zero=replace(w,codes=tuple((0,)*len(row) for row in w.codes),mantissas=(1,)*len(w.codes))
    assert c.records(replace(model,embedding=zero))==records
    try: expected=model_reference(model,[0])
    except ValueError as error:
        assert str(error)=='Overflow'
        return False
    specs={name:spec for name,spec,_ in records}
    def check(role,values,output):
        p=specs[role]; xs=tuple(values)
        assert p.fraction==output.fraction
        assert r.check_relations(p,r.derive(p),xs,r.witness(p,xs))==(output.scale,output.codes)
    for i,b in enumerate(model.blocks):
        p=b.attention; a=p.attention; row=expected['cuts'][i][0]
        cell=block_reference(b,[row],[0])[0]; prefix='layer.'+str(i)+'.'
        check(prefix+'first',norm(b.norm1,row,b.gains1),cell['x1'])
        for role,values,count,fx,policy in (
                ('query',cell['q'],p.heads,p.fq,(p.q_mode,p.q_scale)),
                ('key',cell['k'],p.groups,p.fk,(p.k_mode,p.k_scale))):
            values=rotation_reference(p,0,values,count)
            check(prefix+role,values,quantized(values,fx,policy))
        check(prefix+'value',cell['v'],quantized(cell['v'],a.fv,(a.value_mode,a.value_scale)))
        at=cell['attention']; check(prefix+'attention',at['wide'],c.m.b.Row(tuple(at['codes']),at['scale'],a.fo))
        check(prefix+'second',norm(b.norm2,cell['mid'],b.gains2),cell['x2'])
        check(prefix+'gated',cell['product'],cell['h'])
    head=expected['heads'][0]; check('final',head['normalized'],head['input'])
    return True


def models():
    rng=random.Random(2636); accepted=0
    for case in range(30):
        model=make(rng,case); blocks=[]
        def policy(index): return ('static',259+index) if (case+index)%3==0 else ('dynamic',0)
        for b in model.blocks:
            p=b.attention; a=p.attention; qp,kp,vp,op=(policy(i) for i in range(4))
            a=replace(a,fv=5+case%6,fo=6+case%7,value_mode=vp[0],value_scale=vp[1],output_mode=op[0],output_scale=op[1])
            p=replace(p,fq=7+case%5,fk=6+case%5,q_mode=qp[0],q_scale=qp[1],k_mode=kp[0],k_scale=kp[1],attention=a)
            blocks.append(replace(b,norm1=replace(b.norm1,E=5+case%8),norm2=replace(b.norm2,E=6+case%6),
                attention=p,first=policy(4),second=policy(5),gated=('static',65535) if case%5==0 else ('dynamic',0)))
        model=replace(model,blocks=tuple(blocks),final_norm=replace(model.final_norm,E=5+case%8),policy=policy(6))
        accepted+=model_relations(model)
    assert accepted>0
    return accepted


def check():
    rng=random.Random(2635); digest=hashlib.sha256(); accepted=rejected=0
    for case in range(10000):
        kind='gated' if case%2 else 'wide'; mode='static' if case%3==0 else 'dynamic'
        p=r.Spec(kind,rng.randrange(1,17),rng.randrange(45 if kind=='gated' else 31),mode,
                 rng.randrange(1,65536) if mode=='static' else 0); c=r.derive(p)
        lo=-c['source_max']; hi=c['source_high']
        if mode=='static' and case%5: lo=max(lo,-127*p.scale); hi=min(hi,127*p.scale)
        xs=tuple(rng.randrange(lo,hi+1) for _ in range(p.dimension))
        if case%17==0: xs=(0,)*p.dimension
        if case%19==0: xs=tuple(-c['source_max'] if i%2 else c['source_high'] for i in range(p.dimension))
        for group,specs in r.column_specs(p).items():
            for role,spec in specs.items():
                assert c[group][role]==oracle(spec)
                assert max(c[group][role]['lhs']+c[group][role]['rhs'])<1<<20
                assert len(c[group][role]['result_caps'])<=5
        raw=r.encode(p); assert raw==frame(p,c); r.validate_bytes(p,raw)
        expected=reference(p,xs); good=all(abs(x)<=127 for x in expected[1])
        if good:
            w=r.witness(p,xs); assert r.check_relations(p,c,xs,w)==expected; accepted+=1
            for values in r.row_inputs(p,w).values(): assert numpy_columns(*values,8)==sum(a*b for a,b in zip(*values))
            for x,e in zip(xs,w['entries']):
                for values in r.entry_inputs(p,w,x,e).values(): assert numpy_columns(*values,8)==sum(a*b for a,b in zip(*values))
        else: rejects('OutputRange',lambda:r.witness(p,xs)); rejected+=1
        digest.update(raw+json.dumps([xs,expected,good],separators=(',',':')).encode())
        if case%100==0:
            large=replace(p,dimension=rng.randrange(1,1<<20)); assert r.encode(large)==frame(large,r.derive(large))
    models()
    controls()
    assert (accepted,rejected)==(9613,387)
    assert digest.hexdigest()=='0b67d244cfb85747cffefd78de536a339bd522aa5d228302e58fcb6526b91bcb'
    print(json.dumps(dict(seed=2635,cases=10000,accepted=accepted,rejected=rejected,sha256=digest.hexdigest()),sort_keys=True))
