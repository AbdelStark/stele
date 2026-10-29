"""Q26 / Draft RFC-0004 A3/A6/A7: independent rotary arithmetic and attacks."""
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
import rope
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'cqis-bounds'))
import rotary_bounds as r
from check_limbs import rejects
import model_rotary_bounds as model_bounds
from check_causal_model import make, reference as model_reference
from check_decoder_block import reference as block_reference
from check_projected_attention import rotation as rotation_reference


def rounded(value):
    q=abs(value); whole,rem=divmod(q.numerator,q.denominator)
    return (-1 if value<0 else 1)*(whole+int(2*rem>=q.denominator))


def reference(p,xs,coefficients):
    values=np.asarray(xs,dtype=np.int64).reshape(p.heads,p.width).copy()
    for head in range(p.heads):
        for j,(c,s) in enumerate(coefficients):
            left,right=(2*j,2*j+1) if p.layout=='adjacent' else (j,j+p.rotary//2)
            pair=np.array([[c,-s],[s,c]],dtype=np.int64)@values[head,[left,right]]
            output=np.sign(pair)*((np.abs(pair)+8192)//16384)
            assert list(output)==[rounded(Q(int(v),16384)) for v in pair]
            values[head,left],values[head,right]=output
    return tuple(int(v) for v in values.reshape(-1))


def certificate(p):
    # Independent numeric constants; implementation derives the L1 limit by isqrt.
    return dict(asdict(p),prime=2**31-1,row_width=p.heads*p.width,pair_count=p.heads*(p.rotary//2),
        passthrough_count=p.heads*(p.width-p.rotary),input_max=32768,coefficient_max=16384,
        coefficient_l1_max=23171,product_max=536870912,numerator_max=759267328,divisor=16384,
        bias=8192,biased_max=759275520,quotient_max=32768,remainder_max=16383,
        division_max=536887295,output_max=32768)


def frame(p,c):
    names=('row_width','pair_count','passthrough_count','input_max','coefficient_max','coefficient_l1_max',
           'product_max','numerator_max','divisor','bias','biased_max','quotient_max','remainder_max','division_max','output_max')
    raw=b'stele/research/q26/rotary-bounds/v1\0'
    raw+=struct.pack('<HHHBBI',p.heads,p.width,p.rotary,('adjacent','split').index(p.layout),p.fraction,p.length)
    return raw+struct.pack('<IB',2**31-1,len(names))+struct.pack('<'+'I'*len(names),*(c[k] for k in names))


def controls():
    p=r.Spec(2,6,4,'adjacent',12,8); xs=(17,-3,4,-5,7,-8,-9,10,-11,12,13,-14)
    coeff=((16384,0),(11586,11585)); c=r.derive(p); w=r.witness(p,1,xs,coeff)
    check=lambda w:r.check_relations(p,c,1,xs,coeff,w)
    assert check(w)==reference(p,xs,coeff)
    for key,value in c.items():
        bad=copy.deepcopy(c); bad[key]=value+'x' if type(value) is str else value+1
        rejects('Certificate',lambda:r.validate(p,bad))
    for field,reason in (('numerator','Numerator'),('sign','SourceSign'),('magnitude','SourceSign'),
                         ('quotient','Rounding'),('remainder','Rounding')):
        bad=copy.deepcopy(w); bad['entries'][0][0][field]+=1; rejects(reason,lambda:check(bad))
    bad=copy.deepcopy(w); bad['output']=(bad['output'][0]+1,)+bad['output'][1:]
    rejects('OutputRelation',lambda:check(bad))
    bad=copy.deepcopy(w); values=list(bad['output']); values[4]+=1; bad['output']=tuple(values)
    rejects('Passthrough',lambda:check(bad))
    bad=copy.deepcopy(w); bad['position']=2; rejects('Position',lambda:check(bad))
    bad=copy.deepcopy(w); bad['entries'][0][0]['sign']=True; rejects('Witness',lambda:check(bad))
    for field in ('numerator','magnitude','quotient','remainder'):
        bad=copy.deepcopy(w); bad['entries'][0][0][field]+=r.P; rejects('Range',lambda:check(bad))
    bad=copy.deepcopy(w); bad['entries'][0][0]['remainder']=16384
    rejects('Range',lambda:check(bad))
    # Recomputed witnesses still bind to the separately expected sources and pairing.
    rejects('Numerator',lambda:check(r.witness(p,1,(18,)+xs[1:],coeff)))
    rejects('Numerator',lambda:check(r.witness(p,1,xs,((16384,1),coeff[1]))))
    rejects('Numerator',lambda:check(r.witness(replace(p,layout='split'),1,xs,coeff)))
    zero=r.witness(p,1,(0,)*12,coeff); zero['entries'][0][0]['sign']=1
    rejects('Sign',lambda:r.check_relations(p,c,1,(0,)*12,coeff,zero))
    rejects('CoefficientEnvelope',lambda:r.witness(p,1,(0,)*12,((16384,16384),coeff[1])))
    rejects('Coefficients',lambda:r.witness(p,1,xs,((16385,0),coeff[1])))
    rejects('Input',lambda:r.witness(p,1,(True,)+xs[1:],coeff))
    rejects('Input',lambda:r.witness(p,1,(xs[0]+r.P,)+xs[1:],coeff))
    rejects('Position',lambda:r.witness(p,8,xs,coeff))
    for field,value in (('heads',0),('heads',129),('heads',True),('width',0),('width',16384),
                        ('rotary',3),('rotary',8),('layout','other'),('fraction',31),('length',0),('length',1<<20)):
        rejects('Spec',lambda:r.derive(replace(p,**{field:value})))
    # The extra unit in the envelope is necessary after independently rounding C and S.
    source=rope.Parameters(4,2,Q(16213,10000)); pair=rope.certify(source,1,1)
    assert (pair['cos'],pair['sin'])==(11586,11585) and sum(map(abs,(pair['cos'],pair['sin'])))==23171
    tight=r.Spec(1,4,4,'adjacent',0,2)
    first=rope.certify(source,1,0); coefficients=((first['cos'],first['sin']),(11586,11585))
    assert r.check_relations(tight,r.derive(tight),1,(0,0,1,0),coefficients,
                            r.witness(tight,1,(0,0,1,0),coefficients))==(0,0,1,1)
    single=r.Spec(1,2,2,'adjacent',0,2)
    for x in (-32768,-1,0,1,32767):
        identity=((16384,0),); value=r.witness(single,0,(x,0),identity)
        assert r.check_relations(single,r.derive(single),0,(x,0),identity,value)==(x,0)
    for x in (-1,1): assert r.witness(single,0,(x,0),((8192,14189),))['output']==(x,x)
    negative=r.witness(single,0,(-1,0),((1,0),)); assert negative['entries'][0][0]['sign']==1 and negative['output']==(0,0)
    rejects('OutputRange',lambda:r.witness(single,0,(-32768,-32768),((11586,11585),)))
    for rotary in (0,128):
        largest=r.Spec(128,128,rotary,'split',30,(1<<20)//max(1,rotary//2))
        zeros=(0,)*16384; cs=((16384,0),)*(rotary//2)
        assert r.check_relations(largest,r.derive(largest),largest.length-1,zeros,cs,r.witness(largest,largest.length-1,zeros,cs))==zeros
    for t in (p,single,largest):
        raw=r.encode(t); assert len(raw)<=128
        for end in range(len(raw)): rejects('Encoding',lambda:r.validate_bytes(t,raw[:end]))
        for i in range(len(raw)): rejects('Encoding',lambda:r.validate_bytes(t,raw[:i]+bytes([raw[i]^1])+raw[i+1:]))
        rejects('Encoding',lambda:r.validate_bytes(t,raw+b'\0'))


def models():
    rng=random.Random(2638); accepted=0
    for case in range(30):
        model=make(rng,case); blocks=[]
        for b in model.blocks:
            p=replace(b.attention,fq=5+case%8,fk=6+case%7)
            if case%5==0: p=replace(p,rotary=0,layout='adjacent',rotations=((),)*len(p.rotations))
            blocks.append(replace(b,attention=p))
        model=replace(model,blocks=tuple(blocks)); rows=model_bounds.records(model)
        assert len(rows)==2*len(model.blocks)
        for _,s,raw in rows: r.validate_bytes(s,raw)
        weight=model.embedding; zero=replace(weight,codes=tuple((0,)*len(row) for row in weight.codes),mantissas=(1,)*len(weight.codes))
        assert model_bounds.records(replace(model,embedding=zero))==rows
        try: expected=model_reference(model,[0,1])
        except ValueError as error:
            assert str(error)=='Overflow'
            continue
        for i,b in enumerate(model.blocks):
            cells=block_reference(b,expected['cuts'][i],[0,1]); p=b.attention
            for pos,cell in enumerate(cells):
                for query,role in ((True,'q'),(False,'k')):
                    s=model_bounds.spec(p,query); xs=tuple(cell[role]); w=r.witness(s,pos,xs,p.rotations[pos])
                    assert model_bounds.check_row(p,query,pos,xs,r.derive(s),w)==tuple(rotation_reference(p,pos,xs,s.heads))
                    assert s.fraction==(p.fq if query else p.fk)
        accepted+=1
    assert accepted>0
    # Parameters permit arbitrary test fixtures; records do not certify their source domain.
    p=make(random.Random(7),1).blocks[0].attention; s=model_bounds.spec(p,True)
    rows=list(p.rotations); rows[0]=((16384,16384),)*len(rows[0]); wrong=replace(p,rotations=tuple(rows))
    assert model_bounds.spec(wrong,True)==s
    xs=(0,)*(p.heads*p.width); w=r.witness(s,0,xs,p.rotations[0])
    rejects('CoefficientEnvelope',lambda:model_bounds.check_row(wrong,True,0,xs,r.derive(s),w))


def check():
    rng=random.Random(2637); digest=hashlib.sha256(); accepted=rejected=canonical=0
    for case in range(10000):
        width=rng.randrange(1,9); rotary=2*rng.randrange(width//2+1)
        p=r.Spec(rng.randrange(1,5),width,rotary,'split' if case%2 else 'adjacent',rng.randrange(31),
                 rng.randrange(1,1+(1<<20)//max(1,rotary//2)))
        pos=rng.randrange(p.length); cs=[]
        if case%2==0 and rotary:
            mode=('base','linear','llama3')[(case//2)%3]
            source=rope.Parameters(rotary,p.length,Q(10000),mode,p.layout,Q(1) if mode=='base' else Q(8),
                Q(1) if mode=='llama3' else Q(0),Q(4) if mode=='llama3' else Q(0),8192 if mode=='llama3' else 0)
            for j in range(rotary//2):
                value=rope.certify(source,pos,j); cs.append((value['cos'],value['sin']))
            canonical+=1
        else:
            for _ in range(rotary//2):
                c=rng.randrange(-16384,16385); limit=min(16384,23171-abs(c)); cs.append((c,rng.randrange(-limit,limit+1)))
        cs=tuple(cs); xs=tuple(rng.randrange(-32768,32768) for _ in range(p.heads*width))
        if case%19==0: xs=tuple((-32768,32767)[i%2] for i in range(len(xs)))
        c=r.derive(p); assert c==certificate(p); raw=r.encode(p); assert raw==frame(p,c); r.validate_bytes(p,raw)
        assert all(2*c[k]<r.P for k in ('input_max','coefficient_max','product_max','numerator_max','biased_max','division_max','output_max'))
        expected=reference(p,xs,cs); good=all(-32768<=v<=32767 for v in expected)
        if good:
            w=r.witness(p,pos,xs,cs); assert r.check_relations(p,c,pos,xs,cs,w)==expected; accepted+=1
        else: rejects('OutputRange',lambda:r.witness(p,pos,xs,cs)); rejected+=1
        digest.update(raw+json.dumps([pos,xs,cs,expected,good],separators=(',',':')).encode())
    assert (canonical,accepted,rejected)==(2940,8318,1682)
    assert digest.hexdigest()=='9aba52a7fa8ec78f75591f96e21ad7bc634ebf96657c62938c5a9544f40c5a6c'
    models()
    controls()
    print(json.dumps(dict(seed=2637,cases=10000,canonical=canonical,accepted=accepted,rejected=rejected,sha256=digest.hexdigest()),sort_keys=True))
