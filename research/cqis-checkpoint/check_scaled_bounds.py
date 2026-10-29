"""Q26 scaled-linear static/witness controls via the locked causal script."""
from dataclasses import replace
from fractions import Fraction as Q
import copy
import hashlib
import json
import random
import struct
import numpy as np
import model_scaled_bounds as c
from check_limbs import oracle, numpy_columns, rejects
from check_causal_model import make, reference
from check_decoder_block import reference as block_reference

s=c.s


def rounded(q):
    v=abs(q); return (-1 if q<0 else 1)*((2*v.numerator+v.denominator)//(2*v.denominator))


def frame(p,cert):
    """Independent outer struct framing; columns come from the separate polynomial oracle."""
    raw=b'stele/research/q26/scaled-linear/v1\0'
    raw+=struct.pack('<BIBhBBBH',('wide','gated','embedding').index(p.kind),p.dimension,p.bits,
                     p.exponent,p.input_fraction,p.output_fraction,('dynamic','static').index(p.mode),p.scale)
    raw+=struct.pack('<IBBhB',2**31-1,8,('right','left','zero_right','zero_only').index(cert['branch']),cert['shift'],10)
    names=('acc_max','scale_min','scale_max','weighted_max','product_max','divisor','bias','left_factor','quotient_max','output_max')
    raw+=b''.join(cert[k].to_bytes(20,'little') for k in names)+bytes([len(cert['columns'])])
    for i,record in enumerate(cert['columns'].values(),1):
        raw+=struct.pack('<BI',i,record['count'])
        raw+=b''.join(record[k].to_bytes(20,'little') for k in ('left_max','right_max','result_max'))
        raw+=bytes([len(record[k]) for k in ('left_caps','right_caps','result_caps')])
        raw+=b''.join(bytes(record[k]) for k in ('left_caps','right_caps','result_caps'))
        raw+=b''.join(struct.pack('<I',v) for k in ('carry_caps','lhs','rhs') for v in record[k])
    return raw


def controls():
    p=s.Spec('wide',8,8,0,4,0,'dynamic',0); a,m,scale=-17,19,3
    cert=s.derive(p); w=s.witness(p,a,m,scale); assert s.check_relations(p,cert,a,m,scale,w)==-61
    for key,value in cert.items():
        bad=copy.deepcopy(cert)
        if key=='columns':
            for role,record in value.items():
                for field,v in record.items():
                    bad=copy.deepcopy(cert); bad[key][role][field]=(v[0]+1,)+v[1:] if type(v) is tuple else v+1
                    rejects('Certificate',lambda:s.validate(p,bad))
            continue
        bad[key]=value+'x' if type(value) is str else value+1
        rejects('Certificate',lambda:s.validate(p,bad))
    for field in ('magnitude','weighted','product','quotient','scaled_quotient','remainder'):
        bad=copy.deepcopy(w); bad[field]+=1
        rejects('SourceSign' if field=='magnitude' else 'SourceDigits',lambda:s.check_relations(p,cert,a,m,scale,bad))
    bad=copy.deepcopy(w); bad['sign']=0
    rejects('SourceSign',lambda:s.check_relations(p,cert,a,m,scale,bad))
    bad=copy.deepcopy(w); bad['output']+=1
    rejects('OutputRelation',lambda:s.check_relations(p,cert,a,m,scale,bad))
    # Rebuilt local columns do not establish equality to the preceding result.
    for field in ('weighted','product','quotient','remainder'):
        bad=copy.deepcopy(w); bad[field]+=1
        if field=='quotient': bad['output']-=1
        rejects('IntegerRelation',lambda:s.check_relations(p,cert,a,m,scale,s.attach(p,a,m,scale,bad)))
    for role in cert['columns']:
        bad=copy.deepcopy(w); values=bad['columns'][role]['result']
        bad['columns'][role]['result']=(values[0]+s.P,)+values[1:]
        rejects('Range',lambda:s.check_relations(p,cert,a,m,scale,bad))
        bad=copy.deepcopy(w); values=bad['columns'][role]['carry']
        bad['columns'][role]['carry']=values[:-1]+(1,)
        rejects('Boundary',lambda:s.check_relations(p,cert,a,m,scale,bad))
    bad=copy.deepcopy(w); bad['sign']=True
    rejects('Witness',lambda:s.check_relations(p,cert,a,m,scale,bad))
    zero=s.witness(p,0,m,scale); zero['sign']=1
    rejects('Sign',lambda:s.check_relations(p,cert,0,m,scale,zero))
    rejects('ZeroScale',lambda:s.witness(p,1,1,0))
    rejects('Input',lambda:s.witness(p,0,0,0))
    rejects('Input',lambda:s.check_relations(p,cert,a+s.P,m,scale,w))
    rejects('Certificate',lambda:s.validate(p,s.derive(replace(p,dimension=9))))
    static=replace(p,mode='static',scale=3)
    rejects('Input',lambda:s.witness(static,0,1,2))
    for field,value in (('kind','other'),('dimension',True),('dimension',0),('bits',16),('exponent',1025),
                         ('input_fraction',31),('output_fraction',31),('mode','other'),('scale',1)):
        rejects('Spec',lambda:s.derive(replace(p,**{field:value})))
    bound=(s.P-1)//(2*127*127)
    assert s.derive(replace(p,dimension=bound))['acc_max']==bound*127*127
    rejects('FieldBound',lambda:s.witness(replace(p,dimension=bound+1),0,1,0))
    assert s.derive(replace(p,dimension=1<<20,bits=4))['acc_max']==(1<<20)*127*7
    huge=s.Spec('gated',16384,8,-1099,44,0,'dynamic',0)
    assert s.derive(huge)['branch']=='zero_right'
    assert s.witness(huge,-16384*127*127,65535,8454661)['output']==0
    huge=s.Spec('wide',1,8,1024,0,30,'dynamic',0)
    assert s.derive(huge)['branch']=='zero_only' and s.witness(huge,0,65535,259)['output']==0
    rejects('OutputRange',lambda:s.witness(huge,1,1,1))
    bad=s.witness(huge,0,1,1); bad.update(magnitude=1,weighted=1,product=1)
    rejects('ZeroOnly',lambda:s.check_relations(huge,s.derive(huge),1,1,1,s.attach(huge,1,1,1,bad)))
    ties=replace(p,dimension=5,exponent=-1,input_fraction=0,mode='static',scale=1)
    for a in (-65535,-3,-1,1,3): assert s.witness(ties,a,1,1)['output']==rounded(Q(a,2))
    rejects('OutputRange',lambda:s.witness(ties,65535,1,1))
    for shift in (cert['product_max'].bit_length()-1,cert['product_max'].bit_length(),cert['product_max'].bit_length()+1):
        edge=replace(p,exponent=p.input_fraction-p.output_fraction-shift); actual=s.derive(edge)
        assert actual['branch']==('zero_right' if shift>cert['product_max'].bit_length() else 'right')
        for sign in (-1,1):
            a=sign*cert['acc_max']; value=s.witness(edge,a,65535,cert['scale_max'])
            assert s.check_relations(edge,actual,a,65535,cert['scale_max'],value)==rounded(Q(sign*cert['product_max'],1<<shift))
    left=replace(ties,exponent=15)
    assert s.witness(left,-1,1,1)['output']==-32768
    rejects('OutputRange',lambda:s.witness(left,1,1,1))
    rejects('OutputRange',lambda:s.witness(replace(left,exponent=16),-1,1,1))
    for p in (p,huge,replace(huge,exponent=-1099),ties,replace(ties,exponent=1)):
        raw=s.encode(p); assert len(raw)<=2048
        for end in range(len(raw)): rejects('Encoding',lambda:s.validate_bytes(p,raw[:end]))
        for i in range(len(raw)): rejects('Encoding',lambda:s.validate_bytes(p,raw[:i]+bytes([raw[i]^1])+raw[i+1:]))
        rejects('Encoding',lambda:s.validate_bytes(p,raw+b'\0'))


def model_relations(model, records):
    # The independent numerical composition chooses actual sources and outputs.
    try: expected=reference(model,[0])
    except ValueError as error:
        assert str(error)=='Overflow'
        return False
    specs={role:spec for role,spec,_ in records}
    def scalar(role,acc,mantissa,scale,output):
        p=specs[role]
        assert s.check_relations(p,s.derive(p),acc,mantissa,scale,s.witness(p,acc,mantissa,scale))==output
    def matrix(role,w,row,outputs):
        dots=np.asarray(w.codes,dtype=np.int64)@np.asarray(row.codes,dtype=np.int64)
        for acc,mantissa,output in zip(dots,w.mantissas,outputs):
            scalar(role,int(acc),mantissa,row.scale,output)
    for code,output in zip(model.embedding.codes[0],expected['cuts'][0][0]):
        scalar('embedding',code,model.embedding.mantissas[0],1,output)
    for i,b in enumerate(model.blocks):
        r=block_reference(b,expected['cuts'][i],[0])[0]; at=r['attention']
        attention_row=c.m.b.Row(tuple(at['codes']),at['scale'],b.attention.attention.fo)
        rows=(r['x1'],)*3+(attention_row,r['x2'],r['x2'],r['h'])
        for role,w,row in zip(('q','k','v','o','up','gate','down'),b.weights,rows):
            matrix('layer.'+str(i)+'.'+role,w,row,r[role])
    head=expected['heads'][0]
    matrix('head',model.embedding if model.head is None else model.head,head['input'],head['logits'])
    return True


def check():
    rng=random.Random(2634); digest=hashlib.sha256(); accepted=rejected=0; branches={}
    for case in range(10000):
        kind=('wide','gated','embedding')[case%3]; bits=4 if case%2 else 8
        maximum=min(1<<20,(s.P-1)//(2*127*((1<<(bits-1))-1)))
        dimension=1 if kind=='embedding' else rng.randrange(1,maximum+1)
        fx=0 if kind=='embedding' else rng.randrange(45 if kind=='gated' else 31); fo=rng.randrange(31)
        mode='static' if kind=='embedding' or case%4==0 else 'dynamic'
        static=1 if kind=='embedding' else rng.randrange(1,65536) if mode=='static' else 0
        exponent=rng.randrange(-1099,1025)
        if case%5==1: exponent=fx-fo+rng.randrange(16)
        if case%5==2: exponent=fx-fo-rng.randrange(32,71)
        p=s.Spec(kind,dimension,bits,exponent,fx,fo,mode,static); cert=s.derive(p)
        assert 2*cert['acc_max']<s.P
        for role,spec in s.column_specs(p).items():
            assert cert['columns'][role]==oracle(spec)
            assert max(cert['columns'][role]['lhs']+cert['columns'][role]['rhs'])<1<<21
            assert len(cert['columns'][role]['result_caps'])<=11 and cert['columns'][role]['result_max']<1<<86
        raw=s.encode(p); assert raw==frame(p,cert); s.validate_bytes(p,raw)
        a=0 if case%11==0 else rng.randrange(-cert['acc_max'],cert['acc_max']+1)
        m=rng.randrange(1,65536); scale=static if mode=='static' else rng.randrange(cert['scale_max']+1)
        if scale==0: a=0
        expected=rounded(Q(a*m*scale)*Q(2)**(exponent-fx+fo)); good=-32768<=expected<=32767
        if good:
            w=s.witness(p,a,m,scale); assert s.check_relations(p,cert,a,m,scale,w)==expected
            for values in s.column_inputs(p,w,m,scale).values():
                assert numpy_columns(*values,8)==sum(x*y for x,y in zip(*values))
            accepted+=1
        else: rejects('OutputRange',lambda:s.witness(p,a,m,scale)); rejected+=1
        branches[cert['branch']]=branches.get(cert['branch'],0)+1
        digest.update(raw+json.dumps([a,m,scale,expected,good],separators=(',',':')).encode())
    # Actual matrix arithmetic, including a numerator larger than int64.
    for d,kind in ((1,'wide'),(37,'wide'),(16384,'gated')):
        fx=44 if kind=='gated' else 12; scale=8454661 if kind=='gated' else 259
        p=s.Spec(kind,d,8,-20,fx,0,'dynamic',0)
        row=c.m.b.Row((127,)*d,scale,fx); matrix=c.m.b.Matrix(8,-20,(65535,),((127,)*d,))
        acc=int(np.dot(np.array(row.codes,dtype=np.int64),np.array(matrix.codes[0],dtype=np.int64)))
        result=s.check_relations(p,s.derive(p),acc,65535,scale,s.witness(p,acc,65535,scale))
        assert c.m.b.linear(matrix,row,0)==[result]
    models_checked=0
    for case in range(30):
        p=make(rng,case); records=c.records(p); assert len(records)==2+7*len(p.blocks)
        for _,spec,raw in records: s.validate_bytes(spec,raw)
        models_checked+=model_relations(p,records)
        # Bound derivation uses formats/units, not observed codes or channel mantissas.
        w=p.embedding; changed=replace(w,codes=tuple((0,)*len(row) for row in w.codes),mantissas=(1,)*len(w.codes))
        assert c.records(replace(p,embedding=changed))==records
        b=p.blocks[0]; changed=replace(p,blocks=(replace(b,fu=b.fu+1),)+p.blocks[1:])
        assert dict((k,raw) for k,_,raw in c.records(changed))['layer.0.down']!=dict((k,raw) for k,_,raw in records)['layer.0.down']
    assert models_checked>0
    controls()
    assert (accepted,rejected)==(5297,4703)
    assert branches==dict(left=1918,right=1259,zero_only=2801,zero_right=4022)
    assert digest.hexdigest()=='301994d40fb8dcef20caec81fb86505d577412eac3d839cda318937f07d23673'
    print(json.dumps(dict(seed=2634,cases=10000,accepted=accepted,rejected=rejected,branches=branches,sha256=digest.hexdigest()),sort_keys=True))
