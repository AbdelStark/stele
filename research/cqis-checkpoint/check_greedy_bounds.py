"""Q26 / RFC-0004 §7, Draft A3/A9: independent first-maximum and stopping attacks."""
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
import greedy_bounds as r
from check_limbs import rejects
import model_greedy_bounds as model_bounds
from check_causal_model import make, reference as model_reference
import causal_model as model_impl


def certificate(p):
    return dict(asdict(p),prime=2**31-1,logit_max=32768,logit_high=32767,selected_max=p.vocabulary-1,
                position_max=p.length-1,difference_max=65535,gap_max=65535,prefix_bit_max=1,
                strict_rhs_max=65536,entry_capacity=1<<22)


def frame(p,c):
    raw=b'stele/research/q26/greedy-bounds/v1\0'+struct.pack('<IBI',p.vocabulary,p.fraction,p.length)
    names=('logit_max','logit_high','selected_max','position_max','difference_max','gap_max',
           'prefix_bit_max','strict_rhs_max','entry_capacity')
    return raw+struct.pack('<IB',2**31-1,len(names))+struct.pack('<'+'I'*len(names),*(c[k] for k in names))


def forged(p,position,xs,selected,maximum=None):
    # Coherently rebuild every nonnegative local difference/gap; not an honest witness.
    maximum=xs[selected] if maximum is None else maximum
    entries=tuple(dict(difference=max(0,maximum-x),gap=max(0,maximum-x-int(i<selected))) for i,x in enumerate(xs))
    return dict(position=position,selected=selected,maximum=maximum,entries=entries)


def controls():
    p=r.Spec(4,12,8); xs=(-32768,32767,32767,-1); c=r.derive(p); w=r.witness(p,2,xs)
    check=lambda value:r.check_relations(p,c,2,1,xs,value)
    assert check(w)==1
    for key,value in c.items():
        bad=copy.deepcopy(c); bad[key]=value+1; rejects('Certificate',lambda:r.validate(p,bad))
    bad=copy.deepcopy(w); bad['maximum']-=1; rejects('Attainment',lambda:check(bad))
    bad=copy.deepcopy(w); bad['position']=3; rejects('Position',lambda:check(bad))
    bad=copy.deepcopy(w); bad['selected']=2; rejects('Selected',lambda:check(bad))
    bad=copy.deepcopy(w); bad['entries'][3]['difference']+=1; rejects('Difference',lambda:check(bad))
    bad=copy.deepcopy(w); bad['entries'][0]['gap']-=1; rejects('FirstMaximum',lambda:check(bad))
    for field in ('difference','gap'):
        bad=copy.deepcopy(w); bad['entries'][0][field]+=r.P; rejects('Range',lambda:check(bad))
    bad=copy.deepcopy(w); bad['entries'][0]['gap']=True; rejects('Witness',lambda:check(bad))
    rejects('FirstMaximum',lambda:r.check_relations(p,c,2,2,xs,forged(p,2,xs,2)))
    rejects('Difference',lambda:r.check_relations(p,c,2,3,xs,forged(p,2,xs,3)))
    ys=(-4,2,1,0)
    rejects('Attainment',lambda:r.check_relations(p,c,2,2,ys,forged(p,2,ys,2,3)))
    rejects('Difference',lambda:check(r.witness(p,2,xs[:-1]+(0,))))
    rejects('Input',lambda:r.witness(p,2,(True,)+xs[1:]))
    rejects('Input',lambda:r.witness(p,2,(xs[0]+r.P,)+xs[1:]))
    rejects('Position',lambda:r.witness(p,8,xs))
    rejects('Token',lambda:r.check_relations(p,c,2,True,xs,w))
    rejects('Token',lambda:r.check_relations(p,c,2,p.vocabulary,xs,w))
    rejects('Input',lambda:r.witness(p,2,xs+(32767,)))
    for field,value in (('vocabulary',0),('vocabulary',2**20+1),('vocabulary',True),('fraction',31),('length',0),('length',2**20+1)):
        rejects('Spec',lambda:r.derive(replace(p,**{field:value})))
    for t in (p,r.Spec(1,0,1),r.Spec(1<<20,30,1<<20)):
        raw=r.encode(t); assert len(raw)<=128
        for end in range(len(raw)): rejects('Encoding',lambda:r.validate_bytes(t,raw[:end]))
        for i in range(len(raw)): rejects('Encoding',lambda:r.validate_bytes(t,raw[:i]+bytes([raw[i]^1])+raw[i+1:]))
        rejects('Encoding',lambda:r.validate_bytes(t,raw+b'\0'))
    for xs in ((-32768,),(-32768,-32768),(32767,32767),(-1,-2,-1),(0,)*16384):
        t=r.Spec(len(xs),30,1); w=r.witness(t,0,xs)
        assert r.check_relations(t,r.derive(t),0,0,xs,w)==0
    stopping_controls()


def stopping_controls():
    p=r.Spec(3,8,8); c=r.derive(p); prompt=(2,0); rows=((1,3,2),(1,2,3)); seq=(2,0,1,2)
    ws=tuple(r.witness(p,1+i,row) for i,row in enumerate(rows))
    check=lambda seq,stop,rs,ww:r.check_generation(p,c,prompt,3,2,seq,stop,rs,ww)
    assert check(seq,'eos',rows,ws)==seq  # Prompt EOS does not stop generation.
    rejects('Prefix',lambda:check((1,0,1,2),'eos',rows,ws))
    rejects('Stop',lambda:check(seq,'limit',rows,ws))
    rejects('Stop',lambda:check(seq[:-1],'limit',rows[:1],ws[:1]))
    rejects('Stop',lambda:check(seq+(1,),'eos',rows+(rows[0],),ws+(r.witness(p,3,rows[0]),)))
    rejects('Rows',lambda:check(seq,'eos',rows[:1],ws))
    rejects('Selected',lambda:check((2,0,0,2),'eos',rows,ws))
    bad=copy.deepcopy(ws); bad[0]['position']=0; rejects('Position',lambda:check(seq,'eos',rows,bad))
    # Matching dimensions do not establish the correct source row.
    rejects('Selected',lambda:check(seq,'eos',tuple(reversed(rows)),tuple(r.witness(p,1+i,row) for i,row in enumerate(reversed(rows)))))
    # Correct choices alone do not authenticate the model's actual logit rows.
    other=((0,4,0),(-1,-1,7)); ww=tuple(r.witness(p,1+i,row) for i,row in enumerate(other))
    assert check(seq,'eos',other,ww)==seq
    assert r.check_generation(p,c,prompt,0,2,prompt,'limit',(),())==prompt
    rejects('Stop',lambda:r.check_generation(p,c,prompt,0,2,prompt,'eos',(),()))
    rejects('Length',lambda:r.check_generation(p,c,prompt,7,2,prompt,'limit',(),()))
    # EOS takes priority even when it occurs on the configured final new token.
    assert r.check_generation(p,c,prompt,2,2,seq,'eos',rows,ws)==seq
    end=(2,0,1,1); rr=(rows[0],rows[0]); ww=tuple(r.witness(p,1+i,row) for i,row in enumerate(rr))
    assert r.check_generation(p,c,prompt,2,2,end,'limit',rr,ww)==end
    large=r.Spec(1<<20,0,8)
    rejects('Rows',lambda:r.check_generation(large,r.derive(large),(0,),5,(1<<20)-1,(0,)*6,'limit',((),)*5,({},)*5))


def models():
    rng=random.Random(2642); accepted=0
    for case in range(30):
        model=replace(make(rng,case),logits_fraction=5+case%10); rows=model_bounds.records(model)
        assert len(rows)==1; s=model_bounds.spec(model); r.validate_bytes(s,rows[0][2])
        assert (s.vocabulary,s.fraction,s.length)==(len(model.embedding.codes),model.logits_fraction,8)
        weight=model.embedding; zero=replace(weight,codes=tuple((0,)*len(row) for row in weight.codes),mantissas=(1,)*len(weight.codes))
        assert model_bounds.records(replace(model,embedding=zero))==rows
        prompt=(0,1); sequence=list(prompt); maximum_new=case%4; eos=case%s.vocabulary; logits=[]; stop='limit'
        try:
            for _ in range(maximum_new):
                row=tuple(model_reference(model,sequence)['heads'][-1]['logits']); logits.append(row)
                selected=int(np.argmax(np.asarray(row,dtype=np.int64))); sequence.append(selected)
                if selected==eos: stop='eos'; break
            actual=model_impl.generate(model,list(prompt),maximum_new,eos)
        except ValueError as error:
            assert str(error)=='Overflow'
            continue
        assert (actual['tokens'],actual['stop'])==(sequence,stop)
        ws=tuple(r.witness(s,len(prompt)-1+i,row) for i,row in enumerate(logits))
        assert r.check_generation(s,r.derive(s),prompt,maximum_new,eos,tuple(sequence),stop,tuple(logits),ws)==tuple(sequence)
        accepted+=1
    assert accepted>0


def check():
    rng=random.Random(2641); digest=hashlib.sha256(); tied=0
    for case in range(10000):
        p=r.Spec(rng.randrange(1,33),rng.randrange(31),rng.randrange(1,(1<<20)+1)); pos=rng.randrange(p.length)
        xs=tuple(rng.randrange(-32768,32768) for _ in range(p.vocabulary))
        if case%5==0: xs=tuple((-32768,32767)[(i+case)%2] for i in range(p.vocabulary))
        if case%11==0: xs=(rng.randrange(-32768,32768),)*p.vocabulary
        values=np.asarray(xs,dtype=np.int64); selected=int(np.argmax(values)); maximum=int(np.max(values))
        tied+=int(sum(x==maximum for x in xs)>1)
        c=r.derive(p); assert c==certificate(p); raw=r.encode(p); assert raw==frame(p,c); r.validate_bytes(p,raw)
        w=r.witness(p,pos,xs); assert r.check_relations(p,c,pos,selected,xs,w)==selected
        assert w['maximum']==maximum
        assert tuple(e['difference'] for e in w['entries'])==tuple(int(v) for v in maximum-values)
        # Every selected id is externally expected, not accepted merely because it appears in the witness.
        if p.vocabulary>1:
            alternate=(selected+1)%p.vocabulary
            rejects('Selected',lambda:r.check_relations(p,c,pos,alternate,xs,w))
        digest.update(raw+json.dumps([pos,xs,selected,maximum],separators=(',',':')).encode())
        prompt=tuple(rng.randrange(p.vocabulary) for _ in range(rng.randrange(1,min(3,p.length)+1)))
        maximum_new=rng.randrange(min(3,p.length-len(prompt))+1); eos=rng.randrange(p.vocabulary)
        sequence=list(prompt); rows=[]; stop='limit'
        for _ in range(maximum_new):
            row=tuple(rng.randrange(-32768,32768) for _ in range(p.vocabulary)); rows.append(row)
            token=int(np.argmax(np.asarray(row,dtype=np.int64))); sequence.append(token)
            if token==eos: stop='eos'; break
        ws=tuple(r.witness(p,len(prompt)-1+i,row) for i,row in enumerate(rows))
        assert r.check_generation(p,c,prompt,maximum_new,eos,tuple(sequence),stop,tuple(rows),ws)==tuple(sequence)
        digest.update(json.dumps([prompt,maximum_new,eos,rows,sequence,stop],separators=(',',':')).encode())
    assert tied==2565
    assert digest.hexdigest()=='a7e0094c7b10873822664c15fc8be8bfbca50e35ea0137d14094b366903f8172'
    models()
    controls()
    print(json.dumps(dict(seed=2641,cases=10000,tied=tied,sha256=digest.hexdigest()),sort_keys=True))
