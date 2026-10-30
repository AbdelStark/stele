"""Q26 / RFC-0021/0022, Draft RFC-0004 A3/A8/A9: model RMSNorm record/source composition."""
from dataclasses import asdict, replace
from math import gcd
from pathlib import Path
import copy
import hashlib
import json
import random
import subprocess
import sys
import tempfile
import model_norm_bounds as m
from check_causal_model import make, reference as model_reference
from check_decoder_block import reference as block_reference
from check_encoding import inspect, native_records
from check_norm_bounds import numpy_output
from check_rmsnorm import reference as norm_reference
from check_limbs import rejects
import row_bounds as rows

ROOT=Path(__file__).resolve().parents[2]


def expected_spec(p):
    return m.n.Spec(p.d,p.F,p.G,p.E,p.en,p.ed)


def check_row(p,raw,xs,gs,policy,converted,native=None):
    spec=m.spec(p); c=m.n.derive(spec); w=m.n.witness(spec,xs,gs); output=m.check(p,raw,xs,gs,w)
    a,mantissa,j,ys,_=norm_reference(spec,xs,gs); shift=p.F+p.G+21+a-p.E
    assert output==tuple(ys)==tuple(numpy_output(xs,gs,j,shift))
    assert (w['a'],w['M'],w['J'])==(a,mantissa,j)
    rp=rows.Spec('wide',p.d,p.E,*policy)
    scale,codes=rows.check_relations(rp,rows.derive(rp),output,rows.witness(rp,output))
    assert (scale,codes,p.E)==(converted.scale,converted.codes,converted.fraction)
    if native is not None:
        d=c['P'] << (2*max(a,0)); values=[w['S'],w['N'],c['P'],w['A'],d,w['R'],a,mantissa,j,shift,*output]
        native.append((spec,xs,gs,'ok '+' '.join(map(str,values))))
    return output


def model_rows(model,expected,positions,native=None):
    records=m.records(model); by_role={name:(spec,raw) for name,spec,raw in records}
    assert len(records)==len(by_role)==2*len(model.blocks)+1
    for i,b in enumerate(model.blocks):
        cells=block_reference(b,expected['cuts'][i],positions); prefix='layer.'+str(i)+'.'
        for source,cell in zip(expected['cuts'][i],cells):
            for role,p,xs,gs,policy,converted in (
                ('norm1',b.norm1,tuple(source),b.gains1,b.first,cell['x1']),
                ('norm2',b.norm2,tuple(cell['mid']),b.gains2,b.second,cell['x2'])):
                spec,raw=by_role[prefix+role]; assert spec==expected_spec(p)
                check_row(p,raw,xs,gs,policy,converted,native)
    spec,raw=by_role['final_norm']; assert spec==expected_spec(model.final_norm)
    for source,head in zip(expected['cuts'][-1],expected['heads']):
        output=check_row(model.final_norm,raw,tuple(source),model.gains,model.policy,head['input'],native)
        assert output==tuple(head['normalized'])


def native_rows(cases):
    subprocess.run(['cargo','build','-p','stele-cqis','--example','norm_arithmetic','--locked','--offline'],cwd=ROOT,check=True)
    metadata=subprocess.check_output(['cargo','metadata','--no-deps','--format-version','1','--offline'],cwd=ROOT,text=True)
    binary=Path(json.loads(metadata)['target_directory'])/'debug/examples/norm_arithmetic'
    with tempfile.TemporaryFile(mode='w+t') as source:
        for p,xs,gs,_ in cases: source.write(' '.join(map(str,[*asdict(p).values(),*xs,*gs]))+'\n')
        source.seek(0)
        with subprocess.Popen([str(binary)],stdin=source,stdout=subprocess.PIPE,text=True,cwd=ROOT) as child:
            try:
                for *_,expected in cases: assert child.stdout.readline(1<<20)==expected+'\n'
                assert child.stdout.read(1)=='' and child.wait()==0
            finally:
                if child.poll() is None: child.terminate();child.wait()


def controls():
    p=m.model.b.norm.Parameters(3,8,14,8,1,100000); s=m.spec(p); raw=m.e.encode(s)
    xs=(256,256,1); gs=(16384,)*3; w=m.n.witness(s,xs,gs); check=lambda v:m.check(p,raw,xs,gs,v)
    assert check(w)==tuple(norm_reference(s,xs,gs)[3])
    rejects('SourceSign',lambda:m.check(p,raw,(257,256,1),gs,w))
    rejects('SourceSign',lambda:m.check(p,raw,xs,(16385,16384,16384),w))
    rejects('Input',lambda:m.check(p,raw,xs[:-1],gs,w))
    rejects('Input',lambda:m.check(p,raw,xs,(True,16384,16384),w))
    bad=copy.deepcopy(w); bad['J']+=1; rejects('Table',lambda:check(bad))
    bad=copy.deepcopy(w); bad['S']+=m.n.P
    rejects('IntegerRelation',lambda:check(m.n.attach_columns(s,xs,gs,bad)))
    bad=copy.deepcopy(w); bad['rows'][0]['output']+=1; rejects('OutputRelation',lambda:check(bad))
    bad=copy.deepcopy(w); bad['rows']=bad['rows'][:-1]; rejects('Witness',lambda:check(bad))
    other=replace(p,E=7); rejects('Encoding',lambda:m.check(other,raw,xs,gs,w))
    for bad_raw in (raw[:-1],raw+b'\0',b'\0'+raw[1:],bytearray(raw)):
        rejects('Encoding',lambda:m.check(p,bad_raw,xs,gs,w))
    for changed in (replace(p,F=7),replace(p,G=13),replace(p,E=7),replace(p,en=3),replace(p,ed=99999)):
        rejects('Encoding',lambda:m.check(p,m.e.encode(m.spec(changed)),xs,gs,w))
    rejects('Parameters',lambda:m.spec(s)); rejects('Model',lambda:m.records(None))
    base=make(random.Random(2656),0); records=m.records(base)
    assert [name for name,_,_ in records]==['layer.0.norm1','layer.0.norm2','final_norm']
    assert records[0][1:]==records[1][1:]==records[2][1:]  # Identical bytes retain all source roles.
    changed=replace(base,blocks=(replace(base.blocks[0],norm2=replace(base.blocks[0].norm2,G=9)),))
    now=m.records(changed); assert now[0]==records[0] and now[2]==records[2] and now[1]!=records[1]
    changed=replace(base,final_norm=replace(base.final_norm,E=7)); now=m.records(changed)
    assert now[:2]==records[:2] and now[2]!=records[2]
    return [(m.n.Spec(4,0,0,14,1,2**32-1),(1,0,0,0),(1,0,0,0),'error Overflow')]


def models():
    rng=random.Random(2656); native=[]; specs=[]; accepted=0; digest=hashlib.sha256()
    for case in range(30):
        model=make(rng,case); blocks=[]
        for b in model.blocks:
            blocks.append(replace(b,norm1=replace(b.norm1,E=5+case%7,G=7+case%4),
                norm2=replace(b.norm2,E=6+case%6,G=8+case%3),first=('static',256) if case%4==0 else ('dynamic',0)))
        model=replace(model,blocks=tuple(blocks),final_norm=replace(model.final_norm,E=5+case%8,G=7+case%5),
                      policy=('static',259) if case%5==0 else ('dynamic',0))
        records=m.records(model); expected=[]
        for i,b in enumerate(blocks):
            expected.extend([('layer.'+str(i)+'.norm1',expected_spec(b.norm1)),('layer.'+str(i)+'.norm2',expected_spec(b.norm2))])
        expected.append(('final_norm',expected_spec(model.final_norm)))
        assert [(name,s) for name,s,_ in records]==expected
        for _,s,raw in records: inspect(s,raw); specs.append(s); digest.update(raw)
        weight=model.embedding; zero=replace(weight,codes=tuple((0,)*len(row) for row in weight.codes),mantissas=(1,)*len(weight.codes))
        quiet=replace(model,embedding=zero,gains=(0,)*model.final_norm.d,
                      blocks=tuple(replace(b,gains1=(0,)*b.norm1.d,gains2=(0,)*b.norm2.d) for b in blocks))
        assert m.records(quiet)==records  # Source values cannot tighten expected records.
        try: expected=model_reference(model,[0,1,2])
        except ValueError as error:
            assert str(error)=='Overflow'; rejects('Overflow',lambda:m.model.full(model,[0,1,2])); continue
        actual=m.model.full(model,[0,1,2]); assert {k:actual[k] for k in expected}==expected
        model_rows(model,expected,[0,1,2],native); accepted+=1
    # Native numerical rejection is separate from a witness for a rejected row.
    native.extend(controls()); p,xs,gs,_=native[-1]
    rejects('OutputRange',lambda:m.n.witness(p,xs,gs))
    native_records(specs); native_rows(native)
    assert (accepted,len(specs),len(native))==(24,150,355)
    assert digest.hexdigest()=='de70bba8c00a2d0b90fd5561320d90c55316ea7b5ac845bc5706ffbbb3cc419d'
    return accepted,len(native)-1,digest.hexdigest()


def check():
    rng=random.Random(2655); specs=[]; digest=hashlib.sha256()
    for case in range(10000):
        d,f,g,e=rng.randrange(1,16385),rng.randrange(31),rng.randrange(31),rng.randrange(15)
        en,ed=rng.randrange(1,2**32),rng.randrange(1,2**32); common=gcd(en,ed); en//=common; ed//=common
        p=m.model.b.norm.Parameters(d,f,g,e,en,ed); s=m.spec(p); assert s==m.n.Spec(d,f,g,e,en,ed)
        raw=m.e.encode(s); inspect(s,raw); m.e.validate(s,raw); specs.append(s); digest.update(raw)
    native_records(specs); accepted,native_count,models_sha=models()
    assert digest.hexdigest()=='049f542209a04e4c933814482f40ff18aba7c9e68a0faf9da0f00444830faaa8'
    print(json.dumps(dict(seed=2655,parameters=10000,sha256=digest.hexdigest(),model_seed=2656,
                          models_accepted=accepted,models_overflow=30-accepted,native_model_rows=native_count,
                          native_overflow_rejections=1,model_records_sha256=models_sha),sort_keys=True))
