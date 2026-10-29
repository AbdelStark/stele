# /// script
# requires-python = ">=3.12"
# dependencies = ["numpy==2.3.4"]
# ///
"""Q26 closed RMSNorm bounds; exact/NumPy/native parity and local attacks."""
from dataclasses import asdict, replace
import copy
import hashlib
import json
from math import gcd
from pathlib import Path
from random import Random
import subprocess
import sys
import numpy as np
import norm_bounds as n
from check_limbs import rejects, oracle

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'research/cqis-tables'))
from check_rmsnorm import reference


def numpy_output(xs,gs,j,shift):
    product = np.array(xs,dtype=np.int64)*np.array(gs,dtype=np.int64)*np.int64(j)
    if shift < 0:
        return (product*(1 << -shift)).tolist()
    if shift >= 46:
        return [0]*len(xs)
    divisor = np.int64(1 << shift)
    q,r = np.divmod(np.abs(product),divisor)
    rounded = q+((shift > 0) & (2*r >= divisor)).astype(np.int64)
    return (np.sign(product)*rounded).tolist()


def rejects_malformed_norm():
    p = n.Spec(3,8,14,8,1,100000)
    xs,gs = (256,256,1),(16384,)*3
    cert,w = n.derive(p),n.witness(p,xs,gs)
    check = lambda value: n.check_relations(p,cert,xs,gs,value)
    assert check(w) == tuple(numpy_output(xs,gs,w['J'],p.F+p.G+21+w['a']-p.E))
    for name,value in cert.items():
        if name == 'columns':
            for role,column in value.items():
                for field,item in column.items():
                    bad = copy.deepcopy(cert)
                    bad['columns'][role][field] = (item[0]+1,)+item[1:] if type(item) is tuple else item+1
                    rejects('Certificate',lambda: n.validate(p,bad))
        else:
            bad = copy.deepcopy(cert);bad[name] = value+1
            rejects('Certificate',lambda: n.validate(p,bad))
    for bad in [replace(p,d=0),replace(p,d=16385),replace(p,F=31),replace(p,en=0),
                replace(p,en=2,ed=2),replace(p,E=True)]:
        rejects('Spec',lambda: n.derive(bad))
    for field,value in [('a',-24),('a',10),('M',16383),('M',65536),
                        ('R',cert['P'] << (2*max(w['a'],0)))]:
        bad = copy.deepcopy(w);bad[field] = value
        rejects('Range',lambda: check(bad))
    bad = copy.deepcopy(w);bad['J'] += 1
    rejects('Table',lambda: check(bad))
    bad = copy.deepcopy(w);bad['N'] += n.P
    rejects('IntegerRelation',lambda: check(bad))
    bad_cert = copy.deepcopy(cert);bad_cert['A_max'] = w['A']
    rejects('Certificate',lambda: n.validate(p,bad_cert))
    for role in w['columns']:
        bad = copy.deepcopy(w)
        out = bad['columns'][role]['result']
        bad['columns'][role]['result'] = (out[0]+n.P,)+out[1:]
        rejects('Range',lambda: check(bad))
    for role in w['rows'][0]['columns']:
        bad = copy.deepcopy(w)
        out = bad['rows'][0]['columns'][role]['result']
        bad['rows'][0]['columns'][role]['result'] = (out[0]+n.P,)+out[1:]
        rejects('Range',lambda: check(bad))
    for field in ('S','N','R','MD','A'):
        bad = copy.deepcopy(w);bad[field] += 1
        bad = n.attach_columns(p,xs,gs,bad)
        rejects('IntegerRelation',lambda: check(bad))
    bad = copy.deepcopy(w);bad['a'] += 1
    rejects('IntegerRelation',lambda: check(n.attach_columns(p,xs,gs,bad)))
    bad = copy.deepcopy(w);bad['M'] += 1;bad['J'] = n.reciprocal(bad['M'])
    bad['MD'] = bad['M']*(cert['P'] << (2*max(bad['a'],0)))
    rejects('IntegerRelation',lambda: check(n.attach_columns(p,xs,gs,bad)))
    for field in ('xy','product','quotient'):
        bad = copy.deepcopy(w);bad['rows'][0][field] += 1
        bad = n.attach_columns(p,xs,gs,bad)
        rejects('IntegerRelation',lambda: check(bad))
    bad = copy.deepcopy(w);bad['rows'][0]['output'] += 1
    rejects('OutputRelation',lambda: check(bad))
    bad = copy.deepcopy(w);bad['rows'][0]['x_sign'] = 1
    rejects('SourceSign',lambda: check(bad))
    bad = copy.deepcopy(w);bad['rows'][0]['product_sign'] = 1
    rejects('Sign',lambda: check(bad))
    bad = copy.deepcopy(w);bad['rows'][0]['x_sign'] = True
    rejects('Witness',lambda: check(bad))
    rejects('Input',lambda: n.witness(p,(32768,0,0),gs))
    left = n.Spec(4,0,0,14,1,2**32-1)
    left_x,left_g = (-1,0,0,0),(1,0,0,0)
    lw = n.witness(left,left_x,left_g)
    assert n.check_relations(left,n.derive(left),left_x,left_g,lw) == (-32768,0,0,0)
    lw['rows'][0]['remainder'] = 1
    rejects('Branch',lambda: n.check_relations(left,n.derive(left),left_x,left_g,lw))


def report():
    rng,checksum = Random(2611),hashlib.sha256()
    cases = []
    for i in range(11000):
        d,F,G,E = rng.randrange(1,9),rng.randrange(31),rng.randrange(31),rng.randrange(15)
        en,ed = rng.randrange(1,2**32),rng.randrange(1,2**32)
        common = gcd(en,ed);en //= common;ed //= common
        if i%4 == 0: en,ed = 1,2**32-1
        if i%4 == 1: en,ed = 2**32-1,1
        if i < 10000: G = max(G,E+((d-1).bit_length()+1)//2+1)
        p = n.Spec(d,F,G,E,en,ed)
        xs = tuple(rng.randrange(-32768,32768) for _ in range(d))
        gs = tuple(rng.randrange(-32768,32768) for _ in range(d))
        if i%5 == 0: gs = (0,)*d
        cases.append((p,xs,gs))
    cases += [(n.Spec(16384,30,30,14,1,2**32-1),(-32768,)*16384,(-32768,)*16384),
              (n.Spec(1,30,30,0,1,2**32-1),(0,),(-32768,)),
              (n.Spec(1,0,30,0,2**32-1,1),(-32768,),(-32768,)),
              (n.Spec(4,0,0,14,1,2**32-1),(-1,0,0,0),(1,0,0,0))]
    lines,expected,accepted = [],[],0
    for p,xs,gs in cases:
        cert = n.derive(p)
        for role,spec in n.column_specs(p).items():
            assert cert['columns'][role] == oracle(spec)
        a,m,j,ys,_ = reference(p,xs,gs)
        shift = p.F+p.G+21+a-p.E
        assert numpy_output(xs,gs,j,shift) == ys
        ok = all(-32768 <= y <= 32767 for y in ys)
        if ok:
            w = n.witness(p,xs,gs)
            assert n.check_relations(p,cert,xs,gs,w) == tuple(ys)
            assert (w['a'],w['M'],w['J']) == (a,m,j)
            D = cert['P'] << (2*max(a,0))
            fields = [w['S'],w['N'],cert['P'],w['A'],D,w['R'],a,m,j,shift,*ys]
            expected.append('ok '+' '.join(map(str,fields)));accepted += 1
        else:
            rejects('OutputRange',lambda: n.witness(p,xs,gs))
            expected.append('error Overflow')
        lines.append(' '.join(map(str,[*asdict(p).values(),*xs,*gs])))
        checksum.update(json.dumps([asdict(p),xs,gs,cert,expected[-1]],sort_keys=True).encode())
    assert accepted >= 10000 and accepted < len(cases)
    rejects_malformed_norm()
    subprocess.run(['cargo','build','-p','stele-cqis','--example','norm_arithmetic','--locked','--offline'],cwd=ROOT,check=True)
    meta = subprocess.check_output(['cargo','metadata','--no-deps','--format-version','1','--offline'],cwd=ROOT,text=True)
    binary = Path(json.loads(meta)['target_directory'])/'debug/examples/norm_arithmetic'
    result = subprocess.run([str(binary)],cwd=ROOT,input='\n'.join(lines)+'\n',text=True,capture_output=True,check=True)
    assert result.stdout.splitlines() == expected
    return dict(seed=2611,cases=len(cases),accepted=accepted,overflow=len(cases)-accepted,checksum=checksum.hexdigest())


if __name__ == '__main__':
    encoded = json.dumps(report(),indent=2,sort_keys=True)+'\n'
    path = Path(__file__).with_name('norm-bounds.json')
    if sys.argv[1:] == ['--write']:
        path.write_text(encoded)
    else:
        assert not sys.argv[1:]
        assert path.read_text() == encoded
    print(encoded,end='')
