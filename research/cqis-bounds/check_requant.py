# /// script
# requires-python = ">=3.12"
# dependencies = ["numpy==2.3.4"]
# ///
"""Q26 closed scalar schema: exact/NumPy/native decisions and local attacks."""
from dataclasses import asdict, replace
from fractions import Fraction
import copy
import hashlib
import json
from pathlib import Path
from random import Random
import subprocess
import sys
import numpy as np
import requant as q
from check_limbs import rejects, oracle

ROOT = Path(__file__).resolve().parents[2]


def nearest(value):
    magnitude = abs(value)
    return (-1 if value < 0 else 1)*((2*magnitude.numerator+magnitude.denominator)//(2*magnitude.denominator))


def numpy_reference(acc,mantissa,shift):
    product = np.int64(acc)*np.int64(mantissa)
    divisor = np.left_shift(np.int64(1),np.int64(shift))
    whole,remainder = np.divmod(np.abs(product),divisor)
    return int(np.sign(product)*(whole+np.int64(shift > 0 and 2*remainder >= divisor)))


def rejects_malformed_requant():
    def rebuild(spec,acc,w):
        values = q.column_inputs(spec,acc,w)
        w['columns'] = {name:q.limbs.witness(s,*values[name]) for name,s in q.column_specs(spec).items()}
        return w
    spec = q.Spec(3,2,8)
    cert = q.derive(spec)
    for name,value in cert.items():
        if name == 'columns':
            for column,record in value.items():
                for field,item in record.items():
                    wrong = copy.deepcopy(cert)
                    wrong['columns'][column][field] = ((item[0]+1,)+item[1:] if type(item) is tuple else item+1)
                    rejects('Certificate',lambda: q.validate(spec,wrong))
            wrong = copy.deepcopy(cert);wrong['columns']['extra'] = {}
        else:
            wrong = copy.deepcopy(cert);wrong[name] = value+1
        rejects('Certificate',lambda: q.validate(spec,wrong))
    wrong = copy.deepcopy(cert)
    carry = wrong['columns']['product']['carry_caps']
    wrong['columns']['product']['carry_caps'] = (False,)+carry[1:]
    rejects('Certificate',lambda: q.validate(spec,wrong))
    for bad in [replace(spec,mantissa=0),replace(spec,mantissa=65536),
                replace(spec,shift=-1),replace(spec,shift=63),replace(spec,bits=32),replace(spec,shift=True)]:
        rejects('Spec',lambda: q.derive(bad))
    acc = -17
    witness = q.witness(spec,acc)
    check = lambda w: q.check_relations(spec,cert,acc,w)
    assert check(witness) == -13
    for name in ('magnitude','product','quotient','scaled_quotient','remainder'):
        wrong = copy.deepcopy(witness);wrong[name] += 1
        rejects('SourceDigits',lambda: check(wrong))
    wrong = copy.deepcopy(witness);wrong['sign'] = 0
    rejects('SourceDigits',lambda: check(wrong))
    wrong = copy.deepcopy(witness);wrong['output'] += 1
    rejects('OutputRelation',lambda: check(wrong))
    wrong = copy.deepcopy(witness);wrong['sign'] = True
    rejects('Witness',lambda: check(wrong))
    for name in ('sign','magnitude','product','quotient','scaled_quotient','remainder','output'):
        wrong = copy.deepcopy(witness);wrong[name] += q.P
        rejects('SourceDigits' if name == 'product' else 'Range',lambda: check(wrong))
    # Coherent local columns still need their inter-column and output bindings.
    wrong = copy.deepcopy(witness);wrong['sign'] = 0;wrong['output'] = 13
    rejects('IntegerRelation',lambda: check(rebuild(spec,acc,wrong)))
    wrong = copy.deepcopy(witness);wrong['product'] += 1;wrong['remainder'] += 1
    rejects('IntegerRelation',lambda: check(rebuild(spec,acc,wrong)))
    wrong = copy.deepcopy(witness);wrong['quotient'] += 1;wrong['output'] -= 1
    rejects('IntegerRelation',lambda: check(rebuild(spec,acc,wrong)))
    wrong = copy.deepcopy(witness);wrong['remainder'] += 1
    rejects('IntegerRelation',lambda: check(rebuild(spec,acc,wrong)))
    for name in cert['columns']:
        wrong = copy.deepcopy(witness)
        row = wrong['columns'][name]['result']
        wrong['columns'][name]['result'] = (row[0]+q.P,)+row[1:]
        rejects('Range',lambda: check(wrong))
    zero = q.witness(spec,0);zero['sign'] = 1
    rejects('Sign',lambda: q.check_relations(spec,cert,0,zero))
    # The input sign stays negative when a nonzero input rounds to output zero.
    spec = q.Spec(1,2,8);cert = q.derive(spec)
    negative = q.witness(spec,-1)
    assert negative['sign'] == 1 and q.check_relations(spec,cert,-1,negative) == 0
    # Plaintext source offset digits distinguish two valid int32 M31 aliases.
    spec = q.Spec(1,31,8);cert = q.derive(spec)
    assert 0 % q.P == q.P % q.P
    rejects('SourceDigits',lambda: q.check_relations(spec,cert,q.P,q.witness(spec,0)))
    spec = q.Spec(1,1,8);cert = q.derive(spec)
    valid = q.witness(spec,1)
    wrong = copy.deepcopy(valid);wrong['remainder'] = 2
    rejects('Range',lambda: q.check_relations(spec,cert,1,wrong))
    # Rebuild a coherent but wrong lower quotient: q=0 requires forbidden r=D.
    wrong = copy.deepcopy(valid)
    wrong.update(quotient=0,scaled_quotient=0,remainder=2,output=0)
    rejects('Range',lambda: q.check_relations(spec,cert,1,rebuild(spec,1,wrong)))
    rejects('OutputRange',lambda: q.witness(q.Spec(1,0,8),128))
    assert q.witness(q.Spec(1,0,8),-128)['output'] == -128
    for acc in (-(1 << 31)-1,1 << 31,True):
        rejects('Input',lambda: q.witness(spec,acc))


def report():
    rng,checksum = Random(2610),hashlib.sha256()
    lines,expected = [],[]
    accepted = {8:0,16:0}
    rows = []
    for bits in (8,16):
        rows += [(bits,rng.randrange(-(1 << 31),1 << 31),rng.randrange(1,65536),rng.randrange(63)) for _ in range(10000)]
        edge = 1 << (bits-1)
        accumulators = sorted({-(1 << 31),-3,-1,0,1,3,(1 << 31)-1,1-2*edge,2*edge-1} |
                              {sign*(edge+delta) for sign in (-1,1) for delta in (-1,0,1)})
        rows += [(bits,a,m,e) for a in accumulators
                 for m in (1,65535) for e in (0,1,2,31,47,48,62)]
    for bits,acc,mantissa,shift in rows:
        spec = q.Spec(mantissa,shift,bits)
        cert = q.derive(spec)
        for name,subspec in q.column_specs(spec).items():
            assert cert['columns'][name] == oracle(subspec)
            record = cert['columns'][name]
            assert max(record['lhs']+record['rhs']) < 1 << 20
        value = nearest(Fraction(acc*mantissa,1 << shift))
        assert value == numpy_reference(acc,mantissa,shift)
        valid = -(1 << (bits-1)) <= value < 1 << (bits-1)
        if valid:
            witness = q.witness(spec,acc)
            assert q.check_relations(spec,cert,acc,witness) == value
            accepted[bits] += 1
        else:
            rejects('OutputRange',lambda: q.witness(spec,acc))
        checksum.update(json.dumps([asdict(spec),acc,cert,value,valid],sort_keys=True).encode())
        lines.append(f'q{bits} {acc} {mantissa} {shift}')
        expected.append(f'ok {value}' if valid else 'error Range')
    rejects_malformed_requant()
    subprocess.run(['cargo','build','-p','stele-cqis','--example','arithmetic','--locked','--offline'],cwd=ROOT,check=True)
    metadata = subprocess.check_output(['cargo','metadata','--no-deps','--format-version','1','--offline'],cwd=ROOT,text=True)
    binary = Path(json.loads(metadata)['target_directory'])/'debug/examples/arithmetic'
    native = subprocess.run([str(binary)],cwd=ROOT,input='\n'.join(lines)+'\n',text=True,capture_output=True,check=True)
    assert native.stdout.splitlines() == expected
    return dict(cases=len(rows),seed=2610,accepted=accepted,rejected=len(rows)-sum(accepted.values()),checksum=checksum.hexdigest())


if __name__ == '__main__':
    encoded = json.dumps(report(),indent=2,sort_keys=True)+'\n'
    path = Path(__file__).with_name('requant.json')
    if sys.argv[1:] == ['--write']:
        path.write_text(encoded)
    else:
        assert not sys.argv[1:]
        assert path.read_text() == encoded
    print(encoded,end='')
