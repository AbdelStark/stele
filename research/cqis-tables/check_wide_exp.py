#!/usr/bin/env python3
"""Q25: larger input domains with bounded sub-tables and explicit split identity."""
from fractions import Fraction as Q
import copy
import hashlib
import json
from pathlib import Path
import random
import struct
import sys
import certified_exp as exp
from check_exp import reference, rejects


def report():
    cases,checks = [],0
    rng = random.Random(2506)
    params = [(22,10,12,7),(22,10,12,11),(23,10,12,12),
              (30,30,14,15),(31,0,0,16),(31,30,14,16)]
    for args in params:
        p = exp.Parameters(*args)
        table = exp.generate(p);exp.verify(p,table)
        for tag,multiplier in [('high',1 << p.split),('low',1)]:
            assert len(table[tag]) <= 65536
            for i,cert in enumerate(table[tag]):
                assert cert['value'] == reference(Q(i*multiplier,1 << p.F),1 << p.E)
                checks += 1
        points = sorted({-(1 << p.B),-(1 << p.B)+1,-(1 << p.split)-1,
                         -(1 << p.split),-(1 << p.split)+1,-1,0}
                        | {-rng.randrange((1 << p.B)+1) for _ in range(10000)})
        encoded = []
        for t in points:
            value = exp.evaluate(p,table,t)
            h,l = divmod(-t,1 << p.split)
            expected = reference(Q(h*(1 << p.split),1 << p.F),1 << p.E)*reference(Q(l,1 << p.F),1 << p.E)//(1 << p.E)
            assert value == expected and 0 <= value <= 1 << p.E
            low,high,bits = exp.enclosure(Q(-t,1 << p.F),64)
            a,b = Q((1 << p.E)*low,1 << bits),Q((1 << p.E)*high,1 << bits)
            assert max(abs(value-a),abs(value-b)) < 2
            encoded.append(struct.pack('<qI',t,value))
        assert exp.evaluate(p,table,0) == 1 << p.E
        for t in (-(1 << p.B)-1,1,True):
            rejects('Domain',lambda: exp.evaluate(p,table,t))
        bad = copy.deepcopy(table);bad['parameters'][3] += 1
        rejects('Parameters',lambda: exp.verify(p,bad))
        bad = copy.deepcopy(table);bad['parameters'].pop()
        rejects('Parameters',lambda: exp.verify(p,bad))
        bad = copy.deepcopy(table);bad['high'].pop()
        rejects('TableShape',lambda: exp.verify(p,bad))
        bad = copy.deepcopy(table);bad['high'][-1]['value'] += 1
        rejects('Certificate',lambda: exp.verify(p,bad))
        rejects('CorrectionSize',lambda: exp.corrected(p))
        rejects('CorrectionSize',lambda: exp.verify_corrected(p,{}))
        rejects('CorrectionSize',lambda: exp.evaluate_corrected(p,{},0))
        cases.append(dict(parameters=list(args),high=len(table['high']),low=len(table['low']),
            virtual_entries=(1 << p.B)+1,samples=len(points),
            sha256=hashlib.sha256(b''.join(encoded)).hexdigest()))
    for args in [(32,10,12,16),(31,10,12,15),(22,10,12,6),(14,10,12,15),
                 (14,10,12,0),(14,10,12,17),(14,10,12,True)]:
        rejects('Parameters',lambda: exp.Parameters(*args))
    low,high,bits = exp.enclosure(Q(1 << 31),64)
    assert (low,high,bits) == (0,1,65)
    rejects('Argument',lambda: exp.enclosure(Q((1 << 31)+1),64))
    rejects('Argument',lambda: exp.enclosure(float(1 << 31),64))
    for bits in (32,64,128,256):
        for x in (Q(bits)+Q(1,2),Q(bits+1),Q(bits)+Q(3,2)):
            low,high,precision = exp.enclosure(x,bits)
            assert 0 <= low < high and Q(high-low,1 << precision) < Q(1,1 << bits)
            if x >= bits+1:
                assert (low,high,precision) == (0,1,bits+1)
            for e in (0,14):
                assert exp.certify(x,e)['value'] == reference(x,1 << e)
    # Small boundary configurations preserve the endpoint even when high has two rows.
    for args in [(7,0,0,1),(7,30,14,7),(16,30,14,16)]:
        p = exp.Parameters(*args);table = exp.generate(p);exp.verify(p,table)
        assert len(table['high']) == (1 << (p.B-p.split))+1
        assert len(table['low']) == 1 << p.split
        assert exp.evaluate(p,table,-(1 << p.B)) == reference(Q(1 << p.B,1 << p.F),1 << p.E)
    # The split changes rounded products; it belongs to the function's identity.
    p,q = exp.Parameters(14,10,12,7),exp.Parameters(14,10,12,6)
    a,b = exp.generate(p),exp.generate(q)
    differences = [t for t in range(-(1 << p.B),1) if exp.evaluate(p,a,t) != exp.evaluate(q,b,t)]
    assert differences
    t = differences[0]
    return dict(version=1,scope='research; explicit split, no attention/profile/native admission',
        cases=cases,independent_subtable_checks=checks,absolute_error_strict_upper=2,
        split_witness=dict(parameters=[14,10,12],splits=[7,6],input=t,
            outputs=[exp.evaluate(p,a,t),exp.evaluate(q,b,t)],different_entries=len(differences)))


if __name__ == '__main__':
    result = report()
    path = Path(__file__).with_name('wide-exp-candidates.json')
    if sys.argv[1:] == ['--write']:
        with path.open('x') as output:
            json.dump(result,output,indent=2);output.write('\n')
    else:
        assert not sys.argv[1:]
        assert json.loads(path.read_text()) == result
    print('wide exponential sub-tables and sampled full-domain products match independent exact oracle')
    print('split identity, endpoint, resource and parameter checks pass; research only')
