#!/usr/bin/env python3
"""Q25 / Draft RFC-0004 A2: exact candidate tests, not production lookup controls."""
import copy
from fractions import Fraction as Q
import hashlib
import json
from pathlib import Path
import random
import struct
import sys
import certified_exp as exp


def reference(x, scale):
    """Independent positive Taylor series and reciprocal geometric-tail bound."""
    if x == 0:
        return scale
    # exp(1)>2, so this branch proves an output strictly below half a unit.
    if x.numerator // x.denominator >= scale.bit_length()+1:
        return 0
    term = total = Q(1)
    for n in range(1,513):
        term *= x/n
        total += term
        ratio = x/(n+2)
        if ratio < 1:
            tail = term*x/(n+1)/(1-ratio)
            low, high = scale/(total+tail), scale/total
            if exp.round_nonnegative(low) == exp.round_nonnegative(high):
                return exp.round_nonnegative(low)
    raise ValueError('ReferencePrecision')


def rejects(reason, call):
    try:
        call()
    except ValueError as error:
        assert str(error) == reason, (reason,str(error))
    else:
        raise AssertionError(f'accepted instead of {reason}')


def report():
    assert [exp.round_nonnegative(Q(n,2)) for n in range(7)] == [0,1,1,2,2,3,3]
    for e in range(15):
        scale = 1 << e
        assert 2*max(scale*scale+2*scale-1,2*scale) < (1 << 31)-1
    rejects('Precision',lambda: exp.enclosure(Q(1),33))
    for x in [Q(-1),Q(32769),0.5]:
        rejects('Argument',lambda: exp.enclosure(x,64))
    # Equal numeric values of different types must not bypass validation on hits.
    exp.enclosure(Q(1,2),64)
    exp.enclosure(Q(0),64)
    exp.enclosure(Q(1),64)
    for x in (0.5,0,1,False,True):
        rejects('Argument',lambda: exp.enclosure(x,64))
    rejects('Precision',lambda: exp.enclosure(Q(1,2),64.0))
    rng = random.Random(2502)
    for x in [Q(0),Q(1,2**30),Q(1,2),Q(1),Q(32768)]+[Q(rng.randrange(32769),1 << rng.randrange(31)) for _ in range(100)]:
        low, high, p = exp.enclosure(x,64)
        assert 0 <= low <= high <= 1 << p and Q(high-low,1 << p) < Q(1,1 << 64)
        for e in (0,12,14):
            assert exp.certify(x,e)['value'] == reference(x,1 << e)
    cases, certificates = [], 0
    for b in (7,14,15):
        for f in (0,10,30):
            for e in (0,12,14):
                p = exp.Parameters(b,f,e)
                table = exp.generate(p)
                exp.verify(p,table)
                for tag in ('high','low'):
                    for i, cert in enumerate(table[tag]):
                        x = Q(i*(128 if tag == 'high' else 1),1 << f)
                        assert cert['value'] == reference(x,1 << e)
                        certificates += 1
                output = [exp.evaluate(p,table,t) for t in range(-(1 << b),1)]
                assert len(output) == (1 << b)+1 and output[-1] == 1 << e
                assert all(0 <= v <= 1 << e for v in output)
                cases.append(dict(B=b,F=f,E=e,high=len(table['high']),low=len(table['low']),entries=len(output),
                    decreases=sum(left > right for left,right in zip(output,output[1:])),
                    sha256=hashlib.sha256(b''.join(struct.pack('<I',v) for v in output)).hexdigest()))
    p = exp.Parameters(14,10,12)
    table = exp.generate(p)
    assert (exp.evaluate(p,table,-9216),exp.evaluate(p,table,-9215)) == (1,0)
    for tag in ('high','low'):
        for key in ('value','lower','upper','precision','bits'):
            bad = copy.deepcopy(table)
            bad[tag][1][key] += 1
            rejects('Certificate',lambda: exp.verify(p,bad))
        bad = copy.deepcopy(table);bad[tag].pop()
        rejects('TableShape',lambda: exp.verify(p,bad))
    rejects('Parameters',lambda: exp.verify(exp.Parameters(14,11,12),table))
    zero = exp.generate(exp.Parameters(7,0,0))
    zero['parameters'][1] = False
    rejects('Parameters',lambda: exp.verify(exp.Parameters(7,0,0),zero))
    for args in [(6,10,12),(16,10,12),(14,-1,12),(14,31,12),(14,10,-1),(14,10,15),(True,10,12)]:
        rejects('Parameters',lambda: exp.Parameters(*args))
    for t in [-(1 << 14)-1,1,True]:
        rejects('Domain',lambda: exp.evaluate(p,table,t))
    exact = exp.corrected(p)
    exp.verify_corrected(p,exact)
    for key,reason in [('corrections','Correction'),('direct','Certificate')]:
        bad = copy.deepcopy(exact)
        if key == 'direct':
            bad[key][0]['value'] += 1
        else:
            bad[key][0] += 1
        rejects(reason,lambda: exp.verify_corrected(p,bad))
    max_low, max_high, witness = Q(0),Q(0),None
    corrected_max, previous, changed = Q(0),-1,0
    for t in range(-(1 << p.B),1):
        value = exp.evaluate(p,table,t)
        low, high, bits = exp.enclosure(Q(-t,1 << p.F),64)
        a,b = Q((1 << p.E)*low,1 << bits),Q((1 << p.E)*high,1 << bits)
        lower = max(Q(0),a-value,value-b)
        upper = max(abs(value-a),abs(value-b))
        assert upper < 2  # Independent exhaustive enclosure of the full-domain ideal.
        corrected = exp.evaluate_corrected(p,exact,t)
        assert corrected == exact['direct'][t+(1 << p.B)]['value']
        assert previous <= corrected <= 1 << p.E
        previous = corrected
        changed += corrected != value
        error = max(abs(corrected-a),abs(corrected-b))
        assert error < Q(1,2) or t == 0
        corrected_max = max(corrected_max,error)
        assert corrected == reference(Q(-t,1 << p.F),1 << p.E)
        if lower > max_low:
            max_low, witness = lower,t
        max_high = max(max_high,upper)
    assert max_high-max_low < Q(1,1 << 40)
    ratio = lambda x: [x.numerator,x.denominator]
    return dict(version=1,scope='research candidate; no table/profile/native admission',cases=cases,
        independent_subtable_checks=certificates,example_error=dict(parameters=[14,10,12],units='integer output units',
        lower=ratio(max_low),upper=ratio(max_high),lower_witness_t=witness,analytic_strict_upper=2),
        corrected_example=dict(entries=len(exact['corrections']),changed=changed,
            correction_counts={str(c):exact['corrections'].count(c) for c in (-1,0,1,2)},
            certified_error_upper=ratio(corrected_max),analytic_error_upper=[1,2],
            sha256=hashlib.sha256(b''.join(struct.pack('<I',cert['value']) for cert in exact['direct'])).hexdigest()))


if __name__ == '__main__':
    result = report()
    path = Path(__file__).with_name('exp-candidate.json')
    if sys.argv[1:] == ['--write']:
        with path.open('x') as output:
            lines = []
            for key,value in result.items():
                encoded = ('[\n'+',\n'.join('    '+json.dumps(c,separators=(',',':')) for c in value)+'\n  ]'
                           if key == 'cases' else json.dumps(value,separators=(',',':')))
                lines.append('  '+json.dumps(key)+': '+encoded)
            output.write('{\n'+',\n'.join(lines)+'\n}\n')
    else:
        assert not sys.argv[1:]
        assert json.loads(path.read_text()) == result
    print('27 endpoint-safe exp candidates, independent sub-tables and every corrected example entry agree')
    print('all certificate/index/parameter mutations reject; research only, no NC or fidelity credit')
