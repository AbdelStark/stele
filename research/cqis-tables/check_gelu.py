#!/usr/bin/env python3
"""Q25: GeLU variants against separate pi and positive integral series."""
from fractions import Fraction as Q
from functools import lru_cache
import copy
import hashlib
import json
from pathlib import Path
import random
import struct
import sys
import certified_activations as act
from check_activations import nearest, rejects


def atan_reference(x,bits):
    total,power = Q(0),x
    for n in range(0,512,2):
        total += power/(2*n+1)-power*x*x/(2*n+3)
        power *= x**4
        upper = total+power/(2*n+5)
        if upper-total < Q(1,1 << bits):
            return total,upper
    raise ValueError('ReferencePrecision')


@lru_cache(maxsize=16,typed=True)
def normalizer_reference(bits):
    # atan(1/2)+atan(1/3)=pi/4, independent of the generator's Machin identity.
    a,b = atan_reference(Q(1,2),bits+8),atan_reference(Q(1,3),bits+8)
    pi_low,pi_high = 4*(a[0]+b[0]),4*(a[1]+b[1])
    unit = 1 << bits

    def root_floor(value):
        lo,hi = 0,unit
        while hi-lo > 1:
            mid = (hi+lo)//2
            if mid*mid*value.denominator <= value.numerator*unit*unit:
                lo = mid
            else:
                hi = mid
        return lo

    return Q(root_floor(1/(2*pi_high)),unit),Q(root_floor(1/(2*pi_low))+1,unit)


def exp_reference(a,bits):
    if a == 0:
        return Q(1),Q(1)
    if a >= bits:
        return Q(0),Q(1,1 << bits)
    term = total = Q(1)
    for n in range(1,513):
        term *= a/n;total += term
        ratio = a/(n+2)
        if ratio < 1:
            tail = term*a/(n+1)/(1-ratio)
            low,high = 1/(total+tail),1/total
            if high-low < Q(1,1 << bits):
                return low,high
    raise ValueError('ReferencePrecision')


def reference(p,t):
    x,a,scale = Q(t,1 << p.F),Q(abs(t),1 << p.F),1 << p.E
    if t == 0:
        return 0
    for bits in (32,64,128,256):
        c0,c1 = normalizer_reference(bits+16)
        if p.kind == 'gelu_tanh':
            cubic = a+Q(8943,200000)*a**3
            z0 = exp_reference(4*c1*cubic,bits+16)[0]
            z1 = exp_reference(4*c0*cubic,bits+16)[1]
            low,high = z0/(1+z0),z1/(1+z1)
        elif a >= 8:
            low,high = Q(0),exp_reference(a*a/2,bits)[1]/(2*a)
        else:
            # I(a)=exp(-a²/2)*(a+a³/3+a⁵/15+...), all positive terms.
            z0,z1 = exp_reference(a*a/2,bits+80)
            term = total = a
            for n in range(512):
                ratio = a*a/(2*n+3)
                if ratio < 1:
                    tail = term*ratio/(1-ratio)
                    if z1*tail < Q(1,1 << (bits+16)):
                        break
                term *= ratio;total += term
            else:
                raise ValueError('ReferencePrecision')
            low = max(Q(0),Q(1,2)-c1*z1*(total+tail))
            high = min(Q(1,2),Q(1,2)-c0*z0*total)
        lo,hi = (a*(1-high),a*(1-low)) if x > 0 else (-a*high,-a*low)
        lo,hi = lo*scale,hi*scale
        value = nearest((lo+hi)/2)
        if lo >= value-Q(1,2) and hi <= value+Q(1,2):
            return value
    raise ValueError('ReferencePrecision')


def report():
    import certified_gelu as gelu
    for bits in (32,64,128,256):
        c0,c1 = gelu.normalizer(bits)
        a,b = normalizer_reference(bits)
        assert max(c0,a) < min(c1,b) and 0 < c0 < c1 < Q(1,2)
    rejects('Precision',lambda: gelu.normalizer(64.0))
    rejects('Precision',lambda: gelu.normalizer(273))
    rejects('Argument',lambda: gelu.gaussian_interval('gelu',Q(32769),32))
    for kind in ('gelu','gelu_tanh'):
        rejects('Overflow',lambda: act.generate(act.Parameters(kind,0,14)))
        for f in (0,1,30):
            for e in (0,14):
                p = act.Parameters(kind,f,e)
                for t in (-32768,-1,0,1,32767):
                    expected = reference(p,t)
                    if -32768 <= expected <= 32767:
                        assert act.certify(p,t)['value'] == expected
                    else:
                        rejects('Overflow',lambda: act.certify(p,t))
    cases,outputs = [],{}
    for kind in ('gelu','gelu_tanh'):
        p = act.Parameters(kind,8,8)
        table = act.generate(p)
        act.verify(p,table)
        values = [row['value'] for row in table['rows']]
        for t,value in zip(range(-32768,32768),values):
            assert value == reference(p,t),(kind,t,value)
        for key in ('value','lower','upper','bits','strict'):
            bad = copy.deepcopy(table)
            if key in ('lower','upper'):
                bad['rows'][0][key][0] += 1
            else:
                bad['rows'][0][key] += 1
            rejects('Certificate',lambda: act.verify(p,bad))
        other = act.Parameters('gelu_tanh' if kind == 'gelu' else 'gelu',8,8)
        rejects('Parameters',lambda: act.verify(other,table))
        assert act.certify(act.Parameters(kind,1,0),32767)['value'] == 16383
        assert act.certify(act.Parameters(kind,1,0),-32768)['value'] == 0
        rejects('Overflow',lambda: act.certify(act.Parameters(kind,0,14),32767))
        outputs[kind] = values
        cases.append(dict(parameters=p.metadata(),entries=len(values),minimum=min(values),maximum=max(values),
            sha256=hashlib.sha256(b''.join(struct.pack('<h',v) for v in values)).hexdigest()))
    rng = random.Random(2504)
    for kind in ('gelu','gelu_tanh'):
        for _ in range(10000):
            e = rng.randrange(15)
            p = act.Parameters(kind,rng.randrange(e,31),e)
            t = rng.randrange(-32768,32768)
            assert act.certify(p,t)['value'] == reference(p,t),(p,t)
    return dict(version=1,scope='research; distinct variants, no native identity or model fidelity',cases=cases,
        random_checks_per_variant=10000,absolute_error_to_own_real_variant=[1,2],
        different_example_entries=sum(a != b for a,b in zip(outputs['gelu'],outputs['gelu_tanh'])),
        largest_integer_example_difference=max(abs(a-b) for a,b in zip(outputs['gelu'],outputs['gelu_tanh'])))


if __name__ == '__main__':
    result = report()
    path = Path(__file__).with_name('gelu-candidates.json')
    if sys.argv[1:] == ['--write']:
        with path.open('x') as output:
            json.dump(result,output,indent=2);output.write('\n')
    else:
        assert not sys.argv[1:]
        assert json.loads(path.read_text()) == result
    print('both full GeLU variant tables and 20000 seeded inputs match separate exact pi/integral oracle')
