#!/usr/bin/env python3
"""Q25: independent exact activation rounding, strict boundaries and mutations."""
import copy
from fractions import Fraction as Q
import hashlib
import json
from pathlib import Path
import random
import struct
import sys
import certified_activations as act


def nearest(x):
    magnitude = (abs(x).numerator*2+abs(x).denominator)//(2*abs(x).denominator)
    return -magnitude if x < 0 else magnitude


def reference(p,t):
    """Positive exponential series, reciprocal tail; no dyadic squaring."""
    x,scale = Q(t,1 << p.F),1 << p.E
    if x == 0:
        return nearest(Q(scale,2)) if p.kind == 'sigmoid' else 0
    cap = Q(p.cap_m,1 << p.cap_f) if p.kind == 'softcap' else Q(1)
    exponent = 2*abs(x)/cap if p.kind == 'softcap' else abs(x)

    def candidate(lo,hi):
        # Every nonzero-argument enclosure here is STRICT at both endpoints.
        if p.kind == 'sigmoid':
            a,b = (1/(1+hi),1/(1+lo)) if x > 0 else (lo/(1+lo),hi/(1+hi))
        elif p.kind == 'silu':
            a,b = (x/(1+hi),x/(1+lo)) if x > 0 else (x*hi/(1+hi),x*lo/(1+lo))
        else:
            a,b = cap*(1-hi)/(1+hi),cap*(1-lo)/(1+lo)
            if x < 0:
                a,b = -b,-a
        a,b = a*scale,b*scale
        value = nearest((a+b)/2)
        return value if a >= value-Q(1,2) and b <= value+Q(1,2) else None

    if exponent >= 1:
        value = candidate(Q(0),Q(1,1 << min(256,exponent.numerator//exponent.denominator)))
        if value is not None:
            return value
    term = total = Q(1)
    for n in range(1,513):
        term *= exponent/n
        total += term
        ratio = exponent/(n+2)
        if ratio < 1:
            tail = term*exponent/(n+1)/(1-ratio)
            value = candidate(1/(total+tail),1/total)
            if value is not None:
                return value
    raise ValueError('ReferencePrecision')


def rejects(reason,call):
    try:
        call()
    except ValueError as error:
        assert str(error) == reason,(reason,str(error))
    else:
        raise AssertionError(f'accepted instead of {reason}')


def report():
    for n in range(-8,9):
        tie = Q(2*n+1,2)
        assert act.round_endpoint(tie,-1) == n
        assert act.round_endpoint(tie,1) == n+1
        assert act.round_endpoint(tie,0) == nearest(tie)
    # A tiny positive exponential is not zero: closing this endpoint changes rounding.
    silu = act.Parameters('silu',1,0)
    witness = act.certify(silu,32767)
    assert witness['value'] == 16383 and nearest(Q(32767,2)) == 16384
    assert witness['upper'] == [32767,2] and witness['strict'] == 1
    cap = act.Parameters('softcap',0,0,1,1)
    assert act.certify(cap,32767)['value'] == 0
    assert act.certify(cap,-32768)['value'] == 0
    assert nearest(Q(1,2)) == 1
    for p,t in [(act.Parameters('sigmoid',0,0),0),(silu,0),(cap,0)]:
        assert act.certify(p,t)['value'] == reference(p,t)
    for args in [('unknown',8,8),('silu',True,8),('silu',31,8),('silu',8,15),
                 ('silu',8,8,1,0),('softcap',8,8,0,0),('softcap',8,8,2,1),
                 ('softcap',8,8,1,31),('softcap',8,8,65536,0)]:
        rejects('Parameters',lambda: act.Parameters(*args))
    for t in [-32769,32768,True]:
        rejects('Domain',lambda: act.certify(silu,t))
    rejects('Overflow',lambda: act.certify(act.Parameters('silu',0,14),32767))
    rejects('Overflow',lambda: act.certify(act.Parameters('softcap',0,14,3,0),32767))
    rejects('Precision',lambda: act.strict_exp(Q(1),33))
    rejects('Argument',lambda: act.strict_exp(Q(-1),32))
    boundary_checks = 0
    for f in (0,1,30):
        for e in (0,14):
            for kind in ('sigmoid','silu','softcap'):
                params = ([act.Parameters(kind,f,e,m,c) for m,c in ((1,30),(65535,30),(65535,0))]
                          if kind == 'softcap' else [act.Parameters(kind,f,e)])
                for p in params:
                    for t in (-32768,-1,0,1,32767):
                        expected = reference(p,t)
                        if -32768 <= expected <= 32767:
                            assert act.certify(p,t)['value'] == expected,(p,t)
                        else:
                            rejects('Overflow',lambda: act.certify(p,t))
                        boundary_checks += 1
    configs = [act.Parameters('sigmoid',8,12),act.Parameters('silu',8,8),
               act.Parameters('softcap',8,8,30,0)]
    cases = []
    for p in configs:
        table = act.generate(p)
        act.verify(p,table)
        values = [entry['value'] for entry in table['rows']]
        assert len(values) == 65536 and all(-32768 <= y <= 32767 for y in values)
        for t,value in zip(range(-32768,32768),values):
            assert value == reference(p,t),(p,t,value)
        if p.kind != 'silu':
            assert all(a <= b for a,b in zip(values,values[1:]))
        if p.kind == 'softcap':
            assert all(values[t+32768] == -values[-t+32768] for t in range(32768))
        for key in ('value','bits','strict','lower','upper'):
            bad = copy.deepcopy(table)
            if key in ('lower','upper'):
                bad['rows'][0][key][0] += 1
            else:
                bad['rows'][0][key] += 1
            rejects('Certificate',lambda: act.verify(p,bad))
        bad = copy.deepcopy(table);bad['rows'].pop()
        rejects('TableShape',lambda: act.verify(p,bad))
        bad = copy.deepcopy(table);bad['parameters'][1] = True
        rejects('Parameters',lambda: act.verify(p,bad))
        bad = copy.deepcopy(table);bad['rows'][0]['strict'] = True
        rejects('Certificate',lambda: act.verify(p,bad))
        cases.append(dict(parameters=p.metadata(),entries=len(values),minimum=min(values),maximum=max(values),
            sha256=hashlib.sha256(b''.join(struct.pack('<h',v) for v in values)).hexdigest()))
    rng = random.Random(2503)
    counts = dict.fromkeys(('sigmoid','silu','softcap'),0)
    for kind in counts:
        for _ in range(10000):
            f,e = rng.randrange(31),rng.randrange(15)
            # SiLU F>=E guarantees the full signed input domain fits int16.
            if kind == 'silu':
                f = max(f,e)
            if kind == 'softcap':
                m,c = rng.randrange(1,32768),rng.randrange(e,31)
                while c and m % 2 == 0:
                    m //= 2;c -= 1
                p = act.Parameters(kind,f,e,m,c)
            else:
                p = act.Parameters(kind,f,e)
            t = rng.randrange(-32768,32768)
            assert act.certify(p,t)['value'] == reference(p,t),(p,t)
            counts[kind] += 1
    return dict(version=1,scope='research; no table identity, native admission or fidelity',cases=cases,
        random_checks=counts,boundary_checks=boundary_checks,absolute_error_output_units=[1,2],
        strict_endpoint_witness=dict(parameters=silu.metadata(),input=32767,value=witness['value'],
            rounded_limit=16384),softcap_half_limit=dict(parameters=cap.metadata(),positive_tail=0,rounded_limit=1))


if __name__ == '__main__':
    result = report()
    path = Path(__file__).with_name('activation-candidates.json')
    if sys.argv[1:] == ['--write']:
        with path.open('x') as output:
            json.dump(result,output,indent=2);output.write('\n')
    else:
        assert not sys.argv[1:]
        assert json.loads(path.read_text()) == result
    print('three full signed-int16 activation tables and 30000 varied-scale entries match independent exact oracle')
    print('strict half-boundary cases and certificate/shape/parameter/overflow mutations pass; research only')
