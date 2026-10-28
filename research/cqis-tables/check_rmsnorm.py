#!/usr/bin/env python3
"""Q25: total RMSNorm candidate, exact independent roots and remainder checks."""
from fractions import Fraction as Q
import copy
import hashlib
import json
from pathlib import Path
import random
import struct
import sys
import certified_rmsnorm as norm
import norm_limbs as limbs
from check_activations import nearest, rejects


def root_floor(ratio):
    """Independent integer bisection, with no isqrt or floating arithmetic."""
    low,high = 0,1
    while high*high*ratio.denominator <= ratio.numerator:
        high *= 2
    while high-low > 1:
        mid = (low+high)//2
        if mid*mid*ratio.denominator <= ratio.numerator:
            low = mid
        else:
            high = mid
    return low


def root_round(ratio):
    low = root_floor(ratio)
    return low+int(4*ratio.numerator >= ratio.denominator*(2*low+1)**2)


def reference(p,xs,gs):
    statistic = sum(x*x for x in xs)
    q = Q(statistic,p.d*(1 << (2*p.F)))+Q(p.en,p.ed)
    candidates = [a for a in range(-23,10) if (1 << 14)*Q(4)**a <= q < (1 << 16)*Q(4)**a]
    assert len(candidates) == 1
    a = candidates[0]
    scaled = q/Q(4)**a
    m = scaled.numerator//scaled.denominator
    j = root_round(Q(1 << 42,m))
    factor = Q(2)**(p.E-p.F-p.G-21-a)
    return a,m,j,[nearest(x*g*j*factor) for x,g in zip(xs,gs)],q


def report():
    for a,b in [(0,0),(1,1),((1 << 160)-1,(1 << 160)-1)]:
        record = limbs.multiply(a,b);assert limbs.verify(a,b,record) == a*b
    for key in ('output','carries'):
        bad = copy.deepcopy(record);bad[key][1] += 1
        rejects('LimbIdentity',lambda: limbs.verify(a,b,bad))
    bad = copy.deepcopy(record);bad['output'][0] = 256
    rejects('LimbRange',lambda: limbs.verify(a,b,bad))
    bad = copy.deepcopy(record);bad['carries'][0] = 8192
    rejects('LimbRange',lambda: limbs.verify(a,b,bad))
    rejects('LimbDomain',lambda: limbs.multiply(1 << 160,1))
    table = norm.generate_table()
    norm.verify_table(table)
    entries = [c['value'] for c in table['rows']]
    assert len(entries) == 49152 and entries[0] == 16384 and entries[-1] == 8192
    assert all(a >= b for a,b in zip(entries,entries[1:]))
    minimum,maximum = Q(2),Q(0)
    for m,j in zip(range(16384,65536),entries):
        assert j == root_round(Q(1 << 42,m))
        lo,hi = Q(j*j*m,1 << 42),Q(j*j*(m+1),1 << 42)
        assert (1-Q(1,1 << 14))**2 <= lo <= hi < (1+norm.DELTA)**2
        minimum,maximum = min(minimum,lo),max(maximum,hi)
    for key in ('value','lower_gap','upper_gap'):
        bad = copy.deepcopy(table);bad['rows'][0][key] += 1
        rejects('TableCertificate',lambda: norm.verify_table(bad))
    bad = copy.deepcopy(table);bad['rows'].pop()
    rejects('TableShape',lambda: norm.verify_table(bad))
    for m in (16383,65536,True):
        rejects('Mantissa',lambda: norm.rsqrt_certificate(m))
        rejects('Mantissa',lambda: norm.verify_entry(m,table['rows'][0]))
    for value,shift,expected in [(-3,1,-2),(3,1,2),(-3,-1,-6),(3,-1,6),(1,90,0)]:
        assert norm.round_shift(value,shift) == expected
    for args in [(0,8,8,8,1,100000),(16385,8,8,8,1,100000),
                 (1,31,8,8,1,100000),(1,8,8,15,1,100000),(True,8,8,8,1,100000),
                 (1,8,8,8,0,1),(1,8,8,8,2,2),(1,8,8,8,1,1 << 32)]:
        rejects('Parameters',lambda: norm.Parameters(*args))
    transitions = 0
    for a in range(-22,9):
        power = 14+2*a
        f = max(0,(30-power)//2)
        p = norm.Parameters(1,f,14,8,1,(1 << 32)-1)
        boundary = (Q(2)**power-Q(p.en,p.ed))*(1 << (2*f))
        s = boundary.numerator//boundary.denominator
        below,above = norm.normalize(p,s),norm.normalize(p,s+1)
        norm.verify_normalization(p,s,below);norm.verify_normalization(p,s+1,above)
        assert (below['a'],above['a']) == (a-1,a)
        assert below['J']*Q(2)**(-21-below['a']) >= above['J']*Q(2)**(-21-above['a'])
        transitions += 1
    p = norm.Parameters(1,0,14,8,(1 << 32)-1,1)
    assert (norm.normalize(p,0)['a'],norm.normalize(p,1)['a']) == (8,9)
    assert norm.normalize(p,1)['R'] == 0
    transitions += 1
    for s in (-1,(1 << 30)+1,True):
        rejects('Statistic',lambda: norm.normalize(p,s))
    examples = []
    for xs in ([0],[1],[256],[256,256,1],[-32768]*16384):
        p = norm.Parameters(len(xs),8,14,8,1,100000)
        gs = [16384]*len(xs)
        result = norm.evaluate(p,xs,gs)
        norm.verify(p,xs,gs,result)
        examples.append(dict(statistic=result['norm']['S'],a=result['norm']['a'],
            M=result['norm']['M'],remainder=result['norm']['R'],first_output=result['output'][0]))
    p,xs,gs = norm.Parameters(3,8,14,8,1,100000),[256,256,1],[16384]*3
    result = norm.evaluate(p,xs,gs)
    bad = copy.deepcopy(result);bad['parameters'][1] += 1
    rejects('Parameters',lambda: norm.verify(p,xs,gs,bad))
    for key,reason in [('S','Statistic'),('N','Statistic'),('P','Statistic'),
                       ('a','Normalization'),('M','Normalization'),('R','Normalization'),('J','TableCertificate')]:
        bad = copy.deepcopy(result);bad['norm'][key] += 1
        rejects(reason,lambda: norm.verify(p,xs,gs,bad))
    bad = copy.deepcopy(result);bad['output'][0] += 1
    rejects('Output',lambda: norm.verify(p,xs,gs,bad))
    bad = copy.deepcopy(result);bad['shift'] += 1
    rejects('Output',lambda: norm.verify(p,xs,gs,bad))
    bad = copy.deepcopy(result);bad['norm']['a'] = True
    rejects('Normalization',lambda: norm.verify(p,xs,gs,bad))
    rejects('Shape',lambda: norm.evaluate(p,xs,gs[:-1]))
    rejects('Domain',lambda: norm.evaluate(p,[True,256,1],gs))
    rejects('Overflow',lambda: norm.evaluate(norm.Parameters(1,0,0,14,1,100000),[32767],[32767]))
    edge = norm.evaluate(norm.Parameters(1,8,14,8,1,100000),[-32768],[-32768])
    assert edge['norm']['J']*32768**2 == 1 << 44 and edge['output'] == [512]
    edge = norm.evaluate(norm.Parameters(1,30,30,0,(1 << 32)-1,1),[-32768],[-32768])
    # The independent global bound 90 is conservative: this row has a=8.
    assert edge['shift'] == 89 and edge['output'] == [0]
    rng = random.Random(2505)
    accepted,rejected,changed = 0,0,0
    max_integer_difference = 0
    for case in range(10000):
        d = rng.randrange(1,33)
        p = norm.Parameters(d,rng.randrange(31),rng.randrange(31),rng.randrange(15),
                            *rng.choice([(1,100000),(1,(1 << 32)-1),((1 << 32)-1,1),(1,1)]))
        xs = [rng.randrange(-32768,32768) for _ in range(d)]
        gs = [rng.randrange(-32768,32768) for _ in range(d)]
        a,m,j,expected,q = reference(p,xs,gs)
        w = norm.normalize(p,sum(x*x for x in xs))
        assert (w['a'],w['M'],w['J']) == (a,m,j)
        bounds = norm.bounds(p);norm.verify_bounds(p,bounds)
        assert w['N'] <= bounds['N'] and w['P'] == bounds['P']
        A,D = norm.scaled_ratio(w['N'],w['P'],a)
        assert A <= bounds['scaled_N'] and D <= bounds['scaled_P']
        shift = p.F+p.G+21+a-p.E
        assert -16 <= bounds['shift_min'] <= shift <= bounds['shift_max'] <= 90
        for x,g in zip(xs,gs):
            product = abs(x*g*j)
            assert product <= bounds['product']
            if shift < 0:assert product << -shift <= bounds['left_product']
            else:assert product+(1 << (shift-1) if shift else 0) <= bounds['biased']
        if case < 64:
            products = [(p.ed,w['S']),(w['M'],D),(abs(xs[0]),abs(gs[0])),(abs(xs[0]*gs[0]),j)]
            for left,right in products:
                assert limbs.verify(left,right,limbs.multiply(left,right)) == left*right
        for name in ('hh','hl_abs','ll'):
            assert 2*bounds[name] < (1 << 31)-1
        if any(not -32768 <= y <= 32767 for y in expected):
            rejects('Overflow',lambda: norm.evaluate(p,xs,gs));rejected += 1
            continue
        result = norm.evaluate(p,xs,gs);norm.verify(p,xs,gs,result)
        assert result['output'] == expected
        accepted += 1
        # Compare to the exact real RMSNorm, separately from candidate parity.
        error_bound = Q(1 << p.E)*Q(32768,1 << p.G)*norm.ceil_root(p.d)*norm.DELTA+Q(1,2)
        for x,g,y in zip(xs,gs,expected):
            factor = Q(x*g)*Q(2)**(p.E-p.F-p.G)
            ratio = factor*factor/q
            ideal = root_round(ratio)*(-1 if factor < 0 else 1)
            delta = abs(y-ideal)
            changed += bool(delta);max_integer_difference = max(max_integer_difference,delta)
            lower = Q(root_floor(ratio*(1 << 128)),1 << 64)
            upper = lower+Q(1,1 << 64)
            if factor < 0:lower,upper = -upper,-lower
            assert max(abs(y-lower),abs(y-upper)) <= error_bound
    for key in norm.bounds(p):
        bad = norm.bounds(p);bad[key] += 1
        rejects('Bounds',lambda: norm.verify_bounds(p,bad))
    ratio = lambda q: [q.numerator,q.denominator]
    return dict(version=1,scope='research only; no native norm/range/identity admission',
        exponent_transitions=transitions,
        table=dict(entries=len(entries),minimum=min(entries),maximum=max(entries),
            sha256=hashlib.sha256(b''.join(struct.pack('<h',j) for j in entries)).hexdigest()),
        inverse_relative_squared=dict(lower=ratio(minimum),strict_upper=ratio(maximum),delta=ratio(norm.DELTA)),
        limb_bounds=dict(input_bytes=20,output_bytes=40,carry_bits=13,left=limbs.LEFT_BOUND,right=limbs.RIGHT_BOUND),
        rows=dict(accepted=accepted,overflow_rejected=rejected,changed_output_elements=changed,
                  largest_integer_output_difference=max_integer_difference),examples=examples)


if __name__ == '__main__':
    result = report()
    path = Path(__file__).with_name('rmsnorm-candidate.json')
    if sys.argv[1:] == ['--write']:
        with path.open('x') as output:
            json.dump(result,output,indent=2);output.write('\n')
    else:
        assert not sys.argv[1:]
        assert json.loads(path.read_text()) == result
    print('49152 rsqrt entries, uniform inverse bounds and 10000 RMSNorm rows checked with exact independent roots')
    print('zero statistics, signed rounding, overflow, remainder/table/bound mutations checked; research only')
