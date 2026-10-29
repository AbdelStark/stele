# /// script
# requires-python = ">=3.12"
# dependencies = ["numpy==2.3.4", "blake3==1.0.11"]
# ///
"""Q26 exact attention-unit study; no native/proof/fidelity admission."""
from fractions import Fraction as Q
import hashlib
import json
import random
import numpy as np
from attention import Config, Cache, prepare, row, bounds, minimum_drop, fn, exp


def reject(reason, f):
    try: f()
    except ValueError as error: assert str(error) == reason, (reason, str(error))
    else: raise AssertionError('accepted '+reason)


def rounded(x):
    lo = x.numerator//x.denominator; hi = lo+1
    return min((lo, hi), key=lambda v: (abs(x-v), -abs(v)))


def convert(values, mode, scale):
    if mode == 'dynamic':
        maximum = max(map(abs, values))
        scale = next(s for s in range(260) if 127*s >= maximum)
    result = [rounded(Q(x, scale)) for x in values] if scale else [0]*len(values)
    if any(abs(x)>127 for x in result): raise ValueError('Overflow')
    return scale, result


def oracle(p, scores, allowed, values):
    prepared = [convert(v, p.value_mode, p.value_scale) for v in values]
    indices = [j for j, bit in enumerate(allowed) if bit]
    m = max(scores[j] for j in indices); selected = min(j for j in indices if scores[j] == m)
    b, f, e = p.function.params[:3]
    weights = []
    for j, score in enumerate(scores):
        if not allowed[j]: weights.append(0); continue
        delta = m-score
        if not 0<=delta<=1 << b: raise ValueError('Domain')
        if p.function.name.endswith('nearest'):
            weights.append(exp.certify(Q(delta, 1 << f), e)['value'])
        else:
            split = p.function.params[3]
            high = delta//(1 << split); low = delta-high*(1 << split)
            a = exp.certify(Q(high*(1 << split), 1 << f), e)['value']
            z = exp.certify(Q(low, 1 << f), e)['value']
            weights.append(a*z//(1 << e))
    z = sum(weights); restored = [[s*x for x in codes] for s, codes in prepared]
    matrix = np.asarray(restored, dtype=np.int64)
    products = np.asarray(weights, dtype=np.int64)[:, None]*matrix
    # Each row product and their full sum are within the derived int64 bound.
    assert np.max(np.abs(products), initial=0) < 1 << 50
    sums = [sum(weights[j]*restored[j][c] for j in range(len(values))) for c in range(len(values[0]))]
    assert sums == [int(x) for x in products.sum(axis=0, dtype=np.int64)]
    groups = {}
    for j in range(len(values)):
        group = j//1024 if p.accumulation == 'block1024' else 0
        groups.setdefault(group, [0]*len(values[0]))
        for c in range(len(values[0])): groups[group][c] += weights[j]*restored[j][c]
    partial = [[rounded(Q(x, 1 << p.drop)) for x in part] for part in groups.values()]
    if p.accumulation == 'block1024': assert all(-32768<=x<=32767 for part in partial for x in part)
    total = [sum(part[c] for part in partial) for c in range(len(values[0]))]
    ideals = [Q(x, z)*Q(2)**(p.fo-p.fv+p.drop) for x in total]
    wide = [rounded(x) for x in ideals]
    if any(not -32768<=x<=32767 for x in wide): raise ValueError('Overflow')
    scale, codes = convert(wide, p.output_mode, p.output_scale)
    return dict(maximum=m, selected=selected, z=z, total=total, wide=wide, scale=scale, codes=codes), ideals


def config(*, accumulation='exact', drop=0, value_mode='static', value_scale=1, fv=0, fo=0, e=0):
    return Config(fn.Function('exp_q/nearest', 1, bytes([7, 7, e])), fv, fo,
                  value_mode, value_scale, 'dynamic', 0, accumulation, drop)


def check():
    rng, digest = random.Random(2627), hashlib.sha256()
    success = 0
    for scale in range(1, 65536):
        assert scale*min(127, (65536+scale)//(2*scale)) <= 65535
    for case in range(10000):
        n, width = rng.randrange(1, 33), rng.randrange(1, 5)
        function = fn.Function('exp_q/product' if case%2 else 'exp_q/nearest', 1,
                               bytes([7, (3, 7, 10)[case%3], case%15])+ (bytes([3]) if case%2 else b''))
        mode = 'dynamic' if case%3 else 'static'; scale = 0 if mode == 'dynamic' else rng.randrange(1, 65536)
        accumulation = 'exact' if case%2 else 'block1024'
        provisional = Config(function, rng.randrange(31), rng.randrange(31), mode, scale,
                             'dynamic' if case%4 else 'static', 0 if case%4 else rng.randrange(1, 65536), 'exact', 0)
        drop = 0 if accumulation == 'exact' else min(62, minimum_drop(provisional)+rng.randrange(4))
        p = Config(function, provisional.fv, provisional.fo, mode, scale,
                   provisional.output_mode, provisional.output_scale, accumulation, drop)
        values = [[rng.randrange(-32768, 32768) for _ in range(width)] for _ in range(n)]
        if case%100 == 0: values = [[0]*width for _ in range(n)]
        scores = [rng.randrange(-64, 65) for _ in range(n)]
        allowed = [bool(rng.randrange(2)) for _ in range(n)]; allowed[case%n] = True
        try: expected, ideals = oracle(p, scores, allowed, values)
        except ValueError as error:
            reject(str(error), lambda: row(p, scores, allowed, prepare(p, values)))
            digest.update(b'reject'); continue
        cache = prepare(p, values); actual = row(p, scores, allowed, cache)
        assert {key: actual[key] for key in expected} == expected
        assert all(abs(Q(x)-y)<=Q(1, 2) for x, y in zip(actual['wide'], ideals))
        static = bounds(p, n)
        assert abs(max(actual['total'], key=abs)) <= static['sum_max']
        assert all(x <= static['numerator_max'] and y <= static['denominator_max'] for x, y in actual['division'])
        success += 1; digest.update(json.dumps(actual, sort_keys=True, separators=(',', ':')).encode())
    # Value codes alone cannot identify physical values with different row scales.
    p = config(value_mode='dynamic', value_scale=0)
    cache = prepare(p, [[127], [254]])
    assert cache.codes == ((127,), (127,)) and cache.scales == (1, 2)
    result = row(p, [0, 0], [True, True], cache)
    assert result['wide'] == [191] and rounded(Q(127+127, 2)) == 127
    # Existing A*Z=O+rho, 0<=rho<Z selects ceiling, not signed half-away.
    p = config(); result = row(p, [0, 0], [True, True], prepare(p, [[-1], [-2]]))
    assert result['wide'] == [-2] and -((-(-3))//2) == -1  # ceil(-3/2)
    assert (-2)*2-(-3) == -1
    # A block result carries changed units; normalization must restore 2^drop.
    block = config(accumulation='block1024', drop=2)
    result = row(block, [0]*1024, [True]*1024, prepare(block, [[64]]*1024))
    assert result['wide'] == [64] and rounded(Q(result['total'][0], result['z'])) == 16
    # Fixed absolute key blocks differ from compacting the selected keys.
    values = [[2]]*1025; allowed = [True]+[False]*1023+[True]
    result = row(block, [0]*1025, allowed, prepare(block, values))
    compact = row(block, [0, 0], [True, True], prepare(block, [[2], [2]]))
    assert result['wide'] == [4] and compact['wide'] == [2]
    prefix_cases = 0
    values = [[(j%19)-9, (j%13)-6] for j in range(1031)]
    for p in (config(), block):
        full = prepare(p, values)
        for end in (0, 1, 1022, 1023, 1024, 1030):
            scores = [(j%17)-8 for j in range(len(values))]
            allowed = [max(0, end-1024)<=j<=end for j in range(len(values))]
            a = row(p, scores, allowed, full)
            b = row(p, scores[:end+1], allowed[:end+1], prepare(p, values[:end+1]))
            assert a == b
            prefix_cases += 1
    # Switching mode from allocated sequence length breaks full/prefix agreement.
    assert row(block, [0]*1025, [True]+[False]*1024, prepare(block, [[2]]*1025))['wide'] == [4]
    assert row(config(), [0], [True], prepare(config(), [[2]]))['wide'] == [2]
    # Dynamic row scales also survive absolute block boundaries and masked tails.
    p = config(value_mode='dynamic', value_scale=0)
    p = Config(p.function, 3, 3, 'dynamic', 0, 'dynamic', 0, 'block1024', minimum_drop(p))
    values = [[((j*997)%65536)-32768] for j in range(1031)]
    full = prepare(p, values)
    for end in (0, 1023, 1024, 1030):
        allowed = [j<=end for j in range(1031)]
        assert row(p, [0]*1031, allowed, full) == row(p, [0]*(end+1), [True]*(end+1), prepare(p, values[:end+1]))
        prefix_cases += 1
    multi_block_cases = 0
    for n in (1023, 1024, 1025, 2049):
        for mode, scale in (('static', 1), ('static', 257), ('dynamic', 0)):
            p = config(value_mode=mode, value_scale=scale, e=12)
            for accumulation in ('exact', 'block1024'):
                candidate = Config(p.function, 0, 0, mode, scale, 'dynamic', 0,
                                   accumulation, 0 if accumulation == 'exact' else minimum_drop(p))
                values = [[(j*13)%255-127, (j*19)%255-127] for j in range(n)]
                scores = [(j%127)-63 for j in range(n)]; allowed = [j%3!=1 for j in range(n)]
                expected, _ = oracle(candidate, scores, allowed, values)
                actual = row(candidate, scores, allowed, prepare(candidate, values))
                assert {key: actual[key] for key in expected} == expected
                multi_block_cases += 1
    # Direct signed ties, int16 endpoints and exact output unit conversion.
    for values, fv, fo, expected in (([[-32768]], 0, 0, [-32768]),
            ([[32767]], 0, 0, [32767]), ([[-1], [0]], 0, 0, [-1]),
            ([[1], [0]], 0, 0, [1]), ([[64]], 2, 0, [16]), ([[64]], 0, 2, [256])):
        p = config(value_scale=259 if abs(values[0][0])>127 else 1, fv=fv, fo=fo)
        if abs(values[0][0])>127:
            # Choose scales that restore the endpoint exactly from one code.
            p = config(value_scale=32768 if values[0][0]<0 else 32767)
        assert row(p, [0]*len(values), [True]*len(values), prepare(p, values))['wide'] == expected
    reject('Input', lambda: prepare(config(), [[True]]))
    reject('Units', lambda: config(fv=True))
    reject('Scale', lambda: config(value_mode='dynamic', value_scale=1))
    reject('Score', lambda: row(config(), [1 << 31], [True], prepare(config(), [[1]])))
    reject('Overflow', lambda: row(config(fo=30), [0], [True], prepare(config(fo=30), [[1]])))
    p = config(); cache = prepare(p, [[1], [2]])
    assert row(p, [0, (1 << 31)-1], [True, False], cache)['maximum'] == 0
    reject('EmptyRow', lambda: row(p, [0, 0], [False, False], cache))
    reject('Domain', lambda: row(p, [0, -129], [True, True], cache))
    reject('Mask', lambda: row(p, [0, 0], [1, True], cache))
    reject('CacheScope', lambda: row(config(fv=1), [0, 0], [True, True], cache))
    reject('BlockBound', lambda: config(accumulation='block1024', drop=1))
    reject('Mode', lambda: config(accumulation='adaptive'))
    reject('Drop', lambda: config(drop=1))
    reject('Shape', lambda: prepare(p, [[1], [2, 3]]))
    reject('Input', lambda: prepare(p, [[32768]]))
    dynamic = config(value_mode='dynamic', value_scale=0)
    bad = Cache(dynamic.fv, dynamic.value_mode, dynamic.value_scale, ((1,),), (0,))
    reject('ZeroScale', lambda: row(dynamic, [0], [True], bad))
    # A syntactically legal altered scale is not source authentication.
    honest = prepare(dynamic, [[127], [254]])
    changed = Cache(honest.fv, honest.mode, honest.parameter, honest.codes, (1, 1))
    assert row(dynamic, [0, 0], [True, True], changed)['wide'] == [127]
    maximum = config(value_mode='static', value_scale=65535, fv=0, fo=30, e=14)
    maximum = Config(maximum.function, 0, 30, 'static', 65535, 'dynamic', 0, 'block1024', 62)
    static = bounds(maximum, 1 << 20)
    assert static['numerator_max'] < 1 << 118 and static['denominator_max'] <= 1 << 64
    assert bounds(config(fv=30, e=14), 1 << 20)['denominator_max'] == 1 << 64
    reject('Shape', lambda: bounds(p, (1 << 20)+1))
    print(json.dumps(dict(seed=2627, cases=10000, accepted=success, rejected=10000-success,
                         prefix_cases=prefix_cases, multi_block_cases=multi_block_cases, sha256=digest.hexdigest()), sort_keys=True))
    print('Numerical candidate only: native parity, complete static schemas, proof consumers and fidelity remain open.')


if __name__ == '__main__':
    check()
