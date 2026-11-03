"""Independent exact evidence for Draft RFC-0025, never a native proof gate."""
from dataclasses import asdict
from fractions import Fraction as Q
from hashlib import sha256
import json
from math import gcd
from random import Random

import numerics as candidate


def nearest(x):
    lower = x.numerator//x.denominator
    return min((lower, lower+1), key=lambda n: (abs(x-n), -abs(n)))


def wide(x):
    y = nearest(x)
    if not -32768 <= y <= 32767:
        raise ValueError('Range')
    return y


def reference(p, values, gains, biases):
    mean = sum(map(Q, values))/p.d
    variance = sum((Q(x)-mean)**2 for x in values)/p.d
    statistic = variance/Q(2)**(2*p.F)+Q(p.en, p.ed)
    choices = [a for a in range(-23, 10) if 16384 <= statistic/Q(4)**a < 65536]
    assert len(choices) == 1
    a = choices[0]
    normalized = statistic/Q(4)**a
    m = normalized.numerator//normalized.denominator
    low, high = 0, 32768
    while low+1 < high:
        mid = (low+high)//2
        if m*(2*mid-1)**2 <= 1 << 44:
            low = mid
        else:
            high = mid
    j = low
    arguments = [(Q(x)-mean)*h*j*Q(2)**(p.E-p.F-p.G-21-a)+Q(b)*Q(2)**(p.E-p.Gb)
                 for x, h, b in zip(values, gains, biases)]
    return dict(a=a, M=m, J=j, output=list(map(nearest, arguments))), arguments, statistic


def outcome(fn, *args):
    try:
        return ('accept', fn(*args))
    except ValueError as error:
        return ('reject', str(error))


def rejects(reason, fn, *args):
    assert outcome(fn, *args) == ('reject', reason)


def main():
    rng = Random(2653)
    digest = sha256()
    counts = {name: dict(accept=0, reject=0) for name in ('layer_norm', 'affine', 'embedding')}

    def retain(name, record):
        counts[name][record[0]] += 1
        digest.update(json.dumps([name, record], sort_keys=True, separators=(',', ':')).encode()+b'\n')

    def norm_case(p, values, gains, biases):
        got = outcome(candidate.layer_norm, p, values, gains, biases)
        numerical, arguments, statistic = reference(p, values, gains, biases)
        expected = ('accept', numerical) if all(-32768 <= x <= 32767 for x in numerical['output']) else ('reject', 'Range')
        b = candidate.bounds(p)
        mean = Q(sum(values), p.d)
        centered = [(Q(x)-mean)*p.d for x in values]
        variance = sum((Q(x)-mean)**2 for x in values)*p.d
        denominator = p.ed*p.d*p.d*(1 << (2*p.F))
        numerator = statistic*denominator
        a = numerical['a']
        branch = b['branches'][a]
        e = p.F+p.G+21+a-p.E
        k = max(e, p.Gb-p.E, 0)
        divisor = p.d*(1 << k)
        assert numerator.denominator == 1 and numerator <= b['N'] and denominator <= b['P']
        assert 0 <= variance <= b['V'] and all(abs(x) <= b['C'] for x in centered)
        assert abs(sum(values)) <= b['S'] and sum(x*x for x in values) <= b['Q']
        assert all(abs(x*h*numerical['J']) <= b['T'] for x, h in zip(centered, gains))
        assert numerator*Q(4)**max(-a, 0) <= branch['A']
        assert denominator*Q(4)**max(a, 0) <= branch['D']
        assert divisor == branch['D_out']
        assert all((x*divisor).denominator == 1 and abs(x*divisor) <= branch['U'] for x in arguments)
        assert b['N'] < 1 << 121 and b['P'] < 1 << 120
        assert all(v['A'] < 1 << 167 and v['D'] < 1 << 138 for v in b['branches'].values())
        assert got[0] == expected[0]
        if got[0] == 'reject':
            assert got == expected
        else:
            r = got[1]
            assert {k: r[k] for k in expected[1]} == expected[1]
            assert r['N'] == numerator and r['P'] == denominator
            assert [Q(u, r['D_out']) for u in r['U']] == arguments
            for key in ('S', 'Q', 'V', 'N', 'P'):
                assert abs(r[key]) <= b[key]
            assert r['V'] >= 0
            for key in ('C', 'T'):
                assert all(abs(x) <= b[key] for x in r[key])
            for key in ('A', 'D', 'D_out'):
                assert r[key] <= branch[key]
            assert all(abs(x) <= branch['U'] for x in r['U'])
            assert r['A'] == r['M']*r['D']+r['remainder'] and 0 <= r['remainder'] < r['D']
            assert r['M']*(2*r['J']-1)**2 <= 1 << 44 < r['M']*(2*r['J']+1)**2
        retain('layer_norm', (got[0], [asdict(p), values, gains, biases, got[1]]))

    for i in range(10000):
        d = rng.randrange(1, 25)
        en, ed = rng.randrange(1, 1 << 32), rng.randrange(1, 1 << 32)
        common = gcd(en, ed)
        p = candidate.LayerNorm(d, 8, 10, 8, 8, 1, 100000) if i % 2 == 0 else candidate.LayerNorm(
            d, rng.randrange(31), rng.randrange(31), rng.randrange(15), rng.randrange(31), en//common, ed//common)
        values = [rng.randrange(-32768, 32768) for _ in range(d)]
        gains = [rng.randrange(512, 2049) if i % 2 == 0 else rng.randrange(-32768, 32768) for _ in range(d)]
        biases = [rng.randrange(-128, 129) if i % 2 == 0 else rng.randrange(-32768, 32768) for _ in range(d)]
        norm_case(p, values, gains, biases)

        acc, mantissa, scale = rng.randrange(-(1 << 31), 1 << 31), rng.randrange(1, 65536), rng.randrange(1, 8454662)
        exponent = rng.randrange(-1099, 1025) if i % 2 else rng.randrange(-48, 1)
        f, fo, fb, bias = rng.randrange(45), rng.randrange(31), rng.randrange(31), rng.randrange(-32768, 32768)
        args = acc, mantissa, scale, exponent, f, fo, bias, fb
        got = outcome(candidate.affine, *args)
        expected = outcome(wide, Q(acc*mantissa*scale)*Q(2)**(exponent-f+fo)+Q(bias)*Q(2)**(fo-fb))
        assert got == expected
        retain('affine', (got[0], [args, got[1]]))

        code, pm = rng.randrange(-127, 128), rng.randrange(1, 65536)
        pe, position = rng.randrange(-1099, 1025), rng.randrange(-127, 128)
        args = code, mantissa, exponent, position, pm, pe, fo
        got = outcome(candidate.embedding, *args)
        expected = outcome(wide, Q(code*mantissa)*Q(2)**(exponent+fo)+Q(position*pm)*Q(2)**(pe+fo))
        assert got == expected
        retain('embedding', (got[0], [args, got[1]]))

    for d in (1, 2, 768, 4096, 16384):
        for values in ([32767]*d, [-32768]*d, [-32768 if i % 2 else 32767 for i in range(d)]):
            norm_case(candidate.LayerNorm(d, 8, 10, 8, 8, 1, 100000), values, [1024]*d, [0]*d)
    for en, ed in ((1, (1 << 32)-1), ((1 << 32)-1, 1)):
        norm_case(candidate.LayerNorm(2, 30, 30, 14, 30, en, ed), [0, 0], [32767]*2, [-32768]*2)
    exact = candidate.LayerNorm(2, 0, 0, 4, 0, 1, 1)
    assert candidate.layer_norm(exact, [0, 1], [1, 1], [0, 0])['output'] == [-7, 7]
    one_round = candidate.LayerNorm(2, 0, 0, 0, 1, 1, 1)
    assert candidate.layer_norm(one_round, [-1, 1], [1, 1], [1, 1])['output'] == [0, 1]
    assert candidate.embedding(1, 1, -2, 1, 1, -2, 0) == 1
    assert candidate.embedding(-1, 1, -2, -1, 1, -2, 0) == -1
    assert candidate.affine(1, 1, 1, -2, 0, 0, 1, 2) == 1
    assert candidate.affine(-1, 1, 1, -2, 0, 0, -1, 2) == -1
    assert candidate.affine(0, 1, 0, 1024, 0, 0, -1, 1) == -1
    for bias in (-32768, 32767):
        assert candidate.affine(0, 1, 0, 0, 0, 0, bias, 0) == bias
        rejects('Range', candidate.affine, 0, 1, 0, 0, 0, 1, bias, 0)
    for bias in (-1, 1):
        one = candidate.LayerNorm(1, 0, 0, 0, 1, 1, 1)
        assert candidate.layer_norm(one, [32767], [-32768], [bias])['output'] == [bias]
    rejects('ZeroScale', candidate.affine, 1, 1, 0, 0, 0, 0, 0, 0)
    rejects('Epsilon', candidate.LayerNorm, 2, 0, 0, 0, 0, 2, 2)
    rejects('Dimension', candidate.LayerNorm, True, 0, 0, 0, 0, 1, 1)
    rejects('Shape', candidate.layer_norm, exact, [0], [1, 1], [0, 0])
    rejects('Input', candidate.layer_norm, exact, [False, 1], [1, 1], [0, 0])
    rejects('Range', candidate.embedding, 127, 65535, 1024, 0, 1, 0, 0)
    print(json.dumps(dict(seed=2653, cases=counts, sha256=digest.hexdigest(),
                         scope='Draft numerical correctness only; no native/model/proof/profile admission'), sort_keys=True))


if __name__ == '__main__':
    main()
