#!/usr/bin/env python3
"""Q26: exact scale minimality, rounding and range checks; not proof controls."""
from fractions import Fraction as Q
import hashlib
import json
from pathlib import Path
import random
import sys
from scalars import FORMATS, decode
import quantiser as q
from check_scalars import rejects, value


def nearest(x):
    """Independent signed neighbor distances, with ties away from zero."""
    low = x.numerator//x.denominator
    high = low+1
    a, b = x-low, high-x
    return low if a < b or (a == b and x < 0) else high


def reference(channels, bits):
    limit = (1 << (bits-1))-1
    peak = max(abs(x) for row in channels for x in row)
    # Monotone bisection chooses the first exponent whose maximum scale fits;
    # the candidate uses integer bit lengths. -1100..1024 covers finite inputs.
    low, high = -1100, 1024
    if peak:
        while low < high:
            mid = (low+high)//2
            if peak <= limit*65535*Q(2)**mid:
                high = mid
            else:
                low = mid+1
        exponent = low
    else:
        exponent = 0
    mantissas, output = [], []
    for row in channels:
        maximum, low, high = max(map(abs, row)), 1, 65535
        while low < high:
            mid = (low+high)//2
            if maximum <= limit*mid*Q(2)**exponent:
                high = mid
            else:
                low = mid+1
        mantissas.append(low)
        output.append([nearest(x/(low*Q(2)**exponent)) for x in row])
    return dict(bits=bits, exponent=exponent, mantissas=mantissas, output=output)


def scalar(rng):
    name = rng.choice(tuple(FORMATS))
    size, eb, fb = FORMATS[name]
    while True:
        word = rng.getrandbits(size*8)
        if ((word >> fb) & ((1 << eb)-1)) != (1 << eb)-1:
            return value(decode(name, word.to_bytes(size, 'little')))


def report():
    rng = random.Random(2602)
    digest = hashlib.sha256()
    cases = []
    extremes = [Q(0), Q(1), Q(-1), Q(1, 1 << 1074),
                -Q(1, 1 << 1074), Q((1 << 53)-1)*(1 << 971)]
    for bits in (4, 8):
        zeros, changed = 0, 0
        for i in range(10000):
            channels, width = [], rng.randrange(1, 9)
            for _ in range(rng.randrange(1, 5)):
                channels.append([scalar(rng) for _ in range(width)])
            if i < len(extremes):
                channels = [[extremes[i]], [Q(0)]]
            result = q.weights(channels, bits)
            assert result == reference(channels, bits)
            e, limit = result['exponent'], (1 << (bits-1))-1
            peak = max(abs(x) for row in channels for x in row)
            if peak:
                assert limit*65535*Q(2)**(e-1) < peak <= limit*65535*Q(2)**e
            else:
                zeros += 1
                assert e == 0 and all(m == 1 for m in result['mantissas'])
            for row, m, output in zip(channels, result['mantissas'], result['output']):
                scale = m*Q(2)**e
                assert max(map(abs, row)) <= limit*scale
                if m > 1:
                    assert max(map(abs, row)) > limit*(m-1)*Q(2)**e
                for x, y in zip(row, output):
                    assert abs(y) <= limit and abs(x-y*scale) <= scale/2
                    changed += x != y*scale
            digest.update(json.dumps(result, sort_keys=True, separators=(',', ':')).encode())
        cases.append(dict(bits=bits, tensors=10000, all_zero_tensors=zeros,
                          changed_entries=changed))
    dynamic_zero, static_ok, static_overflow = 0, 0, 0
    for i in range(10000):
        row = [rng.randrange(-32768, 32768) for _ in range(rng.randrange(1, 65))]
        if i < 4:
            row = ([0], [-32768], [32767], [-127, 0, 127])[i]
        result = q.dynamic(row)
        maximum = max(map(abs, row))
        # Independent attained ceiling: search the entire bounded scale domain.
        scale = next(s for s in range(260) if 127*s >= maximum)
        assert result['scale'] == scale and 0 <= 127*scale-maximum < 127
        expected = [nearest(Q(x, scale)) for x in row] if scale else [0]*len(row)
        assert result['output'] == expected
        dynamic_zero += scale == 0
        for x, y in zip(row, expected):
            assert abs(x-y*scale) <= Q(scale, 2)
        fixed = rng.randrange(1, 65536)
        if i % 3 == 0:
            fixed = rng.randrange(1, 260)
        expected = [nearest(Q(x, fixed)) for x in row]
        if any(abs(x) > 127 for x in expected):
            rejects('Overflow', lambda: q.static(row, fixed)); static_overflow += 1
        else:
            assert q.static(row, fixed) == dict(scale=fixed, output=expected)
            static_ok += 1
        digest.update(json.dumps([result, fixed, expected], sort_keys=True).encode())
    for n in range(-1000, 1001, 2):
        assert q.round_away(Q(n, 2)) == nearest(Q(n, 2))
    # Exact positive and negative half ties, including zero-neighbor ties.
    for n in range(-999, 1000, 2):
        assert q.round_away(Q(n, 2)) == (abs(n)//2+1)*(-1 if n < 0 else 1)
    assert q.static([-3, -1, 0, 1, 3], 2)['output'] == [-2, -1, 0, 1, 2]
    assert q.dynamic([0]) == dict(scale=0, output=[0])
    assert q.dynamic([-32768, 32767]) == dict(scale=259, output=[-127, 127])
    assert q.static([-32768, 32767], 258)['output'] == [-127, 127]
    rejects('Overflow', lambda: q.static([-32768], 257))
    for row in ([], [32768], [-32769], [True], (1,)):
        reason = 'Shape' if type(row) is not list or not row else 'Domain'
        rejects(reason, lambda: q.dynamic(row))
        rejects(reason, lambda: q.static(row, 1))
    for scale in (0, -1, 65536, True):
        rejects('Scale', lambda: q.static([0], scale))
    for bits in (0, 7, 16, True):
        rejects('Format', lambda: q.weights([[Q(0)]], bits))
    for rows in ([], [[]], [[Q(1)], [Q(1), Q(2)]]):
        rejects('Shape', lambda: q.weights(rows, 8))
    for x in (True, 1, Q(1, 3), Q(1, 1 << 1075), Q(2)**1024,
              Q((1 << 53)+1, 1 << 53)):
        rejects('Scalar', lambda: q.weights([[x]], 8))
    assert static_ok and static_overflow and dynamic_zero
    return dict(version=1, scope='research scale policy only; no native quantiser or certificate admission',
                weights=cases, dynamic_rows=10000, dynamic_zero_rows=dynamic_zero,
                static_rows=10000, static_accepted=static_ok, static_overflow=static_overflow,
                sha256=digest.hexdigest())


if __name__ == '__main__':
    result = report()
    path = Path(__file__).with_name('quantiser-candidates.json')
    if sys.argv[1:] == ['--write']:
        with path.open('x') as output:
            json.dump(result, output, indent=2); output.write('\n')
    else:
        assert not sys.argv[1:] and json.loads(path.read_text()) == result
    print('20000 weight tensors, 10000 dynamic rows and 10000 static rows match exact independent choices')
