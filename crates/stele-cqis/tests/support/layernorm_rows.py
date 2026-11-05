"""RFC-0025 §2.3/6: new exact NumPy LayerNorm corpus, no historical campaign.

Python 3.12, numpy==1.26.4, blake3==1.0.11. Emits one small digest receipt.
"""
from hashlib import sha256
import json
from math import gcd, isqrt
from pathlib import Path
from struct import pack
import sys

import numpy as np
from blake3 import blake3

ROOT = Path(__file__).resolve().parents[4]
sys.path.insert(0, str(ROOT / 'research/cqis-model-contract'))
from numerics import LayerNorm, layer_norm

state = 50423


def word():
    global state
    state ^= (state << 13) & ((1 << 64) - 1)
    state ^= state >> 7
    state ^= (state << 17) & ((1 << 64) - 1)
    return state & ((1 << 32) - 1)


def signed():
    v = word() & 65535
    return v - 65536 if v >= 32768 else v


def oracle(p, x, h, b):
    # int64 is sufficient for all original statistics; normalized rational words
    # can exceed 128 bits and deliberately use Python integers after this step.
    x, h, b = (np.asarray(v, dtype=np.int64) for v in (x, h, b))
    total = int(x.sum())
    variance = p.d * int(x @ x) - total * total
    n = p.ed * variance + p.en * p.d**2 * 2**(2*p.F)
    den = p.ed * p.d**2 * 2**(2*p.F)
    a = (n.bit_length() - den.bit_length() - 14) // 2
    while (n << max(-2*a, 0)) < (den << max(2*a, 0)) * 16384:
        a -= 1
    m = (n << max(-2*a, 0)) // (den << max(2*a, 0))
    assert -23 <= a <= 9 and 16384 <= m <= 65535
    j = isqrt((1 << 42) // m)
    j += (1 << 44) >= m * (2*j+1)**2
    e = p.F+p.G+21+a-p.E
    k = max(e, p.Gb-p.E, 0)
    divisor = p.d << k
    result = []
    for centered, gain, bias in zip(p.d*x-total, h, b):
        u = (int(centered)*int(gain)*j << (k-e)) + (p.d*int(bias) << (k+p.E-p.Gb))
        q, r = divmod(abs(u), divisor)
        y = (-1 if u < 0 else 1) * (q + (r >= divisor-r))
        if not -32768 <= y <= 32767:
            raise ValueError('Range')
        result.append(y)
    return result


digest = blake3()
accepted = overflow = 0
for i in range(11000):
    d, f, g, e, gb = 1+word()%32, word()%31, word()%31, word()%15, word()%31
    en, ed = max(1, word()), max(1, word())
    common = gcd(en, ed)
    en, ed = en//common, ed//common
    if i % 4 == 0:
        en, ed = 1, (1 << 32)-1
    if i % 4 == 1:
        en, ed = (1 << 32)-1, 1
    if i % 997 == 0:
        d = 16384
    if i < 10000:
        g = max(g, e+((d-1).bit_length()+1)//2+3)
        gb = max(gb, e+2)
    x, h, b = ([signed() for _ in range(d)] for _ in range(3))
    if i % 5 == 0:
        h = [0]*d
    if i % 7 == 0:
        x = [x[0]]*d
    p = LayerNorm(d, f, g, e, gb, en, ed)
    digest.update(pack('<HBBBBII', d, f, g, e, gb, en, ed))
    for values in (x, h, b):
        digest.update(pack('<'+'h'*d, *values))
    try:
        result = oracle(p, x, h, b)
    except ValueError as error:
        assert str(error) == 'Range'
        try:
            layer_norm(p, x, h, b)
        except ValueError as other:
            assert str(other) == 'Range'
        else:
            raise AssertionError('reference accepted overflow')
        overflow += 1
        digest.update(b'\0')
    else:
        assert result == layer_norm(p, x, h, b)['output']
        accepted += 1
        digest.update(b'\1'+pack('<'+'h'*d, *result))

assert accepted >= 10000 and overflow > 0
source = 'research/cqis-model-contract/numerics.py'
receipt = dict(seed=50423, cases=11000, accepted=accepted, overflow=overflow,
               digest=digest.hexdigest(), numpy=np.__version__,
               sources={source: sha256((ROOT/source).read_bytes()).hexdigest()})
(ROOT/'crates/stele-cqis/tests/fixtures/layernorm-rows.json').write_text(json.dumps(receipt, indent=2)+'\n')
print(json.dumps(receipt))
