"""RFC-0025 §2.4: independent Arb fixtures for native integer certification.

Python 3.12, python-flint==0.9.0 and blake3==1.0.11. No historical campaign main.
"""
from fractions import Fraction as Q
from hashlib import sha256
import json
from pathlib import Path
from random import Random
from struct import pack
import sys

from flint import arb, ctx

if not __debug__:
    raise RuntimeError('reference assertions must remain enabled')
ROOT = Path(__file__).resolve().parents[4]
sys.path.insert(0, str(ROOT/'research/cqis-checkpoint'))
from check_rope import oracle, real
from rope import Parameters


def descriptor(p):
    raw = b'stele/v0.1/cqis/rotation'+pack('<HIBBI', p.width, p.length,
        ('base', 'linear', 'llama3').index(p.mode), ('adjacent', 'split').index(p.layout), p.original)
    return raw+b''.join(pack('<QQ', q.numerator, q.denominator)
                       for q in (p.base, p.factor, p.low, p.high))


rng = Random(50333)
definitions = []
for i in range(64):
    width = (16384 if i == 0 else rng.choice((2, 6, 30, 32, 64, 80, 128, 256, 1024)))
    mode = ('base', 'linear', 'llama3')[i % 3]
    base = rng.choice((Q(1), Q(3, 2), Q(10000), Q(500000), Q(2**32),
                       Q(2**64-1, 2**64-2), Q(2**64-1, 2**32)))
    factor = Q(1) if mode == 'base' else rng.choice((Q(8), Q(2**32), Q(2**64-1, 2**64-2)))
    definitions.append(Parameters(width, 2**20, base, mode, ('adjacent', 'split')[i % 2],
        factor, Q(1) if mode == 'llama3' else Q(0), Q(4) if mode == 'llama3' else Q(0),
        8192 if mode == 'llama3' else 0))
# A narrow full-u64 transition requires more than the initial precision.
with ctx.workprec(768):
    middle = Q(str((1/(2*arb.pi())).mid().fmpq()))
    left, right = Q(0), Q(1)
    while left.denominator+right.denominator < 2**64:
        m = Q(left.numerator+right.numerator, left.denominator+right.denominator)
        if m < middle: left = m
        else: right = m
    assert real(left) < 1/(2*arb.pi()) < real(right)
definitions.append(Parameters(2, 2**20, Q(1), 'llama3', 'adjacent', Q(8), left, right, 1))
definitions.append(Parameters(4, 2**20, Q(10000)))
raw = pack('<H', len(definitions))
for p in definitions:
    encoded = descriptor(p)
    raw += pack('<H', len(encoded))+encoded
raw += pack('<I', 10002)
for case in range(10002):
    index = case % 64 if case < 10000 else case-10000+64
    p = definitions[index]
    position, pair = rng.randrange(p.length), rng.randrange(p.width//2)
    if case % 127 == 0: position = 0
    if case == 10000: position, pair = p.length-1, 0
    if case == 10001: position, pair = 100000, 1
    expected = oracle(p, position, pair, minimum=768)
    raw += pack('<HIHhh', index, position, pair, *(v[0] for v in expected))
    # Outward Q128 true-value bounds, independently certified by Arb.
    for _, lo, hi in expected:
        a = (lo.numerator << 128)//lo.denominator
        b = -((-hi.numerator << 128)//hi.denominator)
        raw += a.to_bytes(17, 'little', signed=True)+b.to_bytes(17, 'little', signed=True)
out = ROOT/'crates/stele-cqis/tests/fixtures'
(out/'rotary-coefficients.bin').write_bytes(raw)
paths = ['research/cqis-checkpoint/check_rope.py', 'research/cqis-checkpoint/rope.py']
receipt = dict(seed=50333, definitions=len(definitions), cases=10002,
               oracle_precision=768, enclosure_grid=128, sha256=sha256(raw).hexdigest(),
               sources={p:sha256((ROOT/p).read_bytes()).hexdigest() for p in paths})
(out/'rotary-coefficients.json').write_text(json.dumps(receipt, indent=2)+'\n')
print(json.dumps(receipt))
