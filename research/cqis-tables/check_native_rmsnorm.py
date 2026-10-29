# /// script
# requires-python = ">=3.12"
# dependencies = ["blake3==1.0.11", "numpy==2.3.4"]
# ///
"""RFC-0021 §2.3,§6: exact row oracle plus NumPy table gather/wide rounding."""
import json
from math import gcd
from pathlib import Path
import struct
import sys
from blake3 import blake3
import numpy as np
import certified_rmsnorm as norm
from check_rmsnorm import reference


def words():
    state, mask = 2602038, (1 << 64)-1
    while True:
        state ^= (state << 13) & mask
        state ^= state >> 7
        state ^= (state << 17) & mask
        yield state & ((1 << 32)-1)


def report():
    rng, digest = words(), blake3()
    accepted = overflow = 0
    table = np.array([norm.rsqrt_certificate(m)['value'] for m in range(16384,65536)], dtype=np.int64)
    for i in range(11000):
        d, f, g, e = 1+next(rng)%32, next(rng)%31, next(rng)%31, next(rng)%15
        en, ed = max(1,next(rng)), max(1,next(rng))
        divisor = gcd(en,ed); en //= divisor; ed //= divisor
        if i % 4 == 0: en, ed = 1, (1 << 32)-1
        if i % 4 == 1: en, ed = (1 << 32)-1, 1
        if i % 997 == 0: d = 16384
        # First 10,000 rows are guaranteed to fit by the RFC's uniform output
        # bound. Additional unconstrained scales exercise output rejection.
        if i < 10000: g = max(g,e+((d-1).bit_length()+1)//2+1)
        xs = [((next(rng) & 65535) ^ 32768)-32768 for _ in range(d)]
        gs = [((next(rng) & 65535) ^ 32768)-32768 for _ in range(d)]
        if i % 5 == 0: gs = [0]*d
        if i == 0: xs = [0]*d
        p = norm.Parameters(d,f,g,e,en,ed)
        digest.update(struct.pack('<HBBBII',*p.metadata()))
        for row in (xs,gs): digest.update(struct.pack('<'+'h'*d,*row))
        a,m,j,ys,_ = reference(p,xs,gs)
        w = norm.normalize(p,sum(x*x for x in xs))
        assert (w['a'],w['M'],w['J']) == (a,m,j)
        shift = f+g+21+a-e
        product = np.array(xs,dtype=np.int64)*np.array(gs,dtype=np.int64)*table[m-16384]
        assert np.all(np.abs(product) <= 1 << 44)
        if shift < 0:
            numpy_output = product*(1 << -shift)
        elif shift > 45:
            # |T|<=2^44 is strictly below the half unit when shift>=46.
            numpy_output = np.zeros(d,dtype=np.int64)
        else:
            numpy_output = np.sign(product)*((np.abs(product)+(1 << (shift-1) if shift else 0))//(1 << shift))
        assert numpy_output.tolist() == ys
        if any(y < -32768 or y > 32767 for y in ys):
            try: norm.evaluate(p,xs,gs)
            except ValueError as error: assert str(error) == 'Overflow'
            else: raise AssertionError('accepted overflow')
            digest.update(b'\0'); overflow += 1
        else:
            result = norm.evaluate(p,xs,gs); norm.verify(p,xs,gs,result)
            assert result['output'] == ys
            A,D = norm.scaled_ratio(w['N'],w['P'],a)
            assert A < 1 << 128 and D < 1 << 128
            digest.update(b'\1'+struct.pack('<Q',w['S']))
            for v in (w['N'],w['P'],A,D,w['R']): digest.update(v.to_bytes(16,'little'))
            digest.update(struct.pack('<bHHb',a,m,j,shift))
            digest.update(struct.pack('<'+'h'*d,*ys)); accepted += 1
    assert accepted >= 10000 and overflow
    return dict(version=1,scope='native RMSNorm numerical parity; no full inference or bound-certificate admission',
                count=11000,accepted=accepted,overflow=overflow,digest=digest.hexdigest())


if __name__ == '__main__':
    result = report()
    path = Path(__file__).with_name('native-rmsnorm.json')
    if sys.argv[1:] == ['--write']:
        with path.open('x') as output:
            json.dump(result,output,indent=2); output.write('\n')
    else:
        assert not sys.argv[1:] and json.loads(path.read_text()) == result
    print('11000 RMSNorm rows (at least 10000 accepted) match exact rational/root and NumPy int64 oracles')
