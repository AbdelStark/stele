# /// script
# requires-python = ">=3.12"
# dependencies = ["blake3==1.0.11", "numpy==2.3.4"]
# ///
"""RFC-0021 §2.1,§6: independent full tables and NumPy function gathers."""
from fractions import Fraction as Q
from functools import lru_cache
import json
from pathlib import Path
import random
import struct
import sys
from blake3 import blake3
import numpy as np
from check_exp import reference
from table_identity import Descriptor, DATA, shape, table_id


@lru_cache(maxsize=65536)
def entry(n, f, e):
    # Positive Taylor + reciprocal tail; native uses alternating dyadic bounds.
    return reference(Q(n, 1 << f), 1 << e)


def component(name, params, coordinates, values):
    d = Descriptor(name, 1, bytes(params))
    n, padded, columns = shape(d)
    assert columns == 2 and len(values) == len(coordinates) == n
    rows = np.zeros((padded, 2), dtype=np.int64)
    rows[:n, 0], rows[:n, 1] = coordinates, values
    assert np.all((-(1 << 31) <= rows) & (rows < 1 << 31))
    raw = (DATA + table_id(d) + struct.pack('<IIB', n, padded, columns)
           + rows.astype('<i4').tobytes(order='C'))
    return rows, dict(name=name, parameters=bytes(params).hex(),
                     data_digest=blake3(raw).hexdigest())


def samples(rng, b, k, count):
    # Inclusive endpoint, both sides of a split, and varied full-domain inputs.
    limit, split = 1 << b, 1 << k
    fixed = sorted({-limit, -limit+1, -split, -split+1, -1, 0}
                   | ({-split-1} if split < limit else set()))
    return np.array(fixed + [-rng.randrange(limit+1)
                            for _ in range(count-len(fixed))], dtype=np.int64)


def report():
    product = [(b, (i*7+5) % 31, i*4 % 15, (b+1)//2)
               for i, b in enumerate(range(7, 32))]
    product += [(7, 0, 0, 1), (7, 30, 14, 7), (16, 30, 14, 16),
                (31, 0, 14, 16), (15, 10, 12, 7), (14, 10, 12, 6),
                (14, 10, 12, 7)]
    nearest = [(7+i % 9, i*7 % 31, i*4 % 15, 1+(i*5) % (7+i % 9))
               for i in range(25)]
    nearest += [(7, 0, 14, 1), (7, 30, 14, 7), (15, 0, 14, 15),
                (15, 30, 14, 1), (15, 10, 12, 7), (14, 10, 12, 6),
                (14, 10, 12, 7)]
    rng, cases = random.Random(2502036), []
    for mode, configurations in [('product', product), ('nearest', nearest)]:
        assert len(configurations) == len(set(configurations)) == 32
        total = 0
        for index, params in enumerate(configurations):
            b, f, e, k = params
            hi, hc = component('exp_q/hi', params, range((1 << (b-k))+1),
                               [entry(i << k, f, e) for i in range((1 << (b-k))+1)])
            lo, lc = component('exp_q/lo', params, range(1 << k),
                               [entry(i, f, e) for i in range(1 << k)])
            count = 313 if index < 16 else 312
            ts = samples(rng, b, k, count)
            hs, ls = (-ts)//(1 << k), (-ts) % (1 << k)
            gathered = (hi[hs, 1]*lo[ls, 1])//(1 << e)
            assert np.all((0 <= gathered) & (gathered <= 1 << e))
            components, records = [hc, lc], bytearray()
            if mode == 'nearest':
                domain = np.arange(-(1 << b), 1, dtype=np.int64)
                direct, dc = component('exp_q/direct', params[:3], domain,
                                       [entry(int(-t), f, e) for t in domain])
                products = hi[(-domain)//(1 << k), 1]*lo[(-domain) % (1 << k), 1]//(1 << e)
                corrections = direct[:len(domain), 1]-products
                assert np.all((-1 <= corrections) & (corrections <= 2))
                correction, cc = component('exp_q/correction', params, domain, corrections)
                components += [dc, cc]
            for t, value in zip(ts, gathered):
                t, value = int(t), int(value)
                h, l = divmod(-t, 1 << k)
                expected = entry(h << k, f, e)*entry(l, f, e)//(1 << e)
                assert value == expected
                if mode == 'nearest':
                    d, c = int(direct[t+(1 << b), 1]), int(correction[t+(1 << b), 1])
                    assert d == entry(-t, f, e) == value+c
                    records.extend(struct.pack('<iIi', t, d, c))
                else:
                    records.extend(struct.pack('<iI', t, value))
            total += count
            cases.append(dict(mode=mode, parameters=list(params), count=count,
                              components=components, records=records.hex()))
            print(f'{mode} {index+1}/32: full component bytes and {count} gathers', flush=True)
        assert total == 10000
    return dict(version=1, scope='native exponential function parity; no inference or proof admission',
                product_count=10000, nearest_count=10000,
                product_layout='i32le input, u32le product',
                nearest_layout='i32le input, u32le nearest, i32le correction', cases=cases)


if __name__ == '__main__':
    result = report()
    path = Path(__file__).with_name('native-exp-functions.json')
    if sys.argv[1:] == ['--write']:
        with path.open('x') as output:
            json.dump(result, output, separators=(',', ':')); output.write('\n')
    else:
        assert not sys.argv[1:] and json.loads(path.read_text()) == result
    print('PASS: 10000 product and 10000 nearest/corrected gathers; 192 full component digests')
