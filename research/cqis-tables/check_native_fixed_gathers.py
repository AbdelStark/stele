# /// script
# requires-python = ">=3.12"
# dependencies = ["blake3==1.0.11", "numpy==2.3.4"]
# ///
"""RFC-0021 §2.2,§2.3,§6: fixed table NumPy int64 parity, not native RMSNorm."""
import json
from pathlib import Path
import random
import struct
import sys
from blake3 import blake3
import numpy as np
from table_identity import Descriptor, DATA, encode_data, shape


def report():
    rng, cases = random.Random(2502037), []
    for name in ('range_8', 'range_12', 'range_16', 'rsqrt_q'):
        d = Descriptor(name, 1, b'')
        n, padded, columns = shape(d)
        raw = encode_data(d)
        rows = np.frombuffer(raw[len(DATA)+41:], dtype='<i4').reshape(padded, columns).astype(np.int64)
        assert np.all(rows[n:] == 0)
        start = 16384 if name == 'rsqrt_q' else 0
        domain = np.arange(start, start+n, dtype=np.int64)
        assert np.array_equal(rows[:n, 0], domain)
        if name == 'rsqrt_q':
            # Find the final rounding cell by vectorized integer bisection.
            # Native generation instead uses isqrt followed by one threshold.
            low, high = np.full(n, 8192, dtype=np.int64), np.full(n, 16384, dtype=np.int64)
            while np.any(low < high):
                mid = (low+high+1)//2
                inside = domain*(2*mid-1)**2 <= 1 << 44
                low, high = np.where(inside, mid, low), np.where(inside, high, mid-1)
            assert np.array_equal(rows[:n, 1], low)
            assert np.all(domain*(2*low-1)**2 <= 1 << 44)
            assert np.all(1 << 44 < domain*(2*low+1)**2)
        inputs = np.array([start, start+n-1] + [rng.randrange(start, start+n)
                                               for _ in range(9998)], dtype=np.int64)
        values = rows[inputs-start, columns-1]
        records = b''.join(struct.pack('<Ii', int(x), int(y)) for x, y in zip(inputs, values))
        cases.append(dict(name=name, count=10000, data_digest=blake3(raw).hexdigest(),
                          records=records.hex()))
    return dict(version=1, scope='fixed table integer gathers; native RMSNorm remains E5-04',
                layout='u32le input, i32le output', cases=cases)


if __name__ == '__main__':
    result = report()
    path = Path(__file__).with_name('native-fixed-gathers.json')
    if sys.argv[1:] == ['--write']:
        with path.open('x') as output:
            json.dump(result, output, separators=(',', ':')); output.write('\n')
    else:
        assert not sys.argv[1:] and json.loads(path.read_text()) == result
    print('PASS: 40000 NumPy int64 gathers; every rsqrt entry independently bisected')
