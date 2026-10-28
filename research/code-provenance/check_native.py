# /// script
# requires-python = ">=3.12"
# dependencies = ["blake3==1.0.11"]
# ///
"""RFC-0010 A4 complete-byte native parity; no PCS or benchmark evidence.

Each field gets 1000 independent seeded cases: 900 J=3, 90 J=4, 10 J=5.
The materialized-map oracle does not call the bounded/native traversal.
The bounded binary adapter is research-only: count:u32, then degree:u8,
ID-length:u8, ID, n:u32, q:u32, canonical row limbs and u32 columns.
Its output concatenates complete words and ordered query values without hashes.
"""
from collections import Counter
from pathlib import Path
import random
import struct
import subprocess
import sys
from sampler import manifest, materialize
from recursive import encode_row, sc

ROOT = Path(__file__).resolve().parents[2]
COMMAND = ['cargo', 'run', '-q', '-p', 'stele-code', '--example',
           'encoder_corpus', '--locked', '--offline']


def packed(values):
    return b''.join(struct.pack('<I', limb) for value in values for limb in value)


def request(d, identity, row, columns):
    return (bytes([d, len(identity)])+identity+struct.pack('<II', len(row), len(columns))
            +packed(row)+b''.join(struct.pack('<I', c) for c in columns))


def compare(actual, expected):
    if actual != expected:
        offset = next((i for i, (a, b) in enumerate(zip(actual, expected)) if a != b),
                      min(len(actual), len(expected)))
        raise ValueError(f'native corpus byte mismatch at {offset}; '
                         f'lengths {len(actual)}/{len(expected)}')


def evaluate(requests):
    return subprocess.run(COMMAND, input=struct.pack('<I', len(requests))+b''.join(requests),
                          cwd=ROOT, capture_output=True)


def check():
    # Prove that truncation, extra output and a changed byte cannot silently pass.
    for bad in (b'', b'\x01', b'\x00\x00'):
        try:
            compare(bad, b'\x00')
        except ValueError:
            pass
        else:
            raise AssertionError('byte comparator accepted corruption')
    for d in (1, 4, 8):
        requests, expected, counts = [], bytearray(), Counter()
        for i in range(1000):
            j = 3 if i < 900 else 4 if i < 990 else 5
            n = 4**j
            rng = random.Random(1000*d+i)
            identity = manifest(rng.randbytes(32), j)
            setup, _ = materialize(identity)
            row = [tuple(rng.randrange(sc.P) for _ in range(d)) for _ in range(n)]
            local = i if j == 3 else i-900 if j == 4 else i-990
            if local == 0:
                row = [sc.scalar(0, d)]*n
            elif local == 1:
                row = [tuple((0, 1, sc.P-1)[(k+t) % 3] for k in range(d)) for t in range(n)]
            elif local == 2:
                row = [sc.scalar(rng.randrange(sc.P), d) for _ in range(n)]
            columns = [] if i % 17 == 0 else [2*n-1, 0, n, 0, rng.randrange(2*n)]

            def add(values):
                word, _ = encode_row(setup, values)
                requests.append(request(d, identity, values, columns))
                expected.extend(packed(word)+packed([word[c] for c in columns]))
                return word

            word = add(row)
            counts[j] += 1
            if local == 3:
                other = [tuple(rng.randrange(sc.P) for _ in range(d)) for _ in range(n)]
                scale = tuple(rng.randrange(sc.P) for _ in range(d))
                other_word = add(other)
                combined = add([sc.add(x, sc.mul(scale, y)) for x, y in zip(row, other)])
                assert combined == [sc.add(x, sc.mul(scale, y)) for x, y in zip(word, other_word)]
        assert counts == {3: 900, 4: 90, 5: 10}
        result = evaluate(requests)
        if result.returncode:
            raise ValueError(result.stderr.decode())
        compare(result.stdout, expected)
        print(f'native d={d}: {len(requests)} full words and ordered queries; {dict(counts)} seeds', flush=True)

    identity = manifest(bytes(32), 3)
    row = [sc.scalar(0, 1)]*64
    valid = request(1, identity, row, [127, 0, 0])
    bad_cases = [
        (bytes([2])+valid[1:], 'field degree'),
        (bytes([1, 54])+valid[2:], 'identity length'),
        (request(1, identity, row[:-1], []), 'RowShape'),
        (request(1, identity, row, [128]), 'Column'),
        (request(1, identity, [(sc.P,)]+row[1:], []), 'noncanonical field'),
        (request(1, identity, row, [0]*9), 'corpus bounds'),
        (request(1, identity, row*17, []), 'corpus bounds'),
        (request(1, manifest(bytes(32), 6), row, []), 'corpus bounds'),
        (valid[:-1], 'failed to fill whole buffer'),
        (valid+b'\x00', 'trailing bytes'),
    ]
    for raw, error in bad_cases:
        result = evaluate([raw])
        assert result.returncode and error in result.stderr.decode(), (error, result.stderr)
    result = evaluate([])
    assert result.returncode and 'case count' in result.stderr.decode()
    print('native corpus: malformed adapter inputs reject; no PCS/profile or NC credit')


if __name__ == '__main__':
    if sys.argv[1:] == ['--vectors']:
        import native_vectors
    elif not sys.argv[1:]:
        check()
    else:
        raise SystemExit('usage: check_native.py [--vectors]')
