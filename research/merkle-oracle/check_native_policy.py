"""Draft native PCS query policy: exact bounds and pure sampling controls."""
from collections import Counter
import hashlib
import json
from pathlib import Path
import subprocess
import sys
from native_policy import counts, decode_index


def rejects(function):
    try:
        function()
    except ValueError:
        pass
    else:
        raise AssertionError('invalid parameter accepted')


def check_counts():
    rows = []
    for blowup in (1, 2):
        for exponent in range(31-blowup):
            c = 1 << exponent
            n = c << blowup
            distance = n if c == 1 else n-c
            radius = (distance-1)//3
            cert, opening = counts(exponent, blowup)
            for q, hit in ((cert, radius+1), (opening, distance-radius)):
                # Independent integer inequalities, including minimality at q-1.
                assert 1 <= q <= 495
                assert (1 << 130)*(n-hit)**q <= n**q
                assert (1 << 130)*(n-hit)**(q-1) > n**(q-1)
            rows.append([exponent, blowup, cert, opening])
    assert len(rows) == 59
    for exponent, blowup in ((-1, 1), (30, 1), (29, 2), (0, 0), (0, 3), (True, 1)):
        rejects(lambda: counts(exponent, blowup))
    return rows


def check_sampling():
    cases = 0
    for bits in (3, 5, 7):
        prime = (1 << bits)-1
        for exponent in range(1, bits):
            n = 1 << exponent
            accepted = [decode_index(x, n, prime) for x in range(prime)]
            accepted = [x for x in accepted if x is not None]
            assert Counter(accepted) == Counter({i: prime//n for i in range(n)})
            cases += 1
    prime = (1 << 31)-1
    for exponent in range(1, 31):
        n = 1 << exponent
        threshold = prime-(n-1)
        assert decode_index(threshold-1, n, prime) == n-1
        assert decode_index(threshold, n, prime) is None
        assert decode_index(prime-1, n, prime) is None
        rejects(lambda: decode_index(prime, n, prime))
        # Uniform modulo without rejection is wrong even on a valid M31 limb.
        if n <= 16:
            assert Counter(x % n for x in range(31)) != Counter({i: 31//n for i in range(n)})
    for x, n in ((-1, 2), (0, 3), (0, 1 << 31), (True, 2)):
        rejects(lambda: decode_index(x, n, prime))
    assert cases == 12


if __name__ == '__main__':
    rows = check_counts()
    check_sampling()
    digest = hashlib.sha256(json.dumps(rows, separators=(',', ':')).encode()).hexdigest()
    if sys.argv[1:] == ['--native']:
        result = subprocess.run(['cargo', 'run', '-q', '-p', 'stele-pcs', '--example',
                                 'field_policy', '--locked', '--offline'],
                                cwd=Path(__file__).resolve().parents[2], check=True,
                                capture_output=True, text=True)
        native = [[int(value) for value in line.split()] for line in result.stdout.splitlines()]
        expected = []
        for m, blowup, cert, opening in rows:
            n = (1 << m) << blowup
            distance = n if m == 0 else n-(1 << m)
            expected.append([m, blowup, n, distance, (distance-1)//3, cert, opening])
        assert native == expected, 'native geometry/query policy differs from exact checked values'
        print('59 native query pairs match exact independently checked minima')
    else:
        assert not sys.argv[1:], 'unknown arguments'
    print('59 minimal query pairs; 12 exact toy distributions; 30 M31 thresholds;', digest)
