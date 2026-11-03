"""Independent rational/interval evidence for Draft RFC-0025's decoding choices."""
from fractions import Fraction as Q
from hashlib import sha256
import json
from math import gcd
from random import Random
from struct import pack

from blake3 import blake3

from decoding import seed_values, select, temperature


def rejects(call, reason):
    try:
        call()
    except ValueError as error:
        assert str(error) == reason
    else:
        raise AssertionError(reason)


def rounding(value):
    low = value.numerator//value.denominator
    return min((low, low+1), key=lambda n: (abs(n-value), -abs(n)))


def oracle(weights, pn, pd, draw):
    # Compute ranks directly; no sort or candidate prefix/selection helper.
    order = [None]*len(weights)
    for j, weight in enumerate(weights):
        rank = sum(other > weight or (other == weight and i < j)
                   for i, other in enumerate(weights))
        order[rank] = j
    masses = [Q(weights[i], sum(weights)) for i in order]
    k = next(k for k in range(1, len(weights)+1) if sum(masses[:k]) >= Q(pn, pd))
    z = sum(masses[:k])
    endpoints = [sum(masses[:r+1])/z*(1 << 32) for r in range(k)]
    cdf = [q.numerator//q.denominator for q in endpoints]
    intervals = list(zip([0]+cdf[:-1], cdf))
    selected = [order[r] for r, (low, high) in enumerate(intervals) if low <= draw < high]
    assert len(selected) == 1
    for r, (low, high) in enumerate(intervals):
        assert abs(Q(high-low, 1 << 32)-masses[r]/z) < Q(1, 1 << 32)
    return selected[0], tuple(order), tuple(cdf)


def main():
    rng, digest = Random(2672), sha256()
    temperature_counts = {'accept': 0, 'reject': 0}
    for i in range(10000):
        weights = [rng.randrange((1 << rng.randrange(15))+1) for _ in range(rng.randrange(1, 33))]
        weights[rng.randrange(len(weights))] = 1 << 14
        pd = rng.randrange(1, 1 << 32)
        pn = rng.randrange(1, pd+1)
        common = gcd(pn, pd)
        pn, pd = pn//common, pd//common
        draw = rng.randrange(1 << 32)
        actual = select(weights, pn, pd, draw)
        assert actual == oracle(weights, pn, pd, draw)
        seed = rng.randbytes(32)
        position = rng.randrange(1 << 20)
        commitment, uniform = seed_values(seed, position)
        # Independent framing and low-word reduction; BLAKE3 primitive is shared.
        assert commitment == blake3(b'stele/v0.1/cqis/sample-seed'+seed).digest()
        raw = blake3(b'stele/v0.1/cqis/sample-draw'+seed+pack('<I', position)).digest()
        assert uniform == int.from_bytes(raw, 'little') % (1 << 32)
        logits = [rng.randrange(-32768, 32768) for _ in weights]
        tn, td = rng.randrange(1, 1 << 32), rng.randrange(1, 1 << 32)
        common = gcd(tn, td)
        tn, td = tn//common, td//common
        fraction, exp_fraction, bits = rng.randrange(31), rng.randrange(31), rng.randrange(7, 32)
        real = [Q(x, 1 << fraction) for x in logits]
        reference = [rounding((x-max(real))/Q(tn, td)*(1 << exp_fraction)) for x in real]
        if min(reference) < -(1 << bits):
            rejects(lambda: temperature(logits, fraction, tn, td, exp_fraction, bits), 'ExpDomain')
            temperature_counts['reject'] += 1
        else:
            assert temperature(logits, fraction, tn, td, exp_fraction, bits) == reference
            temperature_counts['accept'] += 1
        data = [weights, pn, pd, draw, actual, commitment.hex(), uniform,
                logits, tn, td, fraction, exp_fraction, bits, reference]
        digest.update(json.dumps(data, separators=(',', ':')).encode()+b'\n')
    assert select([0, 5, 5], 1, 2, 0) == (1, (1, 2, 0), (1 << 32,))
    assert select([0, 5, 5], 1, 1, (1 << 31)-1)[0] == 1
    assert select([0, 5, 5], 1, 1, 1 << 31)[0] == 2
    assert select([1, 1, 1], 1, 1, (1 << 32)-1)[0] == 2
    assert temperature([1, 2], 0, 2, 1, 0, 7) == [-1, 0]
    assert temperature([-32768, 32767], 0, 1, 1, 0, 16) == [-65535, 0]
    assert temperature([0, 128], 0, 1, 1, 0, 7) == [-128, 0]
    rejects(lambda: temperature([0, 129], 0, 1, 1, 0, 7), 'ExpDomain')
    rejects(lambda: select([0, 0], 1, 1, 0), 'ZeroMass')
    rejects(lambda: select([1], 2, 2, 0), 'Rational')
    rejects(lambda: select([1], 2, 1, 0), 'Rational')
    rejects(lambda: select([True], 1, 1, 0), 'Weight')
    rejects(lambda: select([1], 1, 1, 1 << 32), 'Draw')
    rejects(lambda: seed_values(bytes(31), 1), 'Seed')
    rejects(lambda: seed_values(bytes(32), True), 'Position')
    rejects(lambda: seed_values(bytes(32), 1 << 20), 'Position')
    # Tiny positive mass can have an empty bucket at the full supported vocabulary.
    large = [16384]*((1 << 20)-2)+[1, 1]
    result = select(large, 1, 1, (1 << 32)-1)
    assert result[2][-3:] == ((1 << 32)-1, (1 << 32)-1, 1 << 32)
    assert result[0] == (1 << 20)-1
    print(json.dumps({'seed': 2672, 'cases': 10000, 'temperature': temperature_counts,
                      'max_vocabulary_case': 1 << 20, 'corpus_sha256': digest.hexdigest()}, sort_keys=True))


if __name__ == '__main__':
    main()
