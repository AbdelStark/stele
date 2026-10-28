# /// script
# requires-python = ">=3.12"
# dependencies = ["blake3==1.0.11"]
# ///
"""Q23 setup sampler checks; all-seed ideal-oracle bound, not concrete profile admission."""
from collections import Counter
from fractions import Fraction
from itertools import product
from math import comb
from unittest.mock import patch
import struct
from blake3 import blake3
from sampler import manifest, parse_manifest, block, neighbors, coefficients, materialize, check_setup, all_seeds_bound
from recursive import setup_bytes, decode_setup, encode_row, geometry, sc
from check_recursive import base_generator, dense_word


def rejects(call, reason):
    sc.rejects(call, reason)


def independent_row(seed, level, kind, row):
    columns, degree = geometry(level)[kind][1:]
    def stream(which):
        for counter in range(32):
            raw = (b'stele/v0.1/setup/expander/block/v2'+seed+bytes([level, kind])
                   +row.to_bytes(4, 'little')+bytes([which, counter]))
            digest = blake3(raw).digest()
            for i in range(0, 32, 4):
                yield int.from_bytes(digest[i:i+4], 'little')
    selected = []
    for word in stream(0):
        value = word % columns
        if value not in selected:
            selected.append(value)
        if len(selected) == degree:
            break
    values = []
    for word in stream(1):
        value = word % (1 << 31)
        if value != sc.P:
            values.append(value)
        if len(values) == degree:
            break
    assert len(selected) == len(values) == degree
    return list(zip(sorted(selected), values))


def check():
    # Exhaustive finite-stream analogues use the actual rejection utilities.
    selected = Counter()
    for stream in product(range(4), repeat=5):
        try:
            selected[tuple(neighbors(stream, 4, 2))] += 1
        except ValueError as error:
            assert str(error) == 'SamplingExhausted'
    assert len(selected) == 6 and set(selected.values()) == {170}
    accepted = Counter()
    for stream in product((0, 1, sc.P), repeat=5):
        try:
            accepted[tuple(coefficients(stream, 2))] += 1
        except ValueError as error:
            assert str(error) == 'SamplingExhausted'
    assert set(accepted) == set(product((0, 1), repeat=2)) and set(accepted.values()) == {58}
    assert neighbors([0]*255+[1], 64, 2) == [0, 1]
    rejects(lambda: neighbors([0]*256+[1], 64, 2), 'SamplingExhausted')
    assert coefficients([sc.P]*255+[0], 1) == [0]
    rejects(lambda: coefficients([sc.P]*256+[0], 1), 'SamplingExhausted')
    assert coefficients([1 << 31, 1], 2) == [0, 1]
    # Inject failing oracle bytes only in this test; the sampler must return no setup.
    with patch('sampler.block', return_value=bytes(32)):
        rejects(lambda: materialize(manifest(bytes(32), 4)), 'SamplingExhausted')
    with patch('sampler.block', side_effect=lambda *args: bytes([255])*32 if args[4] == 1 else block(*args)):
        rejects(lambda: materialize(manifest(bytes(32), 4)), 'SamplingExhausted')
    for wrong in (-1, 1 << 32, True):
        rejects(lambda: neighbors([wrong], 64, 1), 'InvalidSampler')
        rejects(lambda: coefficients([wrong], 1), 'InvalidSampler')
    for columns, degree in ((3, 1), (0, 1), (4, 0), (4, 5), (64, 27)):
        rejects(lambda: neighbors([], columns, degree), 'InvalidSampler')
    base = base_generator()
    earlier = None
    vectors = {
        (bytes(32), 3): (0, 'c1d75cbec834385807e7745d0e543f9efad5ad842d0b63ce1d629cc29ad3de6b'),
        (bytes(32), 4): (3162, 'ee34c71fa3cca25f5094007a7ff02adc0d6aa5685c009fb8afe1f6d8cc5944c6'),
        (bytes(range(32)), 4): (3158, 'a98952d403dc3e855b0defa4a9d32e704ebc5fd3391ebb3a9808d905b2fbef35'),
        (bytes(32), 5): (12394, 'bece136de56d2651d129853fa71e994ed4e718cdc63db6a5284a41b4626bb62f'),
    }
    for seed, exponent in [(bytes(32), 3), (bytes(32), 4), (bytes(range(32)), 4), (bytes(32), 5)]:
        raw = manifest(seed, exponent)
        assert raw == b'stele/expander-seed/v2'+bytes([exponent])+seed
        assert parse_manifest(raw) == (seed, exponent)
        setup, count = materialize(raw)
        data = setup_bytes(setup)
        check_setup(raw, data)
        rejects(lambda: check_setup(raw[:21]+b'1'+raw[22:], data), 'InvalidManifest')
        rejects(lambda: check_setup(raw, data[:20]+b'1'+data[21:]), 'InvalidSetup')
        assert len(data) == 43+8*sum(len(row) for level in setup['levels'] for matrix in level for row in matrix)
        rows = sum(len(matrix) for level in setup['levels'] for matrix in level)
        assert 0 <= count <= 64*rows
        for level, matrices in zip(range(exponent, 3, -1), setup['levels']):
            for kind, matrix in enumerate(matrices):
                for row in sorted(set((0, len(matrix)//2, len(matrix)-1))):
                    assert matrix[row] == independent_row(seed, level, kind, row)
        if exponent == 4 and seed == bytes(32):
            earlier = setup
            for d in (1, 4, 8):
                values = [tuple((i*37+j*17+9) % sc.P for j in range(d)) for i in range(256)]
                assert encode_row(setup, values)[0] == dense_word(setup, values, base)
            # One canonical source coefficient is changed; regeneration must catch it.
            changed = decode_setup(data)
            column, value = changed['levels'][0][0][0][0]
            changed['levels'][0][0][0][0] = (column, (value+1) % sc.P)
            rejects(lambda: check_setup(raw, setup_bytes(changed)), 'SetupMismatch')
            rejects(lambda: check_setup(manifest(bytes([1])+bytes(31), 4), data), 'SetupMismatch')
            rejects(lambda: check_setup(manifest(seed, 5), data), 'SetupMismatch')
        if exponent == 5:
            assert setup['levels'][1:] == earlier['levels']
        assert (count, blake3(data).hexdigest()) == vectors[seed, exponent]
        for end in range(len(raw)):
            rejects(lambda: parse_manifest(raw[:end]), 'InvalidManifest')
        rejects(lambda: parse_manifest(raw+b'\x00'), 'InvalidManifest')
        for at, value in ((0, 0), (21, ord('1')), (22, 2), (22, 16)):
            rejects(lambda: parse_manifest(raw[:at]+bytes([value])+raw[at+1:]), 'InvalidManifest')
    rejects(lambda: manifest(bytes(31), 4), 'InvalidManifest')
    rejects(lambda: manifest(bytes(32), True), 'InvalidManifest')
    # Independent framing; every record coordinate changes the block's input.
    seed = bytes(range(32))
    framed = b'stele/v0.1/setup/expander/block/v2'+seed+struct.pack('<BBIBB', 4, 1, 7, 1, 2)
    assert block(seed, 4, 1, 7, 1, 2) == blake3(framed).digest()
    for args in ((seed, 3, 0, 0, 0, 0), (seed, 4, 2, 0, 0, 0), (seed, 4, 0, 256, 0, 0),
                 (seed, 4, 0, 0, 2, 0), (seed, 4, 0, 0, 0, 32)):
        rejects(lambda: block(*args), 'InvalidSampler')
    events = 0
    for j in range(4, 16):
        distance, inner = 4**j//25+1, 4**j//100+1
        events += 2*((distance-1)+(distance-inner))
    assert events == 200431782
    epsilon = Fraction(events, 1 << 416)
    assert all_seeds_bound() == (1 << 256)*epsilon < Fraction(1, 1 << 132)
    # The old 288-bit event budget cannot discharge this all-seed obligation.
    assert Fraction(events*(1 << 256), 1 << 288) > Fraction(1, 1 << 128)
    assert Fraction(events*(1 << 272), 1 << 416) > Fraction(1, 1 << 128)
    # Direct all-seed union: any selection succeeds only if a bad seed exists.
    for size in (1, 2, 3):
        bad = sum(any(value == 0 for value in table) for table in product(range(4), repeat=size))
        assert Fraction(bad, 4**size) == 1-Fraction(3, 4)**size <= Fraction(size, 4)
    # Adaptive inspection of independent seed tables: exact toy failure probabilities.
    for q, finals in ((0, 1), (1, 1), (2, 1), (1, 2)):
        total, bad = 0, 0
        for tables in product(range(4), repeat=q+finals+1):
            inspected, last, success = set(), 0, False
            for _ in range(q):
                unseen = [i for i in range(len(tables)) if i not in inspected]
                index = unseen[last % len(unseen)]
                inspected.add(index)
                last = tables[index]
                if last == 0:
                    success = True
                    break
            if not success:
                unseen = [i for i in range(len(tables)) if i not in inspected]
                chosen = [unseen[(last+i) % len(unseen)] for i in range(finals)]
                success = any(tables[i] == 0 for i in chosen)
            bad += success
            total += 1
        assert Fraction(bad, total) == 1-Fraction(3, 4)**(q+finals)
        assert Fraction(bad, total) <= min(1, Fraction(q+finals, 4))
    # One Grover phase (compute/uncompute) plus final verification uses three queries.
    # Independently marked RO outputs: invert about the mean gives marked amplitude 3-4x.
    density, size = Fraction(1, 16), 16
    quantum = sum(Fraction(comb(size, k))*density**k*(1-density)**(size-k)
                  *Fraction(k, size)*(3-4*Fraction(k, size))**2 for k in range(size+1))
    assert quantum > 4*density  # The classical (Q+S)*epsilon rule is not a QROM rule.
    print(f'Quantum toy success {quantum} exceeds classical three-query/one-output bound {4*density}.')
    print('V2 sampler symmetry, exhaustion, framing, regeneration, tower reuse and all-seed bound checks pass.')
    print('BLAKE3 is a concrete candidate, not a proof of the random-oracle assumption or profile admission.')


if __name__ == '__main__':
    check()
