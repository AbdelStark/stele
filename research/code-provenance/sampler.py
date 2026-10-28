"""RFC-0010 A1 / Q23 candidate setup expansion; no concrete distance/profile certificate."""
from fractions import Fraction
from itertools import islice
import struct
from blake3 import blake3
from recursive import geometry, setup_bytes, decode_setup, sc

DOMAIN = b'stele/v0.1/setup/expander/block/v2'
MANIFEST = b'stele/expander-seed/v2'
WORDS = 256
EVENTS = 200431782


def require(condition, reason='InvalidSampler'):
    if not condition:
        raise ValueError(reason)


def manifest(seed, exponent):
    require(type(seed) is bytes and len(seed) == 32, 'InvalidManifest')
    require(type(exponent) is int and 3 <= exponent <= 15, 'InvalidManifest')
    return MANIFEST+bytes([exponent])+seed


def parse_manifest(raw):
    require(type(raw) is bytes and len(raw) == 55 and raw[:22] == MANIFEST, 'InvalidManifest')
    seed, exponent = raw[23:], raw[22]
    require(manifest(seed, exponent) == raw, 'InvalidManifest')
    return seed, exponent


def block(seed, level, kind, row, stream, counter):
    require(type(seed) is bytes and len(seed) == 32)
    require(type(level) is int and 4 <= level <= 15)
    require(type(kind) is int and kind in (0, 1))
    require(type(row) is int and 0 <= row < geometry(level)[kind][0])
    require(type(stream) is int and stream in (0, 1))
    require(type(counter) is int and 0 <= counter < 32)
    raw = DOMAIN+seed+struct.pack('<BBIBB', level, kind, row, stream, counter)
    return blake3(raw).digest()


def neighbors(words, columns, degree):
    require(type(columns) is int and 1 <= columns <= 1 << 29 and columns & (columns-1) == 0)
    require(type(degree) is int and 1 <= degree <= min(columns, 26))
    selected = set()
    for word in islice(words, WORDS):
        require(type(word) is int and 0 <= word < 1 << 32)
        selected.add(word & (columns-1))
        if len(selected) == degree:
            return sorted(selected)
    raise ValueError('SamplingExhausted')


def coefficients(words, degree):
    require(type(degree) is int and 1 <= degree <= 26)
    values = []
    for word in islice(words, WORDS):
        require(type(word) is int and 0 <= word < 1 << 32)
        value = word & sc.P
        if value != sc.P:
            values.append(value)
            if len(values) == degree:
                return values
    raise ValueError('SamplingExhausted')


def materialize(raw):
    seed, exponent = parse_manifest(raw)
    setup, count = dict(exponent=exponent, levels=[]), 0

    def words(level, kind, row, stream):
        nonlocal count
        for counter in range(32):
            value = block(seed, level, kind, row, stream, counter)
            count += 1
            yield from struct.unpack('<8I', value)

    for level in range(exponent, 3, -1):
        matrices = []
        for kind, (rows, columns, degree) in enumerate(geometry(level)):
            matrix = []
            for row in range(rows):
                chosen = neighbors(words(level, kind, row, 0), columns, degree)
                entries = coefficients(words(level, kind, row, 1), degree)
                matrix.append(list(zip(chosen, entries)))
            matrices.append(matrix)
        setup['levels'].append(matrices)
    setup_bytes(setup)
    return setup, count


def check_setup(raw_manifest, raw_setup):
    _, exponent = parse_manifest(raw_manifest)
    supplied = decode_setup(raw_setup)
    require(supplied['exponent'] == exponent, 'SetupMismatch')
    expected, _ = materialize(raw_manifest)
    require(setup_bytes(expected) == raw_setup, 'SetupMismatch')


def all_seeds_bound():
    # Fixed v2 seed universe: no query cap or adversary-selection restriction.
    return Fraction((1 << 256)*EVENTS, 1 << 416)
