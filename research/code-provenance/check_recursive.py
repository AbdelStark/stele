# /// script
# requires-python = ">=3.12"
# dependencies = ["blake3==1.0.11"]
# ///
"""Q23 recursive encoder/bytes checks; no fixed-setup certificate or profile admission."""
import copy
import random
import struct
from recursive import A_DEGREES, B_DEGREES, geometry, setup_bytes, decode_setup, encode_row, eval_row, circle, sc
from check_expander import parameters, CUTOFF

P = sc.P


def fixture(exponent, rng):
    levels = []
    for j in range(exponent, 3, -1):
        matrices = []
        for rows, columns, degree in geometry(j):
            matrices.append([[(c, rng.randrange(P)) for c in sorted(rng.sample(range(columns), degree))] for _ in range(rows)])
        levels.append(matrices)
    return dict(exponent=exponent, levels=levels)


def matrix(rows, columns):
    result = [[0]*columns for _ in rows]
    for i, entries in enumerate(rows):
        for column, value in entries:
            result[i][column] = value
    return result


def product(left, right):
    columns = list(zip(*right))
    return [[sum(a*b for a, b in zip(row, col)) % P for col in columns] for row in left]


def base_generator():
    # Invert the basis evaluation matrix by elimination, independently of the FFT.
    units = [[int(i == j) for i in range(64)] for j in range(64)]
    v = [[circle.direct(unit, pt) for unit in units] for pt in circle.domain(6)]
    augmented = [row+units[i] for i, row in enumerate(v)]
    for col in range(64):
        pivot = next(i for i in range(col, 64) if augmented[i][col])
        augmented[col], augmented[pivot] = augmented[pivot], augmented[col]
        inverse = pow(augmented[col][col], -1, P)
        augmented[col] = [x*inverse % P for x in augmented[col]]
        for i in range(64):
            if i != col:
                coefficient = augmented[i][col]
                augmented[i] = [(a-coefficient*b) % P for a, b in zip(augmented[i], augmented[col])]
    assert [row[:64] for row in augmented] == units
    inverse = [row[64:] for row in augmented]
    expanded = [[circle.direct(unit, pt) for unit in units] for pt in circle.domain(7)]
    return list(map(list, zip(*product(expanded, inverse))))


def dense_word(setup, values, base):
    def run(j, levels, row):
        if j == 3:
            return product([row], base)[0]
        n = 4**j
        a, b = levels[0]
        inner = product([row], matrix(a, n//4))[0]
        z = run(j-1, levels[1:], inner)
        return row+z+product([z], matrix(b, n//2))[0]
    components = [run(setup['exponent'], setup['levels'], list(v)) for v in zip(*values)]
    return list(zip(*components))


def rejects(call, reason):
    sc.rejects(call, reason)


def check():
    rng = random.Random(40123)
    base = base_generator()
    # Derive every fixed degree again from the existing exact sampling inequalities.
    for j in range(4, 16):
        n = 4**j; distance, inner = n//25+1, n//100+1
        a = max(10, parameters(n, n//4, [(k, 1) for k in range(1, min(CUTOFF, distance))]))
        b = max(17, parameters(n//2, n//2, [(k, distance-k) for k in range(inner, min(CUTOFF, distance))]))
        assert (a, b) == (A_DEGREES[j-4], B_DEGREES[j-4])
    cases = 0
    for exponent in (3, 4, 5):
        setup = fixture(exponent, rng)
        raw = setup_bytes(setup)
        assert setup_bytes(decode_setup(raw)) == raw and decode_setup(raw) == setup
        n = 4**exponent
        edges = sum(rows*degree for j in range(4, exponent+1) for rows, _, degree in geometry(j))
        assert len(raw) == 43+8*edges
        if exponent == 3:
            assert raw == b'stele/expander-m31/v1\x03stele/circle-m31/v1\x06\x01'
        generator = None
        if exponent == 4:
            a, b = setup['levels'][0]
            middle = product(matrix(a, 64), base)
            last = product(middle, matrix(b, 128))
            generator = [[int(i == j) for j in range(n)]+middle[i]+last[i] for i in range(n)]
        for d in (1, 4, 8):
            def value():
                return tuple(rng.randrange(P) for _ in range(d))
            x, y = ([value() for _ in range(n)] for _ in range(2))
            word, counts = encode_row(setup, x)
            assert counts == dict(sparse_edges=edges, base_component_encodes=d)
            zeros, zero_counts = encode_row(setup, [sc.scalar(0, d)]*n)
            assert zeros == [sc.scalar(0, d)]*(2*n) and zero_counts == counts
            assert word == dense_word(setup, x, base)
            if generator is not None:
                assert word == list(zip(*(product([list(v)], generator)[0] for v in zip(*x))))
            if exponent > 3:
                assert word[:n] == x
            alpha, beta = value(), value()
            combined = [sc.add(sc.mul(alpha, a), sc.mul(beta, b)) for a, b in zip(x, y)]
            rhs = [sc.add(sc.mul(alpha, a), sc.mul(beta, b)) for a, b in zip(word, encode_row(setup, y)[0])]
            assert encode_row(setup, combined)[0] == rhs
            columns = [2*n-1, 0, n, 0]
            assert eval_row(setup, x, columns) == [word[c] for c in columns]
            assert eval_row(setup, x, []) == []
            for column in (-1, 2*n, True):
                rejects(lambda: eval_row(setup, x, [column]), 'Column')
            rejects(lambda: encode_row(setup, x[:-1]), 'RowShape')
            bad = list(x); bad[0] = (P,)+(0,)*(d-1)
            rejects(lambda: encode_row(setup, bad), 'RowShape')
            rejects(lambda: encode_row(setup, [(0, 0)]*n), 'RowShape')
            cases += 1
        for end in sorted(set([*range(44), len(raw)//2, len(raw)-1])):
            if end < len(raw):
                rejects(lambda: decode_setup(raw[:end]), 'InvalidSetup')
        rejects(lambda: decode_setup(raw+b'\x00'), 'InvalidSetup')
        for at, value in ((0, 0), (20, ord('2')), (21, 2), (21, 16), (21, 15), (41, 7), (42, 2)):
            rejects(lambda: decode_setup(raw[:at]+bytes([value])+raw[at+1:]), 'InvalidSetup')
        if exponent > 3:
            rejects(lambda: decode_setup(raw[:47]+struct.pack('<I', P)+raw[51:]), 'InvalidSetup')
            rejects(lambda: decode_setup(raw[:51]+raw[43:47]+raw[55:]), 'InvalidSetup')
            rejects(lambda: decode_setup(raw[:43]+struct.pack('<I', n//4)+raw[47:]), 'InvalidSetup')
    setup = fixture(4, rng)
    bad = copy.deepcopy(setup); bad['proven'] = True
    rejects(lambda: setup_bytes(bad), 'InvalidSetup')
    bad = copy.deepcopy(setup); bad['levels'][0][0].pop()
    rejects(lambda: setup_bytes(bad), 'InvalidSetup')
    bad = copy.deepcopy(setup); bad['levels'][0][0][0].reverse()
    rejects(lambda: setup_bytes(bad), 'InvalidSetup')
    bad = copy.deepcopy(setup); bad['levels'][0][0][0][0] = (True, 1)
    rejects(lambda: setup_bytes(bad), 'InvalidSetup')
    # Syntax and injectivity never certify this map's distance: zero edges are legal.
    weak = copy.deepcopy(setup)
    for level in weak['levels']:
        for edges in level:
            for row in edges:
                row[:] = [(column, 0) for column, _ in row]
    x = [sc.scalar(int(i == 0), 1) for i in range(256)]
    word, counts = encode_row(decode_setup(setup_bytes(weak)), x)
    assert word == x+[sc.scalar(0, 1)]*256 and sum(v != (0,) for v in word) == 1
    assert counts['sparse_edges'] == 7424
    print(f'{cases} M31/QM31/OM31 encoding, dense parity, linearity and coordinate cases pass.')
    print('Twelve degree pairs re-derived; malformed setup/row/columns reject; legal zero-edge setup has distance one.')
    print('No fixed-setup, proximity, production NC, benchmark or profile certification.')


if __name__ == '__main__':
    check()
