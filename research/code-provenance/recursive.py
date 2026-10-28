"""Q23 candidate recursive map and setup bytes; no distance/profile admission."""
from pathlib import Path
import struct
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'circle-code'))
import check_circle as circle
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'sumcheck'))
import check_sumcheck as sc

PREFIX = b'stele/expander-m31/v1'
BASE = b'stele/circle-m31/v1'+bytes([6, 1])
A_DEGREES = (18, 16, 15, 14, 14, 13, 13, 13, 13, 13, 14, 14)
B_DEGREES = (22,)+(17,)*11


def need(condition):
    if not condition:
        raise ValueError('InvalidSetup')


def exponent(value):
    need(type(value) is int and 3 <= value <= 15)
    return value


def geometry(j):
    need(type(j) is int and 4 <= j <= 15)
    n = 4**j
    return ((n, n//4, A_DEGREES[j-4]), (n//2, n//2, B_DEGREES[j-4]))


def setup_bytes(s):
    need(set(s) == {'exponent', 'levels'})
    j = exponent(s['exponent'])
    need(len(s['levels']) == j-3)
    out = bytearray(PREFIX+bytes([j])+BASE)
    for level, index in zip(s['levels'], range(j, 3, -1)):
        need(len(level) == 2)
        for matrix, (rows, columns, degree) in zip(level, geometry(index)):
            need(len(matrix) == rows)
            for row in matrix:
                need(len(row) == degree)
                previous = -1
                for column, coefficient in row:
                    need(type(column) is int and previous < column < columns)
                    need(type(coefficient) is int and 0 <= coefficient < sc.P)
                    out.extend(struct.pack('<II', column, coefficient))
                    previous = column
    return bytes(out)


def decode_setup(raw):
    need(type(raw) is bytes and len(raw) >= 43 and raw[:21] == PREFIX and raw[22:43] == BASE)
    j = exponent(raw[21])
    expected = 43+8*sum(rows*degree for level in range(j, 3, -1) for rows, _, degree in geometry(level))
    # Check the entire implied byte budget before building any graph rows.
    need(len(raw) == expected)
    s, at = dict(exponent=j, levels=[]), 43
    for level in range(j, 3, -1):
        matrices = []
        for rows, _, degree in geometry(level):
            matrix = []
            for _ in range(rows):
                row = [struct.unpack_from('<II', raw, offset) for offset in range(at, at+8*degree, 8)]
                at += 8*degree
                matrix.append(row)
            matrices.append(matrix)
        s['levels'].append(matrices)
    need(at == len(raw) and setup_bytes(s) == raw)
    return s


def encode_row(s, row):
    setup_bytes(s)
    n = 4**s['exponent']
    if len(row) != n or not row or len(row[0]) not in (1, 4, 8):
        raise ValueError('RowShape')
    d = len(row[0])
    if any(len(v) != d or any(type(x) is not int or not 0 <= x < sc.P for x in v) for v in row):
        raise ValueError('RowShape')
    counts = dict(sparse_edges=0, base_component_encodes=0)

    def sparse(values, matrix, columns):
        out = [sc.scalar(0, d)]*columns
        for value, edges in zip(values, matrix):
            for column, coefficient in edges:
                out[column] = sc.add(out[column], tuple(x*coefficient % sc.P for x in value))
                counts['sparse_edges'] += 1
        return out

    def run(j, levels, values):
        if j == 3:
            counts['base_component_encodes'] += d
            return list(zip(*(circle.encode(list(component), 1) for component in zip(*values))))
        size = 4**j
        a, b = levels[0]
        z = run(j-1, levels[1:], sparse(values, a, size//4))
        return values+z+sparse(z, b, size//2)

    return run(s['exponent'], s['levels'], list(row)), counts


def eval_row(s, row, columns):
    exponent(s['exponent'])
    if any(type(c) is not int or not 0 <= c < 2*4**s['exponent'] for c in columns):
        raise ValueError('Column')
    word, _ = encode_row(s, row)
    return [word[c] for c in columns]
