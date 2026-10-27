"""Q13: independent integer/matrix oracle against a pinned upstream execution."""
import json
import itertools
import math
from pathlib import Path

P = 2**31 - 1
M4 = ((2, 3, 1, 1), (1, 2, 3, 1), (1, 1, 2, 3), (3, 1, 1, 2))
DIAGONAL = [-2, 1, 2, 4, 8, 16, 32, 64, 128, 256, 1024, 4096, 8192, 16384, 32768, 65536]


def external(state):
    blocks = [[sum(c * x for c, x in zip(row, state[i:i+4])) % P for row in M4]
              for i in range(0, 16, 4)]
    return [(blocks[i][j] + sum(block[j] for block in blocks)) % P
            for i in range(4) for j in range(4)]


def permutation(state, constants, initial=True, diagonal=DIAGONAL):
    state = external(state) if initial else list(state)
    for row in constants['initial']:
        state = external([pow((x + c) % P, 5, P) for x, c in zip(state, row)])
    for constant in constants['internal']:
        state[0] = pow((state[0] + constant) % P, 5, P)
        total = sum(state)
        state = [(total + d * x) % P for d, x in zip(diagonal, state)]
    for row in constants['final']:
        state = external([pow((x + c) % P, 5, P) for x, c in zip(state, row)])
    return state


def main():
    records = [json.loads(line) for line in Path(__file__).with_name('reference.jsonl').read_text().splitlines()]
    constants, vectors = records[0], records[1:]
    assert constants['reference'] == 'p3-mersenne-31=0.8.0'
    assert constants['commit'] == 'a21e3ed42905040ad49c519e402f018381c12d0c'
    assert len(constants['initial']) == len(constants['final']) == 4
    assert len(constants['internal']) == 14
    for row in constants['initial'] + constants['final']:
        assert len(row) == 16 and all(0 <= x < P for x in row)
    assert all(0 <= x < P for x in constants['internal'])
    # Invertibility is algebraic; this does not establish cryptographic security.
    determinant = sum((-1)**sum(order[i] > order[j] for i in range(4) for j in range(i+1, 4))
                      * math.prod(M4[i][order[i]] for i in range(4))
                      for order in itertools.permutations(range(4))) % P
    assert determinant != 0 and 5 % P != 0  # External block mixing is I + J on four blocks.
    assert math.gcd(5, P - 1) == 1
    assert math.prod(DIAGONAL) * (1 + sum(pow(d, -1, P) for d in DIAGONAL)) % P != 0
    assert len(vectors) == 35
    for vector in vectors:
        assert len(vector['input']) == len(vector['output']) == 16
        assert all(0 <= x < P for x in vector['input'] + vector['output'])
        assert permutation(vector['input'], constants) == vector['output']
    # Published upstream sequential-input KAT anchors the executed reference.
    expected = [0x0b2c803a, 0x5b1ee4d1, 0x49c6b1e3, 0x2cdc280c, 0x310a60c8, 0x530a729e,
                0x4e61bcb4, 0x2e84d3c3, 0x58709c08, 0x7e82ac42, 0x2162bcef, 0x6d153ab6,
                0x742cf0e3, 0x2f21632d, 0x61adce1e, 0x1973d6f1]
    assert vectors[2] == {'input': list(range(16)), 'output': expected}
    assert permutation(list(range(16)), constants, initial=False) != expected
    wrong_diagonal = DIAGONAL.copy()
    wrong_diagonal[0] = -1
    assert permutation(list(range(16)), constants, diagonal=wrong_diagonal) != expected
    altered = {**constants, 'internal': constants['internal'].copy()}
    altered['internal'][0] = (altered['internal'][0] + 1) % P
    assert permutation(list(range(16)), altered) != expected
    print('35 upstream vectors matched; initial-layer, diagonal and constant mutants detected; no hash security claim')


if __name__ == '__main__':
    main()
