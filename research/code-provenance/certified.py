"""Q27 ideal-oracle functional checks; no commitment, transcript or admission API."""
from fractions import Fraction


def dot(a, b, prime):
    assert len(a) == len(b)
    return sum(x*y for x, y in zip(a, b)) % prime


def combine(a, matrix, prime):
    assert len(a) == len(matrix) and matrix and len({len(row) for row in matrix}) == 1
    return tuple(dot(a, column, prime) for column in zip(*matrix))


def encode(message):
    # Injective [8,2,4] fixture: two independent fourfold repetition blocks.
    assert len(message) == 2
    return (message[0],)*4 + (message[1],)*4


def tensor(point, prime):
    weights = [1]
    for r in reversed(point):  # point[0] controls the low row-index bit.
        weights = [w*s % prime for w in weights for s in (1-r, r)]
    return tuple(weights)


def matches(oracle, a, u, prime):
    word = combine(a, oracle, prime)
    return tuple(i for i, (x, y) in enumerate(zip(encode(u), word)) if x == y)


def certificate(oracle, point, t, draws, prime):
    good = matches(oracle, tensor(point, prime), t, prime)
    return all(c in good for c in draws)


def batch(oracle, statements, gamma, vectors, draws, prime):
    # Full inputs and vectors are fixed before the externally enumerated draws.
    assert statements and len(statements) == len(gamma) == len(vectors) and gamma[0] == 1
    errors = [dot(u, b, prime)-v for (_, b, v), u in zip(statements, vectors)]
    if dot(gamma, errors, prime):
        return False
    return all(all(c in matches(oracle, a, u, prime) for c in draws)
               for (a, _, _), u in zip(statements, vectors))


def groups(statements, gamma, prime):
    """Exact-vector, first-occurrence grouping; not a native descriptor resolver."""
    assert statements and len(statements) == len(gamma) and gamma[0] == 1
    rows = len(statements[0][0])
    grouped = {}
    for (a, b, _), weight in zip(statements, gamma):
        assert len(a) == rows
        key = tuple(b)
        if key not in grouped:
            grouped[key] = [0]*rows
        for i, value in enumerate(a):
            grouped[key][i] = (grouped[key][i]+weight*value) % prime
    return tuple((tuple(a), b) for b, a in grouped.items()), dot(gamma, [s[2] for s in statements], prime)


def grouped_batch(oracle, statements, gamma, vectors, draws, prime):
    grouped, target = groups(statements, gamma, prime)
    assert len(grouped) == len(vectors)
    if sum(dot(u, b, prime) for (_, b), u in zip(grouped, vectors)) % prime != target:
        return False
    return all(all(c in matches(oracle, a, u, prime) for c in draws)
               for (a, _), u in zip(grouped, vectors))


def bound(n, distance, field_size, rows_log, certificate_queries, openings):
    """Conditional lifetime bound; openings contain (query_count, batch_length)."""
    assert 1 <= distance <= n and field_size > 1 and rows_log >= 0 and certificate_queries > 0
    e = (distance-1)//3
    total = Fraction(2*rows_log*(e+1), field_size) + Fraction(n-e-1, n)**certificate_queries
    for q, count in openings:
        assert q > 0 and count > 0
        total += Fraction(n-distance+e, n)**q
        if count > 1:
            total += Fraction(1, field_size)
    return min(Fraction(1), total)
