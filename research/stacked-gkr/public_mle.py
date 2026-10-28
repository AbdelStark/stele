"""Candidate Q20 public-MLE algorithms over M31; not an Accepted protocol/API."""
from check_stacking import P


def axis(point, real):
    if len(point) > 63 or not 1 <= real <= 1 << len(point):
        raise ValueError('axis shape')
    if any(type(r) is not int or not 0 <= r < P for r in point):
        raise ValueError('noncanonical point')


def weights(point):
    result = [1]
    for r in point:
        result = [v*w % P for v in result for w in (1-r, r)]
    return result


def bounded_eq(target, point, real):
    axis(point, real)
    axis(target, real)
    if len(target) != len(point):
        raise ValueError('point shape')
    # Borrow in (real-1)-index; return only nonnegative indices within the bound.
    state = [1, 0]
    for bit, (z, r) in enumerate(zip(reversed(target), reversed(point))):
        out = [0, 0]
        for borrow in range(2):
            for value in range(2):
                next_borrow = int(((real-1) >> bit & 1)-value-borrow < 0)
                weight = (z if value else 1-z)*(r if value else 1-r) % P
                out[next_borrow] = (out[next_borrow]+state[borrow]*weight) % P
        state = out
    return state[0]


def offset(row, column, rows, columns, shift):
    axis(row, rows)
    axis(column, columns)
    if len(row) != len(column) or shift < 0:
        raise ValueError('mask shape')
    if shift >= 1 << len(row):
        return 0
    # Bits: addition carry, comparison borrow, row-bound borrow, column-bound borrow.
    state = [1]+[0]*15
    for bit, (r, s) in enumerate(zip(reversed(row), reversed(column))):
        out = [0]*16
        for old, value in enumerate(state):
            if value == 0:
                continue
            for i in range(2):
                for j in range(2):
                    added = j+(shift >> bit & 1)+(old & 1)
                    carry = added >> 1
                    compare = int(i-(added & 1)-((old >> 1) & 1) < 0)
                    row_bound = int(((rows-1) >> bit & 1)-i-((old >> 2) & 1) < 0)
                    col_bound = int(((columns-1) >> bit & 1)-j-((old >> 3) & 1) < 0)
                    new = carry | (compare << 1) | (row_bound << 2) | (col_bound << 3)
                    weight = (r if i else 1-r)*(s if j else 1-s) % P
                    out[new] = (out[new]+value*weight) % P
        state = out
    return state[0]


def causal(row, column, rows, columns):
    return offset(row, column, rows, columns, 0)


def window(row, column, rows, columns, width):
    if width <= 0:
        raise ValueError('empty window')
    return (offset(row, column, rows, columns, 0)
            -offset(row, column, rows, columns, width)) % P


def onehot(row, column, rows, columns, indices):
    axis(row, rows)
    axis(column, columns)
    if len(indices) != rows or any(type(j) is not int or not 0 <= j < columns for j in indices):
        raise ValueError('selection source')
    a, b = weights(row), weights(column)
    return sum(a[i]*b[j] for i, j in enumerate(indices)) % P


def gqa(head, group, heads, groups):
    axis(head, heads)
    axis(group, groups)
    if heads % groups:
        raise ValueError('head grouping')
    width = heads//groups
    a, b = weights(head), weights(group)
    return sum(a[h]*b[h//width] for h in range(heads)) % P


def dense_table(values, point):
    axis(point, 1 << len(point))
    if len(values) != 1 << len(point) or any(type(v) is not int or not 0 <= v < P for v in values):
        raise ValueError('table shape or canonical value')
    state = list(values)
    for r in point:
        half = len(state)//2
        state = [(a+r*(b-a)) % P for a, b in zip(state[:half], state[half:])]
    return state[0]
