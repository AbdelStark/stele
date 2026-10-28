"""Q20 candidate weighted public-MLE evaluation over full K; no source authenticator."""
import itertools
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'sumcheck'))
from check_sumcheck import add, mul, neg, scalar
from statement import encode, field, need


def bounded(pairs, real, d):
    state = [scalar(1, d), scalar(0, d)]
    for bit, weights in enumerate(reversed(pairs)):
        out = [scalar(0, d)]*2
        for borrow, value in enumerate(state):
            for choice in range(2):
                new = int(((real-1) >> bit & 1)-choice-borrow < 0)
                out[new] = add(out[new], mul(value, weights[choice]))
        state = out
    return state[0]


def offset(row, column, rows, columns, shift, d):
    zero = scalar(0, d)
    if shift >= 1 << len(row):
        return zero
    # State bits: addition carry, comparison borrow, row/column-bound borrows.
    state = [scalar(1, d)]+[zero]*15
    for bit, (r, s) in enumerate(zip(reversed(row), reversed(column))):
        out = [zero]*16
        weights = [[mul(r[i], s[j]) for j in range(2)] for i in range(2)]
        for old, value in enumerate(state):
            if value == zero:
                continue
            for i in range(2):
                for j in range(2):
                    added = j+(shift >> bit & 1)+(old & 1)
                    compare = int(i-(added & 1)-((old >> 1) & 1) < 0)
                    rb = int(((rows-1) >> bit & 1)-i-((old >> 2) & 1) < 0)
                    cb = int(((columns-1) >> bit & 1)-j-((old >> 3) & 1) < 0)
                    new = (added >> 1) | (compare << 1) | (rb << 2) | (cb << 3)
                    out[new] = add(out[new], mul(value, weights[i][j]))
        state = out
    return state[0]


def weights(pairs, d):
    result = [scalar(1, d)]
    for pair in pairs:
        result = [mul(value, weight) for value in result for weight in pair]
    return result


def evaluate(statement, point):
    # Reuse the exact candidate descriptor admission, including source values/shapes.
    encode(statement)
    d, axes, c = statement['field'], statement['layout'], statement['coefficient']
    need(len(point) == sum(bits for bits, _ in axes))
    for value in point:
        field(value, d)
    one, zero = scalar(1, d), scalar(0, d)
    pairs, at = [], 0
    for (bits, _), selector in zip(axes, c['selectors']):
        axis = []
        for bit, r in enumerate(point[at:at+bits]):
            pair = (add(one, neg(r)), r)
            if selector is not None:
                z = selector[bit]
                pair = (mul(pair[0], add(one, neg(z))), mul(pair[1], z))
            axis.append(pair)
        pairs.append(axis)
        at += bits
    kind, chosen = c['kind'], c['axes']
    result = one
    for axis, (_, real) in enumerate(axes):
        if axis not in chosen:
            result = mul(result, bounded(pairs[axis], real, d))
    if kind == 0:
        return result
    if kind in (1, 2, 3, 4):
        a, b = chosen
        rows, columns = axes[a][1], axes[b][1]
        if kind in (1, 2):
            value = offset(pairs[a], pairs[b], rows, columns, 0, d)
            if kind == 2:
                value = add(value, neg(offset(pairs[a], pairs[b], rows, columns, c['width'], d)))
        else:
            r, s = weights(pairs[a], d), weights(pairs[b], d)
            value = zero
            for i in range(rows):
                j = c['values'][i] if kind == 3 else i//(rows//columns)
                value = add(value, mul(r[i], s[j]))
    else:
        vectors = [weights(pairs[axis], d) for axis in chosen]
        value = zero
        for entry, indices in zip(c['values'], itertools.product(*(range(axes[a][1]) for a in chosen))):
            term = scalar(entry, d)
            for vector, index in zip(vectors, indices):
                term = mul(term, vector[index])
            value = add(value, term)
    return mul(result, value)
