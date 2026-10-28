"""RFC-0006 A4 question: stacked MLE semantics, research only; no NC credit."""
import random

P = 2**31 - 1


def mle(table, point):
    assert len(table) == 1 << len(point)
    total = 0
    for index, value in enumerate(table):
        weight = 1
        for axis, r in enumerate(point):
            weight = weight * (r if index >> (len(point)-axis-1) & 1 else 1-r) % P
        total = (total + value * weight) % P
    return total


def fold_axis(table, axis, point):
    m = len(table).bit_length() - 1
    assert len(table) == 1 << m and 0 <= axis < m
    bit = 1 << (m-axis-1)
    return [(table[index] + point*(table[index+bit]-table[index])) % P
            for index in range(len(table)) if not index & bit]


def checks():
    # The two degree bounds cannot be interchanged after a layer challenge.
    f = [1, 3]
    honest = [mle(f, [r])**2 % P for r in range(3)]
    wrong = [mle([v*v % P for v in f], [r]) for r in range(3)]
    assert honest == [1, 9, 25] and wrong == [1, 9, 17]
    assert honest[0]+honest[1] == wrong[0]+wrong[1]
    assert honest[2] != wrong[2]
    # Flattening a Boolean product changes its off-Boolean extension.
    selector, value, point = [1, 0], [0, 1], [2]
    flattened = mle([a*b for a,b in zip(selector, value)], point)
    product = mle(selector, point) * mle(value, point) % P
    assert flattened == 0 and product == P-2
    # Elimination order can vary; returned claims still use canonical MSB axes.
    rng = random.Random(306)
    count = 0
    for m in range(1, 6):
        for _ in range(200):
            table = [rng.randrange(P) for _ in range(1 << m)]
            point = [rng.randrange(P) for _ in range(m)]
            order = list(range(m))
            rng.shuffle(order)
            remaining, state = list(range(m)), table
            for axis in order:
                at = remaining.index(axis)
                state = fold_axis(state, at, point[axis])
                remaining.pop(at)
            assert state == [mle(table, point)]
            count += 1
    print('Nonlinear layer-fold counterexample: 25 != 17; endpoints agree.')
    print('Boolean product extension counterexample: 0 != -2 in M31.')
    print(f'{count} arbitrary elimination orders return the canonical MLE value.')
    print('Research only: no production verifier/control or profile evidence.')


if __name__ == '__main__':
    checks()
