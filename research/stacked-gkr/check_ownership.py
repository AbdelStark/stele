"""Q20: independently check folded-input ownership, not production protocol credit."""
import itertools
import random
from check_stacking import P, mle
from ownership import degree, reorder, owned_round


def check():
    rng = random.Random(30621)
    rounds, changed_points, moved = 0, 0, 0
    for case in range(1000):
        m = case % 5
        layer_bits = rng.randrange(m+1)
        real_layers = rng.randrange(1, (1 << layer_bits)+1)
        tables = [[rng.randrange(P) if index >> (m-layer_bits) < real_layers else 0
                   for index in range(1 << m)] for _ in range(3)]
        delta = (case // 5) % 5
        terms = [(5, []), (7, [0]*delta)]
        if delta >= 2:
            terms.append((P-3, [0, 1]))
        assert degree(terms) == delta
        point = [rng.randrange(P) for _ in range(m)]
        if case % 7 == 0:
            point = [rng.randrange(2) for _ in range(m)]
        for order in (list(range(m)), list(range(layer_bits, m))+list(range(layer_bits))):
            state = [reorder(table, order) for table in tables]
            fixed = {}
            for round_index, axis in enumerate(order):
                remaining = order[round_index:]
                partials, state, transfers = owned_round(state, terms, remaining, layer_bits, point[axis])
                expected = [[0]*(degree(terms)+1) for _ in range(1 << layer_bits)]
                for suffix in itertools.product((0, 1), repeat=len(remaining)-1):
                    assignment = dict(zip(remaining[1:], suffix))
                    owner_bits = [assignment.get(j, 0) for j in range(layer_bits)]
                    owner = int(''.join(map(str, owner_bits)), 2) if owner_bits else 0
                    for x in range(degree(terms)+1):
                        full = [fixed.get(j, assignment.get(j, x)) for j in range(m)]
                        values = [mle(table, full) for table in tables]
                        direct = 5+7*pow(values[0], delta, P)
                        if delta >= 2:
                            direct -= 3*values[0]*values[1]
                        expected[owner][x] = (expected[owner][x]+direct) % P
                assert partials == expected
                assert transfers == (3*(1 << (len(remaining)-1)) if axis < layer_bits else 0)
                moved += transfers
                fixed[axis] = point[axis]
                rounds += 1
            assert [row[0] for row in state] == [mle(table, point) for table in tables]
            draw_order = [point[axis] for axis in order]
            restored = [None]*m
            for axis, value in zip(order, draw_order):
                restored[axis] = value
            assert restored == point
            if draw_order != point and mle(tables[0], draw_order) != mle(tables[0], point):
                changed_points += 1
    for terms in ([], [(9, [])]):
        for order in ([0, 1, 2], [2, 0, 1]):
            state = []
            for j in range(3):
                partials, state, transfers = owned_round(state, terms, order[j:], 2, 17)
                assert sum(row[0] for row in partials) % P == ((9 if terms else 0)*(1 << (2-j))) % P
                assert state == [] and transfers == 0
    assert changed_points > 0 and moved > 0
    print(f'{rounds} rounds: every owned partial equals a direct original-table restriction.')
    print('Both layer orders restore every original claim, including the unused input.')
    print('Layer folds move current input values; scalar partial-message sums alone are insufficient.')
    print('M31 research model only; no production control, transport or performance evidence.')


if __name__ == '__main__':
    check()
