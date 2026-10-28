"""Exact finite-size expander sampling checks; no fixed setup/profile certificate."""
from fractions import Fraction
from itertools import combinations, product
from math import comb

P = (1 << 31) - 1
BITS = 288
CUTOFF = 128
MAX_MESSAGE = 1 << 30


def graph_interval(kind, degree):
    if kind == 'A':
        return Fraction(108 * 2 ** (degree - 2)) * Fraction(4, 25) ** (degree - 3)
    return Fraction(729 * 5 ** (degree - 5)) * Fraction(2, 25) ** (degree - 6)


ENTRY_INTERVAL = {'A': Fraction(3 * MAX_MESSAGE, CUTOFF * P),
                  'B': Fraction(56_250_000, P)}


def graph_bound(n, m, degree, weight, bound):
    if degree > bound:
        return Fraction(0)
    return Fraction(comb(n, weight) * comb(m, bound) * comb(bound, degree) ** weight,
                    comb(m, degree) ** weight)


def entry_bound(n, m, weight, target, bound, prime):
    # On expansion >bound, an image of weight <target requires at least this many zeros.
    zeros = bound - target + 2
    if zeros < 0:
        return Fraction(1)
    return Fraction(comb(n, weight) * (prime - 1) ** weight * comb(m, target - 1),
                    prime ** zeros)


def parameters(n, m, demands):
    if not demands:
        return 0
    limit = Fraction(1, 1 << BITS)
    bounds = []
    for weight, target in demands:
        assert 1 <= weight <= n and 1 <= target <= m
        lo = hi = target - 1
        # Bracket the small threshold before binary search; m-sized powers are unnecessary.
        while entry_bound(n, m, weight, target, hi, P) > limit:
            assert hi < m - 1, 'entry space exhausted'
            hi = min(m - 1, 2 * hi + 1)
        while lo < hi:
            middle = (lo + hi) // 2
            if entry_bound(n, m, weight, target, middle, P) <= limit:
                hi = middle
            else:
                lo = middle + 1
        bounds.append((weight, target, lo))

    def passes(degree):
        return all(graph_bound(n, m, degree, weight, bound) <= limit
                   for weight, _, bound in bounds)

    lo, hi = 1, max(bound for _, _, bound in bounds) + 1
    while lo < hi:
        middle = (lo + hi) // 2
        if passes(middle):
            hi = middle
        else:
            lo = middle + 1
    assert passes(lo)
    assert lo == 1 or not passes(lo - 1)
    assert all(entry_bound(n, m, k, t, b, P) <= limit for k, t, b in bounds)
    return lo


def exhaustive():
    # Uniform distinct-neighbor rows, then independent entries including zero.
    cases = [(3, 3, 2, 3, 1, 1, 1), (3, 3, 2, 3, 2, 1, 2), (2, 3, 3, 5, 1, 2, 2)]
    for n, m, degree, prime, weight, target, bound in cases:
        supports = list(combinations(range(m), degree))
        graphs = list(product(supports, repeat=n))
        coefficients = list(product(range(prime), repeat=n * degree))
        messages = [x for x in product(range(prime), repeat=n)
                    if sum(v != 0 for v in x) == weight]
        bad_graphs, conditional_bad = 0, 0
        for graph in graphs:
            expands = all(len(set().union(*(set(graph[i]) for i in subset))) > bound
                          for subset in combinations(range(n), weight))
            if not expands:
                bad_graphs += 1
                continue
            for entries in coefficients:
                bad = False
                for message in messages:
                    image = [0] * m
                    for i, value in enumerate(message):
                        for j, column in enumerate(graph[i]):
                            image[column] = (image[column] + value * entries[i * degree + j]) % prime
                    if sum(v != 0 for v in image) < target:
                        bad = True
                        break
                conditional_bad += bad
        assert Fraction(bad_graphs, len(graphs)) <= graph_bound(n, m, degree, weight, bound)
        good = len(graphs) - bad_graphs
        assert good and conditional_bad
        claimed = entry_bound(n, m, weight, target, bound, prime)
        assert 0 < claimed < 1, 'exhaustive check must test a nonvacuous bound'
        assert Fraction(conditional_bad, good * len(coefficients)) <= claimed
    print('PASS: three exhaustive F3/F5 graph/entry cases, including zero-valued sampled entries')


def main():
    exhaustive()
    limit = Fraction(1, 1 << BITS)
    for kind, degree in [('A', 10), ('B', 17)]:
        assert 0 < graph_interval(kind, degree) < 1
        assert graph_interval(kind, degree) ** CUTOFF <= limit
        assert graph_interval(kind, degree - 1) ** CUTOFF > limit
        assert 0 < ENTRY_INTERVAL[kind] < 1
        assert ENTRY_INTERVAL[kind] ** CUTOFF <= limit
    # Cross-check the interval inequalities against exact combinatorics at every
    # large support in this finite step; the general proof is in formal/.
    n = 4096
    distance = 2 * n // 50 + 1
    for k in range(CUTOFF, distance):
        for kind, rows, cols, target, bound, degree in [
            ('A', n, n // 4, 1, 2 * k, 10),
            ('B', n // 2, n // 2, distance - k, distance + k, 17),
        ]:
            assert graph_bound(rows, cols, degree, k, bound) <= graph_interval(kind, degree) ** k
            assert entry_bound(rows, cols, k, target, bound, P) <= ENTRY_INTERVAL[kind] ** k
    events = 0
    # Base n=64; twelve steps cover every power of four through n=2^30.
    for message in (4 ** exponent for exponent in range(4, 16)):
        total, inner = 2 * message, message // 2
        distance, inner_distance = total // 50 + 1, inner // 50 + 1
        a_terms, b_terms = distance - 1, distance - inner_distance
        a_degree = max(10, parameters(message, message // 4,
            [(k, 1) for k in range(1, min(CUTOFF, distance))]))
        b_degree = max(17, parameters(inner, total - message - inner,
            [(k, distance - k) for k in range(inner_distance, min(CUTOFF, distance))]))
        events += 2 * (a_terms + b_terms)
        print(f'n={message}: N={total}, D={distance}, A degree={a_degree}, B degree={b_degree}, '
              f'{a_terms+b_terms} support sizes, each graph/entry bound <=2^-{BITS}', flush=True)
    assert Fraction(events, 1 << BITS) < Fraction(1, 1 << 260)
    # Arithmetic headroom only; this does not prove an FS/setup composition theorem.
    assert Fraction(events * (1 << 100), 1 << BITS) < Fraction(1, 1 << 160)
    print(f'PASS: {events} bounded events; union <= {events}/2^{BITS}; not a fixed-setup certificate')


if __name__ == '__main__':
    main()
