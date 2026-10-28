"""Exact finite-size expander sampling checks; no fixed setup/profile certificate."""
from fractions import Fraction
from itertools import combinations, product
from math import comb

P = (1 << 31) - 1
BITS = 160


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
    limit = Fraction(1, 1 << BITS)
    bounds = []
    for weight, target in demands:
        assert 1 <= weight <= n and 1 <= target <= m
        lo, hi = target - 1, m - 1
        assert entry_bound(n, m, weight, target, hi, P) <= limit, 'entry space exhausted'
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

    lo, hi = 1, m
    while lo < hi:
        middle = (lo + hi) // 2
        if passes(middle):
            hi = middle
        else:
            lo = middle + 1
    assert passes(lo)
    assert lo == 1 or not passes(lo - 1)
    assert all(entry_bound(n, m, k, t, b, P) <= limit for k, t, b in bounds)
    return lo, len(bounds)


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
    events = 0
    # Own finite schedule: rate 1/2, contraction 1/4, distance threshold floor(N/50)+1.
    for message in (256, 1024, 4096):
        total, inner = 2 * message, message // 2
        distance, inner_distance = total // 50 + 1, inner // 50 + 1
        a_degree, a_terms = parameters(message, message // 4,
            [(k, 1) for k in range(1, distance)])
        b_degree, b_terms = parameters(inner, total - message - inner,
            [(k, distance - k) for k in range(inner_distance, distance)])
        events += 2 * (a_terms + b_terms)
        print(f'n={message}: N={total}, D={distance}, A degree={a_degree}, B degree={b_degree}, '
              f'{a_terms+b_terms} support sizes, each graph/entry bound <=2^-{BITS}', flush=True)
    assert Fraction(events, 1 << BITS) <= Fraction(1, 1 << 128)
    print(f'PASS: {events} bounded events; union <= {events}/2^{BITS}; not a fixed-setup certificate')


if __name__ == '__main__':
    main()
