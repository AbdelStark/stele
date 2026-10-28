"""Q23: linearity/distance evidence for fixed RAA maps, not PCS parameters."""
import itertools
import random

P = 2**31 - 1


def encode(message, repeat, permutations, p=P):
    if not message or repeat not in (2, 4) or len(permutations) != 2:
        raise ValueError('shape')
    n = repeat*len(message)
    if any(sorted(perm) != list(range(n)) for perm in permutations):
        raise ValueError('permutation')
    state, adds = [x % p for x in message]*repeat, 0
    for perm in permutations:
        state = [state[index] for index in perm]
        for index in range(1, n):
            state[index] = (state[index]+state[index-1]) % p
            adds += 1
    return state, adds


def null_line(rows, k, p):
    """Unique projective null vector when the selected columns have rank k-1."""
    rows = [[x % p for x in row] for row in rows]
    pivots = []
    for col in range(k):
        at = next((j for j in range(len(pivots), len(rows)) if rows[j][col]), None)
        if at is None:
            continue
        pivot = len(pivots)
        rows[pivot], rows[at] = rows[at], rows[pivot]
        inverse = pow(rows[pivot][col], p-2, p)
        rows[pivot] = [x*inverse % p for x in rows[pivot]]
        for j in range(len(rows)):
            if j != pivot:
                factor = rows[j][col]
                rows[j] = [(a-factor*b) % p for a, b in zip(rows[j], rows[pivot])]
        pivots.append(col)
    if len(pivots) != k-1:
        return None
    free = next(col for col in range(k) if col not in pivots)
    v = [int(col == free) for col in range(k)]
    for row, col in zip(rows, pivots):
        v[col] = -row[free] % p
    return v


def exact_distance(k, repeat, permutations, p=P):
    # Full rank follows because repetition is injective and both other maps invert.
    basis = [encode([int(i == j) for j in range(k)], repeat, permutations, p)[0]
             for i in range(k)]
    columns = list(zip(*basis))
    best, witness = len(columns)+1, None
    for positions in itertools.combinations(range(len(columns)), k-1):
        v = null_line([columns[j] for j in positions], k, p)
        if v is None:
            continue
        word, _ = encode(v, repeat, permutations, p)
        weight = sum(x != 0 for x in word)
        if weight < best:
            best, witness = weight, v
    assert witness is not None and 0 < best <= len(columns)
    return best, witness


def checks():
    rng, cases = random.Random(401), 0
    for k in (1, 2, 3):
        for repeat in (2, 4):
            n = repeat*k
            for _ in range(4):
                perms = [rng.sample(range(n), n), rng.sample(range(n), n)]
                # Exhaustive small-prime search independently checks the rank method.
                for p in (2, 3, 5):
                    actual, _ = exact_distance(k, repeat, perms, p)
                    expected = min(sum(x != 0 for x in encode(v, repeat, perms, p)[0])
                                   for v in itertools.product(range(p), repeat=k) if any(v))
                    assert actual == expected
                distance, witness = exact_distance(k, repeat, perms)
                assert sum(x != 0 for x in encode(witness, repeat, perms)[0]) == distance
                sample_min = n
                for _ in range(20):
                    a, b = [[rng.randrange(P) for _ in range(k)] for _ in range(2)]
                    scalar = rng.randrange(P)
                    ea, adds = encode(a, repeat, perms)
                    eb, _ = encode(b, repeat, perms)
                    combined, _ = encode([(x+scalar*y) % P for x, y in zip(a, b)], repeat, perms)
                    assert combined == [(x+scalar*y) % P for x, y in zip(ea, eb)]
                    assert adds == 2*(n-1)
                    sample_min = min(sample_min, sum(x != 0 for x in ea))
                assert distance <= sample_min
                cases += 1
    # Identity permutations are valid but have vanishing relative distance.
    k, repeat = 16, 4
    identity = list(range(k*repeat))
    perms = [identity, identity]
    low = [1, P-2, 1] + [0]*(k-3)
    word, adds = encode(low, repeat, perms)
    assert word == ([1]+[0]*(k-1))*repeat and adds == 2*(k*repeat-1)
    sampled = [sum(x != 0 for x in encode([rng.randrange(P) for _ in range(k)], repeat, perms)[0])
               for _ in range(1000)]
    assert min(sampled) == 64 and sum(x != 0 for x in word) == 4
    # Distinguish the same integer operations in different characteristics.
    assert encode([1, 1], 2, [list(range(4))]*2, 2)[0] != encode([1, 1], 2, [list(range(4))]*2, P)[0]
    for malformed in ([0]*4, [0, 1, 2, 4], [0, 1, 2]):
        try:
            encode([1, 2], 2, [malformed, list(range(4))])
        except ValueError as e:
            assert str(e) == 'permutation'
        else:
            raise AssertionError('malformed permutation accepted')
    print(f'{cases} fixed maps: M31 linearity, exact small-code distance, and addition counts checked.')
    print('Rank-based distance agrees with exhaustive messages over F2/F3/F5 for every map.')
    print('Identity RAA, k=16/r=4: 1000 sampled words have weight 64; explicit nonzero word has weight 4.')
    print('A sampled minimum is an upper bound on minimum distance, never a certified lower bound.')
    print('Research only: no production code, proximity theorem, setup-security budget or benchmark.')


if __name__ == '__main__':
    checks()
