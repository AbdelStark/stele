"""Candidate Q20 ownership over actual folded inputs; M31 research only."""
from check_stacking import P


def degree(terms):
    return max((len(factors) for _, factors in terms), default=0)


def polynomial(terms, values):
    total = 0
    for coefficient, factors in terms:
        value = coefficient
        for ordinal in factors:
            value = value*values[ordinal] % P
        total = (total+value) % P
    return total


def reorder(table, order):
    m = len(order)
    assert len(table) == 1 << m and sorted(order) == list(range(m))
    result = []
    for index in range(1 << m):
        canonical = sum(((index >> (m-j-1)) & 1) << (m-axis-1)
                        for j, axis in enumerate(order))
        result.append(table[canonical])
    return result


def owner(remaining, index, layer_bits):
    # Fixed/currently paired layer bits are zero in the representative block id.
    return sum(((index >> (len(remaining)-j-1)) & 1) << (layer_bits-axis-1)
               for j, axis in enumerate(remaining) if axis < layer_bits)


def owned_round(tables, terms, remaining, layer_bits, challenge):
    assert remaining and all(len(row) == 1 << len(remaining) for row in tables)
    assert degree(terms) <= 4
    half = 1 << (len(remaining)-1)
    partials = [[0]*(degree(terms)+1) for _ in range(1 << layer_bits)]
    folded = [[0]*half for _ in tables]
    transfers = 0
    for suffix in range(half):
        destination = owner(remaining[1:], suffix, layer_bits)
        values = []
        for index in (suffix, suffix+half):
            source = owner(remaining, index, layer_bits)
            values.append([row[index] for row in tables])
            if source != destination:
                transfers += len(tables)
        # Both endpoint input vectors reach the destination before nonlinear P.
        left, right = values
        for x in range(degree(terms)+1):
            at_x = [(a+x*(b-a)) % P for a, b in zip(left, right)]
            partials[destination][x] = (partials[destination][x]+polynomial(terms, at_x)) % P
        for ordinal, (a, b) in enumerate(zip(left, right)):
            folded[ordinal][suffix] = (a+challenge*(b-a)) % P
    return partials, folded, transfers
