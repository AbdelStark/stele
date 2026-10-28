# /// script
# requires-python = ">=3.12"
# dependencies = ["blake3==1.0.11"]
# ///
"""Q27 exact certified-functional study; no production, ZK or FS credit."""
from collections import Counter
from fractions import Fraction
from itertools import product
import random
from certified import batch, bound, certificate, combine, dot, encode, grouped_batch, groups, matches, tensor
from identity import parameters
from proximity import queries
from sampler import manifest


def near_oracles():
    # Exhaust every message and every possible replacement of at most one column.
    for flat in product(range(3), repeat=4):
        message = (flat[:2], flat[2:])
        word = tuple(encode(row) for row in message)
        yield message, word
        for c in range(8):
            for replacement in product(range(3), repeat=2):
                if replacement == (word[0][c], word[1][c]):
                    continue
                altered = [list(row) for row in word]
                for i in range(2):
                    altered[i][c] = replacement[i]
                yield message, tuple(tuple(row) for row in altered)


def check_near():
    vectors = list(product(range(3), repeat=2))
    words = {u: encode(u) for u in vectors}
    count = wrong = 0
    selected = []
    for message, oracle in near_oracles():
        # Independent nearest-message enumeration confirms uniqueness in column metric.
        if count % 251 == 0:
            candidates = []
            for flat in product(range(3), repeat=4):
                m = (flat[:2], flat[2:])
                distance = sum(any(encode(m[i])[c] != oracle[i][c] for i in range(2))
                               for c in range(8))
                if distance <= 1:
                    candidates.append(m)
            assert candidates == [message]
            selected.append((message, oracle))
        count += 1
        for a in vectors:
            truth = combine(a, message, 3)
            for u in vectors:
                if u == truth:
                    continue
                good = matches(oracle, a, u, 3)
                # D-e=3 disagreements, uniformly over every arbitrary coefficient vector.
                assert len(good) <= 5
                wrong += 1
                if wrong % 7919 == 0:
                    accepted = sum(batch(oracle, [(a, (1, 0), u[0])], [1], [u], draws, 3)
                                   for draws in product(range(8), repeat=2))
                    assert accepted == len(good)**2
                    # A separate direct equation oracle checks the actual matching columns.
                    direct = tuple(c for c in range(8)
                                   if words[u][c] == sum(a[i]*oracle[i][c] for i in range(2)) % 3)
                    assert good == direct
    assert (count, wrong) == (5265, 379080)
    print(f'near: {count} exact matrices; {wrong} arbitrary wrong-row checks; D-e bound holds')
    return selected


def check_batches(cases):
    vectors = list(product(range(3), repeat=2))
    total = 0
    for case, (message, oracle) in enumerate(cases):
        a = ((1, 0), (0, 1)); b = ((1, 0), (0, 1))
        truth = [dot(combine(a[i], message, 3), b[i], 3) for i in range(2)]
        agreements = [{u: set(matches(oracle, a[i], u, 3)) for u in vectors} for i in range(2)]
        for error in product(range(3), repeat=2):
            if error == (0, 0):
                continue
            claimed = [(truth[i]+error[i]) % 3 for i in range(2)]
            statements = [(a[i], b[i], claimed[i]) for i in range(2)]
            best_sum = 0
            for g in range(3):
                best = 0; chosen = None
                for u in product(vectors, repeat=2):
                    if (dot(u[0], b[0], 3)-claimed[0]+g*(dot(u[1], b[1], 3)-claimed[1])) % 3:
                        continue
                    good = agreements[0][u[0]] & agreements[1][u[1]]
                    accepted = len(good)**2
                    if accepted >= best:
                        best, chosen = accepted, u
                if case < 2 and chosen is not None:
                    direct = sum(batch(oracle, statements, (1, g), chosen, draws, 3)
                                 for draws in product(range(8), repeat=2))
                    assert direct == best
                best_sum += best
            assert Fraction(best_sum, 3*8**2) <= Fraction(1, 3)+Fraction(5, 8)**2
            total += 1
    # Fixed error vectors, including a lone erroneous first claim and zero gamma.
    for count in (1, 2, 3):
        for errors in product(range(3), repeat=count):
            if not any(errors):
                continue
            roots = sum(dot((1,)+tail, errors, 3) == 0
                        for tail in product(range(3), repeat=count-1))
            assert roots == 0 if count == 1 else roots <= 3**(count-2)
    print(f'batch: {total} false statements; every gamma and adaptive proposed-row pair checked')


def check_certificates():
    rng = random.Random(270028)
    cases = []
    for rows in (1, 2, 4):
        cases.extend(tuple(tuple(rng.randrange(17) for _ in range(8)) for _ in range(rows))
                     for _ in range(24))
        cases.append(tuple(encode((i, i+1)) for i in range(rows)))
    far = 0
    for oracle in cases:
        # Each block repeats one column vector. Counts in distinct blocks add.
        agreement = sum(max(Counter(tuple(row[c] for row in oracle) for c in range(start, start+4)).values())
                        for start in (0, 4))
        ell = (len(oracle)-1).bit_length()
        if agreement >= 7:
            point = (2,)*ell
            message = tuple((row[0], row[4]) for row in oracle)
            t = combine(tensor(point, 17), message, 17)
            assert certificate(oracle, point, t, tuple(range(8)), 17)
            continue
        far += 1
        bad = exceptional = 0
        for point in product(range(17), repeat=ell):
            word = combine(tensor(point, 17), oracle, 17)
            # Optimise over *all* t after the tensor challenge, before two column draws.
            best = sum(max(Counter(word[start:start+4]).values()) for start in (0, 4))
            exceptional += best >= 7
            bad += best**2
        assert Fraction(exceptional, 17**ell) <= Fraction(4*ell, 17)
        assert Fraction(bad, 17**ell*8**2) <= Fraction(4*ell, 17)+Fraction(6, 8)**2
    assert far == 72
    print(f'certificate: {len(cases)} matrices, {far} far; all tensor points and best pre-query rows checked')


def check_groups(cases):
    vectors = list(product(range(3), repeat=2))
    checked = 0
    for message, oracle in cases[::4]:
        for common in (False, True):
            a = ((1, 0), (0, 1)); b = ((1, 0), (1, 0) if common else (0, 1))
            truth = [dot(combine(a[i], message, 3), b[i], 3) for i in range(2)]
            for error in product(range(3), repeat=2):
                if error == (0, 0):
                    continue
                statements = [(a[i], b[i], (truth[i]+error[i]) % 3) for i in range(2)]
                best_sum = 0
                for g in range(3):
                    grouped, target = groups(statements, (1, g), 3)
                    assert len(grouped) == (1 if common else 2)
                    agreement = [{u: set(matches(oracle, ag, u, 3)) for u in vectors} for ag, _ in grouped]
                    best = 0; chosen = None
                    for proposed in product(vectors, repeat=len(grouped)):
                        if sum(dot(u, bg, 3) for (_, bg), u in zip(grouped, proposed)) % 3 != target:
                            continue
                        good = set(range(8)).intersection(*(agreement[i][u] for i, u in enumerate(proposed)))
                        if len(good)**2 >= best:
                            best, chosen = len(good)**2, proposed
                    if checked < 2 and chosen is not None:
                        assert sum(grouped_batch(oracle, statements, (1, g), chosen, draws, 3)
                                   for draws in product(range(8), repeat=2)) == best
                    best_sum += best
                assert Fraction(best_sum, 3*8**2) <= Fraction(1, 3)+Fraction(5, 8)**2
                checked += 1
    fixture = [((1, 2), (1, 0), 0), ((2, 1), (0, 1), 0), ((2, 1), (1, 0), 0)]
    grouped, _ = groups(fixture, (1, 0, 1), 3)
    assert grouped == (((0, 0), (1, 0)), ((0, 0), (0, 1)))
    # A single source traversal accumulates every group; this is not a native measurement.
    message = ((1, 2), (2, 0))
    for gamma in product(range(3), repeat=2):
        grouped, _ = groups(fixture, (1,)+gamma, 3)
        output = [[0, 0] for _ in grouped]; reads = 0
        for i, row in enumerate(message):
            for j, value in enumerate(row):
                reads += 1
                for out, (ag, _) in zip(output, grouped):
                    out[j] = (out[j]+ag[i]*value) % 3
        assert reads == 4
        assert tuple(map(tuple, output)) == tuple(combine(ag, message, 3) for ag, _ in grouped)
    print(f'grouped batch: {checked} false statements; common/different b, zero aggregates and one-traversal algebra checked')


def check_attacks_and_reuse():
    oracle = (encode((0, 0)),)*2
    # An accepted certificate for another oracle cannot discharge this statement.
    changed = (oracle[0], tuple(range(8)))
    assert certificate(oracle, (2,), (0, 0), tuple(range(8)), 17)
    assert not certificate(changed, (2,), (0, 0), tuple(range(8)), 17)
    statements = [((1, 0), (1, 0), 1), ((1, 0), (0, 1), 0)]
    for g in range(1, 7):
        u = ((1, 0), ((-pow(g, -1, 7)) % 7, 0))
        assert dot(u[0], (1, 0), 7)-1+g*dot(u[1], (0, 1), 7) == 0
        # A malicious producer cancels *all* aggregated column discrepancies.
        assert all((encode(u[0])[c]+g*encode(u[1])[c]) % 7 == 0 for c in range(8))
        assert not batch(oracle, statements, (1, g), u, tuple(range(8)), 7)
        grouped_u = ((1, 0), (6, 0))
        assert all((encode(grouped_u[0])[c]+encode(grouped_u[1])[c]) % 7 == 0 for c in range(8))
        assert not grouped_batch(oracle, statements, (1, g), grouped_u, tuple(range(8)), 7)
    # If values are chosen after gamma, even truthful rows can mask false claims.
    for g in range(7):
        late = [((1, 0), (1, 0), g), ((0, 1), (0, 1), 6)]
        assert batch(oracle, late, (1, g), ((0, 0), (0, 0)), tuple(range(8)), 7)
    # A previously observed column is not a fresh random opening challenge.
    statement = [((1, 0), (1, 1), 1)]
    for previous in range(8):
        u = (0, 1) if previous < 4 else (1, 0)
        assert batch(oracle, statement, (1,), (u,), (previous,), 7)
        assert sum(batch(oracle, statement, (1,), (u,), (fresh,), 7) for fresh in range(8)) == 4
    # Two attempts: the second proposed row depends on the first query history.
    bad = 0
    for first in product(range(8), repeat=2):
        u2 = (0, 1) if first[-1] < 4 else (1, 0)
        conditional = sum(batch(oracle, statement, (1,), (u2,), second, 7)
                          for second in product(range(8), repeat=2))
        assert conditional == 16
        for second in product(range(8), repeat=2):
            bad += (batch(oracle, statement, (1,), ((1, 0),), first, 7)
                    or batch(oracle, statement, (1,), (u2,), second, 7))
    assert Fraction(bad, 8**4) == Fraction(7, 16) <= 2*Fraction(5, 8)**2
    assert bound(8, 4, 17, 1, 10, [(3, 1), (4, 2)]) == min(
        1, Fraction(4, 17)+Fraction(6, 8)**10+Fraction(5, 8)**3+Fraction(5, 8)**4+Fraction(1, 17))
    print('attacks: changed oracle, aggregated-column cancellation, late values and reused queries exposed; adaptive fresh reuse bounded')


def check_counts():
    ids = [b'stele/circle-m31/v1'+bytes((m, b)) for b in (1, 2) for m in range(31-b)]
    ids += [manifest(bytes(32), j) for j in range(3, 16)]
    for raw_id in ids:
        info = parameters(raw_id, 8)
        n, distance = info['codeword_len'], info['distance']
        e = (distance-1)//3
        q = queries(n, distance-e)
        assert ((n-distance+e)**q << 130) <= n**q
        assert q == 1 or ((n-distance+e)**(q-1) << 130) > n**(q-1)
        assert q <= queries(n, e+1)
    for raw_id in (ids[10], b'stele/circle-m31/v1'+bytes((10, 2)), manifest(bytes(32), 4), ids[-1]):
        info = parameters(raw_id, 8); n = info['codeword_len']; d = info['distance']; e = (d-1)//3
        print(f'{raw_id[:22]!r} n={n}, D={d}: certificate q={queries(n,e+1)}, certified opening q={queries(n,d-e)}')
    print('72 exact parameter cases; all checks are ideal-oracle research, not PCS/profile admission')


if __name__ == '__main__':
    selected = check_near()
    check_batches(selected)
    check_groups(selected)
    check_certificates()
    check_attacks_and_reuse()
    check_counts()
