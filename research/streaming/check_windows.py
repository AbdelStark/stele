# /// script
# requires-python = ">=3.12"
# dependencies = ["blake3==1.0.11"]
# ///
"""Q22 algebra and logical visits only; no physical I/O or memory measurement."""
import itertools
import random
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'sumcheck'))
import check_sumcheck as s


def weight(point, index, d):
    value = s.scalar(1, d)
    for axis, r in enumerate(point):
        value = s.mul(value, r if index >> (len(point)-axis-1) & 1
                      else s.add(s.scalar(1, d), s.neg(r)))
    return value


def column(tables, point, suffix, m, visits, d):
    """Indexed oracle: deliberately records the nonsequential source order."""
    values = [s.scalar(0, d)] * len(tables)
    for prefix in range(2**len(point)):
        index = prefix * 2**(m-len(point)) + suffix
        w = weight(point, prefix, d)
        for table, values_at_boolean in enumerate(tables):
            visits.append((table, index))
            values[table] = s.add(values[table], s.mul(w, values_at_boolean[index]))
    return values


def window_prove(t, i, tables, windows, alter_tail=False, blocks=None):
    d, m, delta = t.degree, i['m'], s.degree(i)
    assert all(type(w) is int and w > 0 for w in windows) and sum(windows) <= m
    width = max(2, delta+1)
    def indexed_blocks(point, w, visits):
        for suffix in range(2**(m-len(point)-w)):
            yield suffix, [column(tables, point, u*2**(m-len(point)-w)+suffix,
                                  m, visits, d) for u in range(2**w)]
    blocks = indexed_blocks if blocks is None else blocks
    t.absorb(s.INSTANCE, s.instance_bytes(i, d))
    point, rounds, scans = [], [], []
    for w in windows:
        visits = []
        grid = [s.scalar(0, d)] * width**w
        for _, boolean in blocks(point, w, visits):
            for index, nodes in enumerate(itertools.product(range(width), repeat=w)):
                values = [s.scalar(0, d)] * len(tables)
                for u, row in enumerate(boolean):
                    eq = weight([s.scalar(x, d) for x in nodes], u, d)
                    values = [s.add(a, s.mul(eq, v)) for a, v in zip(values, row)]
                grid[index] = s.add(grid[index], s.compose(i['terms'], values, d))
        scans.append(visits)
        for h in range(w):
            values = []
            for node in range(delta+1):
                total = s.scalar(0, d)
                for bits in itertools.product((0, 1), repeat=w-h-1):
                    index = node
                    for bit in bits:
                        index = index*width + bit
                    total = s.add(total, grid[index])
                values.append(total)
            rounds.append(values)
            t.absorb(s.ROUND, s.message(i, len(point), values))
            point.append(s.challenge(t))
            stride = width**(w-h-1)
            grid = [s.interpolate([grid[b*stride+z] for b in range(width)], point[-1])
                    for z in range(stride)]
    # All original inputs survive, even those absent from every monomial.
    visits = []
    state = [[s.scalar(0, d)] * 2**(m-len(point)) for _ in tables]
    for suffix, boolean in blocks(point, 0, visits):
        for a, value in enumerate(boolean[0]):
            state[a][suffix] = value
    scans.append(visits)
    if alter_tail:
        state[-1][0] = s.add(state[-1][0], s.scalar(1, d))
    for r in range(len(point), m):
        values = []
        for node in range(delta+1):
            folded = [s.fold(table, s.scalar(node, d)) for table in state]
            total = s.scalar(0, d)
            for z in range(2**(m-r-1)):
                total = s.add(total, s.compose(i['terms'], [table[z] for table in folded], d))
            values.append(total)
        rounds.append(values)
        t.absorb(s.ROUND, s.message(i, r, values))
        point.append(s.challenge(t))
        state = [s.fold(table, point[-1]) for table in state]
    final = [table[0] for table in state]
    t.absorb(s.FINAL, s.message(i, len(i['ids']), final))
    return {'rounds': rounds, 'final': final}, point, scans


def checks():
    rng, count, nonsequential = random.Random(305), 0, False
    schedules = [(0, []), (2, [1]), (3, [1, 1]), (3, [2]), (3, [1, 2]), (4, [2, 1])]
    for d in (4, 8):
        for delta in range(5):
            for m, windows in schedules:
                tables = [[tuple(rng.randrange(s.P) for _ in range(d)) for _ in range(2**m)]
                          for _ in range(3)]
                factors = [v % 2 for v in range(delta)]
                terms = [(tuple(rng.randrange(s.P) for _ in range(d)), factors), (s.scalar(-3, d), [])]
                if delta:
                    terms.append((s.scalar(0, d), [1]*delta))
                total = s.scalar(0, d)
                for row in zip(*tables):
                    total = s.add(total, s.compose(terms, row, d))
                i = {'id': count, 'm': m, 'ids': [11, 12, 13], 'terms': terms, 'sum': total}
                a, b, c = [s.Transcript(b'streaming-research', d) for _ in range(3)]
                proof, point, scans = window_prove(a, i, tables, windows)
                reference, expected = s.prove(b, i, tables)
                assert (proof, point) == (reference, expected), (d, delta, m, windows)
                receipt = s.verify_public(c, i, proof, tables)
                assert receipt['point'] == point and s.challenge(a) == s.challenge(b) == s.challenge(c)
                expected_visits = [(table, index) for table in range(3) for index in range(2**m)]
                assert len(scans) == len(windows)+1
                for scan in scans:
                    assert sorted(scan) == expected_visits
                    indices = [index for table, index in scan if table == 0]
                    nonsequential |= indices != sorted(indices)
                if m == 3 and windows == [1, 2]:
                    forged, _, _ = window_prove(s.Transcript(b'streaming-research', d), i, tables, windows, True)
                    assert forged['rounds'] == proof['rounds']
                    assert sum(x != y for x, y in zip(forged['final'], proof['final'])) == 1
                    s.rejects(lambda: s.verify_public(s.Transcript(b'streaming-research', d), i, forged, tables), 'ClaimMismatch')
                count += 1
    assert nonsequential
    # A single prefix cannot give these two simultaneous table/grid limits.
    feasible = [k for k in range(1, 21) if 5**k <= 1024 and 3*2**(20-k) <= 1024]
    assert feasible == []
    print(f'{count} both-field window/dense/public-consumer cases and continuations agree.')
    print('Each window plus the final materialization visits each original input exactly once logically.')
    print('The access order is not sequential; two logical visits are not two physical I/O passes.')
    print('Degree four, m=20, three inputs: no single prefix meets both 1024-element grid/tail limits.')
    print('Unused-tail one-value tamper rejected with ClaimMismatch; research only, no NC credit.')


if __name__ == '__main__':
    if sys.argv[1:]:
        import json
        import streaming_corpus
        assert sys.argv[1:] in (['--write-corpus'], ['--check-corpus']), 'unknown arguments'
        if sys.argv[1:] == ['--write-corpus']:
            with streaming_corpus.PATH.open('x') as output:
                output.write(''.join(json.dumps(case, sort_keys=True)+'\n' for case in streaming_corpus.generate()))
        streaming_corpus.check()
    else:
        checks()
