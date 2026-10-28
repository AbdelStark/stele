"""RFC-0006 A6: independent A1 decisions and source-window proof fixtures."""
import copy
import json
import random
from pathlib import Path
import check_windows as w
import corpus as a1
s = w.s
PATH = Path(__file__).with_name('corpus.jsonl')


def record(i, tables, proof):
    result = a1.encode_case(i, tables, proof)
    result.update(instance_hex=s.instance_bytes(i, len(i['sum'])).hex(),
                  round_hex=[s.message(i, r, row).hex() for r, row in enumerate(proof['rounds'])],
                  final_hex=s.message(i, len(i['ids']), proof['final']).hex())
    return result


def honest(name, d, m, windows, tables, terms):
    total = s.scalar(0, d)
    for column in range(2**m):
        total = s.add(total, s.compose(terms, [t[column] for t in tables], d))
    i = dict(id=210, m=m, ids=list(range(11, 11+len(tables))), terms=terms, sum=total)
    pt, rt = s.Transcript(name.encode(), d), s.Transcript(name.encode(), d)
    proof, point, _ = w.window_prove(pt, i, tables, windows)
    assert (proof, point) == s.prove(rt, i, tables), name
    first = record(i, tables, proof)
    first['streaming'] = dict(windows=windows)
    next_i = dict(id=211, m=1, ids=[41], terms=[(s.scalar(2, d), [0])], sum=s.scalar(16, d))
    next_tables = [[s.scalar(3, d), s.scalar(5, d)]]
    follow, follow_point = s.prove(pt, next_i, next_tables)
    assert (follow, follow_point) == s.prove(rt, next_i, next_tables)
    return dict(name=name, field_degree=d, public_hex=name.encode().hex(), expected='accept',
                instances=[first, record(next_i, next_tables, follow)])


def mutation(case, suffix, error):
    bad = copy.deepcopy(case)
    bad.update(name=case['name']+suffix, expected=error)
    for r in bad['instances']:
        for key in ('instance_hex', 'round_hex', 'final_hex'):
            r.pop(key, None)
    return bad


def generate():
    cases, rng = [], random.Random(305003)
    shapes = [(0, [])] + [(3, x) for x in [[], [1], [2], [3], [1, 1], [1, 2], [2, 1], [1, 1, 1]]] + [(5, [4])]
    for d in (4, 8):
        for degree in range(5):
            for m, windows in shapes:
                tables = [[tuple(rng.randrange(s.P) for _ in range(d)) for _ in range(2**m)] for _ in range(3)]
                terms = [(tuple(rng.randrange(s.P) for _ in range(d)), [n % 2 for n in range(degree)]),
                         (s.scalar(-7, d), []), (s.scalar(0, d), [1]*degree)]
                name = f'd{d}-degree{degree}-m{m}-w'+','.join(map(str, windows))
                cases.append(honest(name, d, m, windows, tables, terms))
        for m, windows in [(0, []), (3, [1, 1])]:
            for constant in (0, 9):
                cases.append(honest(f'd{d}-m{m}-empty{constant}', d, m, windows, [],
                                    [] if constant == 0 else [(s.scalar(constant, d), [])]))
    for case in list(cases):
        d = case['field_degree']
        first = case['instances'][0]
        if first['instance']['m']:
            bad = mutation(case, '-round', 'RoundSumMismatch')
            row = bad['instances'][0]['proof']['rounds'][0]
            row[0] = s.encode(s.add(a1.decode(row[0], d), s.scalar(1, d))).hex()
            cases.append(bad)
        bad = mutation(case, '-shape', 'ProofShape')
        bad['instances'][0]['proof']['rounds'].append([s.encode(s.scalar(0, d)).hex()])
        cases.append(bad)
        if first['instance']['ids']:
            bad = mutation(case, '-unused-final', 'ClaimMismatch')
            final = bad['instances'][0]['proof']['final']
            final[-1] = s.encode(s.add(a1.decode(final[-1], d), s.scalar(1, d))).hex()
            cases.append(bad)
            if first['streaming']['windows'] == [1, 2]:
                bad = mutation(case, '-original-shape', 'PublicShape')
                bad['instances'][0]['tables'][-1].pop()
                cases.append(bad)
    assert len({case['name'] for case in cases}) == len(cases)
    return cases


def check():
    cases = [json.loads(line) for line in PATH.read_text().splitlines()]
    assert cases == generate(), 'streaming corpus drift'
    for case in cases:
        result = a1.evaluate(case)
        assert result.get('error', 'accept') == case['expected'], (case['name'], result)
    print(f'{len(cases)} shared streaming decisions checked; no process-memory or profile claim')
