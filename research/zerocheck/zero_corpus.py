"""RFC-0006 A3: shared public-verifier decisions and original-slice obligations."""
import copy
import json
from pathlib import Path
import check_zerocheck as z

sc = z.sc
PATH = Path(__file__).with_name('corpus.jsonl')


def integer(value, bits):
    z.require(type(value) is int and 0 <= value < 2**bits, 'InvalidZerocheck')
    return value


def field(value, d):
    z.require(isinstance(value, (list, tuple)) and len(value) == d and
              all(type(x) is int and 0 <= x < sc.P for x in value), 'NoncanonicalField')
    return tuple(value)


def evaluate(c):
    try:
        d, i = c['field'], copy.deepcopy(c['instance'])
        z.require(type(d) is int and d in (4, 8), 'InvalidZerocheck')
        integer(i['id'], 64); integer(i['m'], 32); integer(i['k'], 8)
        for identity in i['ids']:
            integer(identity, 64)
        i['terms'] = [(field(v, d), [integer(x, 32) for x in factors]) for v, factors in i['terms']]
        z.describe(i, d)
        tables = [[field(v, d) for v in row] for row in c['tables']]
        p = c['proof']
        proof = dict(skip=[field(v, d) for v in p['skip']],
                     rounds=[[field(v, d) for v in row] for row in p['rounds']],
                     final=[field(v, d) for v in p['final']])
        z.shape(i, tables, d)
        s = 2**i['k']
        z.require(len(proof['final']) == len(i['ids'])*s, 'ProofShape')
        proof['final'] = [proof['final'][b:b+s] for b in range(0, len(proof['final']), s)]
        t = z.Transcript(b'zerocheck', d)
        result, _ = z.verify(t, i, proof, tables)
        return dict(claims=result['claims'], sc=result['sc'], continuation=t.challenge()[0].hex())
    except ValueError as error:
        return {'error': str(error)}


def generate():
    cases = []
    def add(name, d, i, tables, proof, expected='accept'):
        case = dict(name=name, field=d, instance=i, tables=tables,
                    proof=dict(skip=proof['skip'], rounds=proof['rounds'], final=sum(proof['final'], [])), expected=expected)
        cases.append(json.loads(json.dumps(case)))
        return cases[-1]
    def mutation(case, suffix, change, expected):
        altered = copy.deepcopy(case); altered['name'] += '-'+suffix
        altered['expected'] = expected; change(altered); cases.append(altered)
    for index, v in enumerate(z.checks()['vectors']):
        d, i, tables = v['field'], v['instance'], v['tables']
        add(f'vector-{index}', d, i, tables, v['proof'])
        if sc.degree(i) and i['m'] <= 2:
            wrong = copy.deepcopy(tables)
            wrong[1][0] = sc.add(wrong[1][0], sc.scalar(1, d))
            # Fresh proof of a false row assertion, not an honest proof with a stale transcript.
            proof = z.prove(z.Transcript(b'zerocheck', d), i, wrong)
            add(f'vector-{index}-false-row', d, i, wrong, proof,
                'RoundSumMismatch' if i['m'] > i['k'] else 'FinalEvaluationMismatch')
    for d in (4, 8):
        for k in (0, 1, 2):
            base = next(c for c in cases if c['field'] == d and c['expected'] == 'accept'
                        and (c['instance']['m'], c['instance']['k'], sc.degree(c['instance'])) == (2, k, 2))
            for part in ('skip', 'rounds', 'final'):
                if base['proof'][part]:
                    mutation(base, part+'-short', lambda c, part=part: c['proof'][part].pop(), 'ProofShape')
                value = [] if part == 'rounds' else sc.scalar(0, d)
                mutation(base, part+'-long', lambda c, part=part, value=value: c['proof'][part].append(value), 'ProofShape')
            if k < 2:
                for size in (-1, 1):
                    mutation(base, f'round-width-{size}', lambda c, size=size:
                             c['proof']['rounds'][0].pop() if size < 0 else c['proof']['rounds'][0].append(sc.scalar(0, d)), 'ProofShape')
            for suffix, change in [
                ('id', lambda c: c['instance'].update(id=99)),
                ('tensor-id', lambda c: c['instance']['ids'].__setitem__(0, 99)),
                ('terms-order', lambda c: c['instance']['terms'].reverse()),
            ]:
                # Complete skip discloses all slices; these honest values remain valid at any u.
                mutation(base, suffix, change, 'RoundSumMismatch' if k < 2 else 'accept')
            mutation(base, 'coefficient', lambda c: c['instance']['terms'][0].__setitem__(0, sc.scalar(2, d)),
                     'RoundSumMismatch' if k < 2 else 'FinalEvaluationMismatch')
            mutation(base, 'dimension', lambda c: c['instance'].update(m=3), 'PublicShape')
            mutation(base, 'skip-change', lambda c: c['instance'].update(k=(k+1)%3), 'ProofShape')
            mutation(base, 'unused-slice', lambda c: c['proof']['final'].__setitem__(-1,
                     sc.add(c['proof']['final'][-1], sc.scalar(1, d))), 'ClaimMismatch')
            mutation(base, 'unused-table', lambda c: c['tables'][-1].__setitem__(0,
                     sc.add(c['tables'][-1][0], sc.scalar(1, d))), 'ClaimMismatch')
        base = next(c for c in cases if c['field'] == d and c['expected'] == 'accept'
                    and (c['instance']['m'], c['instance']['k'], sc.degree(c['instance'])) == (2, 1, 2))
        for suffix, value in [('width', []), ('modulus', [sc.P]+[0]*(d-1)), ('negative', [-1]+[0]*(d-1)),
                              ('overflow', [2**32]+[0]*(d-1)), ('boolean', [True]+[0]*(d-1))]:
            mutation(base, suffix, lambda c, value=value: c['proof']['final'].__setitem__(0, value), 'NoncanonicalField')
        for suffix, change in [
            ('id-overflow', lambda c: c['instance'].update(id=2**64)),
            ('dimension-overflow', lambda c: c['instance'].update(m=2**32)),
            ('skip-overflow', lambda c: c['instance'].update(k=256)),
            ('skip-limit', lambda c: c['instance'].update(k=5)),
            ('skip-dimension', lambda c: c['instance'].update(k=3)),
            ('duplicate-id', lambda c: c['instance']['ids'].__setitem__(1, c['instance']['ids'][0])),
            ('degree', lambda c: c['instance']['terms'][0][1].extend([0]*5)),
            ('ordinal', lambda c: c['instance']['terms'][0][1].append(99)),
            ('constant-skip', lambda c: c['instance'].update(terms=[])),
        ]:
            mutation(base, suffix, change, 'InvalidZerocheck')
        mutation(base, 'field-id', lambda c: c.update(field=1), 'InvalidZerocheck')
        mutation(base, 'coefficient-encoding', lambda c: c['instance']['terms'][0].__setitem__(0, [sc.P]+[0]*(d-1)), 'NoncanonicalField')
        mutation(base, 'table-encoding', lambda c: c['tables'][0].__setitem__(0, [sc.P]+[0]*(d-1)), 'NoncanonicalField')
        mutation(base, 'public-count', lambda c: c['tables'].pop(), 'PublicShape')
        mutation(base, 'public-width', lambda c: c['tables'][0].pop(), 'PublicShape')
        for m in (0, 2):
            i = dict(id=8, m=m, k=0, ids=[], terms=[])
            add(f'd{d}-empty-m{m}', d, i, [], z.prove(z.Transcript(b'zerocheck', d), i, []))
            i['terms'] = [(sc.scalar(1, d), [])]
            add(f'd{d}-constant-false-m{m}', d, i, [], z.prove(z.Transcript(b'zerocheck', d), i, []),
                'RoundSumMismatch' if m else 'FinalEvaluationMismatch')
        i, tables = z.instance(d, 2, 0, 2)
        tables[1][0] = sc.add(tables[1][0], sc.scalar(1, d))
        tables[1][1] = sc.add(tables[1][1], sc.scalar(-1, d))
        add(f'd{d}-zero-sum-false-rows', d, i, tables, z.prove(z.Transcript(b'zerocheck', d), i, tables), 'RoundSumMismatch')
    return json.loads(json.dumps(cases))


def check(cases):
    z.require(cases == generate(), 'zerocheck corpus drift')
    z.require(len({c['name'] for c in cases}) == len(cases), 'duplicate zerocheck case')
    for c in cases:
        result = evaluate(c)
        z.require(result.get('error', 'accept') == c['expected'], f"{c['name']}: {result}")
        print(json.dumps(dict(name=c['name'], **result), separators=(',', ':')))
