"""RFC-0006 A2 shared corpus: real verifier decisions, obligations and exact records."""
import copy
import json
from pathlib import Path
import struct
import check_batching as b

sc = b.sc
PATH = Path(__file__).with_name('corpus.jsonl')


def integer(value, bits):
    b.require(type(value) is int and 0 <= value < 2**bits, 'InvalidBatch')
    return value


def field(value, d):
    b.require(isinstance(value, (list, tuple)) and len(value) == d and
              all(type(x) is int and 0 <= x < sc.P for x in value), 'NoncanonicalField')
    return tuple(value)


def decode(c):
    d, original = c['degree'], c['batch']
    b.require(type(d) is int and d in (4, 8), 'InvalidBatch')
    batch = copy.deepcopy(original)
    integer(batch['id'], 64)
    b.require(type(batch['mode']) is int and batch['mode'] in (0, 1), 'InvalidBatch')
    if batch['mode']:
        integer(batch['tensor'], 64); integer(batch['m'], 32)
        batch['claims'] = [([field(x, d) for x in z], field(v, d)) for z, v in batch['claims']]
        tables = [field(x, d) for x in c['tables']]
    else:
        for i in batch['instances']:
            integer(i['id'], 64); integer(i['m'], 32)
            for identity in i['ids']:
                integer(identity, 64)
            i['sum'] = field(i['sum'], d)
            i['terms'] = [(field(v, d), [integer(x, 32) for x in factors]) for v, factors in i['terms']]
        tables = [[[field(x, d) for x in table] for table in group] for group in c['tables']]
    b.describe(batch, d)
    proof = {key: [[field(x, d) for x in row] for row in c['proof'][key]] if key == 'rounds'
             else [field(x, d) for x in c['proof'][key]] for key in ('rounds', 'final')}
    b.public_shape(batch, tables, d)
    sizes = [1] if batch['mode'] else [len(i['ids']) for i in batch['instances']]
    b.require(len(proof['final']) == sum(sizes), 'ProofShape')
    flat, at = proof['final'], 0
    proof['final'] = []
    for size in sizes:
        proof['final'].append(flat[at:at+size]); at += size
    return batch, tables, proof


def evaluate(c):
    try:
        d = c['degree']
        batch, tables, proof = decode(c)
        t = b.Transcript(b'batch study', d)
        r = b.verify(t, batch, proof, tables)
        point = r['point']
        if batch['mode']:
            claims = [[batch['tensor'], point, proof['final'][0][0]]]
        else:
            claims = [[identity, point[len(point)-i['m']:], value]
                      for i, row in zip(batch['instances'], proof['final']) for identity, value in zip(i['ids'], row)]
        if 'continuation' in c:
            i, data = sc.instance(d, 1, 1, identity=99)
            i['ids'], data = i['ids'][:1], data[:1]
            following = c['continuation']
            following = {'rounds': [[field(x, d) for x in row] for row in following['rounds']],
                         'final': [field(x, d) for x in following['final']]}
            sc.verify_public(t, i, following, data)
        return {'point': point, 'claims': claims,
                'sc': dict(id=batch['id'], m=len(point), degree=r['degree'], field_degree=d, numerator=r['sc']),
                'rlc': dict(id=batch['id'], t=r['rlc'], field_degree=d, numerator=r['rlc'])}
    except ValueError as error:
        return {'error': str(error)}


def generate():
    cases = []
    def add(name, d, batch, tables, proof, expected='accept', continuation=None):
        case = dict(name=name, degree=d, batch=batch, tables=tables,
                    proof=proof, expected=expected)
        if continuation is not None:
            case['continuation'] = continuation
        cases.append(json.loads(json.dumps(case)))
        return cases[-1]
    def mutation(case, suffix, change, expected):
        altered = copy.deepcopy(case); altered['name'] += '-'+suffix
        altered['expected'] = expected; change(altered)
        cases.append(altered)
    vectors, _ = b.checks(all_instances=True, all_claims=True)
    for index, v in enumerate(vectors):
        p = {'rounds': v['proof']['rounds'], 'final': sum(v['proof']['final'], [])}
        c = add(f'vector-{index}', v['degree'], v['batch'], v['tables'], p, continuation=v['continuation'])
        mutation(c, 'shape', lambda x: x['proof']['final'].append(sc.scalar(0, x['degree'])), 'ProofShape')
        if p['rounds']:
            mutation(c, 'round', lambda x: x['proof']['rounds'][0].__setitem__(0,
                     sc.add(x['proof']['rounds'][0][0], sc.scalar(1, x['degree']))), 'RoundSumMismatch')
        wrong, tables, _ = decode(c)
        if wrong['mode']:
            z, value = wrong['claims'][0]; wrong['claims'][0] = (z, sc.add(value, sc.scalar(1, c['degree'])))
        else:
            wrong['instances'][0]['sum'] = sc.add(wrong['instances'][0]['sum'], sc.scalar(1, c['degree']))
        invalid, _, _ = b.prove(b.Transcript(b'batch study', c['degree']), wrong, tables)
        add(c['name']+'-false', c['degree'], wrong, tables,
            dict(rounds=invalid['rounds'], final=sum(invalid['final'], [])),
            'RoundSumMismatch' if invalid['rounds'] else 'FinalEvaluationMismatch')
    for d in (4, 8):
        # Full-extension witnesses/points, singleton and duplicate claims, zero relations.
        for mode in (0, 1):
            for m in (0, 2):
                for zero in (False, True):
                    table = [tuple((j+k+1) % sc.P for k in range(d)) for j in range(2**m)]
                    if zero:
                        table = [sc.scalar(0, d)] * 2**m
                    if mode:
                        z = [tuple(k+j+2 for k in range(d)) for j in range(m)]
                        batch = dict(mode=1, id=1, tensor=77, m=m, claims=[(z, b.folded(table, z))])
                        tables = table
                    else:
                        member = dict(id=10, m=m, ids=[77], terms=[(sc.scalar(1, d), [0])], sum=b.total(table, d))
                        batch, tables = dict(mode=0, id=1, instances=[member]), [[table]]
                    proof, _, _ = b.prove(b.Transcript(b'batch study', d), batch, tables)
                    c = add(f'd{d}-mode{mode}-m{m}-zero{int(zero)}', d, batch, tables,
                            dict(rounds=proof['rounds'], final=sum(proof['final'], [])))
                    # False statement with freshly generated proof, not just a stale transcript.
                    wrong = copy.deepcopy(batch)
                    if mode:
                        z, value = wrong['claims'][0]; wrong['claims'][0] = (z, sc.add(value, sc.scalar(1, d)))
                    else:
                        wrong['instances'][0]['sum'] = sc.add(wrong['instances'][0]['sum'], sc.scalar(1, d))
                    invalid, _, _ = b.prove(b.Transcript(b'batch study', d), wrong, tables)
                    add(c['name']+'-false', d, wrong, tables, dict(rounds=invalid['rounds'], final=sum(invalid['final'], [])),
                        'RoundSumMismatch' if m else 'FinalEvaluationMismatch')
            base = next(c for c in cases if c['degree'] == d and c['batch']['mode'] == mode and c['proof']['rounds'] and c['expected'] == 'accept')
            for suffix, value in [('width', []), ('modulus', [sc.P]+[0]*(d-1)), ('negative', [-1]+[0]*(d-1)),
                                  ('overflow', [2**32]+[0]*(d-1)), ('boolean', [True]+[0]*(d-1))]:
                mutation(base, suffix, lambda c, value=value: c['proof']['final'].__setitem__(0, value), 'NoncanonicalField')
            mutation(base, 'id-overflow', lambda c: c['batch'].update(id=2**64), 'InvalidBatch')
            mutation(base, 'round-width', lambda c: c['proof']['rounds'][0].pop(), 'ProofShape')
            mutation(base, 'round-count', lambda c: c['proof']['rounds'].pop(), 'ProofShape')
            mutation(base, 'public-shape', lambda c: c['tables'].pop(), 'PublicShape')
            mutation(base, 'empty', lambda c: c['batch'].update(**({'claims': []} if mode else {'instances': []})), 'InvalidBatch')
            batch, tables, proof = decode(base)
            omitted = b.Transcript(b'batch study', d)
            context, _, _, count = b.describe(batch, d); b.weights(omitted, context, count)
            for r, row in enumerate(proof['rounds']):
                omitted.absorb(b.tr.ROUND, struct.pack('<QI', batch['id'], r)+b''.join(map(sc.encode, row)))
                sc.challenge(omitted)
            i, data = sc.instance(d, 1, 1, identity=99); i['ids'], data = i['ids'][:1], data[:1]
            following, _ = sc.prove(omitted, i, data)
            mutation(base, 'omitted-final', lambda c: c.update(continuation=following), 'FinalEvaluationMismatch')
            if mode == 0:
                mutation(base, 'member-id', lambda c: c['batch']['instances'][1].update(id=c['batch']['instances'][0]['id']), 'InvalidBatch')
                mutation(base, 'degree', lambda c: c['batch']['instances'][0]['terms'][0][1].extend([0]*5), 'InvalidBatch')
                mutation(base, 'ordinal', lambda c: c['batch']['instances'][0]['terms'][0][1].append(99), 'InvalidBatch')
                mutation(base, 'alias-dimension', lambda c: c['batch']['instances'][1].update(m=0), 'InvalidBatch')
                mutation(base, 'alias-value', lambda c: c['tables'][1][0].__setitem__(0,
                         sc.add(c['tables'][1][0][0], sc.scalar(1, d))), 'PublicShape')
                constant = next(c for c in cases if c['degree'] == d and c['batch']['mode'] == 0 and c['expected'] == 'accept'
                                and c['batch']['instances'][0]['ids'] and not sc.degree(c['batch']['instances'][0]))
                mutation(constant, 'unused-final', lambda c: c['proof']['final'].__setitem__(0,
                         sc.add(c['proof']['final'][0], sc.scalar(1, d))), 'ClaimMismatch')
            else:
                mutation(base, 'point-shape', lambda c: c['batch']['claims'][0][0].append(sc.scalar(0, d)), 'InvalidBatch')
                mutation(base, 'final-value', lambda c: c['proof']['final'].__setitem__(0,
                         sc.add(c['proof']['final'][0], sc.scalar(1, d))), 'FinalEvaluationMismatch')
                mutation(base, 'dimension-overflow', lambda c: c['batch'].update(m=2**32), 'InvalidBatch')
                # Initial claims at zero do not see y[1]; the consumer must still check y(r).
                batch = dict(mode=1, id=1, tensor=77, m=1, claims=[([sc.scalar(0, d)], sc.scalar(3, d))]*2)
                tables = [sc.scalar(3, d), sc.scalar(5, d)]
                bad, _, _ = b.prove(b.Transcript(b'batch study', d), batch, [tables[0], sc.scalar(6, d)])
                add(f'd{d}-unclaimed-entry', d, batch, tables, dict(rounds=bad['rounds'], final=sum(bad['final'], [])), 'ClaimMismatch')
    # JSON roundtrip fixes lists as the shared representation before mutation/checking.
    return json.loads(json.dumps(cases))


def check(cases):
    b.require(cases == generate(), 'batch corpus drift')
    b.require(len({c['name'] for c in cases}) == len(cases), 'duplicate batch case')
    for c in cases:
        result = evaluate(c)
        b.require(result.get('error', 'accept') == c['expected'], f"{c['name']}: {result}")
        print(json.dumps(dict(name=c['name'], **result), separators=(',', ':')))
