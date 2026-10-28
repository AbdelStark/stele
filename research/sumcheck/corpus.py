"""RFC-0006 A1 shared verifier corpus; no protocol coverage until Rust agrees."""
import copy
import json
from pathlib import Path
import struct
import check_sumcheck as sc

PATH = Path(__file__).with_name('corpus.jsonl')


def encode_case(i, tables, proof):
    return {'instance': {**i, 'sum': sc.encode(i['sum']).hex(),
            'terms': [{'coefficient': sc.encode(c).hex(), 'factors': f} for c, f in i['terms']]},
            'tables': [[sc.encode(x).hex() for x in row] for row in tables],
            'proof': {'rounds': [[sc.encode(x).hex() for x in row] for row in proof['rounds']],
                      'final': [sc.encode(x).hex() for x in proof['final']]}}


def decode(value, d):
    raw = bytes.fromhex(value)
    if len(raw) != 4*d:
        raise ValueError('NoncanonicalField')
    limbs = struct.unpack('<' + 'I'*d, raw)
    if any(x >= sc.P for x in limbs):
        raise ValueError('NoncanonicalField')
    return limbs


def evaluate(case):
    """Replay one complete chain; report only the first exact rejection."""
    d = case['field_degree']
    if d not in (4, 8):
        return {'error': 'InvalidInstance'}
    try:
        transcript = sc.Transcript(bytes.fromhex(case['public_hex']), d)
        receipts = []
        for record in case['instances']:
            original = record['instance']
            i = {**original, 'sum': decode(original['sum'], d),
                 'terms': [(decode(t['coefficient'], d), t['factors']) for t in original['terms']]}
            proof = {'rounds': [[decode(x, d) for x in row] for row in record['proof']['rounds']],
                     'final': [decode(x, d) for x in record['proof']['final']]}
            tables = [[decode(x, d) for x in row] for row in record['tables']]
            receipt = sc.verify_public(transcript, i, proof, tables)
            receipts.append({'point': [sc.encode(x).hex() for x in receipt['point']],
                'claims': [[identity, sc.encode(value).hex()] for identity, value in receipt['claims']],
                'sc': receipt['sc']})
            if 'streaming' in record and case['expected'] == 'accept':
                visits = len(record['streaming']['windows']) + 1
                files = len(i['ids'])
                reads = visits * files * 2**i['m']
                receipts[-1]['source'] = dict(reads=reads, read_bytes=reads*4*d,
                                              seeks=visits*files, eof_checks=visits*files)
        return {'receipts': receipts}
    except ValueError as error:
        return {'error': str(error)}


def generate():
    cases = []
    def add(name, d, records, expected='accept', public=b'public'):
        cases.append({'name': name, 'field_degree': d, 'public_hex': public.hex(),
                      'instances': records, 'expected': expected})
    for d in (4, 8):
        for m in range(4):
            for degree in range(5):
                i, tables = sc.instance(d, m, degree)
                proof, _ = sc.prove(sc.Transcript(b'public', d), i, tables)
                record = encode_case(i, tables, proof)
                name = f'd{d}-m{m}-degree{degree}'
                add(name, d, [record])
                bad = copy.deepcopy(record)
                bad['instance']['sum'] = sc.encode(sc.add(i['sum'], sc.scalar(1, d))).hex()
                add(name+'-sum', d, [bad], 'RoundSumMismatch' if m else 'FinalEvaluationMismatch')
                bad = copy.deepcopy(record); bad['proof']['final'].pop()
                add(name+'-shape', d, [bad], 'ProofShape')
                if m:
                    bad = copy.deepcopy(record)
                    bad['proof']['rounds'][0][0] = sc.encode(sc.add(proof['rounds'][0][0], sc.scalar(1, d))).hex()
                    add(name+'-round', d, [bad], 'RoundSumMismatch')
                if degree == 0:
                    bad = copy.deepcopy(record)
                    bad['proof']['final'][0] = sc.encode(sc.add(proof['final'][0], sc.scalar(1, d))).hex()
                    add(name+'-claim', d, [bad], 'ClaimMismatch')
        for name, terms in [
            ('mixed', [(tuple(range(1, d+1)), [0, 1, 0, 1]), (sc.scalar(-3, d), [1, 0]), (sc.scalar(5, d), [])]),
            ('zero-leading', [(sc.scalar(0, d), [0, 1, 0, 1]), (sc.scalar(1, d), [0])]),
        ]:
            i, tables = sc.instance(d, 2, 4)
            i['terms'], i['sum'] = terms, sc.scalar(0, d)
            for row in zip(*tables):
                i['sum'] = sc.add(i['sum'], sc.compose(terms, row, d))
            proof, _ = sc.prove(sc.Transcript(b'public', d), i, tables)
            add(f'd{d}-{name}', d, [encode_case(i, tables, proof)])
        for m in (0, 3):
            for constant in (0, 9):
                i = {'id': 1, 'm': m, 'ids': [], 'terms': [] if constant == 0 else [(sc.scalar(constant, d), [])],
                     'sum': sc.scalar(constant * 2**m, d)}
                proof, _ = sc.prove(sc.Transcript(b'public', d), i, [])
                add(f'd{d}-m{m}-empty{constant}', d, [encode_case(i, [], proof)])
        i, tables = sc.instance(d, 1, 1)
        proof, _ = sc.prove(sc.Transcript(b'public', d), i, tables)
        original = encode_case(i, tables, proof)
        early = sc.Transcript(b'public', d)
        early.absorb(sc.INSTANCE, sc.instance_bytes(i, d))
        _, stale_point = sc.prove(sc.Transcript(b'public', d), {**i, 'id': i['id']+1}, tables)
        for name, point in [('early', sc.challenge(early)), ('stale', stale_point[0])]:
            bad = copy.deepcopy(original)
            replacement = sc.fold(tables[0], point)[0]
            assert replacement != proof['final'][0]
            bad['proof']['final'][0] = sc.encode(replacement).hex()
            add(f'd{d}-{name}', d, [bad], 'FinalEvaluationMismatch')
        second = {**i, 'id': 99, 'ids': [11], 'terms': [(sc.scalar(1, d), [0])], 'sum': sc.add(*tables[0])}
        honest = sc.Transcript(b'public', d)
        first, _ = sc.prove(honest, i, tables)
        next_proof, _ = sc.prove(honest, second, tables[:1])
        omitted = sc.Transcript(b'public', d)
        omitted.absorb(sc.INSTANCE, sc.instance_bytes(i, d))
        omitted.absorb(sc.ROUND, sc.message(i, 0, first['rounds'][0]))
        sc.challenge(omitted)
        next_bad, _ = sc.prove(omitted, second, tables[:1])
        assert next_bad['rounds'] == next_proof['rounds'] and next_bad['final'] != next_proof['final']
        add(f'd{d}-omitted-final', d, [encode_case(i, tables, first), encode_case(second, tables[:1], next_bad)], 'FinalEvaluationMismatch')
        for name, mutation, error in [
            ('degree', lambda r: r['instance']['terms'][0].update(factors=[0]*5), 'InvalidInstance'),
            ('ordinal', lambda r: r['instance']['terms'][0].update(factors=[2]), 'InvalidInstance'),
            ('ids', lambda r: r['instance'].update(ids=[11, 11]), 'InvalidInstance'),
            ('public-shape', lambda r: r['tables'].pop(), 'PublicShape'),
            ('public-length', lambda r: r['tables'][0].pop(), 'PublicShape'),
            ('round-count', lambda r: r['proof']['rounds'].pop(), 'ProofShape'),
            ('round-length', lambda r: r['proof']['rounds'][0].pop(), 'ProofShape'),
            ('field-width', lambda r: r['proof']['final'].__setitem__(0, ''), 'NoncanonicalField'),
            ('field', lambda r: r['proof']['final'].__setitem__(0, struct.pack('<I', sc.P).hex()+'00'*(4*d-4)), 'NoncanonicalField'),
        ]:
            bad = copy.deepcopy(original); mutation(bad)
            add(f'd{d}-{name}', d, [bad], error)
    for chain in sc.vectors():
        add(f'd{chain["field_degree"]}-chain', chain['field_degree'], chain['instances'],
            public=bytes.fromhex(chain['public_hex']))
    return cases


def check():
    cases = [json.loads(line) for line in PATH.read_text().splitlines()]
    assert cases == generate(), 'committed corpus drift'
    assert len({case['name'] for case in cases}) == len(cases), 'duplicate case'
    for case in cases:
        actual = evaluate(case)
        assert actual.get('error', 'accept') == case['expected'], (case['name'], actual)
    print(f'{len(cases)} shared sumcheck cases checked by Python; Rust agreement enforced by sumcheck gate')
