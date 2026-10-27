# /// script
# requires-python = ">=3.12"
# dependencies = ["blake3==1.0.11"]
# ///
"""Research-only RFC-0006 A1 oracle; no core code or NC catalog credit."""
import copy
import json
from pathlib import Path
import struct
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'transcript'))
from check_transcript import Transcript, INSTANCE, ROUND, FINAL, rejects

P = 2**31 - 1


def scalar(x, d):
    return (x % P,) + (0,) * (d - 1)


def add(a, b):
    return tuple((x + y) % P for x, y in zip(a, b))


def neg(a):
    return tuple(-x % P for x in a)


def mul(a, b):
    d = len(a)
    if d == 1:
        return (a[0] * b[0] % P,)
    h = d // 2
    ac, bd = mul(a[:h], b[:h]), mul(a[h:], b[h:])
    nr = {2: (P-1,), 4: (2, 1), 8: (0, 0, 1, 0)}[d]
    return add(ac, mul(nr, bd)) + add(mul(a[:h], b[h:]), mul(a[h:], b[:h]))


def encode(value):
    return struct.pack('<' + 'I' * len(value), *value)


def challenge(t):
    raw, _ = t.challenge()
    return struct.unpack('<' + 'I' * t.degree, raw)


def compose(terms, values, d):
    result = scalar(0, d)
    for coefficient, factors in terms:
        term = coefficient
        for i in factors:
            term = mul(term, values[i])
        result = add(result, term)
    return result


def degree(instance):
    return max((len(factors) for _, factors in instance['terms']), default=0)


def validate(instance, d):
    ids, terms = instance['ids'], instance['terms']
    if d not in (4, 8) or not 0 <= instance['id'] < 2**64 or not 0 <= instance['m'] < 2**32:
        raise ValueError('InvalidInstance')
    if len(ids) >= 2**32 or len(terms) >= 2**32 or len(set(ids)) != len(ids):
        raise ValueError('InvalidInstance')
    if any(not 0 <= i < 2**64 for i in ids) or degree(instance) > 4:
        raise ValueError('InvalidInstance')
    for value in [instance['sum']] + [c for c, _ in terms]:
        if len(value) != d or any(not 0 <= limb < P for limb in value):
            raise ValueError('InvalidInstance')
    if any(not 0 <= i < len(ids) for _, factors in terms for i in factors):
        raise ValueError('InvalidInstance')


def instance_bytes(i, d):
    validate(i, d)
    out = struct.pack('<BBQIBII', 1, d, i['id'], i['m'], degree(i), len(i['ids']), len(i['terms']))
    out += b''.join(struct.pack('<Q', identity) for identity in i['ids'])
    for coefficient, factors in i['terms']:
        out += encode(coefficient) + bytes([len(factors)])
        out += b''.join(struct.pack('<I', index) for index in factors)
    return out + encode(i['sum'])


def message(i, index, values):
    return struct.pack('<QI', i['id'], index) + b''.join(map(encode, values))


def interpolate(values, point):
    d = len(point)
    total = scalar(0, d)
    for i, value in enumerate(values):
        basis, denominator = scalar(1, d), 1
        for j in range(len(values)):
            if i != j:
                basis = mul(basis, add(point, scalar(-j, d)))
                denominator *= i - j
        total = add(total, mul(value, mul(basis, scalar(pow(denominator, -1, P), d))))
    return total


def fold(table, point):
    half = len(table) // 2
    return [add(a, mul(point, add(b, neg(a)))) for a, b in zip(table[:half], table[half:])]


def prove(t, i, tables):
    validate(i, t.degree)
    assert len(tables) == len(i['ids']) and all(len(v) == 2**i['m'] for v in tables)
    state = copy.deepcopy(tables)
    t.absorb(INSTANCE, instance_bytes(i, t.degree))
    rounds, point = [], []
    for r in range(i['m']):
        values = []
        for x in range(degree(i) + 1):
            folded = [fold(table, scalar(x, t.degree)) for table in state]
            total = scalar(0, t.degree)
            for column in range(2**(i['m'] - r - 1)):
                total = add(total, compose(i['terms'], [table[column] for table in folded], t.degree))
            values.append(total)
        rounds.append(values)
        t.absorb(ROUND, message(i, r, values))
        point.append(challenge(t))
        state = [fold(table, point[-1]) for table in state]
    final = [table[0] for table in state]
    t.absorb(FINAL, message(i, len(i['ids']), final))
    return {'rounds': rounds, 'final': final}, point


def verify_reduction(t, i, proof):
    validate(i, t.degree)
    if len(proof['rounds']) != i['m'] or len(proof['final']) != len(i['ids']):
        raise ValueError('ProofShape')
    if any(len(row) != degree(i) + 1 for row in proof['rounds']):
        raise ValueError('ProofShape')
    for value in sum(proof['rounds'], []) + proof['final']:
        if len(value) != t.degree or any(not 0 <= limb < P for limb in value):
            raise ValueError('NoncanonicalField')
    t.absorb(INSTANCE, instance_bytes(i, t.degree))
    running, point = i['sum'], []
    for r, row in enumerate(proof['rounds']):
        at_one = row[1] if degree(i) else row[0]
        if add(row[0], at_one) != running:
            raise ValueError('RoundSumMismatch')
        t.absorb(ROUND, message(i, r, row))
        point.append(challenge(t))
        running = interpolate(row, point[-1])
    if compose(i['terms'], proof['final'], t.degree) != running:
        raise ValueError('FinalEvaluationMismatch')
    t.absorb(FINAL, message(i, len(i['ids']), proof['final']))
    return {'point': point, 'claims': list(zip(i['ids'], proof['final'])),
            'sc': {'id': i['id'], 'm': i['m'], 'degree': degree(i), 'field_degree': t.degree, 'numerator': i['m'] * degree(i)}}


def verify_public(t, i, proof, public):
    receipt = verify_reduction(t, i, proof)
    if len(public) != len(i['ids']) or any(len(v) != 2**i['m'] for v in public):
        raise ValueError('PublicShape')
    if any(len(value) != t.degree or any(not 0 <= limb < P for limb in value) for table in public for value in table):
        raise ValueError('PublicShape')
    # Independent full hypercube evaluation, not the prover's folding loop.
    for table, (_, expected) in zip(public, receipt['claims']):
        total = scalar(0, t.degree)
        for index, value in enumerate(table):
            weight = scalar(1, t.degree)
            for j, coordinate in enumerate(receipt['point']):
                weight = mul(weight, coordinate if index >> (i['m'] - j - 1) & 1 else add(scalar(1, t.degree), neg(coordinate)))
            total = add(total, mul(weight, value))
        if total != expected:
            raise ValueError('ClaimMismatch')
    return receipt


def instance(d, m, delta, identity=7):
    tables = [[scalar(2*j + offset, d) for j in range(2**m)] for offset in (3, 5)]
    terms = [(scalar(2, d), [0] * delta), (scalar(-3, d), [])]
    if delta > 1:
        terms.append((scalar(1, d), [1] * (delta-1)))
    total = scalar(0, d)
    for row in zip(*tables):
        total = add(total, compose(terms, row, d))
    return {'id': identity, 'm': m, 'ids': [11, 12], 'terms': terms, 'sum': total}, tables


def checks():
    for d in (4, 8):
        for index, square in [(1, scalar(-1, d)), (2, (2, 1) + (0,) * (d-2))] + ([(4, (0, 0, 1, 0, 0, 0, 0, 0))] if d == 8 else []):
            unit = tuple(int(j == index) for j in range(d))
            assert mul(unit, unit) == square
        for m in range(4):
            for delta in range(5):
                i, tables = instance(d, m, delta)
                proof, point = prove(Transcript(b'public', d), i, tables)
                receipt = verify_public(Transcript(b'public', d), i, proof, tables)
                assert receipt['point'] == point and receipt['sc']['numerator'] == m * delta
                wrong_sum = {**i, 'sum': add(i['sum'], scalar(1, d))}
                rejects(lambda: verify_public(Transcript(b'public', d), wrong_sum, proof, tables),
                        'RoundSumMismatch' if m else 'FinalEvaluationMismatch')
                for row in proof['rounds']:
                    for x, value in enumerate(row):
                        assert interpolate(row, scalar(x, d)) == value
        for m in (0, 3):
            for terms, constant in [([], 0), ([(scalar(9, d), [])], 9)]:
                empty = {'id': 1, 'm': m, 'ids': [], 'terms': terms, 'sum': scalar(constant * 2**m, d)}
                proof, point = prove(Transcript(b'public', d), empty, [])
                assert verify_public(Transcript(b'public', d), empty, proof, [])['point'] == point
        i, tables = instance(d, 1, 1)
        proof, _ = prove(Transcript(b'public', d), i, tables)
        bad = copy.deepcopy(proof)
        bad['rounds'][0][0] = add(bad['rounds'][0][0], scalar(1, d))
        rejects(lambda: verify_public(Transcript(b'public', d), i, bad, tables), 'RoundSumMismatch')
        early = Transcript(b'public', d)
        early.absorb(INSTANCE, instance_bytes(i, d))
        stale_i = {**i, 'id': i['id'] + 1}
        _, stale_point = prove(Transcript(b'public', d), stale_i, tables)
        for wrong in [challenge(early), stale_point[0]]:
            bad = copy.deepcopy(proof)
            bad['final'][0] = fold(tables[0], wrong)[0]
            assert bad['final'][0] != proof['final'][0]
            rejects(lambda: verify_public(Transcript(b'public', d), i, bad, tables), 'FinalEvaluationMismatch')
        # One omitted final message changes only the next one-round proof's first final value.
        second = {**i, 'id': 99, 'ids': [11], 'terms': [(scalar(1, d), [0])], 'sum': add(*tables[0])}
        honest = Transcript(b'public', d)
        first, _ = prove(honest, i, tables)
        next_proof, _ = prove(honest, second, tables[:1])
        omitted = Transcript(b'public', d)
        omitted.absorb(INSTANCE, instance_bytes(i, d))
        omitted.absorb(ROUND, message(i, 0, first['rounds'][0]))
        challenge(omitted)
        next_bad, _ = prove(omitted, second, tables[:1])
        assert next_bad['rounds'] == next_proof['rounds'] and next_bad['final'] != next_proof['final']
        verifier = Transcript(b'public', d)
        verify_public(verifier, i, first, tables)
        rejects(lambda: verify_public(verifier, second, next_bad, tables[:1]), 'FinalEvaluationMismatch')
        honest_verifier = Transcript(b'public', d)
        verify_public(honest_verifier, i, first, tables)
        verify_public(honest_verifier, second, next_proof, tables[:1])
        rejects(lambda: verify_public(Transcript(b'public', d), i, proof, tables[:1]), 'PublicShape')
        invalid_public = copy.deepcopy(tables); invalid_public[0][0] = (P,) + (0,) * (d-1)
        rejects(lambda: verify_public(Transcript(b'public', d), i, proof, invalid_public), 'PublicShape')
        constant, tables = instance(d, 0, 0)
        bad, _ = prove(Transcript(b'public', d), constant, tables)
        bad['final'][0] = add(bad['final'][0], scalar(1, d))
        assert verify_reduction(Transcript(b'public', d), constant, bad)['claims'][0][1] == bad['final'][0]
        rejects(lambda: verify_public(Transcript(b'public', d), constant, bad, tables), 'ClaimMismatch')
        bad = copy.deepcopy(proof); bad['rounds'].pop()
        rejects(lambda: verify_reduction(Transcript(b'public', d), i, bad), 'ProofShape')
        invalid = {**i, 'terms': [(scalar(1, d), [0] * 5)]}
        rejects(lambda: instance_bytes(invalid, d), 'InvalidInstance')
        bad = copy.deepcopy(proof); bad['final'][0] = (P,) + (0,) * (d-1)
        rejects(lambda: verify_reduction(Transcript(b'public', d), i, bad), 'NoncanonicalField')
        invalid = {**i, 'terms': [(scalar(1, d), [2])]}
        rejects(lambda: instance_bytes(invalid, d), 'InvalidInstance')
        invalid = {**i, 'ids': [11, 11]}
        rejects(lambda: instance_bytes(invalid, d), 'InvalidInstance')
    print('48 honest cases and 40 false sums; wrong round, stale/early challenge, omitted final, unconsumed claim, shape and degree checks passed')


def vectors():
    result = []
    for d in (4, 8):
        t = Transcript(b'synthetic public sumcheck chain', d)
        records = []
        for identity, m, delta in [(7, 2, 4), (8, 1, 1)]:
            i, tables = instance(d, m, delta, identity)
            if identity == 7:
                i['terms'][0] = (tuple(range(1, d+1)), i['terms'][0][1])
                tables[0][1] = tuple(range(d))
                i['sum'] = scalar(0, d)
                for row in zip(*tables):
                    i['sum'] = add(i['sum'], compose(i['terms'], row, d))
            proof, point = prove(t, i, tables)
            records.append({'instance': {'id': i['id'], 'm': m, 'ids': i['ids'],
                'terms': [{'coefficient': encode(c).hex(), 'factors': f} for c, f in i['terms']],
                'sum': encode(i['sum']).hex()},
                'tables': [[encode(x).hex() for x in table] for table in tables],
                'instance_hex': instance_bytes(i, d).hex(),
                'round_hex': [message(i, r, row).hex() for r, row in enumerate(proof['rounds'])],
                'final_hex': message(i, len(i['ids']), proof['final']).hex(),
                'proof': {'rounds': [[encode(x).hex() for x in row] for row in proof['rounds']],
                          'final': [encode(x).hex() for x in proof['final']]},
                'point': [encode(x).hex() for x in point],
                'sc': {'id': identity, 'm': m, 'degree': delta, 'field_degree': d, 'numerator': m*delta}})
        verifier = Transcript(b'synthetic public sumcheck chain', d)
        for record in records:
            decode = lambda value: struct.unpack('<' + 'I'*d, bytes.fromhex(value))
            original = record['instance']
            instance_record = {**original, 'sum': decode(original['sum']),
                'terms': [(decode(term['coefficient']), term['factors']) for term in original['terms']]}
            proof_record = {'rounds': [[decode(x) for x in row] for row in record['proof']['rounds']],
                            'final': [decode(x) for x in record['proof']['final']]}
            receipt = verify_public(verifier, instance_record, proof_record, [[decode(x) for x in row] for row in record['tables']])
            assert [encode(x).hex() for x in receipt['point']] == record['point'] and receipt['sc'] == record['sc']
        result.append({'field_degree': d, 'public_hex': b'synthetic public sumcheck chain'.hex(), 'instances': records})
    return result


if __name__ == '__main__':
    checks()
    path = Path(__file__).with_name('candidate-vectors.jsonl')
    data = vectors()
    if sys.argv[1:] == ['--write-candidate']:
        with path.open('x') as file:
            file.write(''.join(json.dumps(record, sort_keys=True) + '\n' for record in data))
    else:
        assert not sys.argv[1:], 'unknown arguments'
        assert [json.loads(line) for line in path.read_text().splitlines()] == data
    print('both-field two-instance byte vectors matched; no protocol coverage credited')
