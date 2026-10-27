# /// script
# requires-python = ">=3.12"
# dependencies = ["blake3==1.0.11"]
# ///
"""RFC-0006 A2 candidate, exhaustive residual sums; no production NC credit."""
import copy
import itertools
import json
from pathlib import Path
import random
import struct
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'sumcheck'))
import check_sumcheck as sc
import check_transcript as tr
from blake3 import blake3

BATCH = b'stele/v0.1/sumcheck/batch'
BFINAL = b'stele/v0.1/sumcheck/batch-final'
GAMMA = b'stele/v0.1/sumcheck/batch-coefficient'
LABELS = tr.LABELS + (BATCH, BFINAL, GAMMA)


def require(ok, error):
    if not ok:
        raise ValueError(error)


class Transcript(tr.Transcript):
    def __init__(self, public, degree):
        super().__init__(public, degree)
        tr.registry(LABELS)

    def frame(self, tag, label, payload):
        require(label in LABELS, 'InvalidFrame')
        return self.state + bytes([tag]) + struct.pack('<I', len(label)) + label + struct.pack('<Q', len(payload)) + payload

    def absorb(self, label, payload):
        require(label in (tr.INSTANCE, tr.ROUND, tr.FINAL, BATCH, BFINAL), 'InvalidAbsorbLabel')
        self.state = blake3(self.frame(0, label, payload)).digest()

    def challenge(self, label=tr.CHALLENGE):
        require(label in (tr.CHALLENGE, GAMMA), 'InvalidChallengeLabel')
        raw = blake3(self.frame(1, label, bytes([self.degree]))).digest(length=256)
        value, consumed = tr.sample(raw, self.degree)
        self.state = blake3(self.frame(2, label, bytes([self.degree]) + struct.pack('<I', consumed) + value)).digest()
        return value, consumed


def total(values, d):
    out = sc.scalar(0, d)
    for value in values:
        out = sc.add(out, value)
    return out


def product(values, d):
    out = sc.scalar(1, d)
    for value in values:
        out = sc.mul(out, value)
    return out


def eq(a, b, d):
    one = sc.scalar(1, d)
    return product((sc.add(sc.mul(x, y), sc.mul(sc.add(one, sc.neg(x)), sc.add(one, sc.neg(y)))) for x, y in zip(a, b)), d)


def boolean(m, d):
    return itertools.product((sc.scalar(0, d), sc.scalar(1, d)), repeat=m)


def folded(table, point):
    for r in point:
        table = sc.fold(table, r)
    return table[0]


def evaluated(table, point, d):
    return total((sc.mul(value, eq(vertex, point, d)) for value, vertex in zip(table, boolean(len(point), d))), d)


def field(value, d):
    return len(value) == d and all(0 <= limb < sc.P for limb in value)


def describe(b, d):
    require(0 <= b['id'] < 2**64 and b['mode'] in (0, 1), 'InvalidBatch')
    out = struct.pack('<BBBQ', 1, d, b['mode'], b['id'])
    if b['mode'] == 0:
        members = b['instances']
        require(0 < len(members) < 2**32, 'InvalidBatch')
        identities = [i['id'] for i in members]
        require(len(set(identities + [b['id']])) == len(identities) + 1, 'InvalidBatch')
        shapes = {}
        for i in members:
            try:
                sc.validate(i, d)
            except ValueError as error:
                raise ValueError('InvalidBatch') from error
            for identity in i['ids']:
                require(shapes.setdefault(identity, i['m']) == i['m'], 'InvalidBatch')
        m = max(i['m'] for i in members)
        degree = max(max(map(sc.degree, members)), int(any(i['m'] != m for i in members)))
        out += struct.pack('<IIB', len(members), m, degree)
        for i in members:
            payload = sc.instance_bytes(i, d)
            out += struct.pack('<Q', len(payload)) + payload
        return out, m, degree, len(members)
    m, claims = b['m'], b['claims']
    require(0 <= m < 2**32 and 0 <= b['tensor'] < 2**64 and 0 < len(claims) < 2**32, 'InvalidBatch')
    out += struct.pack('<QII', b['tensor'], m, len(claims))
    for point, value in claims:
        require(len(point) == m and all(field(x, d) for x in [*point, value]), 'InvalidBatch')
        out += b''.join(map(sc.encode, point)) + sc.encode(value)
    return out, m, 2, len(claims)


def public_shape(b, tables, d):
    groups = [(b['m'], [b['tensor']], [tables])] if b['mode'] else [(i['m'], i['ids'], group) for i, group in zip(b['instances'], tables)]
    require(b['mode'] == 1 or len(tables) == len(b['instances']), 'PublicShape')
    aliases = {}
    for m, ids, group in groups:
        require(len(group) == len(ids), 'PublicShape')
        for identity, table in zip(ids, group):
            require(len(table) == 2**m and all(field(v, d) for v in table), 'PublicShape')
            require(aliases.setdefault(identity, table) == table, 'PublicShape')


def weights(t, context, count):
    t.absorb(BATCH, context)
    raw, _ = t.challenge(GAMMA)
    gamma = struct.unpack('<' + 'I' * t.degree, raw)
    powers = [sc.scalar(1, t.degree)]
    for _ in range(1, count):
        powers.append(sc.mul(powers[-1], gamma))
    return gamma, powers


def coefficient(b, powers, point, d):
    return total((sc.mul(w, eq(z, point, d)) for w, (z, _) in zip(powers, b['claims'])), d)


def sparse_coefficient(b, powers, d):
    m = b['m']
    out = [sc.scalar(0, d)] * 2**m
    for w, (point, _) in zip(powers, b['claims']):
        prefix, start = 0, 0
        for x in point:
            if x not in (sc.scalar(0, d), sc.scalar(1, d)):
                break
            start = 2 * start + int(x == sc.scalar(1, d))
            prefix += 1
        width = 2**(m - prefix)
        for j, vertex in enumerate(boolean(m - prefix, d)):
            index = start * width + j
            out[index] = sc.add(out[index], sc.mul(w, eq(point[prefix:], vertex, d)))
    return out


def selector(point, padding, d):
    return product((sc.add(sc.scalar(1, d), sc.neg(x)) for x in point[:padding]), d)


def final_bytes(b, final):
    out = struct.pack('<QB', b['id'], b['mode'])
    if b['mode'] == 1:
        return out + struct.pack('<Q', b['tensor']) + sc.encode(final[0][0])
    out += struct.pack('<I', len(b['instances']))
    for i, values in zip(b['instances'], final):
        out += struct.pack('<QI', i['id'], len(i['ids'])) + b''.join(map(sc.encode, values))
    return out


def relation(b, powers, point, final, m, d):
    if b['mode'] == 1:
        return sc.mul(final[0][0], coefficient(b, powers, point, d))
    return total((sc.mul(w, sc.mul(selector(point, m - i['m'], d), sc.compose(i['terms'], values, d)))
                  for i, w, values in zip(b['instances'], powers, final)), d)


def prove(t, b, tables):
    context, m, degree, count = describe(b, t.degree)
    public_shape(b, tables, t.degree)
    gamma, powers = weights(t, context, count)
    if b['mode'] == 1:
        a = sparse_coefficient(b, powers, t.degree)
    def final_at(point):
        if b['mode'] == 1:
            return [[folded(tables, point)]]
        return [[folded(table, point[m - i['m']:]) for table in group] for i, group in zip(b['instances'], tables)]
    def target(point):
        if b['mode'] == 1:
            return sc.mul(folded(tables, point), folded(a, point))
        return relation(b, powers, point, final_at(point), m, t.degree)
    point, rounds = [], []
    for r in range(m):
        row = [total((target([*point, sc.scalar(x, t.degree), *tail]) for tail in boolean(m-r-1, t.degree)), t.degree)
               for x in range(degree+1)]
        rounds.append(row)
        t.absorb(tr.ROUND, struct.pack('<QI', b['id'], r) + b''.join(map(sc.encode, row)))
        point.append(sc.challenge(t))
    final = final_at(point)
    t.absorb(BFINAL, final_bytes(b, final))
    return {'rounds': rounds, 'final': final}, point, gamma


def verify(t, b, proof, tables):
    context, m, degree, count = describe(b, t.degree)
    public_shape(b, tables, t.degree)
    expected = [1] if b['mode'] == 1 else [len(i['ids']) for i in b['instances']]
    require(len(proof['rounds']) == m and all(len(row) == degree+1 for row in proof['rounds']), 'ProofShape')
    require([len(v) for v in proof['final']] == expected, 'ProofShape')
    require(all(field(v, t.degree) for v in sum(proof['rounds'], []) + sum(proof['final'], [])), 'NoncanonicalField')
    gamma, powers = weights(t, context, count)
    values = [v for _, v in b['claims']] if b['mode'] == 1 else [i['sum'] for i in b['instances']]
    running = total((sc.mul(w, v) for w, v in zip(powers, values)), t.degree)
    point = []
    for r, row in enumerate(proof['rounds']):
        require(sc.add(row[0], row[1 if degree else 0]) == running, 'RoundSumMismatch')
        t.absorb(tr.ROUND, struct.pack('<QI', b['id'], r) + b''.join(map(sc.encode, row)))
        point.append(sc.challenge(t))
        running = sc.interpolate(row, point[-1])
    require(relation(b, powers, point, proof['final'], m, t.degree) == running, 'FinalEvaluationMismatch')
    t.absorb(BFINAL, final_bytes(b, proof['final']))
    if b['mode'] == 1:
        actual = [[evaluated(tables, point, t.degree)]]
    else:
        actual = [[evaluated(table, point[m - i['m']:], t.degree) for table in group] for i, group in zip(b['instances'], tables)]
    require(actual == proof['final'], 'ClaimMismatch')
    return {'point': point, 'gamma': gamma, 'rlc': count, 'sc': m * degree, 'degree': degree}


def checks(all_instances=False, all_claims=False):
    vectors, honest = [], 0
    for d in (4, 8):
        for delta, dimensions in itertools.product(range(5), ((0,), (1, 1), (0, 2), (3, 1, 0))):
            pairs = [sc.instance(d, m, (delta+j) % 5 if all_instances and delta < 4 and len(dimensions) == 3 else delta, identity=10+j) for j, m in enumerate(dimensions)]
            for j, (i, _) in enumerate(pairs):
                i['ids'] = [100 + 2*j, 101 + 2*j]
            b = {'mode': 0, 'id': 1, 'instances': [i for i, _ in pairs]}
            tables = [v for _, v in pairs]
            if delta == 0 and dimensions == (1, 1):
                b['instances'][1]['ids'] = b['instances'][0]['ids'][:]
                malformed = copy.deepcopy(tables)
                malformed[1][0][0] = sc.add(malformed[1][0][0], sc.scalar(1, d))
                sc.rejects(lambda: public_shape(b, malformed, d), 'PublicShape')
            exercise(b, tables, d, vectors if all_instances or (delta == 4 and len(dimensions) == 3) else None)
            honest += 1
        for m in (0, 2, 3):
            table = [sc.scalar(2*j+3, d) for j in range(2**m)]
            points = [tuple(sc.scalar((j+k) % 3, d) for k in range(m)) for j in range(3)]
            b = {'mode': 1, 'id': 2, 'tensor': 77, 'm': m, 'claims': [(z, folded(table, z)) for z in points]}
            exercise(b, table, d, vectors if all_claims or m == 2 else None)
            honest += 1
        if all_instances:
            members = [{'id': 10+j, 'm': m, 'ids': [], 'terms': [(sc.scalar(1, d), [])], 'sum': sc.scalar(2**m, d)} for j, m in enumerate((0, 2))]
            exercise({'mode': 0, 'id': 1, 'instances': members}, [[], []], d, vectors)
        rng = random.Random(920+d)
        # Full-extension public coefficient checks; the implementation task retains its 10^4 gate.
        for _ in range(100):
            m = rng.randrange(4)
            point = [tuple(rng.randrange(sc.P) for _ in range(d)) for _ in range(m)]
            b = {'mode': 1, 'm': m, 'claims': [(tuple(sc.scalar(rng.randrange(2), d) if rng.randrange(2) else tuple(rng.randrange(sc.P) for _ in range(d)) for _ in range(m)), sc.scalar(0, d)) for _ in range(3)]}
            powers = [tuple(rng.randrange(sc.P) for _ in range(d)) for _ in range(3)]
            a = sparse_coefficient(b, powers, d)
            assert evaluated(a, point, d) == coefficient(b, powers, point, d)
    # A constant summand of dimension zero must keep sum 1 when embedded in dimension two.
    assert total((selector(x, 2, 4) for x in boolean(2, 4)), 4) == sc.scalar(1, 4)
    assert total((sc.scalar(1, 4) for _ in boolean(2, 4)), 4) != sc.scalar(1, 4)
    # Exact univariate root bound, including coefficient zero and gamma=0 cases.
    for length in range(1, 5):
        for coefficients in itertools.product(range(5), repeat=length):
            if any(coefficients):
                roots = sum(sum(c * pow(x, j, 5) for j, c in enumerate(coefficients)) % 5 == 0 for x in range(5))
                assert roots <= length - 1
    return vectors, honest


def attacks(b, tables, d, proof):
    wrong = copy.deepcopy(b)
    if b['mode'] == 0:
        wrong['instances'][0]['sum'] = sc.add(wrong['instances'][0]['sum'], sc.scalar(1, d))
    else:
        z, v = wrong['claims'][0]; wrong['claims'][0] = (z, sc.add(v, sc.scalar(1, d)))
    false_proof, _, _ = prove(Transcript(b'batch study', d), wrong, tables)
    sc.rejects(lambda: verify(Transcript(b'batch study', d), wrong, false_proof, tables),
               'RoundSumMismatch' if proof['rounds'] else 'FinalEvaluationMismatch')
    malformed = copy.deepcopy(tables)
    if b['mode'] == 1:
        malformed.pop()
    elif malformed[0]:
        malformed[0][0].pop()
    else:
        malformed[0].append([sc.scalar(0, d)])
    sc.rejects(lambda: verify(Transcript(b'batch study', d), b, proof, malformed), 'PublicShape')
    context, m, _, count = describe(b, d)
    if b['mode'] == 0 and proof['final'][0] and all(sc.degree(i) == 0 for i in b['instances']):
        changed = copy.deepcopy(proof)
        changed['final'][0][0] = sc.add(changed['final'][0][0], sc.scalar(1, d))
        sc.rejects(lambda: verify(Transcript(b'batch study', d), b, changed, tables), 'ClaimMismatch')
    if not m:
        return
    _, powers = weights(Transcript(b'batch study', d), context, count)
    early, _ = Transcript(b'batch study', d).challenge(GAMMA)
    early = struct.unpack('<' + 'I' * d, early)
    early_powers = [sc.scalar(1, d)]
    for _ in range(1, count):
        early_powers.append(sc.mul(early_powers[-1], early))
    def first(ws):
        def at(point):
            final = [[folded(tables, point)]] if b['mode'] else [[folded(table, point[m-i['m']:]) for table in group] for i, group in zip(b['instances'], tables)]
            return relation(b, ws, point, final, m, d)
        return total((at([sc.scalar(0, d), *tail]) for tail in boolean(m-1, d)), d)
    # Actual omitted member contribution and early coefficient, each changes one evaluation.
    if count > 1:
        assert first(early_powers) != proof['rounds'][0][0]
    candidates = [early_powers] if count > 1 else []
    candidates += [powers[:j] + [sc.scalar(0, d)] + powers[j+1:] for j in range(count)]
    changed_count = 0
    for ws in candidates:
        value = first(ws)
        if value != proof['rounds'][0][0]:
            changed = copy.deepcopy(proof); changed['rounds'][0][0] = value
            sc.rejects(lambda: verify(Transcript(b'batch study', d), b, changed, tables), 'RoundSumMismatch')
            changed_count += 1
    assert changed_count  # This fixture must exercise a nonzero omitted contribution.


def exercise(b, tables, d, vectors):
    t = Transcript(b'batch study', d)
    proof, point, gamma = prove(t, b, tables)
    receipt = verify(Transcript(b'batch study', d), b, proof, tables)
    attacks(b, tables, d, proof)
    assert receipt['point'] == point and receipt['gamma'] == gamma
    if proof['rounds']:
        changed = copy.deepcopy(proof)
        changed['rounds'][0][0] = sc.add(changed['rounds'][0][0], sc.scalar(1, d))
        sc.rejects(lambda: verify(Transcript(b'batch study', d), b, changed, tables), 'RoundSumMismatch')
    missing = copy.deepcopy(proof); missing['final'].pop()
    sc.rejects(lambda: verify(Transcript(b'batch study', d), b, missing, tables), 'ProofShape')
    malformed = copy.deepcopy(b)
    if b['mode'] == 0:
        malformed['instances'].append(copy.deepcopy(b['instances'][0]))
    else:
        malformed['claims'][0] = (list(b['claims'][0][0]) + [sc.scalar(0, d)], b['claims'][0][1])
    sc.rejects(lambda: describe(malformed, d), 'InvalidBatch')
    if b['mode'] == 0:
        malformed = copy.deepcopy(b); malformed['instances'][0]['m'] = -1
        sc.rejects(lambda: describe(malformed, d), 'InvalidBatch')
    # Final absorption changes a real subsequent sumcheck challenge.
    continuation, data = sc.instance(d, 1, 1, identity=99)
    continuation['ids'] = continuation['ids'][:1]; data = data[:1]
    next_proof, _ = sc.prove(t, continuation, data)
    verifier = Transcript(b'batch study', d); verify(verifier, b, proof, tables)
    sc.verify_public(copy.deepcopy(verifier), continuation, next_proof, data)
    omitted = Transcript(b'batch study', d)
    context, _, _, count = describe(b, d); weights(omitted, context, count)
    for r, row in enumerate(proof['rounds']):
        omitted.absorb(tr.ROUND, struct.pack('<QI', b['id'], r) + b''.join(map(sc.encode, row)))
        sc.challenge(omitted)
    wrong_next, _ = sc.prove(omitted, continuation, data)
    assert next_proof['rounds'] == wrong_next['rounds'] and next_proof['final'] != wrong_next['final']
    sc.rejects(lambda: sc.verify_public(verifier, continuation, wrong_next, data), 'FinalEvaluationMismatch')
    if vectors is not None:
        vectors.append({'degree': d, 'batch': b, 'tables': tables, 'context_hex': context.hex(), 'proof': proof,
                        'point': point, 'gamma': gamma, 'receipt': receipt, 'continuation': next_proof})


if __name__ == '__main__':
    if sys.argv[1:2] in (['--write-corpus'], ['--verify-corpus']):
        import batch_corpus as corpus
        if sys.argv[1:] == ['--write-corpus']:
            corpus.PATH.write_text(''.join(json.dumps(c, separators=(',', ':'))+'\n' for c in corpus.generate()))
        else:
            require(len(sys.argv) == 3, 'Arguments')
            corpus.check([json.loads(line) for line in Path(sys.argv[2]).read_text().splitlines()])
        sys.exit(0)
    if sys.argv[1:] in (['--instance-vectors'], ['--claim-vectors']):
        mode = int(sys.argv[1] == '--claim-vectors')
        for record in checks(all_instances=mode == 0, all_claims=mode == 1)[0]:
            if record['batch']['mode'] == mode:
                print(json.dumps(record, separators=(',', ':')))
        sys.exit(0)
    vectors, honest = checks()
    path = Path(__file__).with_name('vectors.jsonl')
    if sys.argv[1:] == ['--write-vectors']:
        with path.open('x') as output:
            for record in vectors:
                output.write(json.dumps(record, separators=(',', ':')) + '\n')
    else:
        require(not sys.argv[1:], 'Arguments')
        assert json.loads(json.dumps(vectors)) == [json.loads(line) for line in path.read_text().splitlines()]
    print(f'candidate batching: {honest} honest cases, two fields/modes, 200 coefficient checks and root-bound exhaustion; no NC credit')
