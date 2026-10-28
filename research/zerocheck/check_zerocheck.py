# /// script
# requires-python = ">=3.12"
# dependencies = ["blake3==1.0.11"]
# ///
"""RFC-0006 A3 exact-arithmetic oracle; research only, no production NC credit."""
import copy
import json
from pathlib import Path
import random
import struct
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'batching'))
import check_batching as batch
from check_batching import sc, tr, require, total, eq, boolean, folded, evaluated, field
from blake3 import blake3

ZERO, WEIGHT, SKIP, FINAL = (b'stele/v0.1/sumcheck/' + s for s in (b'zero', b'zero-weight', b'zero-skip', b'zero-final'))
LABELS = batch.LABELS + (ZERO, WEIGHT, SKIP, FINAL)


class Transcript(batch.Transcript):
    def frame(self, tag, label, payload):
        require(label in LABELS, 'InvalidFrame')
        return self.state + bytes([tag]) + struct.pack('<I', len(label)) + label + struct.pack('<Q', len(payload)) + payload

    def absorb(self, label, payload):
        require(label in (tr.INSTANCE, tr.ROUND, tr.FINAL, ZERO, SKIP, FINAL), 'InvalidAbsorbLabel')
        self.state = blake3(self.frame(0, label, payload)).digest()

    def challenge(self, label=tr.CHALLENGE):
        require(label in (tr.CHALLENGE, WEIGHT), 'InvalidChallengeLabel')
        raw = blake3(self.frame(1, label, bytes([self.degree]))).digest(length=256)
        value, consumed = tr.sample(raw, self.degree)
        self.state = blake3(self.frame(2, label, bytes([self.degree]) + struct.pack('<I', consumed) + value)).digest()
        return value, consumed


def describe(i, d):
    try:
        sc.validate({**i, 'sum': sc.scalar(0, d)}, d)
        require(0 <= i['k'] <= min(i['m'], 4) and (sc.degree(i) > 0 or i['k'] == 0), 'InvalidZerocheck')
    except ValueError as error:
        raise ValueError('InvalidZerocheck') from error
    # Reuse the term encoder, with A3's k inserted and no A1 claimed sum.
    payload = sc.instance_bytes({**i, 'sum': sc.scalar(0, d)}, d)
    return payload[:14] + bytes([i['k']]) + payload[14:-4*d]


def shape(i, tables, d):
    require(len(tables) == len(i['ids']) and all(len(v) == 2**i['m'] for v in tables), 'PublicShape')
    require(all(field(v, d) for table in tables for v in table), 'PublicShape')


def basis(u, s):
    d = len(u)
    out = []
    for b in range(s):
        v, den = sc.scalar(1, d), 1
        for c in range(s):
            if b != c:
                v = sc.mul(v, sc.add(u, sc.scalar(-c, d)))
                den *= b-c
        out.append(sc.mul(v, sc.scalar(pow(den, -1, sc.P), d)))
    return out


def dot(a, b, d):
    return total((sc.mul(x, y) for x, y in zip(a, b)), d)


def start(t, i):
    t.absorb(ZERO, describe(i, t.degree))
    return [struct.unpack('<' + 'I'*t.degree, t.challenge(WEIGHT)[0]) for _ in range(i['m']-i['k'])]


def skip(t, i, values):
    if not i['k']:
        return None, sc.scalar(0, t.degree)
    t.absorb(SKIP, sc.message(i, len(values), values))
    u = sc.challenge(t)
    return u, sc.interpolate([sc.scalar(0, t.degree)] * 2**i['k'] + values, u)


def final_bytes(i, values):
    return struct.pack('<QII', i['id'], len(i['ids']), 2**i['k']) + b''.join(sc.encode(v) for row in values for v in row)


def prove(t, i, tables):
    describe(i, t.degree)
    shape(i, tables, t.degree)
    d, s, j = t.degree, 2**i['k'], i['m']-i['k']
    delta, alpha = sc.degree(i), start(t, i)
    def slices(point):
        return [[folded(table[b*2**j:(b+1)*2**j], point) for b in range(s)] for table in tables]
    def relation(weights, point):
        return sc.compose(i['terms'], [dot(weights, row, d) for row in slices(point)], d)
    initial = []
    for node in range(s, delta*(s-1)+1) if i['k'] else ():
        weights = basis(sc.scalar(node, d), s)
        initial.append(total((sc.mul(eq(alpha, z, d), relation(weights, z)) for z in boolean(j, d)), d))
    u, _ = skip(t, i, initial)
    weights = basis(u, s) if i['k'] else [sc.scalar(1, d)]
    rounds, point = [], []
    for h in range(j):
        row = [total((sc.mul(eq(alpha[h+1:], z, d), relation(weights, [*point, sc.scalar(x, d), *z]))
                      for z in boolean(j-h-1, d)), d) for x in range(delta+1)]
        rounds.append(row)
        t.absorb(tr.ROUND, sc.message(i, h, row))
        point.append(sc.challenge(t))
    final = slices(point)
    t.absorb(FINAL, final_bytes(i, final))
    return {'skip': initial, 'rounds': rounds, 'final': final}


def verify(t, i, proof, tables):
    describe(i, t.degree)
    shape(i, tables, t.degree)
    d, s, j, delta = t.degree, 2**i['k'], i['m']-i['k'], sc.degree(i)
    count = (delta-1)*(s-1) if i['k'] else 0
    require(len(proof['skip']) == count and len(proof['rounds']) == j, 'ProofShape')
    require(all(len(row) == delta+1 for row in proof['rounds']), 'ProofShape')
    require(len(proof['final']) == len(i['ids']) and all(len(row) == s for row in proof['final']), 'ProofShape')
    require(all(field(v, d) for v in proof['skip'] + sum(proof['rounds'], []) + sum(proof['final'], [])), 'NoncanonicalField')
    alpha = start(t, i)
    u, running = skip(t, i, proof['skip'])
    point = []
    for h, row in enumerate(proof['rounds']):
        at_one = row[1] if delta else row[0]
        weighted = sc.add(sc.mul(sc.add(sc.scalar(1, d), sc.neg(alpha[h])), row[0]), sc.mul(alpha[h], at_one))
        require(weighted == running, 'RoundSumMismatch')
        t.absorb(tr.ROUND, sc.message(i, h, row))
        point.append(sc.challenge(t))
        running = sc.interpolate(row, point[-1])
    weights = basis(u, s) if i['k'] else [sc.scalar(1, d)]
    require(sc.compose(i['terms'], [dot(weights, row, d) for row in proof['final']], d) == running, 'FinalEvaluationMismatch')
    before_final = copy.deepcopy(t)
    t.absorb(FINAL, final_bytes(i, proof['final']))
    claims = []
    for identity, table, values in zip(i['ids'], tables, proof['final']):
        for prefix, value in zip(boolean(i['k'], d), values):
            full = [*prefix, *point]
            require(evaluated(table, full, d) == value, 'ClaimMismatch')
            claims.append((identity, full, value))
    records = [(j, 1, j), (int(i['k'] > 0), delta*(s-1), delta*(s-1)), (j, delta, j*delta)]
    return {'alpha': alpha, 'u': u, 'point': point, 'claims': claims,
            'sc': [{'id': i['id'], 'phase': phase, 'm': m, 'degree': degree, 'field_degree': d, 'numerator': numerator}
                   for phase, (m, degree, numerator) in enumerate(records)]}, before_final


def instance(d, m, k, delta):
    rng = random.Random(123 + m*100 + k*10 + delta)
    a = [tuple(rng.randrange(sc.P) for _ in range(d)) for _ in range(2**m)]
    b = [batch.product([v]*delta, d) for v in a]
    terms = [(sc.scalar(1, d), [0]*delta), (sc.scalar(-1, d), [1])] if delta else []
    return {'id': 7, 'm': m, 'k': k, 'ids': [11, 12, 13], 'terms': terms}, [a, b, a]


def checks():
    tr.registry(LABELS)
    vectors, count = [], 0
    for d in (4, 8):
        for delta in range(5):
            for m in range(5):
                for k in range(min(m, 4)+1) if delta else (0,):
                    i, tables = instance(d, m, k, delta)
                    prover = Transcript(b'zerocheck', d)
                    proof = prove(prover, i, tables)
                    verifier = Transcript(b'zerocheck', d)
                    receipt, before_final = verify(verifier, i, proof, tables)
                    assert prover.state == verifier.state
                    assert len(receipt['claims']) == len(i['ids'])*2**k
                    assert sum(v['numerator'] for v in receipt['sc']) == (m-k)*(delta+1)+delta*(2**k-1)
                    count += 1
                    vectors.append({'field': d, 'instance': i, 'tables': tables, 'descriptor_hex': describe(i, d).hex(),
                                        'proof': proof, 'receipt': receipt, 'final_state_hex': verifier.state.hex(),
                                        'continuation_challenge': copy.deepcopy(verifier).challenge()[0].hex()})
                    bad = copy.deepcopy(proof)
                    bad['final'][-1][-1] = sc.add(bad['final'][-1][-1], sc.scalar(1, d))
                    tr.rejects(lambda: verify(Transcript(b'zerocheck', d), i, bad, tables), 'ClaimMismatch')
                    if delta and m <= 2:
                        wrong = copy.deepcopy(tables)
                        wrong[1][0] = sc.add(wrong[1][0], sc.scalar(1, d))
                        false = prove(Transcript(b'zerocheck', d), i, wrong)
                        tr.rejects(lambda: verify(Transcript(b'zerocheck', d), i, false, wrong),
                                   'RoundSumMismatch' if m > k else 'FinalEvaluationMismatch')
                    if proof['skip']:
                        bad = copy.deepcopy(proof)
                        bad['skip'][0] = sc.add(bad['skip'][0], sc.scalar(1, d))
                        tr.rejects(lambda: verify(Transcript(b'zerocheck', d), i, bad, tables),
                                   'RoundSumMismatch' if m > k else 'FinalEvaluationMismatch')
                    if proof['rounds']:
                        bad = copy.deepcopy(proof)
                        bad['rounds'][0][0] = sc.add(bad['rounds'][0][0], sc.scalar(1, d))
                        tr.rejects(lambda: verify(Transcript(b'zerocheck', d), i, bad, tables), 'RoundSumMismatch')
                    if (m, k, delta) == (2, 1, 2):
                        next_i, next_tables = sc.instance(d, 1, 1, identity=99)
                        honest, _ = sc.prove(prover, next_i, next_tables)
                        omitted, _ = sc.prove(before_final, next_i, next_tables)
                        assert honest['rounds'] == omitted['rounds']
                        bad = copy.deepcopy(honest)
                        bad['final'][0] = omitted['final'][0]
                        assert bad['final'][0] != honest['final'][0]
                        tr.rejects(lambda: sc.verify_public(verifier, next_i, bad, next_tables), 'FinalEvaluationMismatch')
        # Interpolation endpoints and weighted checks include zero/one without division.
        for s in (2, 4, 8, 16):
            for node in range(s):
                assert basis(sc.scalar(node, d), s) == [sc.scalar(int(b == node), d) for b in range(s)]
        weights = basis(sc.scalar(4, d), 4)
        assert sc.mul(weights[0], weights[3]) != sc.mul(weights[1], weights[2])  # Not an MLE point's eq weights.
        a, b = sc.scalar(3, d), sc.scalar(7, d)
        for alpha, expected in ((sc.scalar(0, d), a), (sc.scalar(1, d), b)):
            assert sc.add(sc.mul(sc.add(sc.scalar(1, d), sc.neg(alpha)), a), sc.mul(alpha, b)) == expected
        i, tables = instance(d, 2, 1, 2)
        proof = prove(Transcript(b'zerocheck', d), i, tables)
        early = Transcript(b'zerocheck', d)
        alpha = [struct.unpack('<' + 'I'*d, early.challenge(WEIGHT)[0])]
        weights = basis(sc.scalar(2, d), 2)
        wrong = total((sc.mul(eq(alpha, z, d), sc.compose(i['terms'],
                       [dot(weights, [folded(table[b*2:(b+1)*2], z) for b in range(2)], d) for table in tables], d))
                       for z in boolean(1, d)), d)
        bad = copy.deepcopy(proof); bad['skip'][0] = wrong
        assert wrong != proof['skip'][0]
        tr.rejects(lambda: verify(Transcript(b'zerocheck', d), i, bad, tables), 'RoundSumMismatch')
        for key in ('skip', 'rounds', 'final'):
            for replacement in (proof[key][:-1], proof[key]+proof[key][:1]):
                bad = copy.deepcopy(proof); bad[key] = replacement
                tr.rejects(lambda: verify(Transcript(b'zerocheck', d), i, bad, tables), 'ProofShape')
        bad = copy.deepcopy(proof); bad['skip'][0] = (sc.P,) + (0,)*(d-1)
        tr.rejects(lambda: verify(Transcript(b'zerocheck', d), i, bad, tables), 'NoncanonicalField')
        for changed in ({**i, 'k': 5}, {**i, 'k': 3}, {**i, 'terms': []}, {**i, 'ids': [11, 11, 13]}):
            tr.rejects(lambda: describe(changed, d), 'InvalidZerocheck')
        tr.rejects(lambda: verify(Transcript(b'zerocheck', d), i, proof, tables[:-1]), 'PublicShape')
        for m in (0, 2):
            empty = {'id': 8, 'm': m, 'k': 0, 'ids': [], 'terms': []}
            zero = prove(Transcript(b'zerocheck', d), empty, [])
            verify(Transcript(b'zerocheck', d), empty, zero, [])
            nonzero = {**empty, 'terms': [(sc.scalar(1, d), [])]}
            false = prove(Transcript(b'zerocheck', d), nonzero, [])
            tr.rejects(lambda: verify(Transcript(b'zerocheck', d), nonzero, false, []),
                       'RoundSumMismatch' if m else 'FinalEvaluationMismatch')
    return {'honest_cases': count, 'vectors': vectors}


if __name__ == '__main__':
    result = checks()
    encoded = ''.join(json.dumps(v, separators=(',', ':')) + '\n' for v in result['vectors'])
    path = Path(__file__).with_name('vectors.jsonl')
    if '--write-vectors' in sys.argv:
        path.write_text(encoded)
    else:
        assert path.read_text() == encoded, 'zerocheck candidate vectors drifted'
    print(f"zerocheck: {result['honest_cases']} honest cases, both fields, exact errors and {len(result['vectors'])} byte vectors")
