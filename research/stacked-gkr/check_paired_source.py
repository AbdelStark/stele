# /// script
# requires-python = ">=3.12"
# dependencies = ["blake3==1.0.11"]
# ///
"""Q20 paired source: actual quartic consumers, no private PCS or ZK admission."""
import copy
import hashlib
import json
import math
import random
from paired_source import (Transcript, derive, encode, unpack, prove, verify_reduction,
                           resolve_prove, resolve_verify, selection_claims, link, low_descriptor, PAIRS, sc, source)
from check_selection_source import view as bit_view
from stage import evaluation
from check_stage import context as tensor_context
from check_private_stage import fixture as stage_fixture, claim as stage_claim
from private_stage import prove as stage_prove, verify_reduction as stage_verify
from weighted_private_selection import prove as select_prove, verify_reduction as select_verify


def view(axes=((1, 2),), bits=2, categories=3):
    return bit_view(axes, bits, categories)


def context(v, fields, d):
    return b'Q20/paired-source/v1'+derive(v, d)[0]+len(fields).to_bytes(8, 'little')+b''.join(map(sc.encode, fields))


def consume(v, fields, receipt, d):
    dimension = derive(v, d)[-1]
    for identity, point, value in receipt['claims']:
        if identity != v['source_id'] or len(point) != dimension:
            raise ValueError('SourceClaimScope')
        if evaluation(fields, point, d) != value:
            raise ValueError('SourceClaimMismatch')


class Counted(Transcript):
    def __init__(self, public, d):
        super().__init__(public, d); self.draws = []
    def challenge(self, label=source.zc.tr.CHALLENGE):
        self.draws.append(label)
        return super().challenge(label)


def run(v, fields, d):
    p, q = Counted(context(v, fields, d), d), Counted(context(v, fields, d), d)
    proof = prove(p, v, fields); receipt = verify_reduction(q, v, proof)
    consume(v, fields, receipt, d)
    _, spec, virtual, _, dp = derive(v, d)
    a, k, db = spec.row_bits, spec.category_bits, source.derive(virtual, d)[-1]
    extra, low = spec.categories != 1 << k, k < 2
    records = []
    def zero(identity, m, delta):
        records.extend(dict(id=identity, phase=h, m=n, degree=e, field_degree=d, numerator=loss)
                       for h, (n, e, loss) in enumerate([(m, 1, m), (0, 0, 0), (m, delta, m*delta)]))
    if low: zero(v['instance_base']+257, a, 2)
    zero(v['instance_base'], db, 3); zero(v['instance_base']+1, db, 2)
    if extra:
        zero(v['instance_base']+2, a, 2)
        records.extend(dict(id=v['instance_base']+3+j, m=a, degree=3, field_degree=d, numerator=3*a) for j in range(k))
    dimensions = [len(part['rounds']) for part in proof['resolutions']]
    assert dimensions == [dp, dp]+([a]*k if extra else [])
    records.extend(dict(id=v['instance_base']+128+j, m=m, degree=4, field_degree=d, numerator=4*m)
                   for j, m in enumerate(dimensions))
    assert receipt['sc'] == records
    assert sum(r['numerator'] for r in records) == 8*dp+7*db+(3*a if low else 0)+((7*k+3)*a if extra else 0)
    z, c = source.zc.WEIGHT, source.zc.tr.CHALLENGE
    draws = ([z]*a+[c]*a if low else [])+([z]*db+[c]*db)*2
    if extra: draws += [z]*a+[c]*(a*(k+1))
    draws += [c]*sum(dimensions)
    assert p.draws == q.draws == draws
    assert len(receipt['claims']) == 2+int(low)+(k if extra else 0)
    core = proof['source']
    zeros = [core['bits'], core['padding']]+([proof['low']] if low else [])+([core['range']['root']] if extra else [])
    nodes = proof['resolutions']+(core['range']['nodes'] if extra else [])
    size = sum(sum(map(len, x['rounds']))+sum(map(len, x['final'])) for x in zeros)
    size += sum(sum(map(len, x['rounds']))+len(x['final']) for x in nodes)
    assert size == 10*dp+7*db+8+(3*a+1 if low else 0)+(3*a+2+k*(9*a+5) if extra else 0)
    assert p.state == q.state and sc.challenge(p) == sc.challenge(q)
    return proof, receipt


def check():
    rng, digest = random.Random(30627), hashlib.sha256()
    for d in (4, 8):
        zero, one = sc.scalar(0, d), sc.scalar(1, d)
        for symbol in range(4):
            v = view(((0, 1),), 2, 4)
            assert unpack(v, [sc.scalar(symbol, d)], d) == [sc.scalar(symbol//2, d), sc.scalar(symbol%2, d)]
        for case in range(64):
            axes = ((case%2, 1+case%2), (1, 1+case%2))
            k = case%10; v = view(axes, k, rng.randrange(1, (1 << k)+1))
            indices = [rng.randrange(v['categories']) for _ in range(math.prod(n for _, n in axes))]
            fields = encode(v, indices, d); proof, receipt = run(v, fields, d)
            virtual = derive(v, d)[2]
            assert unpack(v, fields, d) == source.encode(virtual, indices, d)
            expected_cells = len(unpack(v, fields, d))//2 if k >= 2 else 1 << sum(b for b, _ in axes)
            assert len(fields) == expected_cells
            digest.update(json.dumps([v, fields, proof, receipt], sort_keys=True, separators=(',', ':')).encode())
            if case < 8:
                raw = derive(v, d)[0]
                p, q = Transcript(context(v, fields, d), d), Transcript(context(v, fields, d), d)
                p.absorb(PAIRS, raw); q.absorb(PAIRS, raw)
                if k < 2:
                    i = low_descriptor(v, d)
                    assert source.zero_prove(p, i, [fields])[0] == source.zc.prove(q, i, [fields])
                    assert p.state == q.state
                s, tables, _ = stage_fixture(rng, d, case, (axes[0], (k, v['categories']), axes[1]), (0, 2), 1, 2)
                s['id'] = 65; stage_claim(s, tables, indices)
                public = context(v, fields, d)+tensor_context(s, tables)
                p, q = Transcript(public, d), Transcript(public, d)
                link(p, v, s); link(q, v, s)
                first = prove(p, v, fields); consume(v, fields, verify_reduction(q, v, first), d)
                shadow = copy.deepcopy(p); body = stage_prove(p, s, tables, indices)
                produced = stage_verify(shadow, s, body)
                claims = selection_claims(v, produced['selection'], d)
                openings = resolve_prove(p, v, fields, claims, 65)
                actual = stage_verify(q, s, body)
                actual_claims = selection_claims(v, actual['selection'], d)
                consume(v, fields, resolve_verify(q, v, actual_claims, 65, openings), d)
                assert [len(part['rounds']) for part in openings] == [sum(b for b, _ in axes)]*k
                assert all(evaluation(table, actual['point'], d) == value for table, (_, value) in zip(tables, actual['claims']))
                assert p.state == q.state and sc.challenge(p) == sc.challenge(q)
                for bad_view, bad_stage in [({**v, 'source_id': 901}, s), ({**v, 'instance_base': 0}, {**s, 'id': 260}),
                                             (v, {**s, 'coefficient_id': v['tensor_base']+600})]:
                    before = q.state
                    sc.rejects(lambda: link(q, bad_view, bad_stage), 'SourceClaimScope')
                    assert q.state == before
        # Actual false symbol, unused low bit, spare high plane, grid hole and range proofs.
        false = [(view(((0, 1),), 2, 4), [sc.scalar(4, d)], 'RoundSumMismatch'),
                 (view(((0, 1),), 2, 4), [sc.scalar(7*pow(2, -1, sc.P), d)], 'RoundSumMismatch'),
                 (view(((0, 1),), 2, 4), [sc.scalar(5*pow(2, -1, sc.P), d)], 'RoundSumMismatch'),
                 (view(((0, 1),), 2, 4), [(0, 1)+(0,)*(d-2)], 'RoundSumMismatch'),
                 (view(((0, 1),), 0, 1), [one], 'FinalEvaluationMismatch'),
                 (view(((0, 1),), 1, 2), [one], 'FinalEvaluationMismatch'),
                 (view(((0, 1),), 3, 8), [zero, one], 'RoundSumMismatch'),
                 (view(((0, 1),), 2, 3), [sc.scalar(3, d)], 'FinalEvaluationMismatch')]
        v = view(((2, 3),), 2, 4); fields = encode(v, [0, 0, 0], d); fields[3] = one
        false.append((v, fields, 'RoundSumMismatch'))
        for v, fields, error in false:
            public = context(v, fields, d); proof = prove(Transcript(public, d), v, fields)
            sc.rejects(lambda: verify_reduction(Transcript(public, d), v, proof), error)
        # A repeated bit value cannot discard its changed original-symbol final.
        v = view(((0, 1),), 1, 2); fields = [zero]
        proof, _ = run(v, fields, d); proof['resolutions'][-1]['final'][1] = one
        receipt = verify_reduction(Transcript(context(v, fields, d), d), v, proof)
        sc.rejects(lambda: consume(v, fields, receipt, d), 'SourceClaimMismatch')
        proof, _ = run(v, fields, d); proof['resolutions'][-1]['final'][0] = zero
        sc.rejects(lambda: verify_reduction(Transcript(context(v, fields, d), d), v, proof), 'SourceMaskMismatch')
        proof, _ = run(v, fields, d)
        for changed in ({**proof, 'low': None}, {**proof, 'resolutions': proof['resolutions'][:-1]}):
            sc.rejects(lambda: verify_reduction(Transcript(context(v, fields, d), d), v, changed), 'ProofShape')
        # MLE(high(P)) differs from high(MLE(P)); the real consumer rejects substitution.
        v = view(((1, 2),), 2, 4); fields = [zero, sc.scalar(3, d)]
        virtual = derive(v, d)[2]; point = [zero, sc.scalar(2, d)]
        claims = [(virtual['source_id'], point, sc.scalar(2, d)), (virtual['source_id'], [one, point[1]], sc.scalar(2, d))]
        public = context(v, fields, d)
        p, q = Transcript(public, d), Transcript(public, d)
        proof = resolve_prove(p, v, fields, claims, 65)
        consume(v, fields, resolve_verify(q, v, claims, 65, proof), d)
        wrong = list(claims); wrong[0] = (virtual['source_id'], point, sc.scalar(-25, d))
        proof = resolve_prove(Transcript(public, d), v, fields, wrong, 65)
        sc.rejects(lambda: resolve_verify(Transcript(public, d), v, wrong, 65, proof), 'RoundSumMismatch')
        # Cancellation of the cubic coefficient does not lower the declared degree.
        claims[0] = (virtual['source_id'], [sc.scalar(pow(3, -1, sc.P), d), point[1]], sc.scalar(2, d))
        p, q = Transcript(public, d), Transcript(public, d)
        proof = resolve_prove(p, v, fields, claims, 0)
        resolved = resolve_verify(q, v, claims, 0, proof); consume(v, fields, resolved, d)
        assert all(record['degree'] == 4 for record in resolved['sc']) and p.state == q.state
        # General points and a fixed pair-plane select different, derived dimensions.
        v = view(((1, 2),), 4, 16); fields = encode(v, [1, 14], d)
        virtual = derive(v, d)[2]; bits = unpack(v, fields, d)
        points = [[one, sc.scalar(2, d), sc.scalar(3, d)], [sc.scalar(2, d)]*3]
        claims = [(virtual['source_id'], u, evaluation(bits, u, d)) for u in points]
        public = context(v, fields, d); p, q = Transcript(public, d), Transcript(public, d)
        proof = resolve_prove(p, v, fields, claims, 0)
        assert [len(part['rounds']) for part in proof] == [1, 2]
        resolved = resolve_verify(q, v, claims, 0, proof); consume(v, fields, resolved, d)
        assert resolved['claims'][0][1][0] == one and p.state == q.state
        complete, _ = run(v, fields, d)
        sc.rejects(lambda: verify_reduction(Transcript(public, d), v, {**complete, 'low': {}}), 'ProofShape')
        # 0 and p have distinct canonical symbols; every aliased selection claim is consumed.
        v = view(((0, 1),), 31, 1 << 31); fields = encode(v, [sc.P], d)
        assert fields != encode(v, [0], d)
        public = context(v, fields, d); p, q = Transcript(public, d), Transcript(public, d)
        first = prove(p, v, fields); consume(v, fields, verify_reduction(q, v, first), d)
        meta = dict(layout=((0, 1), (31, 1 << 31)), source_axes=(0,), category_axis=1, selectors=(None, None), source_id=900)
        body = select_prove(p, meta, (zero,)*31, one, [0], instance_base=66)
        receipt = select_verify(q, meta, (zero,)*31, one, body, instance_base=66)
        changed = {**receipt, 'source': (901, *receipt['source'][1:])}
        sc.rejects(lambda: selection_claims(v, changed, d), 'SourceClaimScope')
        claims = selection_claims(v, receipt, d); proof = resolve_prove(p, v, fields, claims, 65)
        original = copy.deepcopy(q)
        sc.rejects(lambda: resolve_verify(q, v, claims, 65, proof), 'FinalEvaluationMismatch')
        forged = copy.deepcopy(proof)
        for part in forged: part['final'][1] = zero
        receipt = resolve_verify(original, v, claims, 65, forged)
        sc.rejects(lambda: consume(v, fields, receipt, d), 'SourceClaimMismatch')
        v['categories'] = sc.P; public = context(v, fields, d)
        proof = prove(Transcript(public, d), v, fields)
        sc.rejects(lambda: verify_reduction(Transcript(public, d), v, proof), 'FinalEvaluationMismatch')
        for v, indices in [(view(((0, 1),), 63, (1 << 63)-1), [(1 << 63)-2]), (view(((0, 1),)*63, 0, 1), [0])]:
            run(v, encode(v, indices, d), d)
        assert len(derive(v, d)[0]) == 604
        raw = derive(view(((2, 3),), 3, 5), d)[0]
        expected = bytes([1, d, 2])+(900).to_bytes(8, 'little')+bytes([1, 2])+(3).to_bytes(8, 'little')+bytes([3])
        expected += b''.join(x.to_bytes(8, 'little') for x in (5, 1024, 2048))
        assert raw == expected
        # All paired planes are distinct; both general and plane-restricted consumers run.
        v = view(((3, 6),), 60, (1 << 60)-1)
        indices = [sum(((j >> row) & 1) << (59-j) for j in range(60)) for row in range(6)]
        fields = encode(v, indices, d); run(v, fields, d)
        assert len(fields) == 32*8
        t = Transcript(context(v, fields, d), d); before = t.state
        for key, value in [('instance_base', 128), ('tensor_base', 256), ('source_id', 2900), ('values', [0])]:
            sc.rejects(lambda: prove(t, {**v, key: value}, fields), 'SourceShape')
            assert t.state == before
        sc.rejects(lambda: prove(t, view(((30, 1),), 2, 4), []), 'SourceCapacity')
        assert t.state == before
        edge = view(((0, 1),), 0, 1); edge.update(instance_base=(1 << 64)-512, tensor_base=(1 << 64)-1024)
        run(edge, [zero], d)
        # Omitting only the outer frame changes an actual successor's final value.
        v = view(((0, 1),), 0, 1); fields = [zero]
        next_i = dict(id=5000, m=1, ids=[4000], terms=[(one, [0])], sum=sc.scalar(7, d))
        tables = [[sc.scalar(2, d), sc.scalar(5, d)]]
        public = context(v, fields, d)+b''.join(map(sc.encode, tables[0]))
        p = Transcript(public, d); first = prove(p, v, fields); honest, _ = sc.prove(p, next_i, tables)
        stale = Transcript(public, d)
        source.zc.verify_reduction(stale, low_descriptor(v, d), first['low'])
        receipt = source.verify_reduction(stale, derive(v, d)[2], first['source'])
        resolve_verify(stale, v, receipt['claims'], 0, first['resolutions'])
        wrong, _ = sc.prove(stale, next_i, tables)
        assert honest['rounds'] == wrong['rounds'] and honest['final'] != wrong['final']
        q = Transcript(public, d); consume(v, fields, verify_reduction(q, v, first), d)
        sc.rejects(lambda: sc.verify_public(q, next_i, wrong, tables), 'FinalEvaluationMismatch')
        q = Transcript(public, d); consume(v, fields, verify_reduction(q, v, first), d)
        sc.verify_public(q, next_i, honest, tables); assert p.state == q.state
    print(json.dumps(dict(seed=30627, sources_per_field=64, stages_per_field=8, sha256=digest.hexdigest()), sort_keys=True))
    print('Candidate packed source only: private PCS, joint ZK and format/cost admission remain open.')


if __name__ == '__main__':
    check()
