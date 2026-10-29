# /// script
# requires-python = ">=3.12"
# dependencies = ["blake3==1.0.11"]
# ///
"""Q20 typed bit-source reductions; public original consumer, no private PCS/ZK."""
import copy
import hashlib
import itertools
import json
import math
import random
from selection_source import (Transcript, derive, encode, prove, verify_reduction,
                              selection_claims, link, mask, zero_prove, descriptors, chain, SOURCE, sc, zc)
from stage import evaluation
from check_stage import context as tensor_context
from check_private_stage import fixture as stage_fixture, claim as stage_claim
from private_stage import prove as stage_prove, verify_reduction as stage_verify
from weighted_private_selection import prove as select_prove, verify_reduction as select_verify


def view(axes=((1, 2),), bits=2, categories=3):
    return dict(source_id=900, axes=axes, bits=bits, categories=categories, instance_base=1024, tensor_base=2048)


def context(v, fields, d):
    return b'Q20/source-fields/v1'+derive(v, d)[0]+len(fields).to_bytes(8, 'little')+b''.join(map(sc.encode, fields))


def consume(v, fields, claims, d):
    _, _, _, dimension = derive(v, d)
    for identity, point, value in claims:
        if identity != v['source_id'] or len(point) != dimension:
            raise ValueError('SourceClaimScope')
        if evaluation(fields, point, d) != value:
            raise ValueError('SourceClaimMismatch')


def expected_records(v, d):
    _, spec, _, dimension = derive(v, d)
    result = []
    def zero(identity, m, delta):
        result.extend(dict(id=identity, phase=phase, m=variables, degree=degree, field_degree=d, numerator=numerator)
            for phase, (variables, degree, numerator) in enumerate([(m, 1, m), (0, 0, 0), (m, delta, m*delta)]))
    zero(v['instance_base'], dimension, 3); zero(v['instance_base']+1, dimension, 2)
    if spec.categories != 1 << spec.category_bits:
        zero(v['instance_base']+2, spec.row_bits, 2)
        result.extend(dict(id=v['instance_base']+3+j, m=spec.row_bits, degree=3, field_degree=d, numerator=3*spec.row_bits)
                      for j in range(spec.category_bits))
    return result


class Counted(Transcript):
    def __init__(self, public, d):
        super().__init__(public, d); self.draws = []
    def challenge(self, label=zc.tr.CHALLENGE):
        self.draws.append(label)
        return super().challenge(label)


def run(v, fields, d):
    public = context(v, fields, d)
    p, verifier = Counted(public, d), Counted(public, d)
    proof = prove(p, v, fields)
    receipt = verify_reduction(verifier, v, proof)
    consume(v, fields, receipt['claims'], d)
    _, spec, _, dimension = derive(v, d)
    a, k = spec.row_bits, spec.category_bits
    extra = spec.categories != 1 << k
    assert receipt['sc'] == expected_records(v, d)
    draws = ([zc.WEIGHT]*dimension+[zc.tr.CHALLENGE]*dimension)*2
    if extra:
        draws += [zc.WEIGHT]*a+[zc.tr.CHALLENGE]*(a*(k+1))
    assert p.draws == verifier.draws == draws
    assert len(receipt['claims']) == 2+(k if extra else 0)
    zeros = [proof['bits'], proof['padding']]+([proof['range']['root']] if extra else [])
    size = sum(sum(map(len, z['rounds']))+sum(map(len, z['final'])) for z in zeros)
    if extra:
        size += sum(sum(map(len, n['rounds']))+len(n['final']) for n in proof['range']['nodes'])
    assert size == 7*dimension+4+(3*a+2+k*(4*a+3) if extra else 0)
    assert p.state == verifier.state and sc.challenge(p) == sc.challenge(verifier)
    return proof, receipt


def check():
    rng, digest = random.Random(30626), hashlib.sha256()
    for d in (4, 8):
        zero, one = sc.scalar(0, d), sc.scalar(1, d)
        comparisons = 0
        for k in range(7):
            for bound in range(1, (1 << k)+1):
                v = view(((0, 1),), k, bound)
                for index in range(1 << k):
                    value = one if bound == 1 << k else zero
                    if bound != 1 << k:
                        for j in reversed(range(k)):
                            bit = sc.scalar(index >> (k-j-1) & 1, d)
                            value = sc.compose(chain(v, j, zero, d)['terms'], [one, bit, value], d)
                    assert value == sc.scalar(int(index < bound), d)
                    comparisons += 1
        assert comparisons == 5461
        for case in range(64):
            axes = ((case % 2, 1+(case % 2)), (1, 1+case % 2))
            k = case % 7
            v = view(axes, k, rng.randrange(1, (1 << k)+1))
            indices = [rng.randrange(v['categories']) for _ in range(math.prod(n for _, n in axes))]
            fields = encode(v, indices, d)
            proof, receipt = run(v, fields, d)
            digest.update(json.dumps([v, fields, proof, receipt], sort_keys=True, separators=(',', ':')).encode())
            raw, spec, plane_bits, dimension = derive(v, d)
            point = [tuple(rng.randrange(sc.P) for _ in range(d)) for _ in range(dimension)]
            public_mask = []
            for plane in range(1 << plane_bits):
                for coords in itertools.product(*(range(1 << b) for b, _ in axes)):
                    public_mask.append(sc.scalar(int(plane < k and all(c < n for c, (_, n) in zip(coords, axes))), d))
            assert mask(v, point, d) == evaluation(public_mask, point, d)
            if case < 8:
                for i in descriptors(v, d)[:2]:
                    p, q = Transcript(context(v, fields, d), d), Transcript(context(v, fields, d), d)
                    p.absorb(SOURCE, raw); q.absorb(SOURCE, raw)
                    assert zero_prove(p, i, [fields, public_mask])[0] == zc.prove(q, i, [fields, public_mask])
                    assert p.state == q.state
                s, tables, _ = stage_fixture(rng, d, case, (axes[0], (k, v['categories']), axes[1]), (0, 2), 1, 2)
                s['id'] = 65; stage_claim(s, tables, indices)
                public = context(v, fields, d)+tensor_context(s, tables)
                p, q = Transcript(public, d), Transcript(public, d)
                link(p, v, s); link(q, v, s)
                source_proof = prove(p, v, fields); stage_proof = stage_prove(p, s, tables, indices)
                consume(v, fields, verify_reduction(q, v, source_proof)['claims'], d)
                stage = stage_verify(q, s, stage_proof)
                consume(v, fields, selection_claims(v, stage['selection'], d), d)
                assert all(evaluation(table, stage['point'], d) == value for table, (_, value) in zip(tables, stage['claims']))
                assert p.state == q.state and sc.challenge(p) == sc.challenge(q)
                for bad_view in ({**v, 'source_id': 901}, {**v, 'instance_base': 0}, {**v, 'tensor_base': 0}):
                    before = q.state
                    sc.rejects(lambda: link(q, bad_view, s), 'SourceClaimScope')
                    assert q.state == before
        # False Boolean, padded and out-of-range sources are proved without a verifier bypass.
        for v, fields, error in [(view(((0, 1),), 1, 2), [sc.scalar(2, d)], 'FinalEvaluationMismatch'),
                                 (view(((0, 1),), 0, 1), [one], 'FinalEvaluationMismatch'),
                                 (view(((0, 1),), 2, 3), [one, one], 'FinalEvaluationMismatch')]:
            public = context(v, fields, d); proof = prove(Transcript(public, d), v, fields)
            sc.rejects(lambda: verify_reduction(Transcript(public, d), v, proof), error)
        v = view(((1, 2), (2, 3)), 2, 3)
        fields = encode(v, [0]*6, d); fields[3] = one
        public = context(v, fields, d); proof = prove(Transcript(public, d), v, fields)
        sc.rejects(lambda: verify_reduction(Transcript(public, d), v, proof), 'RoundSumMismatch')
        # An unused original under a zero mask still reaches the real source consumer.
        v = view(((0, 1),), 0, 1); fields = [zero]
        proof, _ = run(v, fields, d)
        sc.rejects(lambda: verify_reduction(Transcript(context(v, fields, d), d), v, {**proof, 'range': {}}), 'ProofShape')
        proof['bits']['final'][0][0] = one
        receipt = verify_reduction(Transcript(context(v, fields, d), d), v, proof)
        sc.rejects(lambda: consume(v, fields, receipt['claims'], d), 'SourceClaimMismatch')
        v = view(((0, 1),), 1, 1); fields = [zero]
        proof, _ = run(v, fields, d)
        sc.rejects(lambda: verify_reduction(Transcript(context(v, fields, d), d), v, {**proof, 'range': None}), 'ProofShape')
        proof['range']['nodes'][0]['final'][2] = one
        sc.rejects(lambda: verify_reduction(Transcript(context(v, fields, d), d), v, proof), 'ConstantRangeLeaf')
        proof, _ = run(v, fields, d); proof['bits']['final'][1][0] = zero
        sc.rejects(lambda: verify_reduction(Transcript(context(v, fields, d), d), v, proof), 'SourceMaskMismatch')
        # Field-congruent integers remain distinct committed bit sources.
        v = view(((0, 1),), 31, 1 << 31)
        fields = encode(v, [sc.P], d)
        assert fields != encode(v, [0], d)
        public = context(v, fields, d); p, q = Transcript(public, d), Transcript(public, d)
        source_proof = prove(p, v, fields)
        consume(v, fields, verify_reduction(q, v, source_proof)['claims'], d)
        meta = dict(layout=((0, 1), (31, 1 << 31)), source_axes=(0,), category_axis=1, selectors=(None, None), source_id=900)
        proof = select_prove(p, meta, (zero,)*31, one, [0], instance_base=66)
        receipt = select_verify(q, meta, (zero,)*31, one, proof, instance_base=66)
        sc.rejects(lambda: consume(v, fields, selection_claims(v, receipt, d), d), 'SourceClaimMismatch')
        v['categories'] = sc.P
        public = context(v, fields, d); proof = prove(Transcript(public, d), v, fields)
        sc.rejects(lambda: verify_reduction(Transcript(public, d), v, proof), 'FinalEvaluationMismatch')
        for v, indices in [(view(((0, 1),), 63, (1 << 63)-1), [(1 << 63)-2]), (view(((0, 1),)*63, 0, 1), [0])]:
            fields = encode(v, indices, d); run(v, fields, d)
        assert len(derive(v, d)[0]) == 603
        # Distinct 60-bit planes over six rows exercise every plane coordinate.
        v = view(((3, 6),), 60, (1 << 60)-1)
        indices = [sum(((j >> row) & 1) << (59-j) for j in range(60)) for row in range(6)]
        fields = encode(v, indices, d); run(v, fields, d)
        public = context(v, fields, d); p, q = Transcript(public, d), Transcript(public, d)
        proof = prove(p, v, fields); consume(v, fields, verify_reduction(q, v, proof)['claims'], d)
        meta = dict(layout=((3, 6), (60, (1 << 60)-1)), source_axes=(0,), category_axis=1, selectors=(None, None), source_id=900)
        point, value = (zero,)*3+tuple(sc.scalar(j+2, d) for j in range(60)), one
        for j, coordinate in enumerate(point[3:]):
            value = sc.mul(value, coordinate if indices[0] >> (59-j) & 1 else sc.add(one, sc.neg(coordinate)))
        proof = select_prove(p, meta, point, value, indices, instance_base=66)
        receipt = select_verify(q, meta, point, value, proof, instance_base=66)
        consume(v, fields, selection_claims(v, receipt, d), d)
        assert p.state == q.state
        changed = copy.deepcopy(receipt); changed['source'] = (901, *changed['source'][1:])
        sc.rejects(lambda: selection_claims(v, changed, d), 'SourceClaimScope')
        t = Transcript(context(v, fields, d), d); before = t.state
        for key, wrong in [('instance_base', 1), ('instance_base', 1 << 64), ('tensor_base', 1),
                           ('tensor_base', 1 << 64), ('source_id', 2048), ('bits', 64), ('values', [0])]:
            sc.rejects(lambda: prove(t, {**v, key: wrong}, fields), 'SourceShape')
            assert t.state == before
        sc.rejects(lambda: prove(t, view(((30, 1),), 1, 2), []), 'SourceCapacity')
        assert t.state == before
        raw = derive(view(((2, 3),), 3, 5), d)[0]
        expected = bytes([1, d])+(900).to_bytes(8, 'little')+bytes([1, 2])+(3).to_bytes(8, 'little')+bytes([3])
        expected += b''.join(x.to_bytes(8, 'little') for x in (5, 1024, 2048))
        assert raw == expected
        edge = view(((0, 1),), 0, 1)
        edge.update(instance_base=(1 << 64)-128, tensor_base=(1 << 64)-256)
        run(edge, [zero], d)
        # Omit only Source before a scalar source proof and a real A1 successor.
        v = view(((0, 1),), 0, 1); fields = [zero]
        next_i = dict(id=5000, m=1, ids=[4000], terms=[(one, [0])], sum=sc.scalar(7, d))
        tables = [[sc.scalar(2, d), sc.scalar(5, d)]]
        public = context(v, fields, d)+b''.join(map(sc.encode, tables[0]))
        p = Transcript(public, d); first = prove(p, v, fields)
        honest, _ = sc.prove(p, next_i, tables)
        stale = Transcript(public, d)
        for i, part in zip(descriptors(v, d)[:2], [first['bits'], first['padding']]):
            zc.verify_reduction(stale, i, part)
        wrong, _ = sc.prove(stale, next_i, tables)
        assert wrong['rounds'] == honest['rounds'] and wrong['final'] != honest['final']
        q = Transcript(public, d); consume(v, fields, verify_reduction(q, v, first)['claims'], d)
        sc.rejects(lambda: sc.verify_public(q, next_i, wrong, tables), 'FinalEvaluationMismatch')
        q = Transcript(public, d); consume(v, fields, verify_reduction(q, v, first)['claims'], d)
        sc.verify_public(q, next_i, honest, tables)
        assert p.state == q.state
    print(json.dumps(dict(seed=30626, sources_per_field=64, stages_per_field=8, comparisons_per_field=5461,
                         sha256=digest.hexdigest()), sort_keys=True))
    print('Candidate bit representation only: actual private PCS, joint ZK and storage-cost admission remain open.')


if __name__ == '__main__':
    check()
