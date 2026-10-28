# /// script
# requires-python = ">=3.12"
# dependencies = ["blake3==1.0.11"]
# ///
"""Q20 closed public-stage checks; not production NC credit or private-source admission."""
import copy
import random
from blake3 import blake3
from check_statement import fixture
from check_weighted_mle import boolean_table
from stage import Transcript, prove, verify_reduction, verify_public, evaluation, instance, permutation, STACK, sc
from statement import encode, layout, field


def total(values, d):
    result = sc.scalar(0, d)
    for value in values:
        result = sc.add(result, value)
    return result


def claim(s, tables):
    s['output']['value'] = total([sc.mul(a, sc.compose(s['terms'], [t[i] for t in tables], s['field']))
        for i, a in enumerate(boolean_table(s))], s['field'])


def context(s, tables):
    # The fixed public input includes actual original values before any challenge.
    return (b'Q20/public-tables/v1'+bytes([s['field']])+layout(s['layout'])
            +len(tables).to_bytes(4, 'little')+b''.join(identity.to_bytes(8, 'little')
            +b''.join(field(v, s['field']) for v in table) for identity, table in zip(s['inputs'], tables)))


def check():
    rng = random.Random(30622)
    counts = [0, 0]
    for d in (4, 8):
        def element():
            return tuple(rng.randrange(sc.P) for _ in range(d))
        for case in range(600):
            s = fixture(d, case % 6, case // 6 % 2, bool(case % 3))
            bits = case // 12 % 2
            s['layout'] = [(bits, 1 << bits)]*3
            c = s['coefficient']
            c['selectors'] = [[element() for _ in range(bits)] if case >> axis & 1 else None for axis in range(3)]
            if c['kind'] == 3:
                c['values'] = [rng.randrange(1 << bits) for _ in range(1 << bits)]
            if c['kind'] == 5:
                c['values'] = [rng.randrange(sc.P) for _ in range(1 << (2*bits))]
            power = case // 24 % 5
            s['terms'] = [] if power == 4 else [(element(), [0]*power), (element(), [] if power == 0 else [1])]
            tables = [[element() for _ in range(1 << (3*bits))] for _ in s['inputs']]
            claim(s, tables)
            public = context(s, tables)
            prover, verifier = Transcript(public, d), Transcript(public, d)
            if case == 0:
                framed = Transcript(public, d)
                raw = encode(s)
                expected = (framed.state+bytes([0])+len(STACK).to_bytes(4, 'little')
                            +STACK+len(raw).to_bytes(8, 'little')+raw)
                framed.absorb(STACK, raw)
                assert framed.state == blake3(expected).digest()
                changed = copy.deepcopy(tables)
                changed[2][0] = sc.add(changed[2][0], sc.scalar(1, d))
                assert context(s, changed) != public
                assert Transcript(context(s, changed), d).state != verifier.state
            proof = prove(prover, s, tables)
            receipt = verify_public(verifier, s, proof, tables)
            assert prover.state == verifier.state
            assert receipt['claims'] == [(identity, evaluation(table, receipt['point'], d)) for identity, table in zip(s['inputs'], tables)]
            assert receipt['sc']['numerator'] == 3*bits*(0 if power == 4 else power+1)
            assert receipt['sc']['field_degree'] == d
            assert sc.challenge(prover) == sc.challenge(verifier)
            counts[d//4-1] += 1
        for bits in (0, 1, 3):
            for empty in (False, True):
                s = fixture(d)
                s.update(layout=[(bits, 1 << bits)], inputs=[], terms=[] if empty else [(element(), [])])
                s['coefficient']['selectors'] = [None]
                claim(s, [])
                public = context(s, [])
                prover, verifier = Transcript(public, d), Transcript(public, d)
                proof = prove(prover, s, [])
                assert verify_public(verifier, s, proof, [])['claims'] == []
                assert prover.state == verifier.state
        # One wrong-layer final from an unused original still requires its actual consumer.
        s = fixture(d, 0, 1)
        s['layout'] = [(1, 2)]*3
        s['terms'] = [(sc.scalar(1, d), [0])]
        tables = [[element() for _ in range(8)] for _ in s['inputs']]
        claim(s, tables)
        public = context(s, tables)
        proof = prove(Transcript(public, d), s, tables)
        receipt = verify_public(Transcript(public, d), s, proof, tables)
        wrong_layer = list(receipt['point']); wrong_layer[0] = sc.add(sc.scalar(1, d), sc.neg(wrong_layer[0]))
        bad = copy.deepcopy(proof)
        bad['final'][2] = evaluation(tables[2], wrong_layer, d)
        assert bad['final'][2] != proof['final'][2]
        verify_reduction(Transcript(public, d), s, bad)
        sc.rejects(lambda: verify_public(Transcript(public, d), s, bad, tables), 'ClaimMismatch')
        # A nested draw-order point is not an original canonical point.
        bad = copy.deepcopy(proof)
        draw_order = [receipt['point'][axis] for axis in permutation(s)]
        bad['final'][2] = evaluation(tables[2], draw_order, d)
        assert bad['final'][2] != proof['final'][2]
        verify_reduction(Transcript(public, d), s, bad)
        sc.rejects(lambda: verify_public(Transcript(public, d), s, bad, tables), 'ClaimMismatch')
        # Empty P and m=0 still check the public coefficient's one changed source value.
        s = fixture(d, 5)
        s['layout'] = [(0, 1)]*3
        s['terms'] = []
        s['coefficient'].update(selectors=[None]*3, values=[7])
        tables = [[element()] for _ in s['inputs']]
        claim(s, tables)
        public = context(s, tables)
        changed = copy.deepcopy(s); changed['coefficient']['values'][0] = 8
        proof = prove(Transcript(public, d), s, tables)
        bad = prove(Transcript(public, d), changed, tables)
        assert proof['rounds'] == bad['rounds'] and sum(a != b for a, b in zip(proof['final'], bad['final'])) == 1
        sc.rejects(lambda: verify_public(Transcript(public, d), s, bad, tables), 'CoefficientMismatch')
        # Exact original shapes, canonical values and zero padding precede replay.
        s = fixture(d, 0)
        s['layout'] = [(1, 1)]
        s['coefficient']['selectors'] = [None]
        s['inputs'] = [14]
        s['terms'] = [(sc.scalar(1, d), [0])]
        tables = [[sc.scalar(2, d), sc.scalar(0, d)]]
        claim(s, tables)
        public = context(s, tables)
        proof = prove(Transcript(public, d), s, tables)
        verify_public(Transcript(public, d), s, proof, tables)
        verifier = Transcript(public, 12-d); before = verifier.state
        sc.rejects(lambda: verify_public(verifier, s, proof, tables), 'InvalidStacked')
        assert verifier.state == before
        for wrong in ([], [[sc.scalar(2, d)]], [[sc.scalar(2, d), sc.scalar(1, d)]], [[(sc.P,)+(0,)*(d-1), sc.scalar(0, d)]]):
            verifier = Transcript(public, d); before = verifier.state
            sc.rejects(lambda: verify_public(verifier, s, proof, wrong), 'PublicShape')
            assert verifier.state == before
        # Omit the first Final only in an adversarial prover, never in the verifier.
        s['layout'] = [(1, 2)]
        tables = [[sc.scalar(2, d), sc.scalar(5, d)]]
        claim(s, tables)
        public = context(s, tables)
        second = copy.deepcopy(s); second['id'] += 1
        prover = Transcript(public, d)
        first = prove(prover, s, tables)
        honest = prove(prover, second, tables)
        omitted = Transcript(public, d)
        omitted.absorb(STACK, encode(s))
        i = instance(s)
        omitted.absorb(sc.INSTANCE, sc.instance_bytes(i, d))
        omitted.absorb(sc.ROUND, sc.message(i, 0, first['rounds'][0])); sc.challenge(omitted)
        stale = prove(omitted, second, tables)
        assert stale['rounds'] == honest['rounds'] and sum(a != b for a, b in zip(stale['final'], honest['final'])) == 1
        verifier = Transcript(public, d)
        verify_public(verifier, s, first, tables)
        sc.rejects(lambda: verify_public(verifier, second, stale, tables), 'FinalEvaluationMismatch')
        verifier = Transcript(public, d)
        verify_public(verifier, s, first, tables)
        verify_public(verifier, second, honest, tables)
        assert verifier.state == prover.state
    print(f'Closed public-stage cases per field: {counts}; exact rejection reasons and continuation checks pass.')
    print('Synthetic public relation only: no private source, CQIS identity, production NC or inference certification.')


if __name__ == '__main__':
    check()
