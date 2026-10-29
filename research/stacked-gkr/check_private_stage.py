# /// script
# requires-python = ">=3.12"
# dependencies = ["blake3==1.0.11"]
# ///
"""Q20 actual stacked-final composition; public oracle fixture, no private/ZK admission."""
import copy
import hashlib
import itertools
import json
import math
import random
from private_stage import Transcript, descriptor, prove, verify_reduction, PRIVATE_STACK, sc
from stage import evaluation, instance, public_tables
from check_stage import context as tensor_context, total
from check_weighted_private_selection import consume as consume_source, oracle, weight
from check_private_selection import public as source_context
from weighted_private_selection import prove as select_prove, verify_reduction as select_verify
from statement import layout


def context(s, tables, indices):
    c = s['coefficient']
    source_layout = tuple(c['layout'][a] for a in c['source_axes'])
    return (b'Q20/private-stage-fixture/v1'+tensor_context(s, tables)
            +c['source_id'].to_bytes(8, 'little')+layout(source_layout)
            +len(indices).to_bytes(8, 'little')+b''.join(i.to_bytes(8, 'little') for i in indices))


def coefficient(s, indices):
    # Independent sparse construction: place each source index, then broadcast.
    c, d = s['coefficient'], s['field']
    axes, chosen, category = c['layout'], c['source_axes'], c['category_axis']
    table = [sc.scalar(0, d)]*(1 << sum(b for b, _ in axes))
    broadcast = [a for a in range(len(axes)) if a not in chosen and a != category]
    for flat, index in enumerate(indices):
        coords = [0]*len(axes)
        coords[category] = index
        for axis in reversed(chosen):
            flat, coords[axis] = divmod(flat, axes[axis][1])
        assert flat == 0
        for values in itertools.product(*(range(axes[a][1]) for a in broadcast)):
            for axis, value in zip(broadcast, values):
                coords[axis] = value
            padded, value = 0, sc.scalar(1, d)
            for coordinate, (bits, _), selector in zip(coords, axes, c['selectors']):
                padded = (padded << bits)+coordinate
                if selector is not None:
                    value = sc.mul(value, weight(selector, coordinate, d))
            table[padded] = value
    return table


def claim(s, tables, indices):
    s['output']['value'] = total([sc.mul(a, sc.compose(s['terms'], [t[i] for t in tables], s['field']))
                                 for i, a in enumerate(coefficient(s, indices))], s['field'])


def consume(s, tables, indices, receipt):
    assert [i for i, _ in receipt['claims']] == s['inputs']
    for table, (_, value) in zip(tables, receipt['claims']):
        if evaluation(table, receipt['point'], s['field']) != value:
            raise ValueError('ClaimMismatch')
    consume_source(s['coefficient'], indices, receipt['selection'], s['field'])


def run(s, tables, indices):
    claim(s, tables, indices)
    public_tables(s, tables)
    public = context(s, tables, indices)
    p, v = Transcript(public, s['field']), Transcript(public, s['field'])
    proof = prove(p, s, tables, indices)
    assert len(descriptor(v, s)) <= 9361
    receipt = verify_reduction(v, s, proof)
    consume(s, tables, indices, receipt)
    assert p.state == v.state and sc.challenge(p) == sc.challenge(v)
    m = sum(b for b, _ in s['layout'])
    delta = max((len(factors)+1 for _, factors in s['terms']), default=0)
    assert receipt['sc'] == dict(id=s['id'], m=m, degree=delta, field_degree=s['field'], numerator=m*delta)
    assert proof['stage']['final'][-1] == oracle(s['coefficient'], receipt['point'], indices, s['field'])
    a = sum(s['layout'][i][0] for i in s['coefficient']['source_axes'])
    k = s['layout'][s['coefficient']['category_axis']][0]
    leaves = 1 << (max(1, k)-1).bit_length()
    assert receipt['selection']['sc'] == [dict(id=s['id']+1+j, m=a, degree=2 if j == 0 else 3,
        field_degree=s['field'], numerator=a*(2 if j == 0 else 3)) for j in range(leaves)]
    child = proof['selection']
    cells = sum(sum(map(len, part['rounds']))+len(part['final'])
                for part in [proof['stage'], child['root'], *child['nodes']])+len(child['originals'])
    assert cells == m*(delta+1)+len(s['inputs'])+1+a*(4*leaves-1)+3*leaves-1+k
    assert set(proof) == {'stage', 'selection'}
    return proof, receipt


def fixture(rng, d, case, axes=None, chosen=None, category=None, count=None):
    element = lambda: tuple(rng.randrange(sc.P) for _ in range(d))
    if axes is None:
        while True:
            bits = [rng.randrange(3) for _ in range(4)]
            if sum(bits) <= 5:
                break
        axes = tuple((b, rng.randrange(1, (1 << b)+1)) for b in bits)
    category = case % len(axes) if category is None else category
    chosen = tuple(a for a in range(len(axes)) if a != category and case >> a & 1) if chosen is None else chosen
    chosen = chosen or ((category+1) % len(axes),)
    c = dict(layout=axes, source_axes=chosen, category_axis=category, source_id=900,
             selectors=tuple(None if case >> a & 1 else tuple(element() for _ in range(b)) for a, (b, _) in enumerate(axes)))
    count = case % 4 if count is None else count
    power = case % 5 if count else 0
    terms = [] if power == 4 else [(element(), [0]*power)]
    s = dict(field=d, id=65*(case+1), layout=axes, order=case % 2, inputs=list(range(10, 10+count)),
             coefficient_id=30, coefficient=c, terms=terms,
             output=dict(id=20, layout=(), point=(), value=sc.scalar(0, d)))
    tables = [[element() for _ in range(1 << sum(b for b, _ in axes))] for _ in range(count)]
    for index, coords in enumerate(itertools.product(*(range(1 << b) for b, _ in axes))):
        if any(i >= n for i, (_, n) in zip(coords, axes)):
            for table in tables:
                table[index] = sc.scalar(0, d)
    indices = [rng.randrange(axes[category][1]) for _ in range(math.prod(axes[a][1] for a in chosen))]
    return s, tables, indices


def check():
    rng, digest = random.Random(30625), hashlib.sha256()
    for d in (4, 8):
        zero, one = sc.scalar(0, d), sc.scalar(1, d)
        for case in range(128):
            s, tables, indices = fixture(rng, d, case)
            proof, receipt = run(s, tables, indices)
            digest.update(json.dumps([s, tables, indices, proof, receipt], sort_keys=True, separators=(',', ':')).encode())
        for empty in (False, True):
            s, tables, indices = fixture(rng, d, 0, ((0, 1),)*3, (0, 2), 1, 0)
            s['terms'] = [] if empty else [(one, [])]
            run(s, tables, indices)
        # Independently assemble a metadata-only scalar frame, including empty selectors.
        s = dict(field=d, id=65, layout=((0, 1),)*2, order=0, inputs=[], terms=[], coefficient_id=30,
                 output=dict(id=20, layout=(), point=(), value=zero),
                 coefficient=dict(layout=((0, 1),)*2, source_axes=(0,), category_axis=1,
                                  selectors=(None, ()), source_id=900))
        u64 = lambda n: n.to_bytes(8, 'little')
        axes = bytes([2, 0])+u64(1)+bytes([0])+u64(1)
        expected = bytes([1, d])+u64(65)+axes+bytes([0])+u64(20)+bytes([0])+bytes(4*d)+u64(30)+bytes(8)
        expected += bytes([1, d])+axes+bytes([1, 0, 1])+u64(900)+bytes([0, 1])
        assert descriptor(Transcript(context(s, [], [0]), d), s) == expected
        run(s, [], [0])
        if d == 8:
            maximum = copy.deepcopy(s)
            axes = ((63, 1),)+((0, 1),)*63
            maximum.update(layout=axes, inputs=list(range(100, 164)), terms=[(zero, [0, 0, 0])]*64)
            maximum['output'].update(layout=axes, point=(zero,)*63)
            maximum['coefficient'].update(layout=axes, source_axes=tuple(range(63)), category_axis=63,
                                          selectors=((zero,)*63,)+((),)*63)
            assert len(descriptor(Transcript(b'frame-cap-only', d), maximum)) == 9361
        # A zero-dimensional source makes descendants invariant to one unused final.
        s, tables, indices = fixture(rng, d, 1, ((1, 2), (0, 1), (1, 2)), (1,), 2, 2)
        s['terms'] = [(one, [0])]
        proof, receipt = run(s, tables, indices)
        public = context(s, tables, indices)
        wrong_layer = list(receipt['point']); wrong_layer[0] = sc.add(one, sc.neg(wrong_layer[0]))
        for point in (wrong_layer, list(reversed(receipt['point']))):
            bad = copy.deepcopy(proof)
            bad['stage']['final'][1] = evaluation(tables[1], point, d)
            assert bad['stage']['final'][1] != proof['stage']['final'][1]
            conditional = verify_reduction(Transcript(public, d), s, bad)
            sc.rejects(lambda: consume(s, tables, indices, conditional), 'ClaimMismatch')
        # Empty P still consumes the actual coefficient final.
        s['terms'] = []
        proof, _ = run(s, tables, indices)
        bad = copy.deepcopy(proof); bad['stage']['final'][-1] = sc.add(bad['stage']['final'][-1], one)
        sc.rejects(lambda: verify_reduction(Transcript(context(s, tables, indices), d), s, bad), 'FinalEvaluationMismatch')
        # A coherent child at draw-order coordinates cannot replace the canonical child.
        s, tables, indices = fixture(rng, d, 1, ((1, 2),)*3, (1,), 2, 1)
        s['terms'], indices = [], [0, 1]
        proof, receipt = run(s, tables, indices)
        public = context(s, tables, indices)
        wrong_point = receipt['point'][1:]+receipt['point'][:1]
        bad = copy.deepcopy(proof)
        bad['stage']['final'][-1] = oracle(s['coefficient'], wrong_point, indices, d)
        assert bad['stage']['final'][-1] != proof['stage']['final'][-1]
        t = Transcript(public, d); t.absorb(PRIVATE_STACK, descriptor(t, s))
        sc.verify_reduction(t, instance(s), bad['stage'])
        bad['selection'] = select_prove(t, s['coefficient'], wrong_point, bad['stage']['final'][-1], indices, instance_base=s['id']+1)
        sc.rejects(lambda: verify_reduction(Transcript(public, d), s, bad), 'FinalEvaluationMismatch')
        # Closed metadata rejects source values, aliases and inconsistent views before absorb.
        for key, value in [('values', indices), ('source_id', s['coefficient_id']), ('source_id', s['inputs'][0]),
                           ('source_id', s['output']['id']),
                           ('layout', ((0, 1),)*3)]:
            bad_s = copy.deepcopy(s); bad_s['coefficient'][key] = value
            if key == 'layout':
                bad_s['coefficient']['selectors'] = (None,)*3
            t = Transcript(public, d); before = t.state
            sc.rejects(lambda: verify_reduction(t, bad_s, proof), 'InvalidStacked')
            assert t.state == before
        for key, value in [('inputs', list(range(65))), ('terms', [(zero, [])]*65),
                           ('id', 1), ('id', ((1 << 64)-1)//65*65)]:
            bad_s = {**s, key: value}
            sc.rejects(lambda: verify_reduction(t, bad_s, proof), 'InvalidStacked')
            assert t.state == before
        sc.rejects(lambda: prove(t, s, tables, [2, 1]), 'SelectionSource')
        assert t.state == before
        t = Transcript(public, d); before = t.state
        sc.rejects(lambda: verify_reduction(t, s, {**proof, 'extra': None}), 'ProofShape')
        assert t.state == before
        # A zero coefficient term retains its degree and all original obligations.
        s['terms'] = [(zero, [0, 0, 0])]
        run(s, tables, indices)
        huge = copy.deepcopy(s); huge['layout'] = ((20, 1), (0, 1), (0, 1))
        huge['coefficient'].update(layout=huge['layout'], selectors=(None,)*3)
        sc.rejects(lambda: prove(t, huge, [], [0]), 'StageCapacity')
        assert t.state == before
        # Omit only PrivateStack in a scalar first stage, then prove a real successor.
        first, ft, fi = fixture(rng, d, 0, ((0, 1),)*2, (0,), 1, 1)
        first['terms'] = [(one, [0])]; claim(first, ft, fi)
        second, st, si = fixture(rng, d, 1, ((1, 2), (0, 1)), (0,), 1, 1)
        second.update(inputs=[11], coefficient_id=31)
        second['output']['id'], second['coefficient']['source_id'] = 21, 901
        second['terms'] = [(one, [0])]; second['coefficient']['selectors'] = (None, None)
        st, si = [[sc.scalar(2, d), sc.scalar(5, d)]], [0, 0]; claim(second, st, si)
        public = context(first, ft, fi)+context(second, st, si)
        p = Transcript(public, d); initial = prove(p, first, ft, fi)
        honest = prove(p, second, st, si)
        stale = Transcript(public, d)
        sc.verify_reduction(stale, instance(first), initial['stage'])
        select_prove(stale, first['coefficient'], [], initial['stage']['final'][-1], fi, instance_base=first['id']+1)
        wrong = prove(stale, second, st, si)
        assert honest['stage']['rounds'] == wrong['stage']['rounds']
        assert sum(a != b for a, b in zip(honest['stage']['final'], wrong['stage']['final'])) == 1
        v = Transcript(public, d)
        consume(first, ft, fi, verify_reduction(v, first, initial))
        consume(second, st, si, verify_reduction(v, second, honest))
        assert v.state == p.state and sc.challenge(v) == sc.challenge(p)
        v = Transcript(public, d); verify_reduction(v, first, initial)
        sc.rejects(lambda: verify_reduction(v, second, wrong), 'FinalEvaluationMismatch')
        # A 64-node selection range reaches u64::MAX exactly; overflow rejects before absorb.
        meta = dict(layout=((0, 1), (63, 1)), source_axes=(0,), category_axis=1, selectors=(None, None), source_id=900)
        p, v = Transcript(source_context([0]), d), Transcript(source_context([0]), d)
        top = (1 << 64)-64
        proof = select_prove(p, meta, (zero,)*63, one, [0], instance_base=top)
        receipt = select_verify(v, meta, (zero,)*63, one, proof, instance_base=top)
        consume_source(meta, [0], receipt, d)
        assert receipt['sc'][-1]['id'] == (1 << 64)-1 and p.state == v.state
        before = v.state
        sc.rejects(lambda: select_verify(v, meta, (zero,)*63, one, proof, instance_base=top+1), 'SelectionShape')
        assert v.state == before
    print(json.dumps(dict(seed=30625, stages_per_field=128, sha256=digest.hexdigest()), sort_keys=True))
    print('Unmasked conditional composition: private source/bit/range/PCS and joint ZK remain required.')


if __name__ == '__main__':
    check()
