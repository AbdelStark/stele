# /// script
# requires-python = ">=3.12"
# dependencies = ["blake3==1.0.11"]
# ///
"""RFC-0006 A4 / Q20 weighted private-selection composition; research only."""
import copy
import hashlib
import itertools
import json
import math
import random
from weighted_private_selection import derive, prove, verify_reduction, Transcript, sc
from private_selection import _prepare, frame as legacy_frame, instance, ORIGINALS
from check_private_selection import weight, total, public
from weighted_mle import bounded as borrow_prefix


def oracle(meta, point, indices, d):
    axes, chosen, category = meta['layout'], meta['source_axes'], meta['category_axis']
    result = sc.scalar(0, d)
    for coords in itertools.product(*(range(1 << b) for b, _ in axes)):
        if any(i >= real for i, (_, real) in zip(coords, axes)):
            continue
        source_index, padded = 0, 0
        for axis in chosen:
            source_index = source_index*axes[axis][1]+coords[axis]
        if coords[category] != indices[source_index]:
            continue
        for i, (bits, _) in zip(coords, axes):
            padded = (padded << bits)+i
        value = weight(point, padded, d)
        for i, selector in zip(coords, meta['selectors']):
            if selector is not None:
                value = sc.mul(value, weight(selector, i, d))
        result = sc.add(result, value)
    return result


def consume(meta, indices, receipt, d):
    axes = tuple(meta['layout'][a] for a in meta['source_axes'])
    k, categories = meta['layout'][meta['category_axis']]
    if receipt['source'] != (meta['source_id'], axes, k, categories):
        raise ValueError('OriginalSourceScope')
    if len(indices) != math.prod(n for _, n in axes) or any(type(i) is not int or not 0 <= i < categories for i in indices):
        raise ValueError('SelectionSource')
    assert [j for j, _, _ in receipt['claims']] == list(range(k))
    for j, point, claimed in receipt['claims']:
        expected = sc.scalar(0, d)
        for index, coords in zip(indices, itertools.product(*(range(n) for _, n in axes))):
            padded = 0
            for coordinate, (bits, _) in zip(coords, axes):
                padded = (padded << bits)+coordinate
            if index >> (k-j-1) & 1:
                expected = sc.add(expected, weight(point, padded, d))
        if expected != claimed:
            raise ValueError('OriginalSourceMismatch')


def fixture(rng, d, case):
    while True:
        axes = [(rng.randrange(3), 0) for _ in range(4)]
        if sum(b for b, _ in axes) <= 6:
            break
    axes = [(b, rng.randrange(1, (1 << b)+1)) for b, _ in axes]
    category = case % 4
    candidates = [a for a in range(4) if a != category]
    chosen = sorted(a for j, a in enumerate(candidates) if case >> j & 1) or candidates[:1]
    element = lambda: tuple(rng.randrange(sc.P) for _ in range(d))
    selectors = [None if case >> a & 1 else tuple(element() for _ in range(b)) for a, (b, _) in enumerate(axes)]
    meta = dict(layout=tuple(axes), source_axes=tuple(chosen), category_axis=category,
                selectors=tuple(selectors), source_id=80+case)
    point = tuple(element() for _ in range(sum(b for b, _ in axes)))
    indices = [rng.randrange(axes[category][1]) for _ in range(math.prod(axes[a][1] for a in chosen))]
    return meta, point, indices


def run(meta, point, indices, value, d):
    p, v = Transcript(public(indices), d), Transcript(public(indices), d)
    proof = prove(p, meta, point, value, indices)
    receipt = verify_reduction(v, meta, point, value, proof)
    consume(meta, indices, receipt, d)
    assert p.state == v.state and sc.challenge(p) == sc.challenge(v)
    a = sum(meta['layout'][axis][0] for axis in meta['source_axes'])
    k = meta['layout'][meta['category_axis']][0]
    m = 1 << (max(1, k)-1).bit_length()
    assert receipt['sc'] == [dict(id=j, m=a, degree=2 if j == 0 else 3, field_degree=d,
                                numerator=a*(2 if j == 0 else 3)) for j in range(m)]
    size = sum(sum(map(len, p['rounds']))+len(p['final']) for p in [proof['root'], *proof['nodes']])+len(proof['originals'])
    assert size == a*(4*m-1)+3*m-1+k
    return proof, receipt


def check():
    rng, digest = random.Random(30624), hashlib.sha256()
    for d in (4, 8):
        zero, one = sc.scalar(0, d), sc.scalar(1, d)
        half, third = sc.scalar(pow(2, -1, sc.P), d), sc.scalar(pow(3, -1, sc.P), d)
        for case in range(1000):
            meta, point, indices = fixture(rng, d, case)
            value = oracle(meta, point, indices, d)
            raw, spec, rows, columns, scale, _ = derive(meta, point, value, d)
            assert len(raw) <= 4780
            _, tree, mask = _prepare(spec, rows, columns, scale, indices, d)
            assert total([sc.mul(a, b) for a, b in zip(mask, tree[1])], d) == value
            if case < 128:
                proof, receipt = run(meta, point, indices, value, d)
                digest.update(json.dumps([meta, point, indices, value, proof, receipt], sort_keys=True, separators=(',', ':')).encode())
        # Selector factors multiply on Boolean entries, before extension.
        meta = dict(layout=((0, 1), (1, 2)), source_axes=(0,), category_axis=1,
                    selectors=(None, (sc.scalar(3, d),)), source_id=7)
        point = (sc.scalar(2, d),)
        value = oracle(meta, point, [1], d)
        assert value == sc.scalar(6, d) and value != sc.scalar(16, d)
        run(meta, point, [1], value, d)
        # Valid zero-sum category pairs must not be normalized by division.
        meta['selectors'] = (None, (third,))
        _, _, _, pairs, _, _ = derive(meta, point, zero, d)
        assert sc.add(*pairs[0]) == zero and pairs[0][0] != zero
        run(meta, point, [1], oracle(meta, point, [1], d), d)
        # A private source has holes, not trailing padding, in its canonical grid.
        meta = dict(layout=((1, 2), (1, 2), (2, 3), (1, 2)), source_axes=(0, 2),
                    category_axis=1, selectors=(None, None, None, (third,)), source_id=19)
        point = (sc.scalar(2, d), half, sc.scalar(3, d), sc.scalar(4, d), sc.scalar(2, d))
        indices = [0, 1, 1, 0, 1, 0]
        value = oracle(meta, point, indices, d)
        assert value == zero  # Broadcast pair sums to zero, without erasing originals.
        raw, grid, *_ = derive(meta, point, value, d)
        encoded = bytes([1, d, 4])+b''.join(bytes([b])+n.to_bytes(8, 'little') for b, n in meta['layout'])
        encoded += bytes([2, 0, 2, 1])+(19).to_bytes(8, 'little')+bytes([0, 0, 0, 1])
        encoded += b''.join(limb.to_bytes(4, 'little') for v in [third, *point, value] for limb in v)
        assert raw == encoded
        sc.rejects(lambda: legacy_frame(grid, [zero]*3, [zero], value, d), 'SelectionShape')
        proof, receipt = run(meta, point, indices, value, d)
        assert len(receipt['claims']) == 1 and len(receipt['claims'][0][1]) == 3
        delta = weight(receipt['claims'][0][1], 3, d)  # First padded grid cell.
        assert delta != zero
        bad = copy.deepcopy(proof); bad['originals'][0] = sc.add(bad['originals'][0], delta)
        conditional = verify_reduction(Transcript(public(indices), d), meta, point, value, bad)
        sc.rejects(lambda: consume(meta, indices, conditional, d), 'OriginalSourceMismatch')
        bad_receipt = copy.deepcopy(receipt)
        bad_receipt['source'] = (20, *bad_receipt['source'][1:])
        sc.rejects(lambda: consume(meta, indices, bad_receipt, d), 'OriginalSourceScope')
        # Shape/identity/selector errors are rejected before transcript mutation.
        for key, wrong in [('source_axes', (2, 0)), ('source_axes', (0, 0)), ('category_axis', 0),
                           ('source_id', True), ('selectors', (None,)), ('values', indices)]:
            bad = {**meta, key: wrong}
            t = Transcript(public(indices), d); before = t.state
            sc.rejects(lambda: verify_reduction(t, bad, point, value, proof), 'SelectionShape')
            assert t.state == before
        sc.rejects(lambda: verify_reduction(Transcript(public(indices), d), meta, point[:-1], value, proof), 'SelectionShape')
        t = Transcript(public(indices), d); before = t.state
        sc.rejects(lambda: verify_reduction(t, meta, point, value, {**proof, 'extra': []}), 'ProofShape')
        assert t.state == before
        huge = dict(layout=((20, 1), (1, 2)), source_axes=(0,), category_axis=1,
                    selectors=(None, None), source_id=26)
        sc.rejects(lambda: prove(t, huge, (zero,)*21, zero, [0]), 'SelectionCapacity')
        assert t.state == before
        # Zero-width axes retain explicit selector flags and source scope.
        meta = dict(layout=((0, 1),)*64, source_axes=(1, 3, 63), category_axis=7,
                    selectors=tuple(() if a % 2 else None for a in range(64)), source_id=21)
        run(meta, (), [0], one, d)
        # Wide category and broadcast domains are never materialized by the candidate.
        meta = dict(layout=((0, 1), (63, (1 << 63)-1)), source_axes=(0,), category_axis=1,
                    selectors=(None, None), source_id=22)
        point = tuple(tuple(rng.randrange(sc.P) for _ in range(d)) for _ in range(63))
        index = (1 << 63)-2
        run(meta, point, [index], weight(point, index, d), d)
        meta = dict(layout=((0, 1), (1, 2), (62, (1 << 62)-3)), source_axes=(0,), category_axis=1,
                    selectors=(None, None, None), source_id=23)
        _, _, _, pairs, scale, _ = derive(meta, point, zero, d)
        expected_scale = borrow_prefix([(sc.add(one, sc.neg(q)), q) for q in point[1:]], (1 << 62)-3, d)
        assert scale == expected_scale
        run(meta, point, [1], sc.mul(expected_scale, pairs[0][1]), d)
        # Omit only the first Weighted absorb in an adversarial prover replay.
        first_meta = dict(layout=((0, 1), (1, 2)), source_axes=(0,), category_axis=1,
                          selectors=(None, None), source_id=24)
        p = Transcript(public([1]), d)
        first = prove(p, first_meta, (half,), half, [1])
        stale = Transcript(public([1]), d)
        sc.verify_reduction(stale, instance(0, 0, half, d), first['root'])
        stale.absorb(ORIGINALS, (1).to_bytes(4, 'little')+sc.encode(one))
        second_meta = dict(layout=((1, 2), (0, 1)), source_axes=(0,), category_axis=1,
                           selectors=(None, None), source_id=25)
        point = (sc.scalar(2, d),)
        honest = prove(p, second_meta, point, one, [0, 0])
        wrong = prove(stale, second_meta, point, one, [0, 0])
        assert honest['root']['rounds'] == wrong['root']['rounds']
        assert sum(a != b for a, b in zip(honest['root']['final'], wrong['root']['final'])) == 1
        v = Transcript(public([1]), d)
        consume(first_meta, [1], verify_reduction(v, first_meta, (half,), half, first), d)
        consume(second_meta, [0, 0], verify_reduction(v, second_meta, point, one, honest), d)
        assert v.state == p.state and sc.challenge(v) == sc.challenge(p)
        v = Transcript(public([1]), d)
        verify_reduction(v, first_meta, (half,), half, first)
        sc.rejects(lambda: verify_reduction(v, second_meta, point, one, wrong), 'FinalEvaluationMismatch')
    print(json.dumps(dict(algebra_per_field=1000, seeded_reductions_per_field=128,
                         seed=30624, sha256=digest.hexdigest()), sort_keys=True))
    print('Research composition only: original source/bit/range/PCS and joint ZK consumers remain required.')


if __name__ == '__main__':
    check()
