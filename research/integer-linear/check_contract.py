# /// script
# requires-python = ">=3.12"
# dependencies = ["blake3==1.0.11"]
# ///
"""RFC-0024 algebra evidence; no native proof, control or performance credit."""
import itertools
import json
from pathlib import Path
import random
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'sumcheck'))
import check_sumcheck as field
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'zerocheck'))
import check_zerocheck as zero

P = field.P


def weights(point, degree):
    result = [field.scalar(1, degree)]
    for coordinate in point:
        complement = field.add(field.scalar(1, degree), field.neg(coordinate))
        result = [field.mul(value, factor) for value in result
                  for factor in (complement, coordinate)]
    return result


def dot(left, right, degree):
    result = field.scalar(0, degree)
    for a, b in zip(left, right, strict=True):
        result = field.add(result, field.mul(a, b))
    return result


def mle(table, point, degree):
    # Direct Boolean-basis evaluation, independent of the folding implementation.
    return dot(table, weights(point, degree), degree)


def cap_residuals(value, bound, width=4):
    """Honest slack modulo the chosen width exposes a truncated-cap attack."""
    slack = (bound-value) % 256**width
    carry, residuals = 0, []
    for index in range(width):
        shift = 8*index
        total = ((value >> shift) & 255) + ((slack >> shift) & 255) + carry
        following = total // 256 if index+1 < width else 0
        residuals.append(total-((bound >> shift) & 255)-256*following)
        carry = following
    return residuals


def matches_reference_affine_join(degree, shape, rng):
    h, a, b, c = shape
    layers, rows, inner, columns = (2**exponent for exponent in shape)
    scalar = lambda value: field.scalar(value, degree)
    point = [tuple(rng.randrange(P) for _ in range(degree)) for _ in range(h+a+c)]
    layer_weights = weights(point[:h], degree)
    ax, aw = weights(point[h:h+a], degree), weights(point[h+a:], degree)
    x = [rng.randrange(-128, 128) for _ in range(rows*layers*inner)]
    w = [rng.randrange(-128, 128) for _ in range(columns*layers*inner)]
    x[0], w[0] = -128, -128
    signed = lambda source, row, layer, k: source[(row*layers+layer)*inner+k]
    accumulators = [sum(signed(x, i, l, k)*signed(w, j, l, k) for k in range(inner))
                    for l in range(layers) for i in range(rows) for j in range(columns)]
    assert all(abs(value) <= inner*128**2 for value in accumulators)
    expected = mle(list(map(scalar, accumulators)), point, degree)
    u_planes = [[scalar(((value+2**31) >> (8*t)) & 255) for value in accumulators]
                for t in range(4)]
    joined = field.neg(scalar(2**31))
    for t, plane in enumerate(u_planes):
        joined = field.add(joined, field.mul(scalar(256**t), mle(plane, point, degree)))
    assert joined == expected
    partials = []
    terminal = [tuple(rng.randrange(P) for _ in range(degree)) for _ in range(h+b)]
    for source, row_weights in ((x, ax), (w, aw)):
        raw = [dot(row_weights, [scalar(source[row*layers*inner+k]+128)
                                 for row in range(len(row_weights))], degree)
               for k in range(layers*inner)]
        sum_a = dot(row_weights, [scalar(1)]*len(row_weights), degree)
        shifted = [field.add(value, field.neg(field.mul(scalar(128), sum_a))) for value in raw]
        partials.append(shifted)
        folded = shifted
        for coordinate in terminal:
            folded = field.fold(folded, coordinate)
        b_col = weights(terminal, degree)
        sum_b = dot(b_col, [scalar(1)]*len(b_col), degree)
        restored = field.add(folded[0], field.mul(scalar(128), field.mul(sum_a, sum_b)))
        assert restored == dot(raw, b_col, degree)
        # The A9 physical point is row bits followed by (layer, inner) bits.
        row_point = point[h:h+a] if source is x else point[h+a:]
        assert restored == mle([scalar(value+128) for value in source], row_point+terminal, degree)
        assert sum_a == sum_b == scalar(1)
    reduced = scalar(0)
    for l in range(layers):
        for k in range(inner):
            reduced = field.add(reduced, field.mul(layer_weights[l],
                                field.mul(partials[0][l*inner+k], partials[1][l*inner+k])))
    assert reduced == expected


def rejects_changed_cap_and_join_finals(degree):
    scalar = lambda value: field.scalar(value, degree)
    # At B=16384, the new high cap column is v_2+s_2+c_2=256*c_3.
    # This actual reference A3 relation includes sigma as its first factor.
    terms = [(scalar(coefficient), factors) for coefficient, factors in
             [(1, [0, 1]), (1, [0, 2]), (1, [0, 3]), (0, [0]), (-256, [0, 4])]]
    instance = {'id': 9, 'm': 0, 'k': 0, 'ids': list(range(10, 15)), 'terms': terms}
    tables = [[scalar(value)] for value in (1, 0, 0, 0, 0)]
    proof = zero.prove(zero.Transcript(b'integer-linear-cap', degree), instance, tables)
    zero.verify(zero.Transcript(b'integer-linear-cap', degree), instance, proof, tables)
    # One changed encoded high slack final, after an accepted baseline.
    proof['final'][2][0] = scalar(1)
    field.rejects(lambda: zero.verify(zero.Transcript(b'integer-linear-cap', degree),
                                     instance, proof, tables), 'FinalEvaluationMismatch')
    joined = {'id': 20, 'm': 0, 'ids': [21, 22, 23], 'sum': scalar(6),
              'terms': [(scalar(1), [0, 1, 2])]}
    inputs = [[scalar(value)] for value in (2, 3, 1)]
    proof, _ = field.prove(field.Transcript(b'integer-linear-join', degree), joined, inputs)
    field.verify_public(field.Transcript(b'integer-linear-join', degree), joined, proof, inputs)
    proof['final'][0] = scalar(3)
    field.rejects(lambda: field.verify_public(field.Transcript(b'integer-linear-join', degree),
                                            joined, proof, inputs), 'FinalEvaluationMismatch')


def checks():
    shapes = list(itertools.product(range(2), repeat=4)) + [(1, 2, 2, 1), (2, 1, 1, 2)]
    for degree in (4, 8):
        rejects_changed_cap_and_join_finals(degree)
        rng = random.Random(0xE701E+degree)
        for shape in shapes:
            matches_reference_affine_join(degree, shape, rng)
        scalar = lambda value: field.scalar(value, degree)
        point = [scalar(2)]
        signed = mle([scalar(-1), scalar(2)], point, degree)
        sign = mle([scalar(1), scalar(0)], point, degree)
        magnitude = mle([scalar(1), scalar(2)], point, degree)
        wrong = field.mul(field.add(scalar(1), field.neg(field.mul(scalar(2), sign))), magnitude)
        assert signed == scalar(5) and wrong == scalar(9) and signed != wrong
        table = list(map(scalar, (0, 1, 2, 4)))
        assert mle(table, list(map(scalar, (2, 3))), degree) != mle(table, list(map(scalar, (3, 2))), degree)
    for b in range(16):
        bound = 2**b*128**2
        assert 2*bound < P
        for value in (0, 1, bound-1, bound):
            assert cap_residuals(value, bound) == [0]*4
        assert any(cap_residuals(bound+1, bound))
    assert 2*(2**16*128**2) >= P
    assert (P-0) % P == 0 and P > 2**15*128**2
    # Low two bytes alone cannot cap the original four-byte magnitude.
    bound, value = 128**2, 128**2+2**16
    assert cap_residuals(value, bound, 2) == [0, 0]
    assert any(cap_residuals(value, bound))
    assert any(cap_residuals(P, bound))
    # Each integer column equality is faithful under M31 without a new bound record.
    assert 2*255+1 < P and 255+256 < P
    return {'fields': [4, 8], 'affine_cases': 2*len(shapes), 'admitted_inner_exponents': list(range(16)),
            'rejected_inner_exponent': 16, 'counterexamples': ['0/p alias', 'truncated cap',
            'product of sign/magnitude MLEs', 'swapped physical point'],
            'reference_scalar_rejections': 4, 'native_proofs': False,
            'negative_control_credit': False, 'profile_admission': False}


if __name__ == '__main__':
    print(json.dumps(checks(), sort_keys=True))
