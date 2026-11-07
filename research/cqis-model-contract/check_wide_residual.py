# /// script
# requires-python = "==3.12.*"
# dependencies = ["blake3==1.0.11", "python-flint==0.9.0", "safetensors==0.6.2"]
# ///
"""RFC-0004 A14 / RFC-0021 A4: wide int24 residual stream, checked against its own text.

- rmsnorm_q version 2 against an exact-rational oracle written from RFC-0021 §2.3,
  including the extreme statistic, exponent, shift and int16 output endpoints.
- The quoted static bounds, the d <= 8192 faithfulness boundary and record sizes of
  schemas 20/21/22 over extreme parameters.
- Model codec: version selection, `Width` for mixed versions, distinct identity.
- Execution: a wide model accepts everything its narrow twin accepts, with identical
  results (the arithmetic is the same; only range limits differ), and the collection
  selects schemas 20/21/22 exactly at the wide slots.
Runs inside check_ci.py (model-contract group); standalone:
uv run --locked --script research/cqis-model-contract/check_wide_residual.py
"""
from dataclasses import replace
from fractions import Fraction
from itertools import product
import json
from math import gcd
from pathlib import Path
from random import Random
import sys

from blake3 import blake3

import arithmetic_bounds as arithmetic
import bound_collection
import check_bound_collection as bounds
from check_model_execution import fixture
import flow_bounds as flow
import model_codec
import model_execution as c
import rms_bounds as rms

sys.path.insert(0, str(Path(__file__).resolve().parents[1]/'cqis-tables'))
import certified_rmsnorm as norm  # noqa: E402

P2 = ((1 << 31)-1)//2


def rejects(f, reason):
    try:
        f()
    except ValueError as error:
        assert str(error) == reason, (str(error), reason)
        return
    raise AssertionError(('accepted', reason))


def oracle(d, F, G, E, en, ed, X, H, a_max):
    """RFC-0021 §2.3 from its definition with exact rationals."""
    q = Fraction(ed*sum(x*x for x in X)+en*d*4**F, ed*d*4**F)
    a = next((a for a in range(-23, a_max+1) if 16384 <= q/Fraction(4)**a < 65536), None)
    if a is None:
        raise ValueError('Normalization')
    M = int(q/Fraction(4)**a)
    J = next(j for j in range(8192, 16385) if M*(2*j-1)**2 <= 1 << 44 < M*(2*j+1)**2)
    e = F+G+21+a-E
    out = []
    for x, h in zip(X, H):
        T = x*h*J
        y = T*2**-e if e < 0 else (1 if T >= 0 else -1)*((abs(T)+(1 << e >> 1)) >> e)
        if not -32768 <= y <= 32767:
            raise ValueError('Overflow')
        out.append(int(y))
    return out


def norm_cases(rng):
    n = 0
    low, high = -(1 << 23), (1 << 23)-1
    for _ in range(10000):
        d = rng.choice((1, 2, 3, 5, 16))
        F, G, E = rng.choice((0, 1, 10, 30)), rng.randint(0, 30), rng.randint(0, 14)
        en, ed = rng.choice(((1, 1), (1, 100000), (7, (1 << 32)-1), ((1 << 32)-1, 1)))
        X = [rng.choice((low, high, 0, -1, rng.randint(low, high), rng.randint(-40000, 40000))) for _ in range(d)]
        H = [rng.choice((-32768, 32767, 0, rng.randint(-32768, 32767))) for _ in range(d)]
        p = norm.Parameters(d, F, G, E, en, ed, 2)
        try:
            expected = oracle(d, F, G, E, en, ed, X, H, 16)
        except ValueError as error:
            expected = str(error)
        try:
            result = norm.evaluate(p, X, H)
            got = result['output']
            norm.verify(p, X, H, result)
            assert -16 <= result['shift'] <= 97 and -23 <= result['norm']['a'] <= 16
        except ValueError as error:
            got = str(error)
        assert got == expected, (p, X, H, got, expected)
        n += 1
    # Domains: int24 X only at version 2, int16 gains always, d <= 8192 at version 2.
    rejects(lambda: norm.evaluate(norm.Parameters(1, 0, 0, 0, 1, 1), [32768], [1]), 'Domain')
    rejects(lambda: norm.evaluate(norm.Parameters(1, 0, 0, 0, 1, 1, 2), [1 << 23], [1]), 'Domain')
    rejects(lambda: norm.evaluate(norm.Parameters(1, 0, 0, 0, 1, 1, 2), [1], [32768]), 'Domain')
    rejects(lambda: norm.Parameters(8193, 0, 0, 0, 1, 1, 2), 'Parameters')
    rejects(lambda: norm.Parameters(1, 0, 0, 0, 1, 1, 3), 'Parameters')
    norm.Parameters(16384, 0, 0, 0, 1, 1, 1)
    # The largest exponent a = 16 is attained (F = 0, a maximal int24 statistic).
    assert norm.evaluate(norm.Parameters(1, 0, 0, 14, 1, (1 << 32)-1, 2), [low], [1])['norm']['a'] == 16
    return n


def bound_claims():
    """Every number RFC-0021 A4 and RFC-0004 A14 quote, at the parameter extremes."""
    worst = dict(N=0, P=0, A=0, D=0, MD=0, T=0, left=0, biased=0, size=0)
    eps = (1, (1 << 32)-2, (1 << 32)-1)  # includes the coprime near-maximal pairs
    for d, F, G, E, en, ed in product((1, 4097, 8191, 8192), (0, 30), (0, 30), (0, 14), eps, eps):
        if gcd(en, ed) != 1:
            continue
        schema, scalars, (emin, emax), roles = rms.derive(rms.RMSNorm(d, F, G, E, en, ed, 2))
        assert schema == 20 and len(scalars) == 42 and len(roles) == 28 and emax == F+G+37-E
        assert all(max(r[4]+r[5]) < P2 for r in roles)
        h, o, unit, s, n, p, fa, fd, aa, dd, md = scalars[:11]
        assert s == d << 46 and fd == 1 << 32 and scalars[13] == 1 << 38 and scalars[14] == 1 << 52
        worst.update(N=max(worst['N'], n), P=max(worst['P'], p), A=max(worst['A'], aa), D=max(worst['D'], dd),
                     MD=max(worst['MD'], md), T=max(worst['T'], scalars[14]),
                     left=max(worst['left'], scalars[18]), biased=max(worst['biased'], scalars[19]),
                     size=max(worst['size'], len(rms.encode(rms.RMSNorm(d, F, G, E, en, ed, 2)))))
    # Exactly the bounds quoted in RFC-0021 A4 / RFC-0004 A14.
    assert worst['N'] < 1 << 106 and worst['P'] < 1 << 105 and worst['A'] < 1 << 152
    assert worst['D'] < 1 << 137 and worst['MD'] < 1 << 153 and worst['T'] <= 1 << 52
    assert worst['left'] <= 1 << 68 and worst['biased'] < 1 << 97 and worst['size'] < 52*1024
    # Statistic faithfulness: largest side at 8192 as quoted; 8208 is the last faithful width.
    _, _, _, _, left, right = arithmetic._column(((8192, 1 << 23, 1 << 23),))
    assert max(left+right) == 1071628543
    arithmetic._column(((8208, 1 << 23, 1 << 23),))
    rejects(lambda: arithmetic._column(((8209, 1 << 23, 1 << 23),)), 'FieldBound')
    rejects(lambda: rms.RMSNorm(8193, 0, 0, 0, 1, 1, 2), 'Dimension')
    # Schema 22: Umax <= 2^54 at the extreme alignment, and faithful columns; schema 21 caps at 2^23.
    for fx, fy, fo in product((0, 30), (0, 30), (0, 30)):
        schema, scalars, _, roles = flow.derive(flow.Residual(8192, fx, fy, fo, 24))
        assert schema == 22 and scalars[6] <= 1 << 54 and scalars[1] == 1 << 23
        assert len(flow.encode(flow.Residual(8192, fx, fy, fo, 24))) < 52*1024
    for policy, scale in ((0, 0), (1, 1), (1, 65535)):
        a = arithmetic.Affine(14336, 8, 0, 65535, 0, 10, 30, policy, scale, None, 24)
        schema, scalars, _, _ = arithmetic.derive(a)
        assert schema == 21 and scalars[10] == 1 << 23 and scalars[9] <= 1 << 23 and len(arithmetic.encode(a)) < 52*1024
        assert arithmetic.derive(replace(a, output_bits=16))[0] == 1
    rejects(lambda: arithmetic.Affine(16, 8, 0, 1, 0, 0, 0, 0, 0, 0, 24), 'Width')
    return {k: v.bit_length() for k, v in worst.items() if k != 'size'} | dict(record_bytes=worst['size'])


def widen(m):
    w = lambda n: replace(n, version=2)
    return replace(m, blocks=tuple(replace(b, norm1=w(b.norm1), norm2=w(b.norm2)) for b in m.blocks),
                   final_norm=w(m.final_norm))


def model_cases(rng):
    counts = dict(narrow_accepted=0, wide_accepted=0, wide_only=0, rejected_both=0)
    for i in range(160):
        seed = rng.getrandbits(64)
        m, mp, sr, raw, _ = fixture(Random(seed), 1)
        w, wmp, wsr, wraw, _ = fixture(Random(seed), 1, version=2)
        assert w == widen(m) and (wmp, wsr, wraw) != (mp, sr, raw)
        # Codec: round trip, distinct identity, mixed versions reject, GPT-2 has no wide form.
        assert model_codec.decode(model_codec.encode(w)) == w
        assert blake3(model_codec.encode(w)).digest() != blake3(model_codec.encode(m)).digest()
        mixed = replace(w, final_norm=m.final_norm)
        rejects(lambda: model_codec.encode(mixed), 'Width')
        tokens = tuple(rng.randrange(m.shape.vocabulary) for _ in range(rng.randint(1, m.shape.context)))
        results = []
        for model, mp_, sr_, raw_ in ((m, mp, sr, raw), (w, wmp, wsr, wraw)):
            try:
                results.append(c.full(c.load(model, mp_, sr_, raw_, blake3(raw_).digest()), tokens))
            except ValueError as error:
                results.append(str(error))
        narrow, wide = results
        if type(narrow) is not str:
            assert type(wide) is not str and (wide.cuts, wide.logits) == (narrow.cuts, narrow.logits), (i, wide if type(wide) is str else 'differs')
            counts['narrow_accepted'] += 1
        if type(wide) is not str:
            counts['wide_accepted'] += 1
            counts['wide_only'] += type(narrow) is str
            assert all(-(1 << 23) <= v < 1 << 23 for cut in wide.cuts for row in cut for v in row)
        counts['rejected_both'] += type(narrow) is str and type(wide) is str
    assert counts['wide_only'] > 0, counts
    return counts


def collection_cases(rng):
    family, slots = 1, 0
    shape = bounds.Shape(family, 2, 4, 2, 1, 2, 7, 5, 3)
    m = widen(bounds.fixture(rng, family, shape, 0))
    scales = bounds.make_scales(rng, m)
    sr, rr = bounds.c.scales_codec.encode(m, scales), bounds.c.registry_codec.encode(m)
    raw = bound_collection.encode(m, sr, rr)
    bound_collection.validate(m, sr, rr, raw)
    wide = {'norm1': 20, 'norm2': 20, 'final.norm': 20, 'project.O': 21, 'project.down': 21,
            'residual.mid': 22, 'residual.out': 22}
    for name, _, value in bound_collection._records(m, scales):
        schema = bound_collection._encode(value)[len(arithmetic.PREFIX)+4]
        assert (schema in (20, 21, 22)) == (name in wide), (name, schema)
        if name in wide:
            assert schema == wide[name], (name, schema)
            slots += 1
    assert slots == 6*2+1  # six per layer, plus the final norm
    return dict(wide_slots=slots, collection_bytes=len(raw))


def report():
    rng = Random(0xA14)
    return dict(norm_cases=norm_cases(rng), bounds=bound_claims(), models=model_cases(rng),
                collection=collection_cases(rng))


if __name__ == '__main__':
    print(json.dumps(report(), sort_keys=True))
