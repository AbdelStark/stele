# /// script
# requires-python = "==3.12.*"
# dependencies = ["blake3==1.0.11", "python-flint==0.9.0", "safetensors==0.6.2"]
# ///
"""RFC-0004 A15: grouped activation rows, checked against their own text.

- Conversion and the grouped affine against exact-rational oracles written from the A15
  text, including int16 and gated endpoints, zero groups and the one-group identity
  (a grouped row with g = n is today's conversion and today's affine).
- The signed radix-256 digits of every folded value s*q and the per-digit matmul bound.
- The joins over Z (review B1/B2): the fold sign join rejects the gated X-p digit alias
  that a field equality admits, and the signed recombination rejects a flipped C_t that a
  magnitude recombination admits, with mixed-sign and extreme accumulators.
- Every number A15 quotes: digit counts and top digits, the fold-without-digits
  faithfulness limit, schemas 23/24/25 over extreme parameters (faithful columns,
  schema 1/21 totals, record sizes) and the Llama-3.1-8B cost counts.
- Model codec: mode 2 round trip and identity; every rejected encoding.
- Execution: grouped twins against the exact-rational model oracle, full/step/cache parity,
  and schemas 23/24/25 at exactly the grouped collection slots.
Runs inside check_ci.py (model-contract group); standalone:
uv run --locked --script research/cqis-model-contract/check_grouped_rows.py
"""
from dataclasses import replace
from fractions import Fraction
from itertools import product
import json
from random import Random

from blake3 import blake3

import arithmetic_bounds as arithmetic
import bound_collection
import check_bound_collection as bounds
from check_model_execution import compare, fixture, grouped, reference
import flow_bounds as flow
import model_codec
import model_execution as c
from numerics import affine, grouped_affine

P = (1 << 31)-1


def rejects(f, reason):
    try:
        f()
    except ValueError as error:
        assert str(error) == reason, (str(error), reason)
        return
    raise AssertionError(('accepted', reason))


def nearest(x):
    """R of RFC-0025 §2: signed round half away from zero of a rational."""
    q, r = divmod(abs(x.numerator), x.denominator)
    return (1 if x >= 0 else -1)*(q+(2*r >= x.denominator))


def oracle_row(X, g):
    """A15: each group k of g values is one dynamic conversion, s_k = ceil(max|X|/127)."""
    codes, scales = [], []
    for k in range(0, len(X), g):
        part = X[k:k+g]; s = -(-max(map(abs, part))//127)
        scales.append(s); codes += [nearest(Fraction(x, s)) if s else 0 for x in part]
    return tuple(codes), tuple(scales)


def oracle_affine(codes, scales, w, m, e, f, fo, bias, fb, bits):
    """A15: Y = R(sum_i s_k(i)*q_i*w_i*m*2^(e-f+fo) + B*2^(fo-fb)), one rounding."""
    g = len(codes)//len(scales)
    a = sum(scales[i//g]*q*x for i, (q, x) in enumerate(zip(codes, w)))
    y = nearest(Fraction(a*m)*Fraction(2)**(e-f+fo)+Fraction(bias)*Fraction(2)**(fo-fb))
    if not -(1 << (bits-1)) <= y < 1 << (bits-1):
        raise ValueError('Range')
    return y


def digits(v, count):
    """Signed radix-256 digits of v: all but the last in [-128,127] (balanced remainders)."""
    out = []
    for _ in range(count-1):
        b = (v+128) % 256-128; out.append(b); v = (v-b)//256
    return out+[v]


def conversion_cases(rng):
    n, widest = 0, [0, 0]
    for _ in range(10000):
        kind = rng.randrange(2); h = 1 << 30 if kind else 32768
        size = rng.choice((1, 2, 3, 4, 6, 8, 12, 16)); g = rng.choice([1 << t for t in range(5) if size % (1 << t) == 0])
        X = tuple(rng.choice((-h, h-1+kind, 0, rng.randint(-h, h-1+kind), rng.randint(-300, 300))) for _ in range(size))
        expected = oracle_row(X, g)
        row = c.convert(X, 7, (0, 0), bool(kind)) if g == size else c.convert(X, 7, (2, g), bool(kind))
        got = (row.codes, (row.scale,) if g == size else row.scale)
        assert got == expected, (X, g, got, expected)
        smax, x, count, top = arithmetic.digit_bounds(kind)
        for i, q in enumerate(row.codes):
            v = expected[1][i//g]*q
            assert abs(v) <= x and abs(q) <= 127 and expected[1][i//g] <= smax
            d = digits(v, count)
            assert sum(b << (8*t) for t, b in enumerate(d)) == v and all(-128 <= b <= 127 for b in d[:-1])
            assert abs(d[-1]) <= top; widest[kind] = max(widest[kind], abs(d[-1]))
        n += 1
    assert widest == [128, 64], widest  # both quoted top digits are attained
    # The extreme folded value: 127*259 at an int16 endpoint, 127*8454661 at 2^30.
    assert c.convert((32767, 0), 0, (2, 1)).scale == (259, 0) and c.convert((32767,), 0, (0, 0)).codes == (127,)
    assert c.convert((1 << 30, 1), 0, (2, 1), True).scale == (8454661, 1)
    rejects(lambda: c.convert((1, 2, 3, 4), 0, (2, 4)), 'Scale')
    rejects(lambda: c.convert((1, 2, 3, 4, 5, 6), 0, (2, 4)), 'Scale')
    rejects(lambda: c.convert((1, 2, 3), 0, (2, 3)), 'Scale')
    return n


def affine_cases(rng):
    n = equal = 0
    for _ in range(4000):
        kind = rng.randrange(2); h = 1 << 30 if kind else 32768
        inner = rng.choice((1, 2, 4, 8, 16)); g = rng.choice([1 << t for t in range(5) if inner % (1 << t) == 0 and 1 << t < inner] or [1])
        bits = rng.choice((4, 8)); qw = (1 << (bits-1))-1
        X = tuple(rng.choice((-h, h-1+kind, 0, rng.randint(-h, h-1+kind))) for _ in range(inner))
        w = tuple(rng.choice((-qw, qw, rng.randint(-qw, qw))) for _ in range(inner))
        m, e = rng.choice((1, 65535, rng.randint(1, 65535))), rng.choice((-1099, 1024, rng.randint(-40, 10)))
        f, fo, fb = rng.randint(0, 44 if kind else 30), rng.randint(0, 30), rng.randint(0, 30)
        bias, out = rng.choice((0, -32768, 32767, rng.randint(-99, 99))), rng.choice((16, 24))
        codes, scales = oracle_row(X, g)
        a = sum(scales[i//g]*q*x for i, (q, x) in enumerate(zip(codes, w)))
        assert abs(a) <= inner*127*arithmetic.digit_bounds(kind)[0]*qw
        # Digit rows: each C_t is an ordinary bounded dot, and A' = sum_t 256^t*C_t exactly.
        smax, x, count, top = arithmetic.digit_bounds(kind)
        rows = [digits(scales[i//g]*q, count) for i, q in enumerate(codes)]
        C = [sum(r[t]*y for r, y in zip(rows, w)) for t in range(count)]
        assert sum(v << (8*t) for t, v in enumerate(C)) == a and all(8*abs(v) < P for v in C)
        try:
            expected = oracle_affine(codes, scales, w, m, e, f, fo, bias, fb, out)
        except ValueError as error:
            expected = str(error)
        try:
            got = grouped_affine(a, m, e, f, fo, bias, fb, out)
        except ValueError as error:
            got = str(error)
        assert got == expected, (X, g, got, expected)
        # One group: A' = s*A and the grouped affine is today's affine.
        one, (s,) = oracle_row(X, inner)
        dot = sum(q*y for q, y in zip(one, w))
        try:
            today = affine(dot, m, s, e, f, fo, bias, fb, out)
        except ValueError as error:
            today = str(error)
        try:
            again = grouped_affine(s*dot, m, e, f, fo, bias, fb, out)
        except ValueError as error:
            again = str(error)
        assert today == again, (X, today, again)
        equal += 1; n += 1
    return dict(cases=n, one_group_equal=equal)


def bound_claims():
    """Every number RFC-0004 A15 quotes, at the parameter extremes."""
    assert arithmetic.digit_bounds(0) == (259, 32893, 2, 128) and arithmetic.digit_bounds(1) == (8454661, 1073741947, 4, 64)
    # Folding without digits: one field matmul over s*q is faithful only for inner <= 257 (int16
    # sources), and a single gated folded value already exceeds p/2.
    assert 2*257*32893*127 < P <= 2*258*32893*127 and 2*1073741947 > P
    worst = dict(affine=0, row=0, ratio=Fraction(0))
    for inner, bits, kind, m, e, out, bias, f, fo in product((1, 2, 4096, 14336, 16384), (4, 8), (0, 1), (1, 65535),
                                                             (-1099, 0, 1024), (16, 24), (None, 0, 30), (0, 30, 44), (0, 30)):
        if out == 24 and bias is not None or f > (44 if kind else 30):
            continue
        for g in sorted({1, 128, grouped((0, 0), inner)[1]} & {1 << t for t in range(14) if 1 << t < inner and inner % (1 << t) == 0}):
            p = arithmetic.Affine(inner, bits, e, m, kind, f, fo, 2, g, bias, out)
            schema, scalars, shifts, roles = arithmetic.derive(p)
            today = arithmetic.derive(replace(p, policy=0, scale=0))
            assert schema == (24 if out == 16 else 25) and today[0] == (1 if out == 16 else 21)
            assert scalars[8] == today[1][4] and scalars[9:15] == today[1][5:11] and shifts == today[2]
            assert scalars[7] >= scalars[6] and roles[4+scalars[3]:] == today[3][2:]  # V >= amax; schema 1/21's sign, alignment, rounding
            assert all(2*max(r[4]+r[5]) < P for r in roles) and 8*scalars[5] < P
            worst['ratio'] = max(worst['ratio'], Fraction(8*scalars[5], P))
            worst['affine'] = max(worst['affine'], len(arithmetic.encode(p)))
    assert 8*16384*128*127 == 2130706432 < P and 16384*1073741947*127 < 1 << 51
    for d, kind, fraction in product((2, 4096, 14336, 16384), (0, 1), (0, 30)):
        for g in {1, 128, grouped((0, 0), d)[1]}:
            if g >= d:
                continue
            r = flow.Row(d, kind, fraction, 2, g)
            schema, scalars, _, roles = flow.derive(r)
            base = flow.derive(flow.Row(g, kind, fraction, 0, 0))
            assert schema == 23 and roles[:len(base[3])] == base[3] and scalars[:len(base[1])] == base[1]
            assert all(2*max(x[4]+x[5]) < P for x in roles)
            worst['row'] = max(worst['row'], len(flow.encode(r)))
    assert worst['affine'] < 54*1024 and worst['row'] < 27*1024
    rejects(lambda: flow.Row(4, 0, 0, 2, 4), 'Scale')
    rejects(lambda: arithmetic.Affine(6, 8, 0, 1, 0, 0, 0, 2, 4, None), 'Scale')
    return dict(affine_record_bytes=worst['affine'], row_record_bytes=worst['row'],
                digit_bound_over_p=float(worst['ratio']))


def fold_join(d, F, b, count, top):
    """Schema 23's join over Z: digit ranges and sum_t 256^t*o_t + 2*b*F = c + F."""
    c = 128*((1 << (8*(count-1)))-1)//255+(top << (8*(count-1)))
    o = [x+128 for x in d[:-1]]+[d[-1]+top]
    return all(0 <= x <= 255 for x in o[:-1]) and 0 <= o[-1] <= 2*top and \
        sum(x << (8*t) for t, x in enumerate(o))+2*b*F == c+F


def recombine_join(U, cmax, a, sign, W=None):
    """Schemas 24/25's consumer as the spec states it, over Z: each U_t has four range_8 bytes,
    sum_t 256^t*U_t + 2*sign*|A'| = V + |A'| with |A'| <= amax, and (B3) each W_t has four
    range_8 bytes with U_t + W_t = 2*cmax_t. W=None is the pre-B3 consumer without W."""
    v = sum(m << (8*t) for t, m in enumerate(cmax))
    ok = all(0 <= u < 1 << 32 for u in U) and sum(u << (8*t) for t, u in enumerate(U))+2*sign*a == v+a and a <= v
    if W is None:
        return ok
    return ok and all(0 <= w < 1 << 32 and u+w == 2*m for u, w, m in zip(U, W, cmax))


def join_cases(rng):
    """B1/B2 of the A15 review: honest witnesses satisfy both joins, and the forgeries that
    a field equality or a magnitude recombination would admit fail them."""
    n = 0
    for kind in (0, 1):
        smax, x, count, top = arithmetic.digit_bounds(kind)
        for v in (x, -x, 0, 1, -1)+tuple(rng.randint(-x, x) for _ in range(2000)):
            assert fold_join(digits(v, count), abs(v), int(v < 0), count, top); n += 1
            assert not fold_join(digits(v, count), abs(v), int(v >= 0), count, top) or v == 0
    # The gated X-p alias: in range, equal to X mod p, wrong over Z.
    smax, x, count, top = arithmetic.digit_bounds(1)
    alias = (124, 0, 0, -64)
    assert sum(b << (8*t) for t, b in enumerate(alias)) == x-P and digits(x-P, 4) == list(alias)
    assert not fold_join(alias, x, 0, count, top) and fold_join(digits(x, 4), x, 0, count, top)
    for F in (1065320319, x)+tuple(rng.randint(1065320319, x) for _ in range(200)):
        d = digits(F-P, 4)
        assert all(-128 <= b <= 127 for b in d[:-1]) and abs(d[-1]) <= top  # an in-range alias exists
        assert not fold_join(d, F, 0, count, top); n += 1
    assert abs(digits(1065320318-P, 4)[-1]) > top  # and none below that magnitude
    # Recombination: mixed signs and extremes pass; a magnitude sum gives the wrong A'.
    assert sum(abs(c) << (8*t) for t, c in enumerate((-5, 1))) == 261 != 251 == -5+256
    for kind, inner in product((0, 1), (1, 4096, 16384)):
        smax, x, count, top = arithmetic.digit_bounds(kind)
        cmax = [inner*127*(128 if t < count-1 else top) for t in range(count)]
        draws = [[rng.choice((-m, m, 0, -5, 1, rng.randint(-m, m))) for m in cmax] for _ in range(300)]
        for C in draws+[[-5, 1]+[0]*(count-2), [-m for m in cmax], cmax]:
            a = sum(c << (8*t) for t, c in enumerate(C))
            U = [c+m for c, m in zip(C, cmax)]
            assert recombine_join(U, cmax, abs(a), int(a < 0), [2*m-u for u, m in zip(U, cmax)]); n += 1
            # A flipped C_t with a recomputed |A'| is another consistent recombination: the join
            # cannot catch it; the C_t <-> digit-row matmul claim does. NC-0135 targets U_t+p.
            for t, c in enumerate(C):
                if c:
                    F = C[:t]+[-c]+C[t+1:]; b = sum(y << (8*j) for j, y in enumerate(F)); FU = [y+m for y, m in zip(F, cmax)]
                    assert recombine_join(FU, cmax, abs(b), int(b < 0), [2*m-u for u, m in zip(FU, cmax)])
    # B3: U_0 + p keeps valid bytes and its residue. It balances the pre-B3 join with
    # A'' = A'+p <= amax, and fails U_t + W_t = 2*cmax_t for every W_t in byte range.
    inner = 16384; cmax = [inner*127*128, inner*127*128]
    amax = inner*32893*127
    C = [1000, -3]; a = 1000-3*256; U = [c+m for c, m in zip(C, cmax)]
    forged = [U[0]+P, U[1]]
    assert a == 232 and forged[0] < 1 << 32 and a+P <= amax and (forged[0]-C[0]-cmax[0]) % P == 0
    assert recombine_join(forged, cmax, a+P, 0)  # bytes only: the forgery passes
    assert 2*cmax[0]-forged[0] < 0  # no W_0 in byte range closes U_0 + W_0 = 2*cmax_0
    assert not recombine_join(forged, cmax, a+P, 0, [2*m-u for u, m in zip(forged, cmax)])
    assert all(not recombine_join(forged, cmax, a+P, 0, [w, 2*cmax[1]-U[1]]) for w in (0, 1, (1 << 32)-1))
    return n


def llama_costs():
    """A15 cost counts for Llama-3.1-8B with all four affine-input rows and Policy(final)
    grouped at g = 128. Per token and layer unless noted. Memberships: one range_8 per low
    digit, two range_16 per last digit, four range_8 per added digit-row accumulator."""
    d, ff, kv, vocab, layers = 4096, 14336, 1024, 128256, 32
    outputs = dict(Q=d, K=kv, V=kv, O=d, up=ff, gate=ff, down=d)
    T = dict(Q=2, K=2, V=2, O=2, up=2, gate=2, down=4)
    base = sum(outputs.values())
    extra = sum((T[k]-1)*v for k, v in outputs.items())
    folds = 3*d+ff
    digit_values = 2*3*d+4*ff
    digit_memberships = 3*3*d+5*ff
    accumulator_memberships = 4*extra+4*(base+extra)  # U bytes of added rows; W bytes of every row (B3)
    partials = sum(v*(d if k != 'down' else ff)//128 for k, v in outputs.items())
    assert (base, extra, folds, digit_values, partials) == (43008, 51200, 26624, 81920, 1703936)
    assert (digit_memberships, accumulator_memberships) == (108544, 581632)
    # Head, per token: T = 2 accumulators per logit, d folds, 3d digit memberships.
    head = dict(accumulators=vocab, folds=d, memberships=3*d+4*vocab+4*2*vocab)
    assert head == dict(accumulators=128256, folds=4096, memberships=1551360)
    # Estimate (not a bound): an accumulator or fold is one N_act element; two memberships
    # count as one element (docs/cost-model.md assumes 1.5-3 lookups per element).
    n_act = 7*d+4*kv+4*ff
    layer = extra+folds+(digit_memberships+accumulator_memberships)//2
    per_token_head = head['accumulators']+head['folds']+head['memberships']//2
    total = n_act+layer+per_token_head//layers
    assert (n_act, layer, per_token_head, total, 3*d//128+ff//128) == (90112, 422912, 908032, 541400, 208)
    assert Fraction(6, 1) < Fraction(total, n_act) < Fraction(61, 10)  # T_act 0.9 s -> about 5.4 s
    return dict(projection_outputs=base, extra_digit_accumulators=extra, folds=folds,
                digit_memberships=digit_memberships, accumulator_memberships=accumulator_memberships,
                per_group_partials=partials, n_act_estimate=total)


def codec_cases(rng):
    n = 0
    for i in range(80):
        seed = rng.getrandbits(64)
        m = fixture(Random(seed), i % 2)[0]
        gm = fixture(Random(seed), i % 2, group=True)[0]
        assert model_codec.decode(model_codec.encode(gm)) == gm
        if gm != m:
            assert blake3(model_codec.encode(gm)).digest() != blake3(model_codec.encode(m)).digest()
            n += 1
        b = m.blocks[0]; s = m.shape
        for j in (1, 2, 3):  # Q/K/V rows are never grouped (A15 defers them)
            rejects(lambda: model_codec.encode(replace(m, blocks=(replace(b, policies=b.policies[:j]+((2, 1),)+b.policies[j+1:]),)+m.blocks[1:])), 'Policy')
        for value in ((2, s.width), (2, 0), (2, 3) if s.width % 3 else (2, s.width+1), (3, 0), (2, 1 << 20)):
            rejects(lambda: model_codec.encode(replace(m, final_policy=value)), 'Policy')
    assert model_codec.policy((0, 0)) == bytes(5) and model_codec.policy((2, 128), n=4096) == b'\2'+(128).to_bytes(4, 'little')
    rejects(lambda: model_codec.policy((2, 128)), 'Policy')
    assert grouped((0, 0), 6) == (2, 2) and grouped((0, 0), 8) == (2, 4) and grouped((1, 3), 8) == (1, 3) and grouped((0, 0), 1) == (0, 0)
    return n


def model_cases(rng):
    counts = dict(accepted=0, rejected=0, grouped_differs=0)
    for i in range(60):
        seed = rng.getrandbits(64)
        m, mp, sr, raw, arrays = fixture(Random(seed), i % 2, group=True)
        tokens = tuple(rng.randrange(m.shape.vocabulary) for _ in range(rng.randint(1, m.shape.context)))
        try:
            expected = reference(m, arrays, tokens)
        except ValueError as error:
            data = c.load(m, mp, sr, raw, blake3(raw).digest())
            rejects(lambda: c.full(data, tokens), str(error)); counts['rejected'] += 1
            continue
        compare(m, mp, sr, raw, arrays, tokens, expected)  # exact-rational oracle, full/step/cache parity
        counts['accepted'] += 1
        u, ump, usr, uraw, _ = fixture(Random(seed), i % 2)
        try:
            counts['grouped_differs'] += c.full(c.load(u, ump, usr, uraw, blake3(uraw).digest()), tokens).logits != \
                c.full(c.load(m, mp, sr, raw, blake3(raw).digest()), tokens).logits
        except ValueError:
            pass
    assert counts['accepted'] > 20 and counts['grouped_differs'] > 0, counts
    return counts


def collection_cases(rng):
    found = {}
    for family, version in ((0, 1), (1, 1), (1, 2)):
        shape = bounds.Shape(family, 2, 4, 2, 2 if not family else 1, 2, 16 if not family else 8, 5, 3)
        m = bounds.fixture(rng, family, shape, 0)
        if version == 2:
            v = lambda n: replace(n, version=2)
            m = replace(m, blocks=tuple(replace(b, norm1=v(b.norm1), norm2=v(b.norm2)) for b in m.blocks), final_norm=v(m.final_norm))
        m = replace(m, blocks=tuple(replace(b, policies=tuple(grouped((0, 0) if n else p, n) for p, n in zip(b.policies, (4, 0, 0, 0, 4, 4, shape.hidden))))
                                    for b in m.blocks), final_policy=grouped((0, 0), 4))
        scales = bounds.make_scales(rng, m)
        sr, rr = bounds.c.scales_codec.encode(m, scales), bounds.c.registry_codec.encode(m)
        bound_collection.validate(m, sr, rr, bound_collection.encode(m, sr, rr))
        index = {'convert.first': 0, 'convert.attention': 4, 'convert.second': 5, 'convert.ffn': 6,
                 'project.Q': 0, 'project.K': 0, 'project.V': 0, 'project.O': 4, 'project.up': 5, 'project.gate': 5, 'project.down': 6}
        for name, layer, value in bound_collection._records(m, scales):
            schema = bound_collection._encode(value)[len(arithmetic.PREFIX)+4]
            policy = (m.final_policy if name in ('convert.final', 'project.head') else
                      m.blocks[layer].policies[index[name]] if name in index else (0, 0))
            if name.startswith('convert.') and policy[0] == 2:
                assert schema == 23, (name, schema)
            elif name.startswith('project.') and policy[0] == 2:
                assert schema == (25 if version == 2 and name in ('project.O', 'project.down') else 24), (name, schema)
            else:
                assert schema not in (23, 24, 25), (name, schema)
            if schema in (23, 24, 25):
                found[schema] = found.get(schema, 0)+1
    assert set(found) == {23, 24, 25}, found
    return {str(k): v for k, v in sorted(found.items())}


def report():
    rng = Random(0xA15)
    return dict(conversions=conversion_cases(rng), affines=affine_cases(rng), bounds=bound_claims(), joins=join_cases(rng),
                costs=llama_costs(), codec=codec_cases(rng), models=model_cases(rng),
                collection=collection_cases(rng))


if __name__ == '__main__':
    print(json.dumps(report(), sort_keys=True))
