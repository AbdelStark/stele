"""RFC-0004 A15 / RFC-0025 A2: native grouped-row fixtures from the research reference.

Python 3.12, blake3==1.0.11, python-flint==0.9.0, safetensors==0.6.2.
Expected values come from the research production reference (model_execution.convert,
arithmetic/flow bounds, model/registry/bound codecs and model_execution), which
check_grouped_rows.py qualifies against exact-rational oracles.
"""
from dataclasses import replace
from hashlib import sha256
import json
from pathlib import Path
from random import Random
from struct import pack
import sys
from blake3 import blake3

ROOT = Path(__file__).resolve().parents[4]
sys.path.insert(0, str(ROOT/'research/cqis-model-contract'))
sys.path.insert(0, str(ROOT/'research/cqis-tables'))
from check_model_execution import fixture
import arithmetic_bounds as arithmetic
import artifact_codec
import bound_collection
import flow_bounds as flow
import model_codec
import model_execution as execution
import registry_codec
import request_bounds as request

SEED = 0xA15F
rng = Random(SEED)
binary = bytearray()


def store(raw):
    at = dict(offset=len(binary), length=len(raw))
    binary.extend(raw)
    return at


def outcome(f):
    try:
        return f()
    except ValueError as error:
        return str(error)


# Grouped conversions, int16 and gated, with endpoint, zero and one-value groups.
conversions = []
for i in range(600):
    kind = i % 2
    h = 1 << 30 if kind else 32768
    size = rng.choice((2, 4, 6, 8, 12, 16))
    g = rng.choice([1 << t for t in range(5) if size % (1 << t) == 0 and 1 << t < size])
    X = tuple(rng.choice((-h, h-1+kind, 0, rng.randint(-h, h-1+kind), rng.randint(-300, 300))) for _ in range(size))
    if i < 2:
        X, g = ((32767, 0), 1) if kind == 0 else ((1 << 30, 1), 1)  # the extreme folds 127*259, 127*8454661
    row = execution.convert(X, 7, (2, g), bool(kind))
    conversions.append(dict(kind=kind, group=g, input=X, codes=row.codes, scales=row.scale))
assert conversions[0]['scales'] == (259, 0) and conversions[1]['scales'] == (8454661, 1)
bad_conversions = []
for X, g in (((1, 2, 3, 4), 4), ((1, 2, 3, 4, 5, 6), 4), ((1, 2, 3), 3), ((1, 2, 3, 4), 0), ((1,), 1)):
    assert outcome(lambda: execution.convert(X, 0, (2, g))) == 'Scale'
    bad_conversions.append(dict(dimension=len(X), group=g))


def record(kind, parameters, raw):
    offset = len(arithmetic.PREFIX)
    return dict(kind=kind, parameters=parameters, schema=raw[offset+4], length=len(raw), digest=blake3(raw).hexdigest())


records = []
for d, kind, fraction, g in ((2, 0, 0, 1), (4096, 0, 30, 128), (14336, 1, 44, 128), (16384, 1, 0, 8192),
                             (16384, 0, 7, 1), (12, 1, 30, 4), (8, 0, 10, 4)):
    raw = flow.encode(flow.Row(d, kind, fraction, 2, g))
    records.append(record('Row', [d, kind, fraction, 2, g], raw))
for inner, bits, exponent, mantissa, kind, fraction, output, g, bias, bits_out in (
        (16384, 8, 0, 65535, 1, 44, 30, 128, None, 24), (16384, 8, 0, 65535, 0, 30, 30, 1, 30, 16),
        (14336, 4, -20, 3, 1, 8, 10, 128, None, 16), (2, 8, 1024, 1, 0, 0, 0, 1, None, 24),
        (4096, 8, -1099, 65535, 0, 0, 30, 128, 0, 16), (16, 8, -4, 2, 0, 7, 6, 4, 6, 16), (8, 4, 0, 1, 1, 13, 7, 2, None, 24)):
    a = arithmetic.Affine(inner, bits, exponent, mantissa, kind, fraction, output, 2, g, bias, bits_out)
    records.append(record('Affine', [inner, bits, exponent, mantissa, kind, fraction, output, 2, g,
                                     -1 if bias is None else bias, bits_out], arithmetic.encode(a)))
assert {r['schema'] for r in records} == {23, 24, 25}
assert outcome(lambda: flow.Row(4, 0, 0, 2, 4)) == 'Scale'
assert outcome(lambda: arithmetic.Affine(6, 8, 0, 1, 0, 0, 0, 2, 4, None)) == 'Scale'

# Grouped twins: family 0 and 1 at version 1, and wide Llama (schema 25 at O/down).
models = []
counts = dict(accepted=0, rejected=0, grouped_differs=0)
for i in range(120):
    family, version = ((0, 1), (1, 1), (1, 2))[i % 3]
    seed = rng.getrandbits(64)
    m, mp, sr, raw, _ = fixture(Random(seed), family, version=version, group=True)
    u, ump, usr, uraw, _ = fixture(Random(seed), family, version=version)
    mr = model_codec.encode(m)
    assert model_codec.decode(mr) == m
    assert any(p[0] == 2 for b in m.blocks for p in b.policies) or m.final_policy[0] == 2
    prep = artifact_codec.encode_preparation(m, mp)
    tokens = tuple(rng.randrange(m.shape.vocabulary) for _ in range(m.shape.context))
    data = execution.load(m, mp, sr, raw, blake3(raw).digest())
    try:
        result = execution.full(data, tokens)
    except ValueError as error:
        assert str(error) in ('Range', 'RowRange', 'ExpDomain'), error
        expected = str(error); counts['rejected'] += 1
    else:
        counts['accepted'] += 1
        counts['grouped_differs'] += outcome(lambda: execution.full(execution.load(
            u, ump, usr, uraw, blake3(uraw).digest()), tokens).logits) != result.logits
        expected = dict(cuts=store(b''.join(pack('<'+'i'*len(row), *row) for cut in result.cuts for row in cut)),
                        logits=store(b''.join(pack('<'+'h'*len(row), *row) for row in result.logits)),
                        cache=store(b''.join(pack('<IB', r.scale, r.fraction)+bytes(x % 256 for x in r.codes)
                                             for layer in result.cache.layers for pair in layer for r in pair)))
    generations = []
    if isinstance(expected, dict):
        for limit, eos in ((1, tuple(range(m.shape.vocabulary))), (m.shape.context-1, (m.shape.vocabulary-1,))):
            seed_bytes = None if m.decoding is None else rng.randbytes(32)
            boundary = request.Request(1, limit, eos, None if seed_bytes is None else
                                       blake3(b'stele/v0.1/cqis/sample-seed'+seed_bytes).digest())
            try:
                sequence, reason, _ = execution.generate(data, boundary, tokens[:1], seed_bytes)
            except ValueError as error:
                assert str(error) in ('Range', 'RowRange', 'ExpDomain'), error
                result_ = str(error)
            else:
                result_ = dict(tokens=sequence, reason=reason)
            spec = request.Spec(m.shape.vocabulary, m.shape.context, int(m.decoding is not None))
            generations.append(dict(request=store(request.encode_request(spec, boundary)), prompt=tokens[:1],
                                    seed=None if seed_bytes is None else seed_bytes.hex(), expected=result_))
    case = dict(model=store(mr), preparation=store(prep), scales=store(sr), artifact=store(raw),
                artifact_id=blake3(raw).hexdigest(), tokens=tokens, expected=expected, generations=generations,
                ungrouped_model_id=blake3(model_codec.encode(u)).hexdigest())
    if i < 6:  # complete static identity, including schemas 23/24/25
        rr = registry_codec.encode(m)
        bounds = bound_collection.encode(m, sr, rr)
        bound_collection.validate(m, sr, rr, bounds)
        case.update(registry=store(rr), bounds_id=blake3(bounds).hexdigest(), bounds_length=len(bounds))
    models.append(case)
assert counts['accepted'] >= 24 and counts['rejected'] and counts['grouped_differs'], counts

# Rejected Policy encodings (RFC-0004 A15 `Policy`): the research codec refuses to write them,
# so a permissive writer substitutes exactly one Policy frame of an accepted grouped Model.
strict = model_codec.policy
model_codec.policy = lambda value, gated=False, n=None: bytes((value[0],))+value[1].to_bytes(4, 'little')
invalid = []
base = model_codec.decode(bytes(binary[models[0]['model']['offset']:][:models[0]['model']['length']]))
b, s = base.blocks[0], base.shape
for j in (1, 2, 3):  # Q/K/V rows are never grouped
    bad = replace(base, blocks=(replace(b, policies=b.policies[:j]+((2, 1),)+b.policies[j+1:]),)+base.blocks[1:])
    invalid.append(dict(reason='qkv', model=store(model_codec.encode(bad))))
for value in ((2, s.width), (2, 0), (2, 3) if s.width % 3 else (2, s.width+1), (3, 0), (2, 1 << 20)):
    invalid.append(dict(reason=str(value), model=store(model_codec.encode(replace(base, final_policy=value)))))
model_codec.policy = strict
for case in invalid:
    raw = bytes(binary[case['model']['offset']:][:case['model']['length']])
    assert outcome(lambda: model_codec.decode(raw)) == 'Policy', case

out = ROOT/'crates/stele-cqis/tests/fixtures'
paths = ['research/cqis-model-contract/'+name for name in
         ('arithmetic_bounds.py', 'flow_bounds.py', 'bound_collection.py', 'model_codec.py',
          'model_execution.py', 'numerics.py', 'check_model_execution.py', 'check_grouped_rows.py')]
(out/'grouped-rows.bin').write_bytes(binary)
receipt = dict(seed=SEED, conversions=conversions, bad_conversions=bad_conversions, records=records, cases=models,
               invalid=invalid, counts=counts, fixture_sha256=sha256(binary).hexdigest(),
               sources={p: sha256((ROOT/p).read_bytes()).hexdigest() for p in paths})
(out/'grouped-rows.json').write_text(json.dumps(receipt, separators=(',', ':'))+'\n')
print(json.dumps(dict(counts, cases=len(models), conversions=len(conversions), records=len(records),
                      invalid=len(invalid), bytes=len(binary))))
