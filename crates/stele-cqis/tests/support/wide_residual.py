"""RFC-0004 A14 / RFC-0021 A4: native wide-residual fixtures from the research reference.

Python 3.12, blake3==1.0.11, python-flint==0.9.0, safetensors==0.6.2.
Expected values come from the research production reference (certified_rmsnorm,
function_identity, rms/arithmetic/flow bounds, model/registry/bound codecs and
model_execution), which check_wide_residual.py qualifies against exact oracles.
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
import certified_rmsnorm as norm
import flow_bounds as flow
import function_identity as fn
import model_codec
import model_execution as execution
import registry_codec
import request_bounds as request
import rms_bounds as rms

SEED = 0xA14C
rng = Random(SEED)
binary = bytearray()


def store(raw):
    at = dict(offset=len(binary), length=len(raw))
    binary.extend(raw)
    return at


def norm_params(d, F, G, E, en, ed):
    return pack('<HBBBII', d, F, G, E, en, ed)


# FunctionIds: version 2 encodes its version; parameter bytes are unchanged.
functions = []
for d, F, G, E, en, ed in ((1, 0, 0, 0, 1, 1), (8192, 30, 30, 14, (1 << 32)-1, (1 << 32)-2), (4096, 10, 14, 7, 1, 100000)):
    for version in (1, 2):
        f = fn.Function('rmsnorm_q', version, norm_params(d, F, G, E, en, ed))
        functions.append(dict(version=version, parameters=f.params.hex(), descriptor=fn.encode(f).hex(),
                              function_id=fn.function_id(f).hex()))

# Version-2 rows with the extreme statistic, exponent, shift and int16 output endpoints.
rows = []
low, high = -(1 << 23), (1 << 23)-1
for i in range(1000):
    d = rng.choice((1, 2, 3, 5, 16))
    F, G, E = rng.choice((0, 1, 10, 30)), rng.randint(0, 30), rng.randint(0, 14)
    en, ed = rng.choice(((1, 1), (1, 100000), (7, (1 << 32)-1), ((1 << 32)-1, 1)))
    X = [rng.choice((low, high, 0, -1, rng.randint(low, high), rng.randint(-40000, 40000))) for _ in range(d)]
    H = [rng.choice((-32768, 32767, 0, rng.randint(-32768, 32767))) for _ in range(d)]
    if i == 0:
        (d, F, G, E, en, ed), X, H = (1, 0, 0, 14, 1, (1 << 32)-1), [low], [1]  # a = 16 is attained
    p = norm.Parameters(d, F, G, E, en, ed, 2)
    try:
        r = norm.evaluate(p, X, H)
        expected = dict(output=r['output'], statistic=r['norm']['S'], exponent=r['norm']['a'],
                        mantissa=r['norm']['M'], reciprocal=r['norm']['J'], shift=r['shift'])
    except ValueError as error:
        expected = str(error)
    rows.append(dict(parameters=[d, F, G, E, en, ed], input=X, gain=H, expected=expected))
assert rows[0]['expected']['exponent'] == 16


def record(kind, parameters, raw):
    offset = len(arithmetic.PREFIX)
    return dict(kind=kind, parameters=parameters, schema=raw[offset+4], length=len(raw), digest=blake3(raw).hexdigest())


records = []
for d, F, G, E, en, ed in ((1, 0, 0, 0, 1, 1), (8192, 30, 30, 0, (1 << 32)-1, (1 << 32)-2), (8192, 0, 0, 14, 1, (1 << 32)-1),
                           (4097, 30, 0, 14, (1 << 32)-2, (1 << 32)-1), (16, 10, 14, 7, 1, 100000)):
    for version in (1, 2):
        records.append(record('RMSNorm', [d, F, G, E, en, ed, version], rms.encode(rms.RMSNorm(d, F, G, E, en, ed, version))))
for inner, bits, exponent, mantissa, kind, fraction, output, policy, scale in (
        (14336, 8, 0, 65535, 0, 10, 30, 0, 0), (14336, 8, 0, 65535, 1, 30, 30, 1, 8454661),
        (4096, 4, -20, 3, 0, 8, 10, 1, 1), (1, 8, 1024, 1, 0, 0, 0, 1, 65535), (16, 8, -1099, 65535, 1, 44, 30, 0, 0)):
    for bits_out in (16, 24):
        a = arithmetic.Affine(inner, bits, exponent, mantissa, kind, fraction, output, policy, scale, None, bits_out)
        records.append(record('Affine', [inner, bits, exponent, mantissa, kind, fraction, output, policy, scale, bits_out],
                              arithmetic.encode(a)))
for d, fx, fy, fo in ((8192, 0, 30, 0), (8192, 30, 30, 30), (1, 10, 8, 30), (4096, 30, 0, 0), (16384, 7, 8, 6)):
    for bits_out in (16, 24):
        records.append(record('Residual', [d, fx, fy, fo, bits_out], flow.encode(flow.Residual(d, fx, fy, fo, bits_out))))

# Wide Llama models: full/step/cache/generation results, Registry and Bounds.
models = []
counts = dict(accepted=0, rejected=0, wide_only=0, beyond_int16=0)
for i in range(48):
    seed = rng.getrandbits(64)
    m, mp, sr, raw, _ = fixture(Random(seed), 1, version=2)
    n, nmp, nsr, nraw, _ = fixture(Random(seed), 1)
    mr = model_codec.encode(m)
    assert model_codec.decode(mr) == m and execution.width(m) == 24
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
        try:
            execution.full(execution.load(n, nmp, nsr, nraw, blake3(nraw).digest()), tokens)
        except ValueError:
            counts['wide_only'] += 1
        counts['beyond_int16'] += any(not -32768 <= v < 32768 for cut in result.cuts for row in cut for v in row)
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
                outcome = str(error)
            else:
                outcome = dict(tokens=sequence, reason=reason)
            spec = request.Spec(m.shape.vocabulary, m.shape.context, int(m.decoding is not None))
            generations.append(dict(request=store(request.encode_request(spec, boundary)), prompt=tokens[:1],
                                    seed=None if seed_bytes is None else seed_bytes.hex(), expected=outcome))
    case = dict(model=store(mr), preparation=store(prep), scales=store(sr), artifact=store(raw),
                artifact_id=blake3(raw).hexdigest(), tokens=tokens, expected=expected, generations=generations)
    if i < 4:  # complete static identity, including schemas 20/21/22
        rr = registry_codec.encode(m)
        bounds = bound_collection.encode(m, sr, rr)
        bound_collection.validate(m, sr, rr, bounds)
        case.update(registry=store(rr), bounds_id=blake3(bounds).hexdigest(), bounds_length=len(bounds))
    models.append(case)
assert counts['accepted'] and counts['rejected'] and counts['wide_only'] and counts['beyond_int16'], counts

# Mixed versions: one norm of a version-2 Model at version 1 (RFC-0004 A14 `Width`).
mr = bytes(binary[models[0]['model']['offset']:][:models[0]['model']['length']])
first = model_codec.decode(mr).blocks[0].norm1
mixed = mr
for wide_frame, narrow_frame in zip(model_codec.function_frames(first),
                                    model_codec.function_frames(replace(first, version=1))):
    assert wide_frame in mixed and len(wide_frame) == len(narrow_frame)
    mixed = mixed.replace(wide_frame, narrow_frame, 1)
try:
    model_codec.decode(mixed)
except ValueError as error:
    assert str(error) == 'Width', error
else:
    raise AssertionError('mixed versions accepted')

mixed = store(mixed)
out = ROOT/'crates/stele-cqis/tests/fixtures'
paths = ['research/cqis-tables/certified_rmsnorm.py', 'research/cqis-tables/function_identity.py'] + [
    'research/cqis-model-contract/'+name for name in
    ('rms_bounds.py', 'arithmetic_bounds.py', 'flow_bounds.py', 'bound_collection.py', 'model_codec.py',
     'model_execution.py', 'numerics.py', 'check_model_execution.py')]
(out/'wide-residual.bin').write_bytes(binary)
receipt = dict(seed=SEED, functions=functions, rows=rows, records=records, cases=models, mixed=mixed,
               counts=counts, fixture_sha256=sha256(binary).hexdigest(),
               sources={p: sha256((ROOT/p).read_bytes()).hexdigest() for p in paths})
(out/'wide-residual.json').write_text(json.dumps(receipt, separators=(',', ':'))+'\n')
print(json.dumps(dict(counts, cases=len(models), rows=len(rows), records=len(records), bytes=len(binary))))
