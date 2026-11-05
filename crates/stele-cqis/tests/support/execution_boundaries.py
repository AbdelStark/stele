"""RFC-0025 numerical boundary fixtures; no historical campaign entry points.

Fixed 2048-key absolute blocks and complete original-role synthetic failure cases.
"""
from dataclasses import replace
from hashlib import sha256
import json
from pathlib import Path
from random import Random

from blake3 import blake3
from numpy_execution import load
from check_model_execution import fixture, rebuild
from check_artifact_codec import preparation
from function_bounds import Activation, Exponential
from model_codec import encode
from scales_codec import decode, encode as encode_scales

ROOT = Path(__file__).resolve().parents[4]
binary = bytearray()
cases = {}


def store(raw):
    span = dict(offset=len(binary), length=len(raw))
    binary.extend(raw)
    return span


def save(name, m, mapping, sr, raw):
    cases[name] = dict(model=store(encode(m)), preparation=store(preparation(m, mapping)),
        scales=store(sr), artifact=store(raw), artifact_id=blake3(raw).hexdigest())


rng = Random(50428)
m, mapping, sr, raw, _ = fixture(rng, 1, layers=1, context=2048, heads=1, width=2)
scales = decode(m, sr)
b = replace(m.blocks[0], norm1=replace(m.blocks[0].norm1, F=6),
    norm2=replace(m.blocks[0].norm2, F=6), fractions=(6,)*7, mid=6, out=6,
    policies=((0, 0),)*7, attention=6, accumulation=1, drop=17,
    exp=Exponential(2048, 15, 6, 6, 0, 0), activation=Activation(m.shape.hidden, 1, 6, 6))
m = replace(m, f0=6, blocks=(b,), final_norm=replace(m.final_norm, F=6), decoding=None)
for name, block in (('blocks', b), ('exact', replace(b, accumulation=0, drop=0)),
                    ('score_overflow', replace(b, score_e=30)), ('block_overflow', replace(b, drop=0))):
    variant = replace(m, blocks=(block,))
    save(name, variant, mapping, encode_scales(variant, scales), raw)

m, _, _, _, _ = fixture(rng, 1, layers=1, context=3, heads=1, width=2)
m = replace(m, decoding=None, blocks=tuple(replace(b, policies=((0, 0),)*7) for b in m.blocks))
arrays = {}
for name, layer, ds in m.shape.roles():
    if len(ds) == 1:
        arrays[name, layer] = (ds, (64,)*ds[0])
        continue
    n = ds[0]*ds[1]
    codes, scales, exponent = (0,)*n, (1,)*ds[0], 0
    if name == 'token': codes, scales = (1,)*n, (1, 65535)+(1,)*(ds[0]-2)
    if name == 'head': codes, exponent = (0,)*ds[1]+(1,)*ds[1]+(0,)*(n-2*ds[1]), -4
    arrays[name, layer] = ds, exponent, scales, codes
mapping, sr, raw = rebuild(m, arrays, rng)
load(m, mapping, sr, raw, blake3(raw).digest())
save('early_failure', m, mapping, sr, raw)

ds, _, _, codes = arrays['token', -1]
arrays['token', -1] = ds, 0, (1,)*ds[0], (0,)*ds[1]+(1,)*ds[1]+(0,)*(len(codes)-2*ds[1])
ds, _, scales, codes = arrays['head', -1]
arrays['head', -1] = ds, 1024, scales, codes
mapping, sr, raw = rebuild(m, arrays, rng)
load(m, mapping, sr, raw, blake3(raw).digest())
save('late_failure', m, mapping, sr, raw)

directory = ROOT/'crates/stele-cqis/tests/fixtures'
(directory/'execution-boundaries.bin').write_bytes(binary)
(directory/'execution-boundaries.json').write_text(json.dumps(dict(seed=50428, cases=cases,
    fixture_sha256=sha256(binary).hexdigest()), separators=(',', ':'))+'\n')
print(json.dumps(dict(cases=list(cases), bytes=len(binary))))
