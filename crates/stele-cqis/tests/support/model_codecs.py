"""RFC-0025 encoding §§1,4: native codec fixtures from qualified pure helpers.

Run with Python 3.12 and blake3==1.0.11. No historical campaign main runs.
"""
from dataclasses import replace
from hashlib import sha256
import json
from pathlib import Path
from random import Random
from struct import pack
import sys

from blake3 import blake3

if not __debug__:
    raise RuntimeError('reference assertions must remain enabled')
ROOT = Path(__file__).resolve().parents[4]
sys.path.insert(0, str(ROOT / 'research/cqis-model-contract'))
from check_model_codec import make, oracle, roles
from function_bounds import Exponential
from model_codec import Sampled, decode, encode
from rms_bounds import RMSNorm
from source_map import Shape


def blob(raw):
    return pack('<I', len(raw)) + raw


rng = Random(50331)
shapes = [Shape(0, 12, 768, 12, 12, 64, 3072, 50257, 1024),
          Shape(1, 32, 4096, 32, 8, 128, 14336, 128256, 131072),
          Shape(0, 128, 4096, 128, 128, 32, 16384, 2**20, 2**20),
          Shape(1, 128, 16384, 128, 128, 128, 16384, 2**20, 2**20)]
models = [make(rng, s.family, s) for s in shapes]
models += [make(rng, i % 2) for i in range(64)]
gpt = make(rng, 0, Shape(0, 2, 4, 1, 1, 4, 16, 3, 2))
llama = make(rng, 1, Shape(1, 1, 2, 1, 1, 2, 3, 5, 2))
b = llama.blocks[0]
rotation = replace(b.rotation, family=2, original=1,
                   rationals=((2**64-1, 2**32), (2**64-1, 2**64-2),
                              (1, 2**64-1), (2**32, 1)))
llama = replace(llama, blocks=(replace(b, rotation=rotation,
                       policies=b.policies[:6]+((1, 8454661),)),))
models += [gpt, llama]
valid = pack('<I', len(models))
for p in models:
    raw = encode(p)
    assert raw == oracle(p) and decode(raw) == p
    expected_roles = roles(p.shape)
    assert tuple(expected_roles) == p.shape.roles()
    valid += blob(raw) + blake3(raw).digest() + pack('<H', len(expected_roles))
    for name, layer, dimensions in expected_roles:
        valid += blob(name.encode()) + pack('<hB', layer, len(dimensions))
        valid += pack('<' + 'I'*len(dimensions), *dimensions)

bad = []


def rejects(name, p):
    raw = oracle(p)
    try:
        decode(raw)
    except ValueError:
        bad.append((name, raw))
    else:
        raise AssertionError(name)


def block_change(p, **changes):
    return replace(p, blocks=(replace(p.blocks[0], **changes),)+p.blocks[1:])


b = gpt.blocks[0]
rejects('norm kind', block_change(gpt, norm1=RMSNorm(b.norm1.d, b.norm1.F,
        b.norm1.G, b.norm1.E, b.norm1.en, b.norm1.ed)))
rejects('norm dimension', block_change(gpt, norm1=replace(b.norm1, d=5)))
rejects('incoming units', block_change(gpt, norm1=replace(b.norm1, F=(gpt.f0+1) % 31)))
rejects('middle units', block_change(gpt, norm2=replace(b.norm2, F=(b.mid+1) % 31)))
rejects('next layer units', block_change(gpt, out=(b.out+1) % 31))
rejects('final units', replace(gpt, final_norm=replace(gpt.final_norm, F=(gpt.final_norm.F+1) % 31)))
for index in (2, 3, 16, 17, len(gpt.formats)-2, len(gpt.formats)-1):
    formats = list(gpt.formats); bits, fraction = formats[index]
    formats[index] = bits, (fraction+1) % 31
    rejects('norm source '+str(index), replace(gpt, formats=tuple(formats)))
rejects('wrong FFN', block_change(gpt, activation=replace(b.activation, kind=1)))
rejects('activation units', block_change(gpt, activation=replace(b.activation, F=(b.fractions[4]+1) % 31)))
rejects('inactive dynamic scale', block_change(gpt, policies=((0, 1),)+b.policies[1:]))
rejects('wide static scale', replace(gpt, final_policy=(1, 65536)))
rejects('inactive exact drop', block_change(gpt, accumulation=0, drop=1))
rejects('missing rotation', block_change(llama, rotation=None))
rejects('rotation context', block_change(llama, rotation=replace(rotation, length=1)))
rejects('rotation width', block_change(llama, rotation=replace(rotation, width=4)))
rejects('nonreduced rotation', block_change(llama, rotation=replace(rotation,
        rationals=((1000000, 2),)+rotation.rationals[1:])))
rejects('gated high bytes', block_change(llama, policies=llama.blocks[0].policies[:6]+((1, 8454662),)))
rejects('nonreduced temperature', replace(llama, decoding=Sampled(2, 2, 1, 1,
        Exponential(llama.shape.vocabulary, 7, 0, 0, 0))))
rejects('top p greater than one', replace(llama, decoding=Sampled(1, 1, 2, 1,
        Exponential(llama.shape.vocabulary, 7, 0, 0, 0))))
p = block_change(gpt, exp=Exponential(gpt.shape.context, 7, 0, 0, 0))
rejects('conflicting representation', replace(p, decoding=Sampled(1, 1, 1, 1,
        Exponential(p.shape.vocabulary, 7, 0, 0, 2, 1))))
invalid = pack('<I', len(bad)) + b''.join(blob(name.encode())+blob(raw) for name, raw in bad)
out = ROOT / 'crates/stele-cqis/tests/fixtures'
(out / 'models.bin').write_bytes(valid)
(out / 'models-invalid.bin').write_bytes(invalid)
paths = ['research/cqis-model-contract/'+p for p in
         ('check_model_codec.py', 'model_codec.py', 'source_map.py')]
receipt = dict(seed=50331, valid=len(models), invalid=len(bad),
               sources={p: sha256((ROOT/p).read_bytes()).hexdigest() for p in paths},
               fixtures={name: sha256((out/name).read_bytes()).hexdigest()
                         for name in ('models.bin', 'models-invalid.bin')})
(out / 'models.json').write_text(json.dumps(receipt, indent=2)+'\n')
print(json.dumps(receipt))
