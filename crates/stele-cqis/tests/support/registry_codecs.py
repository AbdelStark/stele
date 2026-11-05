"""RFC-0025 encoding §6: independent complete Registry and metadata fixtures.

Python 3.12, python-flint==0.9.0, blake3==1.0.11. No historical campaign main.
"""
from dataclasses import replace
from hashlib import sha256
import json
from pathlib import Path
from random import Random
from struct import pack, unpack_from
import sys
from blake3 import blake3

if not __debug__:
    raise RuntimeError('reference assertions must remain enabled')
ROOT = Path(__file__).resolve().parents[4]
sys.path.insert(0, str(ROOT/'research/cqis-model-contract'))
from check_registry_codec import configured, oracle
from model_codec import encode as encode_model, decode as decode_model, Rotation
from registry_codec import _parts
from source_map import Shape


def blob(raw): return pack('<I', len(raw))+raw


def layout(model):
    raw, slots = b'', []
    for part in _parts(model):
        if type(part) is bytes: raw += part
        else:
            slots.append((len(raw), int(type(part) is Rotation)))
            raw += bytes(32)
    return raw, slots


def slots_bytes(slots):
    return pack('<H', len(slots))+b''.join(pack('<IB', p, kind) for p, kind in slots)


rng = Random(50334)
full = pack('<I', 6)
for family in range(2):
    for mode in range(3):
        shape = Shape(family, 2, 4, 2, 2 if family == 0 else 1, 2, 16 if family == 0 else 7, 11, 5)
        model = configured(rng, family, shape, mode)
        # Exercise nonzero nearest-exp corrections and fractional activations.
        blocks = []
        for b in model.blocks:
            fractions = list(b.fractions); fractions[4 if family == 0 else 5] = 7
            blocks.append(replace(b, fractions=tuple(fractions), activation=replace(b.activation, F=7, E=7),
                                  exp=replace(b.exp, F=7, E=7)))
        decoding = model.decoding
        if decoding is not None: decoding = replace(decoding, exp=replace(decoding.exp, F=7, E=7))
        model = replace(model, blocks=tuple(blocks), decoding=decoding)
        model_raw = encode_model(model); assert decode_model(model_raw) == model
        raw = oracle(model)
        metadata, slots = layout(model)
        assert len(raw) == len(metadata)
        masked = bytearray(raw)
        for offset, _ in slots: masked[offset:offset+32] = bytes(32)
        assert bytes(masked) == metadata
        full += blob(model_raw)+blob(raw)+blake3(raw).digest()+slots_bytes(slots)

# Full named and maximum metadata layouts without generating potentially huge data.
source = (ROOT/'crates/stele-cqis/tests/fixtures/models.bin').read_bytes()
position = 4
large = pack('<I', 4)
for _ in range(4):
    n = unpack_from('<I', source, position)[0]; position += 4
    model_raw = source[position:position+n]; position += n+32
    count = unpack_from('<H', source, position)[0]; position += 2
    for _ in range(count):
        n = unpack_from('<I', source, position)[0]; position += 4+n+2
        rank = source[position]; position += 1+4*rank
    model = decode_model(model_raw)
    metadata, slots = layout(model)
    large += blob(model_raw)+blob(metadata)+slots_bytes(slots)

# A structurally valid Model whose complete activation table overflows.
model = configured(rng, 1, Shape(1, 1, 2, 1, 1, 2, 1, 3, 2), 2)
b = model.blocks[0]
bad = replace(model, blocks=(replace(b, activation=replace(b.activation, E=14)),))
metadata, slots = layout(bad)
overflow = blob(encode_model(bad))+blob(metadata)+slots_bytes(slots)
out = ROOT/'crates/stele-cqis/tests/fixtures'
files = {'registries.bin':full, 'registry-layouts.bin':large, 'registry-overflow.bin':overflow}
for name, raw in files.items(): (out/name).write_bytes(raw)
paths = ['research/cqis-model-contract/'+p for p in ('check_registry_codec.py', 'registry_codec.py', 'model_codec.py', 'check_model_codec.py')]
receipt = dict(seed=50334, complete=6, metadata_only=4, whole_table_overflow=1,
               sources={p:sha256((ROOT/p).read_bytes()).hexdigest() for p in paths},
               fixtures={p:sha256(raw).hexdigest() for p, raw in files.items()})
(out/'registries.json').write_text(json.dumps(receipt, indent=2)+'\n')
print(json.dumps(receipt))
