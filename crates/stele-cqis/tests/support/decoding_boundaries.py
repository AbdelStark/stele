"""RFC-0025 decoding: complete vocabulary/CDF and last-position boundaries.

Run from the repository root with --output pointing to the fixture JSON. Sparse
test frames expand to complete ordinary Model/Preparation/Scales/Artifact bytes;
no production loader or numerical validation is bypassed.
"""
import argparse
from dataclasses import replace
from pathlib import Path
from random import Random
from struct import pack
import json
import sys

from blake3 import blake3
import numpy as np

ROOT = Path.cwd()
sys.path.insert(0, str(ROOT/'crates/stele-cqis/tests/support'))
from numpy_execution import Oracle, load
from check_model_codec import make
from check_artifact_codec import artifact, mapping, preparation
from function_bounds import Activation, Exponential
from model_codec import Rotation, Sampled, encode
from source_map import Shape
from scales_codec import Scale, encode as encode_scales
import artifact_codec


def chunk(raw, count=1): return dict(bytes=raw.hex(), repeat=count)


def choice_bytes(position, token, parts):
    arguments, weights, order, cdf, draw = parts
    out = bytearray(pack('<II', position, token))
    for values, fmt in ((arguments, 'i'), (weights, 'I'), (order, 'I'), (cdf, 'Q')):
        out.extend(pack('<I', len(values))+pack('<'+fmt*len(values), *values))
    out.extend(bytes((draw is not None,))+(b'' if draw is None else pack('<I', draw)))
    return out


def build(v, n, sampled):
    rng = Random(50432+sampled)
    shape = Shape(1, 1, 2, 1, 1, 2, 2, v, n)
    old = make(rng, 1, shape)
    def norm(p): return replace(p, F=6, G=6, E=6, en=1, ed=100000)
    rotation = Rotation(2, n, 0, 0, 0, ((10000, 1), (1, 1), (0, 1), (0, 1)))
    b = replace(old.blocks[0], norm1=norm(old.blocks[0].norm1), norm2=norm(old.blocks[0].norm2),
        fractions=(6,)*7, mid=6, out=6, attention=6, policies=((0, 0),)*7,
        score_m=1, score_e=-4, accumulation=0, drop=0, exp=Exponential(n, 15, 6, 6, 0, 0),
        activation=Activation(2, 1, 6, 6), rotation=rotation)
    m = replace(old, formats=tuple((8, 0) if len(ds) == 2 else (16, 6) for _, _, ds in shape.roles()),
        f0=6, blocks=(b,), final_norm=norm(old.final_norm), final_policy=(0, 0), logits_fraction=0,
        decoding=Sampled(1, 1, 1, 1, Exponential(v, 15, 0, 14, 0, 0)) if sampled else None)
    mp = mapping(m, rng, False)
    scales, payloads = [], []
    for _, _, ds in shape.roles():
        if len(ds) == 2:
            scales.append(Scale(0, b'\1\0'*ds[0]))
            payloads.append(bytes(ds[0]*ds[1]))
        else:
            payloads.append(bytes(2*ds[0]))
    sr = encode_scales(m, tuple(scales))
    raw = artifact(m, mp, tuple(scales), payloads)
    header, records, public_scales, _ = artifact_codec._context(m, mp, sr)
    compressed = [chunk(part) for part in header]
    ordered_scales = iter(public_scales)
    for record in records:
        scale = next(ordered_scales) if len(record.dimensions) == 2 else None
        for part, _ in artifact_codec._header(record, scale):
            repeated = len(part) > 32 and len(part) % 2 == 0 and part == b'\1\0'*(len(part)//2)
            compressed.append(chunk(b'\1\0', len(part)//2) if repeated else chunk(part))
        compressed.append(chunk(b'\0', record.payload_length))
    assert b''.join(bytes.fromhex(c['bytes'])*c['repeat'] for c in compressed) == raw
    compact_scales = [chunk(sr[:len(b'stele/v0.1/cqis/scales')+32])]
    at = len(b'stele/v0.1/cqis/scales')+32
    for record in records:
        if len(record.dimensions) == 2:
            compact_scales.extend((chunk(sr[at:at+4]), chunk(b'\1\0', record.dimensions[0])))
            at += 4+2*record.dimensions[0]
    assert b''.join(bytes.fromhex(c['bytes'])*c['repeat'] for c in compact_scales) == sr
    data = load(m, mp, sr, raw, blake3(raw).digest())
    logits = np.zeros(v, dtype=np.int64)
    if sampled: logits[-3:] = -10
    seed = bytes(range(32)) if sampled else None
    position = 1 if sampled else n-1
    token, parts = Oracle(data).choose(logits, seed, position)
    empty = sum(a == b for a, b in zip(parts[3], parts[3][1:]))
    if sampled:
        assert parts[1] == (16384,)*(v-3)+(1,)*3
        assert parts[2] == tuple(range(v)) and empty == 2 and parts[3][-1] == 2**32
    return dict(model=encode(m).hex(), preparation=preparation(m, mp).hex(), scales=compact_scales,
        artifact=compressed, artifact_id=blake3(raw).hexdigest(), position=position,
        seed=None if seed is None else seed.hex(), token=token, empty_cdf_buckets=empty,
        decision_blake3=blake3(choice_bytes(position, token, parts)).hexdigest())


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    cases = [build(2**20, 2, True), build(1, 2**20, False)]
    args.output.write_text(json.dumps(dict(cases=cases), separators=(',', ':'))+'\n')
    print(json.dumps(dict(cases=2, vocabulary=2**20, last_position=2**20-1, empty_cdf_buckets=2)))
