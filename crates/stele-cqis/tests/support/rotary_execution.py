"""RFC-0025 rotation application: NumPy int64 rows and independent rational oracle.

New 12000-row corpus; imports pure helpers without running historical campaigns.
"""
from dataclasses import replace
from hashlib import sha256
import json
from pathlib import Path
from random import Random
from struct import pack

from blake3 import blake3
import numpy as np
from numpy_execution import load
from check_model_execution import fixture, rotate, rotary_point
from check_artifact_codec import preparation
from model_codec import Rotation, encode
from scales_codec import decode, encode as encode_scales
from fractions import Fraction as Q
import rope

ROOT = Path(__file__).resolve().parents[4]
binary = bytearray()
groups = []


def store(raw):
    span = dict(offset=len(binary), length=len(raw))
    binary.extend(raw)
    return span


for family in range(3):
    for layout in range(2):
        index = 2*family+layout
        base, mapping, sr, raw, _ = fixture(Random(504310+index), 1,
            layers=1, context=64, heads=2, width=4 if family == 0 else 8)
        r = Rotation(2 if layout == 0 else base.shape.head_width, 64, family, layout,
            8192 if family == 2 else 0, ((500000, 1), (1 if family == 0 else 8, 1),
            (1 if family == 2 else 0, 1), (4 if family == 2 else 0, 1)))
        m = replace(base, blocks=(replace(base.blocks[0], rotation=r),))
        scales = encode_scales(m, decode(base, sr))
        load(m, mapping, scales, raw, blake3(raw).digest())
        ratios = tuple(Q(*v) for v in r.rationals)
        p = rope.Parameters(r.width, r.length, ratios[0], ('base', 'linear', 'llama3')[family],
            ('adjacent', 'split')[layout], *ratios[1:], r.original)
        state = seed = 504320+index
        def word():
            global state
            state = (state*6364136223846793005+1442695040888963407) % 2**64
            return state >> 32
        digest = blake3()
        accepted = 0
        for _ in range(2000):
            position = word() % 64
            values = tuple(word() % 65536-32768 for _ in range(m.shape.width))
            output = np.asarray(values, dtype=np.int64).copy()
            for head in range(m.shape.heads):
                for pair in range(r.width//2):
                    c, s = (v[0] for v in rotary_point(p, position, pair))
                    left = head*m.shape.head_width+(2*pair if layout == 0 else pair)
                    right = left+(1 if layout == 0 else r.width//2)
                    x, y = values[left], values[right]
                    products = np.asarray((x*c-y*s, x*s+y*c), dtype=np.int64)
                    magnitude = np.abs(products)
                    rounded = magnitude//16384+(magnitude % 16384 >= 8192)
                    output[[left, right]] = np.where(products < 0, -rounded, rounded)
            digest.update(pack('<I', position)+pack('<'+'h'*len(values), *values))
            if np.any(output < -32768) or np.any(output > 32767):
                try: rotate(r, values, position, m.shape.heads, m.shape.head_width)
                except ValueError as error: assert str(error) == 'Range'
                else: raise AssertionError('missing independent rejection')
                digest.update(b'\0')
            else:
                assert tuple(map(int, output)) == rotate(r, values, position, m.shape.heads, m.shape.head_width)
                digest.update(b'\1'+output.astype('<i2').tobytes())
                accepted += 1
        groups.append(dict(seed=seed, count=2000, accepted=accepted, digest=digest.hexdigest(),
            model=store(encode(m)), preparation=store(preparation(m, mapping)),
            scales=store(scales), artifact=store(raw)))
directory = ROOT/'crates/stele-cqis/tests/fixtures'
(directory/'rotary-execution.bin').write_bytes(binary)
(directory/'rotary-execution.json').write_text(json.dumps(dict(groups=groups,
    fixture_sha256=sha256(binary).hexdigest()), separators=(',', ':'))+'\n')
print(json.dumps(dict(cases=12000, accepted=sum(g['accepted'] for g in groups))))
