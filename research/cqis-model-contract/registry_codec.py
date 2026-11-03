"""Draft RFC-0025 encoding appendix §6; all data digests require regeneration."""
from fractions import Fraction
from functools import lru_cache
from pathlib import Path
from struct import pack
import sys

from blake3 import blake3

from model_codec import Rotation, encode as encode_model, function_frames, fn
from numerics import LayerNorm

sys.path.insert(0, str(Path(__file__).resolve().parents[1]/'cqis-checkpoint'))
import rope

PREFIX = b'stele/v0.1/cqis/registry'
ROTATION_DATA = b'stele/v0.1/cqis/rotation-data'
LIMIT = 1 << 20


@lru_cache(maxsize=516, typed=True)
def table_digest(value):
    # Only complete regenerated definitions populate this immutable digest cache.
    return blake3(fn.table.encode_data(value)).digest()


def rotation_digest(value):
    if type(value) is not Rotation:
        raise ValueError('Rotation')
    value.encode()  # Validate before cache lookup; Boolean fields can alias integer keys.
    return _rotation_digest(value)


@lru_cache(maxsize=128, typed=True)
def _rotation_digest(value):
    raw = value.encode(); ratios = tuple(Fraction(n, d) for n, d in value.rationals)
    p = rope.Parameters(value.width, value.length, ratios[0], ('base', 'linear', 'llama3')[value.family],
                        ('adjacent', 'split')[value.layout], *ratios[1:], value.original)
    digest = blake3(ROTATION_DATA+blake3(raw).digest())
    for position in range(value.length):
        row = bytearray()
        for j in range(value.width//2):
            entry = rope.certify(p, position, j)
            row += pack('<hh', entry['cos'], entry['sin'])
        digest.update(row)
    return digest.digest()


def _size(parts): return sum(len(p) if type(p) is bytes else 32 for p in parts)


def _parts(model):
    # Bytes are exact metadata; typed entries require regenerated data digests.
    model_id = blake3(encode_model(model)).digest()
    roles = [v for b in model.blocks for v in (b.norm1, b.exp, b.norm2, b.activation)]+[model.final_norm]
    if model.decoding is not None: roles.append(model.decoding.exp)
    functions, tables, refs = {}, {}, []
    for value in roles:
        f, r = function_frames(value); fid = blake3(f).digest()
        if fid in functions and functions[fid] != (f, r):
            raise ValueError('RepresentationConflict')
        functions[fid] = f, r; refs.append(fid+blake3(r).digest())
        dependencies = ((fn.table.Descriptor('rsqrt_q', 1, b''),) if type(value) is LayerNorm else
                        fn.dependencies(fn.decode_representation(fn.decode(f), r)))
        for d in dependencies:
            tid = fn.table.table_id(d)
            if tid in tables and tables[tid] != d:
                raise ValueError('IdentityCollision')
            tables[tid] = d
    if len(functions) > 514 or len(tables) > 516:
        raise ValueError('Capacity')
    manifest = [fn.MANIFEST, pack('<I', len(functions))]
    for _, (f, r) in sorted(functions.items()): manifest += [pack('<H', len(f)), f, pack('<H', len(r)), r]
    manifest.append(pack('<I', len(tables)))
    for _, d in sorted(tables.items()):
        raw = fn.table.encode(d); manifest += [pack('<H', len(raw)), raw, d]
    size = _size(manifest)
    if size > 1 << 18:
        raise ValueError('Capacity')
    parts = [PREFIX, model_id, pack('<H', len(roles)), b''.join(refs), pack('<I', size)]+manifest
    parts.append(pack('<H', len(model.blocks))); rotations = {}
    for block in model.blocks:
        value = block.rotation
        if value is None: parts.append(b'\0')
        else:
            rid = blake3(value.encode()).digest()
            if rid in rotations and rotations[rid] != value:
                raise ValueError('IdentityCollision')
            rotations[rid] = value; parts.append(b'\1'+rid)
    parts.append(pack('<H', len(rotations)))
    for _, value in sorted(rotations.items()):
        raw = value.encode(); parts += [pack('<I', len(raw)), raw, value]
    if _size(parts) > LIMIT:
        raise ValueError('Capacity')
    return tuple(parts)


def _digest(value):
    if type(value) is Rotation: return rotation_digest(value)
    if type(value) is fn.table.Descriptor: return table_digest(value)
    raise ValueError('Definition')


def encode(model):
    return b''.join(p if type(p) is bytes else _digest(p) for p in _parts(model))


def verify(model, raw):
    if type(raw) is not bytes or len(raw) > LIMIT:
        raise ValueError('Capacity')
    parts = _parts(model)
    if len(raw) != _size(parts):
        raise ValueError('Length')
    pos, entries = 0, []
    for part in parts:
        size = len(part) if type(part) is bytes else 32; data = raw[pos:pos+size]; pos += size
        if type(part) is bytes:
            if data != part: raise ValueError('Structure')
        else: entries.append((part, data))
    # Reject malformed metadata before any expensive definition regeneration.
    for value, data in entries:
        if data != _digest(value):
            raise ValueError('RotationData' if type(value) is Rotation else 'TableData')
