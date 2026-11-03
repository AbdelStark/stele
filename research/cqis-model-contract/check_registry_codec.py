"""Draft RFC-0025 Registry: independent framing and complete real-data oracles."""
from dataclasses import replace
from fractions import Fraction as Q
from functools import lru_cache
from hashlib import sha256
import json
from random import Random
from struct import pack, unpack_from

from blake3 import blake3
from flint import arb, ctx

from check_arithmetic_bounds import rejects
from check_model_codec import descriptor, make, oracle as model_oracle, rotation, selection
from function_bounds import Activation, Exponential
from model_codec import Rotation
from numerics import LayerNorm
from rms_bounds import RMSNorm
import registry_codec as candidate
from source_map import Shape


def split_selection(value):
    raw = selection(value); n = unpack_from('<I', raw)[0]; pos = 4+n
    return raw[4:pos], raw[pos+4:]


def components(value):
    if type(value) in (LayerNorm, RMSNorm): return [('rsqrt_q', b'')]
    if type(value) is Activation: return [('silu_q' if value.kind == 1 else 'gelu_tanh_q', bytes((value.F, value.E)))]
    p = bytes((value.bits, value.F, value.E))
    return ([('exp_q/direct', p)] if value.mode == 0 else
            [(name, p+bytes((value.k,))) for name in ('exp_q/hi', 'exp_q/lo')+(('exp_q/correction',) if value.mode == 2 else ())])


def nearest(value):
    sign = -1 if value < 0 else 1
    n = (sign*value+arb(1)/2).floor().unique_fmpz()
    assert n is not None, 'OraclePrecision'
    return sign*int(n)


@lru_cache(maxsize=16)
def table_bytes(spec):
    name, p = spec
    encoded = descriptor(b'stele/v0.1/table/identity', name, p)
    if name == 'rsqrt_q': n, start = 49152, 16384
    elif name in ('silu_q', 'gelu_tanh_q'): n, start = 65536, -32768
    else:
        n = (2**(p[0]-p[3])+1 if name.endswith('/hi') else 2**p[3] if name.endswith('/lo') else 2**p[0]+1)
        start = 0 if name.endswith(('/hi', '/lo')) else -2**p[0]
    padded = 2**(n-1).bit_length()
    data = bytearray(b'stele/v0.1/table/data'+blake3(encoded).digest()+pack('<IIB', n, padded, 2))
    with ctx.workprec(256):
        for t in range(start, start+n):
            if name == 'rsqrt_q': y = nearest((arb(2**42)/t).sqrt())
            elif name in ('silu_q', 'gelu_tanh_q'):
                x = arb(t)/2**p[0]
                y = nearest((x/(1+(-x).exp()) if name == 'silu_q' else
                             x*(1+((arb(2)/arb.pi()).sqrt()*(x+arb(8943)/200000*x**3)).tanh())/2)*2**p[1])
                assert -32768 <= y <= 32767
            else:
                def exp_round(i): return nearest((-arb(i)/2**p[1]).exp()*2**p[2])
                if name.endswith('/hi'): y = exp_round(t*2**p[3])
                elif name.endswith('/lo'): y = exp_round(t)
                elif name.endswith('/direct'): y = exp_round(-t)
                else:
                    hi, lo = divmod(-t, 2**p[3]); product = exp_round(hi*2**p[3])*exp_round(lo)
                    y = exp_round(-t)-product//2**p[2]
            data += pack('<ii', t, y)
    data += bytes(8*(padded-n))
    return bytes(data)


@lru_cache(maxsize=516)
def table_digest(spec): return blake3(table_bytes(spec)).digest()


@lru_cache(maxsize=128)
def rotation_digest(value):
    # The existing independent Arb point oracle is reused, not its old campaign.
    from check_rope import oracle
    from rope import Parameters
    ratios = tuple(Q(n, d) for n, d in value.rationals)
    p = Parameters(value.width, value.length, ratios[0], ('base', 'linear', 'llama3')[value.family],
                   ('adjacent', 'split')[value.layout], *ratios[1:], value.original)
    digest = blake3(b'stele/v0.1/cqis/rotation-data'+blake3(rotation(value)).digest())
    for i in range(value.length):
        row = b''.join(pack('<hh', *(x[0] for x in oracle(p, i, j))) for j in range(value.width//2))
        digest.update(row)
    return digest.digest()


def oracle(model):
    roles = [v for b in model.blocks for v in (b.norm1, b.exp, b.norm2, b.activation)]+[model.final_norm]
    if model.decoding is not None: roles.append(model.decoding.exp)
    functions, tables, rotations = {}, {}, {}
    refs = []
    for value in roles:
        f, r = split_selection(value); fid = blake3(f).digest(); functions[fid] = (f, r)
        refs.append(fid+blake3(r).digest())
        for spec in components(value):
            encoded = descriptor(b'stele/v0.1/table/identity', *spec)
            tables[blake3(encoded).digest()] = (encoded, spec)
    manifest = [b'stele/v0.1/cqis/functions', pack('<I', len(functions))]
    for _, (f, r) in sorted(functions.items()): manifest += [pack('<H', len(f)), f, pack('<H', len(r)), r]
    manifest.append(pack('<I', len(tables)))
    for _, (raw, spec) in sorted(tables.items()): manifest += [pack('<H', len(raw)), raw, table_digest(spec)]
    manifest = b''.join(manifest)
    raw = [b'stele/v0.1/cqis/registry', blake3(model_oracle(model)).digest(), pack('<H', len(roles)),
           b''.join(refs), pack('<I', len(manifest)), manifest, pack('<H', len(model.blocks))]
    for block in model.blocks:
        value = block.rotation
        if value is None: raw.append(b'\0')
        else:
            rid = blake3(rotation(value)).digest(); rotations[rid] = value; raw.append(b'\1'+rid)
    raw.append(pack('<H', len(rotations)))
    for _, value in sorted(rotations.items()):
        r = rotation(value); raw += [pack('<I', len(r)), r, rotation_digest(value)]
    return b''.join(raw)


def configured(rng, family, shape=None, mode=0):
    shape = shape or Shape(family, rng.randint(1, 4), 4, 2, 2 if not family else 1, 2,
                           16 if not family else rng.randint(1, 32), rng.randint(1, 64), rng.randint(1, 8))
    model = make(rng, family, shape); blocks = []
    for block in model.blocks:
        fractions = list(block.fractions); fractions[5 if family else 4] = 0
        rot = block.rotation
        if rot is not None: rot = replace(rot, width=2)
        blocks.append(replace(block, fractions=tuple(fractions), activation=Activation(shape.hidden, 1 if family else 4, 0, 0),
                              exp=Exponential(shape.context, 7, 0, 0, mode, 4 if mode else 0), rotation=rot))
    sampling = None if model.decoding is None else replace(model.decoding, exp=Exponential(shape.vocabulary, 7, 0, 0, mode, 4 if mode else 0))
    return replace(model, blocks=tuple(blocks), decoding=sampling)


def boundaries():
    rng = Random(26840); model = configured(rng, 1, Shape(1, 1, 2, 1, 1, 2, 1, 3, 2), 2)
    raw = candidate.encode(model); assert raw == oracle(model); candidate.verify(model, raw)
    for end in range(len(raw)): rejects(lambda: candidate.verify(model, raw[:end]), 'Length')
    rejects(lambda: candidate.verify(model, raw+b'\0'), 'Length')
    rejects(lambda: candidate.verify(model, bytearray(raw)), 'Capacity')
    rejects(lambda: candidate.verify(model, bytes(2**20+1)), 'Capacity')
    rejects(lambda: candidate.verify(replace(model, logits_fraction=(model.logits_fraction+1) % 31), raw), 'Structure')
    pos, data_slots = 0, []
    for part in candidate._parts(model):
        if type(part) is not bytes: data_slots.append((pos, part))
        pos += len(part) if type(part) is bytes else 32
    reasons = []
    for pos, part in data_slots:
        changed = raw[:pos]+bytes((raw[pos] ^ 1,))+raw[pos+1:]
        reason = 'RotationData' if type(part) is Rotation else 'TableData'
        rejects(lambda: candidate.verify(model, changed), reason); reasons.append(reason)
    # A digest of a fully framed but corrupted rsqrt table still cannot pass.
    table = table_bytes(('rsqrt_q', b'')); changed = bytearray(table); changed[-8] = 1
    pos = next(p for p, d in data_slots if type(d) is not Rotation and d.name == 'rsqrt_q')
    forged = raw[:pos]+blake3(bytes(changed)).digest()+raw[pos+32:]
    rejects(lambda: candidate.verify(model, forged), 'TableData')
    b = model.blocks[0]; invalid = replace(b, activation=replace(b.activation, E=14))
    rejects(lambda: candidate.encode(replace(model, blocks=(invalid,))), 'Overflow')
    # Every metadata byte, reference and digest is mandatory, not merely self-consistent.
    for i in range(len(raw)):
        changed = raw[:i]+bytes((raw[i] ^ 1,))+raw[i+1:]
        try: candidate.verify(model, changed)
        except ValueError as error: assert str(error) in ('Structure', 'TableData', 'RotationData')
        else: raise AssertionError(('Mutation', i))
    # Identical coefficient values under a different pairing still have distinct data ids.
    rot = b.rotation; other = replace(rot, layout=1-rot.layout)
    assert candidate.rotation_digest(rot) == rotation_digest(rot)
    assert candidate.rotation_digest(other) == rotation_digest(other) != rotation_digest(rot)
    rejects(lambda: candidate.rotation_digest(replace(rot, layout=bool(rot.layout))), 'Rotation')
    # Full metadata domains do not require generating their potentially large data here.
    layouts = []
    for s in (Shape(0, 12, 768, 12, 12, 64, 3072, 50257, 1024),
              Shape(1, 32, 4096, 32, 8, 128, 14336, 128256, 131072),
              Shape(0, 128, 4096, 128, 128, 32, 16384, 2**20, 2**20),
              Shape(1, 128, 16384, 128, 128, 128, 16384, 2**20, 2**20)):
        full = make(rng, s.family, s); parts = candidate._parts(full)
        tables = sum(type(p) is candidate.fn.table.Descriptor for p in parts)
        rotations = sum(type(p) is Rotation for p in parts)
        size = sum(len(p) if type(p) is bytes else 32 for p in parts)
        assert size < 312000 and tables <= 516 and rotations <= 128
        layouts.append((4*s.layers+1+int(full.decoding is not None), tables, rotations, size))
    # Both largest product components retain their complete real and padded row sets.
    for name in ('exp_q/hi', 'exp_q/lo'):
        spec = (name, bytes((31, 0, 14, 16))); d = candidate.fn.table.Descriptor(spec[0], 1, spec[1])
        assert candidate.table_digest(d) == table_digest(spec)
    # Nontrivial exp corrections and nonintegral activation inputs retain all rows.
    for name, params in [('exp_q/direct', bytes((7, 7, 7))),
                         *((name, bytes((7, 7, 7, 4))) for name in ('exp_q/hi', 'exp_q/lo', 'exp_q/correction')),
                         ('silu_q', bytes((7, 7))), ('gelu_tanh_q', bytes((7, 7)))]:
        assert candidate.table_digest(candidate.fn.table.Descriptor(name, 1, params)) == table_digest((name, params))
    data = table_bytes(('exp_q/correction', bytes((7, 7, 7, 4))))
    offset = len(b'stele/v0.1/table/data')+32+9
    corrections = sum(unpack_from('<ii', data, offset+8*i)[1] != 0 for i in range(129))
    assert corrections > 0
    assert unpack_from('<ii', data, offset+8*2) == (-126, 1)  # Rounding the product would give correction zero.
    wide_rotations = []
    for width, length, family in ((8, 17, 0), (8, 17, 1), (128, 3, 2), (16384, 1, 2)):
        value = Rotation(width, length, family, 1, 8192 if family == 2 else 0,
                         ((500000, 1), (1, 1) if family == 0 else (8, 1),
                          (1, 1) if family == 2 else (0, 1), (4, 1) if family == 2 else (0, 1)))
        actual = candidate.rotation_digest(value); assert actual == rotation_digest(value)
        wide_rotations.append((width, length, family, actual.hex()))
    # Stream a complete table beyond the former 65536-pair research limit.
    large = Rotation(2, 65537, 0, 0, 0, ((1, 1), (1, 1), (0, 1), (0, 1)))
    assert candidate.rotation_digest(large) == rotation_digest(large)
    return dict(full_fixture_bytes=len(raw), data_slots=len(data_slots), mutations=len(raw), streamed_pairs=65537,
                metadata_only_named_and_maximal_roles_tables_rotations_bytes=layouts,
                nonzero_correction_entries=corrections, wide_rotation_definitions=wide_rotations,
                streamed_rotation_digest=candidate.rotation_digest(large).hex())


def main():
    rng, digest = Random(2684), sha256(); counts = [0, 0]; modes = [0, 0, 0]; maximum = 0
    for i in range(10000):
        model = configured(rng, i % 2, mode=i % 3); raw = candidate.encode(model)
        assert raw == oracle(model); candidate.verify(model, raw)
        point = rng.randrange(len(raw)); changed = raw[:point]+bytes((raw[point] ^ 1,))+raw[point+1:]
        try: candidate.verify(model, changed)
        except ValueError as error: assert str(error) in ('Structure', 'TableData', 'RotationData')
        else: raise AssertionError(('Mutation', i))
        counts[i % 2] += 1; modes[i % 3] += 1; maximum = max(maximum, len(raw)); digest.update(pack('<I', len(raw))+raw)
    boundary = boundaries()
    print(json.dumps(dict(seed=2684, configurations=10000, families=counts, modes=modes, maximum_bytes=maximum,
                         complete_table_definitions=table_digest.cache_info().currsize,
                         complete_rotation_definitions=rotation_digest.cache_info().currsize,
                         boundaries=boundary, corpus_sha256=digest.hexdigest()), sort_keys=True))


if __name__ == '__main__': main()
