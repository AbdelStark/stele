"""Independent whole-Model struct framing and role/unit checks, Draft RFC-0025."""
from dataclasses import replace
from hashlib import sha256
import json
from math import gcd
from random import Random
from struct import pack

from blake3 import blake3

from check_arithmetic_bounds import rejects
from function_bounds import Activation, Exponential
from model_codec import Block, Model, Rotation, Sampled, decode, decode_expected, encode
from numerics import LayerNorm
from rms_bounds import RMSNorm
from source_map import Shape


def roles(s):
    result = [('token', -1, (s.vocabulary, s.width))]
    if s.family == 0:
        result += [('position', -1, (s.context, s.width))]
    for i in range(s.layers):
        result += [('norm1.gain', i, (s.width,))]
        if s.family == 0:
            result += [('norm1.bias', i, (s.width,))]
        for name, output, inner in [('Q', s.width, s.width), ('K', s.groups*s.head_width, s.width),
                                    ('V', s.groups*s.head_width, s.width), ('O', s.width, s.width),
                                    ('up', s.hidden, s.width)]+([('gate', s.hidden, s.width)] if s.family else [])+[('down', s.width, s.hidden)]:
            result += [(name, i, (output, inner))]
            if s.family == 0:
                result += [(name+'.bias', i, (output,))]
        result += [('norm2.gain', i, (s.width,))]
        if s.family == 0:
            result += [('norm2.bias', i, (s.width,))]
    result += [('final.gain', -1, (s.width,))]
    result += [('head', -1, (s.vocabulary, s.width))] if s.family else [('final.bias', -1, (s.width,))]
    return result


def blob(raw): return pack('<I', len(raw))+raw


def descriptor(prefix, name, params):
    name = name.encode('ascii')
    return prefix+pack('<H', len(name))+name+pack('<IH', 1, len(params))+params


def selection(value):
    if type(value) is LayerNorm:
        name, mode, extra = 'layernorm_q', 4, b''
        params = pack('<HBBBBII', value.d, value.F, value.G, value.E, value.Gb, value.en, value.ed)
        components = [('rsqrt_q', b'')]
    elif type(value) is RMSNorm:
        name, mode, extra = 'rmsnorm_q', 3, b''
        params = pack('<HBBBII', value.d, value.F, value.G, value.E, value.en, value.ed)
        components = [('rsqrt_q', b'')]
    elif type(value) is Exponential:
        mode, extra = value.mode, bytes((value.k,)) if value.mode == 2 else b''
        params = bytes((value.bits, value.F, value.E))
        name = 'exp_q/product' if mode == 1 else 'exp_q/nearest'
        if mode == 1:
            params += bytes((value.k,))
        full = bytes((value.bits, value.F, value.E, value.k))
        components = ([('exp_q/direct', params)] if not mode else
                      [(n, full) for n in ('exp_q/hi', 'exp_q/lo')+ (('exp_q/correction',) if mode == 2 else ())])
    else:
        name, mode, extra = ('silu_q' if value.kind == 1 else 'gelu_tanh_q'), 0, b''
        params = bytes((value.F, value.E)); components = [(name, params)]
    f = descriptor(b'stele/v0.1/function/identity', name, params)
    r = (b'stele/v0.1/function/representation'+blake3(f).digest()+pack('<BB', mode, len(extra))+extra
         +pack('<B', len(components))+b''.join(blake3(descriptor(b'stele/v0.1/table/identity', n, p)).digest() for n, p in components))
    return blob(f)+blob(r)


def rotation(r):
    if r is None:
        return b''
    return (b'stele/v0.1/cqis/rotation'+pack('<HIBBI', r.width, r.length, r.family, r.layout, r.original)
            +b''.join(pack('<QQ', n, d) for n, d in r.rationals))


def policy(value): return pack('<BI', *value)


def oracle(p):
    s = p.shape
    raw = b'stele/v0.1/cqis/model'+blob(pack('<B6H2I', s.family, s.layers, s.width, s.heads, s.groups, s.head_width, s.hidden, s.vocabulary, s.context))
    for i, ((_, _, dimensions), (bits, parameter)) in enumerate(zip(roles(s), p.formats)):
        raw += pack('<HB', i, len(dimensions))+pack('<'+'I'*len(dimensions), *dimensions)+pack('<BB', bits, parameter)
    raw += pack('<B', p.f0)
    for b in p.blocks:
        raw += selection(b.norm1)+selection(b.norm2)+bytes(b.fractions)+bytes((b.mid, b.out, b.attention))
        raw += b''.join(policy(v) for v in b.policies)+pack('<HbBB', b.score_m, b.score_e, b.accumulation, b.drop)
        raw += selection(b.exp)+selection(b.activation)+blob(rotation(b.rotation))
    raw += selection(p.final_norm)+policy(p.final_policy)+bytes((p.logits_fraction,))
    decoding = b'\0' if p.decoding is None else b'\1'+pack('<4I', p.decoding.tn, p.decoding.td, p.decoding.pn, p.decoding.pd)+selection(p.decoding.exp)
    return raw+blob(decoding)


def rational(rng, probability=False):
    d = rng.randint(1, 2**32-1); n = rng.randint(1, d if probability else 2**32-1)
    common = gcd(n, d)
    return n//common, d//common


def make(rng, family, shape=None):
    if shape is None:
        h = rng.choice((1, 2, 4, 8)); width = rng.choice((2, 16, 64, 128)); d = h*width
        shape = Shape(family, rng.randint(1, 4), d, h, h if not family else rng.choice([g for g in range(1, h+1) if h % g == 0]),
                      width, 4*d if not family else rng.randint(1, 16384),
                      rng.choice((1, 2**20, rng.randint(1, 2**20))), rng.choice((1, 2**20, rng.randint(1, 2**20))))
    s = shape
    def norm(f):
        en, ed = rational(rng); common = (s.width, f, rng.randrange(31), rng.randrange(15))
        return RMSNorm(*common, en, ed) if family else LayerNorm(*common, rng.randrange(31), en, ed)
    def row_policy(gated=False):
        return (1, rng.randint(1, 8454661 if gated else 65535)) if rng.randrange(2) else (0, 0)
    selected = {}
    def exp(n):
        mode = rng.randrange(3); bits = rng.randint(7, 31 if mode == 1 else 15)
        f, e = rng.randrange(31), rng.randrange(15)
        split = rng.randint(max(1, bits-15), min(16, bits)) if mode else 0
        key = (mode == 1, bits, f, e, split if mode == 1 else 0)
        mode, split = selected.setdefault(key, (mode, split))
        return Exponential(n, bits, f, e, mode, split)
    blocks = []; f0 = fraction = rng.randrange(31)
    for _ in range(s.layers):
        mid, out, att = (rng.randrange(31) for _ in range(3))
        fractions = tuple(rng.randrange(31) for _ in range(7 if family else 6))
        activation = Activation(s.hidden, 1 if family else 4, fractions[5 if family else 4], rng.randrange(15))
        rotation_value = None
        if family:
            kind = rng.randrange(3)
            ratios = ((500000, 1), (1, 1) if kind == 0 else (8, 1), (1, 1) if kind == 2 else (0, 1), (4, 1) if kind == 2 else (0, 1))
            rotation_value = Rotation(2*rng.randint(1, s.head_width//2), s.context, kind, rng.randrange(2), 8192 if kind == 2 else 0, ratios)
        accumulation = rng.randrange(2)
        blocks.append(Block(norm(fraction), norm(mid), fractions, mid, out, att,
                            tuple(row_policy(bool(family and j == 6)) for j in range(7)), rng.randint(1, 65535),
                            rng.randint(-62, 30), accumulation, rng.randrange(63) if accumulation else 0,
                            exp(s.context), activation, rotation_value))
        fraction = out
    final = norm(fraction); formats = []
    for name, layer, dimensions in roles(s):
        if len(dimensions) == 2:
            formats.append((rng.choice((4, 8)), 0))
        elif name.startswith(('norm1.', 'norm2.', 'final.')):
            n = final if name.startswith('final.') else getattr(blocks[layer], name.split('.')[0])
            formats.append((16, n.Gb if name.endswith('.bias') else n.G))
        else:
            formats.append((16, rng.randrange(31)))
    decoding = Sampled(*rational(rng), *rational(rng, True), exp(s.vocabulary)) if rng.randrange(2) else None
    return Model(s, tuple(formats), f0, tuple(blocks), final, row_policy(), rng.randrange(31), decoding)


def boundaries():
    rng = Random(26820)
    named = [Shape(0, 12, 768, 12, 12, 64, 3072, 50257, 1024),
             Shape(1, 32, 4096, 32, 8, 128, 14336, 128256, 131072)]
    counts = []
    for s in named+[Shape(0, 128, 4096, 128, 128, 32, 16384, 2**20, 2**20),
                    Shape(1, 128, 16384, 128, 128, 128, 16384, 2**20, 2**20)]:
        p = make(rng, s.family, s); raw = encode(p)
        assert raw == oracle(p) and decode(raw) == p and len(raw) < 220000
        counts.append((len(p.formats), len(raw)))
    assert [n for n, _ in counts[:2]] == [196, 291]
    assert named[1].vocabulary*named[1].width == 525336576
    p = make(rng, 0, Shape(0, 1, 4, 1, 1, 4, 16, 3, 2)); raw = encode(p)
    for end in range(len(raw)):
        try: decode(raw[:end])
        except ValueError: pass
        else: raise AssertionError(('Truncation', end))
    rejects(lambda: decode(raw+b'\0'), 'Trailing')
    rejects(lambda: decode(bytearray(raw)), 'Capacity')
    rejects(lambda: decode(bytes(2**20+1)), 'Capacity')
    rejects(lambda: encode(replace(p, formats=p.formats[:-1])), 'Roles')
    bad = list(p.formats); bad[2] = (16, (bad[2][1]+1) % 31)
    rejects(lambda: encode(replace(p, formats=tuple(bad))), 'NormSource')
    b = p.blocks[0]
    rejects(lambda: encode(replace(p, blocks=(replace(b, norm1=replace(b.norm1, F=(p.f0+1) % 31)),))), 'Units')
    rejects(lambda: encode(replace(p, blocks=(replace(b, activation=replace(b.activation, kind=1)),))), 'Activation')
    rejects(lambda: encode(replace(p, blocks=(replace(b, fractions=b.fractions[:-1]),))), 'Block')
    rejects(lambda: encode(replace(p, blocks=(replace(b, policies=((0, 1),)+b.policies[1:]),))), 'Policy')
    rejects(lambda: encode(replace(p, blocks=(replace(b, accumulation=0, drop=1),))), 'Drop')
    rejects(lambda: encode(replace(p, f0=True)), 'Fraction')
    rejects(lambda: encode(replace(p, final_norm=replace(p.final_norm, F=(p.final_norm.F+1) % 31))), 'Units')
    rejects(lambda: encode(replace(p, final_policy=(1, 65536))), 'Policy')
    header = len(b'stele/v0.1/cqis/model')
    rejects(lambda: decode(raw[:header]+pack('<I', 2**32-1)+raw[header+4:]), 'Capacity')
    first_record = header+4+21
    forged_dimension = raw[:first_record+3]+pack('<I', p.shape.vocabulary+2147483647)+raw[first_record+7:]
    rejects(lambda: decode(forged_dimension), 'Record')
    rep_start = raw.index(b'stele/v0.1/function/representation')
    damaged = raw[:rep_start+35]+bytes((raw[rep_start+35] ^ 1,))+raw[rep_start+36:]
    rejects(lambda: decode(damaged), 'Representation')
    llama = make(rng, 1, Shape(1, 1, 2, 1, 1, 2, 1, 1, 1)); b = llama.blocks[0]
    rejects(lambda: encode(replace(llama, blocks=(replace(b, rotation=None),))), 'Rotation')
    rot = replace(b.rotation, rationals=((1000000, 2),)+b.rotation.rationals[1:])
    rejects(lambda: encode(replace(llama, blocks=(replace(b, rotation=rot),))), 'Rational')
    rot = replace(b.rotation, family=2, original=1,
                  rationals=((2**64-1, 2**32), (2**64-1, 2**64-2), (1, 2**64-1), (2**32, 1)))
    large_rationals = replace(llama, blocks=(replace(b, rotation=rot, policies=b.policies[:6]+((1, 8454661),)),))
    assert decode(encode(large_rationals)) == large_rationals and encode(large_rationals) == oracle(large_rationals)
    rejects(lambda: encode(replace(llama, blocks=(replace(b, policies=b.policies[:6]+((1, 8454662),)),))), 'Policy')
    bad_sample = Sampled(1, 1, 1, 1, Exponential(2, 7, 0, 0, 0))
    rejects(lambda: encode(replace(llama, decoding=bad_sample)), 'FunctionShape')
    rejects(lambda: encode(replace(llama, decoding=replace(bad_sample, tn=2, td=2))), 'Rational')
    exp = Exponential(p.shape.context, 7, 0, 0, 0)
    p = replace(p, blocks=(replace(p.blocks[0], exp=exp),), decoding=Sampled(1, 1, 1, 1, Exponential(p.shape.vocabulary, 7, 0, 0, 2, 1)))
    rejects(lambda: encode(p), 'RepresentationConflict')
    return counts


def main():
    rng, digest = Random(2682), sha256(); family_counts = [0, 0]; sampled = 0; maximum = [0, 0]; mutations = [0, 0]
    for i in range(10000):
        p = make(rng, i % 2); raw = encode(p)
        assert raw == oracle(p) and decode(raw) == p
        expected = blake3(raw).digest(); assert decode_expected(expected, raw) == p
        point = rng.randrange(len(raw)); changed = raw[:point]+bytes((raw[point] ^ 1,))+raw[point+1:]
        try: decoded = decode(changed)
        except ValueError: mutations[0] += 1
        else:
            assert decoded != p and encode(decoded) == changed
            rejects(lambda: decode_expected(expected, changed), 'Identity'); mutations[1] += 1
        family_counts[p.shape.family] += 1; sampled += p.decoding is not None
        maximum = [max(maximum[0], len(raw)), max(maximum[1], len(p.formats))]
        digest.update(pack('<I', len(raw))+raw)
    named_and_maximal = boundaries()
    print(json.dumps(dict(seed=2682, configurations=10000, families=family_counts, sampled=sampled,
                         mutations_structural_identity=mutations, maxima_bytes_records=maximum,
                         named_and_maximal_records_bytes=named_and_maximal, corpus_sha256=digest.hexdigest()), sort_keys=True))


if __name__ == '__main__':
    main()
