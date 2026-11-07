"""Draft RFC-0025 structural Model codec; Registry/Bounds/source admission is separate."""
from dataclasses import dataclass
from math import gcd
from pathlib import Path
from struct import pack, unpack
import sys

from blake3 import blake3

from decoding import rational
from function_bounds import Activation, Exponential
from numerics import LayerNorm, group, integer
from rms_bounds import RMSNorm
from source_map import Shape, uint

sys.path.insert(0, str(Path(__file__).resolve().parents[1]/'cqis-tables'))
import function_identity as fn

PREFIX = b'stele/v0.1/cqis/model'
ROTATION = b'stele/v0.1/cqis/rotation'
LIMIT = 1 << 20


def blob(raw): return uint(len(raw), 4)+raw


@dataclass(frozen=True)
class Rotation:
    width: int
    length: int
    family: int
    layout: int
    original: int
    rationals: tuple[tuple[int, int], ...]

    def encode(self):
        integer(self.width, 2, 16384, 'Rotation')
        integer(self.length, 1, 1 << 20, 'Rotation')
        integer(self.family, 0, 2, 'Rotation'); integer(self.layout, 0, 1, 'Rotation')
        integer(self.original, 1 if self.family == 2 else 0, (1 << 20) if self.family == 2 else 0, 'Rotation')
        if self.width % 2 or type(self.rationals) is not tuple or len(self.rationals) != 4:
            raise ValueError('Rotation')
        for pair in self.rationals:
            if type(pair) is not tuple or len(pair) != 2:
                raise ValueError('Rational')
            n, d = pair
            integer(n, 0, (1 << 64)-1, 'Rational'); integer(d, 1, (1 << 64)-1, 'Rational')
            if gcd(n, d) != 1 or n > (1 << 32)*d:
                raise ValueError('Rational')
        theta, factor, low, high = self.rationals
        if theta[0] < theta[1] or factor[0] < factor[1]:
            raise ValueError('Rational')
        if self.family == 2:
            if low[0] == 0 or low[0]*high[1] >= high[0]*low[1]:
                raise ValueError('Rational')
        elif low != (0, 1) or high != (0, 1) or (self.family == 0 and factor != (1, 1)):
            raise ValueError('Rational')
        return (ROTATION+uint(self.width, 2)+uint(self.length, 4)+bytes((self.family, self.layout))+uint(self.original, 4)
                +b''.join(uint(n, 8)+uint(d, 8) for n, d in self.rationals))


def function_frames(value):
    if type(value) is LayerNorm:
        params = pack('<HBBBBII', value.d, value.F, value.G, value.E, value.Gb, value.en, value.ed)
        name = b'layernorm_q'
        f = fn.FUNCTION+uint(len(name), 2)+name+uint(1, 4)+uint(len(params), 2)+params
        r = fn.REPRESENTATION+blake3(f).digest()+bytes((4, 0, 1))+fn.table.table_id(fn.table.Descriptor('rsqrt_q', 1, b''))
        return f, r
    version = 1
    if type(value) is RMSNorm:
        name, mode, extra = 'rmsnorm_q', 3, b''
        params = pack('<HBBBII', value.d, value.F, value.G, value.E, value.en, value.ed)
        version = value.version
    elif type(value) is Exponential:
        name = 'exp_q/product' if value.mode == 1 else 'exp_q/nearest'
        params = bytes((value.bits, value.F, value.E))+ (bytes((value.k,)) if value.mode == 1 else b'')
        mode, extra = value.mode, bytes((value.k,)) if value.mode == 2 else b''
    elif type(value) is Activation and value.kind in (1, 4):
        name, mode, extra = ('silu_q' if value.kind == 1 else 'gelu_tanh_q'), 0, b''
        params = bytes((value.F, value.E))
    else:
        raise ValueError('Function')
    f = fn.Function(name, version, params); r = fn.Representation(f, mode, extra)
    return fn.encode(f), fn.encode_representation(r)


def selection(value):
    f, r = function_frames(value)
    return blob(f)+blob(r)


def policy(value, gated=False, n=None):
    """n is the row length of an affine-input row, which alone may be grouped (RFC-0004 A15)."""
    if type(value) is not tuple or len(value) != 2:
        raise ValueError('Policy')
    mode, scale = value
    integer(mode, 0, 1 if n is None else 2, 'Policy')
    if mode == 2:
        group(scale, n, 'Policy')
    else:
        integer(scale, 1 if mode else 0, (8454661 if gated else 65535) if mode else 0, 'Policy')
    return bytes((mode,))+uint(scale, 4)


@dataclass(frozen=True)
class Sampled:
    tn: int
    td: int
    pn: int
    pd: int
    exp: Exponential

    def encode(self, vocabulary):
        rational(self.tn, self.td); rational(self.pn, self.pd, top_p=True)
        if type(self.exp) is not Exponential or self.exp.n != vocabulary:
            raise ValueError('FunctionShape')
        return b'\1'+b''.join(uint(v, 4) for v in (self.tn, self.td, self.pn, self.pd))+selection(self.exp)


@dataclass(frozen=True)
class Block:
    norm1: LayerNorm | RMSNorm
    norm2: LayerNorm | RMSNorm
    fractions: tuple[int, ...]
    mid: int
    out: int
    attention: int
    policies: tuple[tuple[int, int], ...]
    score_m: int
    score_e: int
    accumulation: int
    drop: int
    exp: Exponential
    activation: Activation
    rotation: Rotation | None


@dataclass(frozen=True)
class Model:
    shape: Shape
    formats: tuple[tuple[int, int], ...]
    f0: int
    blocks: tuple[Block, ...]
    final_norm: LayerNorm | RMSNorm
    final_policy: tuple[int, int]
    logits_fraction: int
    decoding: Sampled | None


def _norm(value, shape, fraction):
    if type(value) is not (RMSNorm if shape.family else LayerNorm) or value.d != shape.width:
        raise ValueError('NormShape')
    if value.F != fraction:
        raise ValueError('Units')


def encode(p):
    if type(p) is not Model or type(p.shape) is not Shape:
        raise ValueError('Model')
    s = p.shape; roles = s.roles()
    if type(p.formats) is not tuple or len(p.formats) != len(roles):
        raise ValueError('Roles')
    if type(p.blocks) is not tuple or len(p.blocks) != s.layers or any(type(b) is not Block for b in p.blocks):
        raise ValueError('Block')
    integer(p.f0, 0, 30, 'Fraction'); integer(p.logits_fraction, 0, 30, 'Fraction')
    current, chunks, selections = p.f0, [PREFIX, blob(s.encode())], []
    for i, ((name, layer, dimensions), fmt) in enumerate(zip(roles, p.formats)):
        if type(fmt) is not tuple or len(fmt) != 2:
            raise ValueError('Format')
        bits, parameter = fmt
        integer(bits, 0, 255, 'Format'); integer(parameter, 0, 30 if len(dimensions) == 1 else 0, 'Format')
        if bits not in ((16,) if len(dimensions) == 1 else (4, 8)):
            raise ValueError('Format')
        if name.startswith(('norm1.', 'norm2.', 'final.')):
            n = p.final_norm if name.startswith('final.') else getattr(p.blocks[layer], name.split('.')[0])
            if type(n) is not (RMSNorm if s.family else LayerNorm):
                raise ValueError('NormShape')
            if parameter != (n.Gb if name.endswith('.bias') else n.G):
                raise ValueError('NormSource')
        chunks.append(uint(i, 2)+bytes((len(dimensions),))+b''.join(uint(d, 4) for d in dimensions)+bytes(fmt))
    chunks.append(bytes((p.f0,)))
    for b in p.blocks:
        if type(b.fractions) is not tuple or len(b.fractions) != (7 if s.family else 6) or type(b.policies) is not tuple or len(b.policies) != 7:
            raise ValueError('Block')
        for fraction in b.fractions+(b.mid, b.out, b.attention):
            integer(fraction, 0, 30, 'Fraction')
        _norm(b.norm1, s, current); _norm(b.norm2, s, b.mid); current = b.out
        if type(b.exp) is not Exponential or b.exp.n != s.context:
            raise ValueError('FunctionShape')
        if (type(b.activation) is not Activation or b.activation.d != s.hidden or b.activation.kind != (1 if s.family else 4)
                or b.activation.F != b.fractions[5 if s.family else 4]):
            raise ValueError('Activation')
        if s.family:
            if type(b.rotation) is not Rotation or b.rotation.width > s.head_width or b.rotation.length != s.context:
                raise ValueError('Rotation')
            rotation = b.rotation.encode()
        else:
            if b.rotation is not None:
                raise ValueError('Rotation')
            rotation = b''
        integer(b.score_m, 1, 65535, 'Multiplier'); integer(b.score_e, -62, 30, 'Multiplier')
        integer(b.accumulation, 0, 1, 'Mode'); integer(b.drop, 0, 62 if b.accumulation else 0, 'Drop')
        chunks += [selection(b.norm1), selection(b.norm2), bytes(b.fractions), bytes((b.mid, b.out, b.attention)),
                   b''.join(policy(v, bool(s.family and j == 6), (s.width, None, None, None, s.width, s.width, s.hidden)[j])
                            for j, v in enumerate(b.policies)),
                   uint(b.score_m, 2), b.score_e.to_bytes(1, 'little', signed=True), bytes((b.accumulation, b.drop)),
                   selection(b.exp), selection(b.activation), blob(rotation)]
        selections += [b.norm1, b.exp, b.norm2, b.activation]
    _norm(p.final_norm, s, current)
    # RFC-0004 A14: a wide (int24) residual stream is selected by rmsnorm_q version 2 in every norm.
    if len({getattr(n, 'version', 1) for b in p.blocks for n in (b.norm1, b.norm2, p.final_norm)}) != 1:
        raise ValueError('Width')
    chunks += [selection(p.final_norm), policy(p.final_policy, n=s.width), bytes((p.logits_fraction,))]
    selections.append(p.final_norm)
    if p.decoding is None:
        chunks.append(blob(b'\0'))
    elif type(p.decoding) is Sampled:
        chunks.append(blob(p.decoding.encode(s.vocabulary))); selections.append(p.decoding.exp)
    else:
        raise ValueError('Decoding')
    chosen = {}
    for value in selections:
        f, r = function_frames(value); key = blake3(f).digest()
        if key in chosen and chosen[key] != (f, r):
            raise ValueError('RepresentationConflict')
        chosen[key] = f, r
    if sum(map(len, chunks)) > LIMIT:
        raise ValueError('Capacity')
    return b''.join(chunks)


class Reader:
    def __init__(self, raw):
        if type(raw) is not bytes or len(raw) > LIMIT:
            raise ValueError('Capacity')
        self.raw, self.pos = raw, 0

    def take(self, n):
        if not 0 <= n <= len(self.raw)-self.pos:
            raise ValueError('Truncated')
        result = self.raw[self.pos:self.pos+n]; self.pos += n
        return result

    def u(self, size, signed=False): return int.from_bytes(self.take(size), 'little', signed=signed)

    def blob(self, limit):
        size = self.u(4)
        if size > limit:
            raise ValueError('Capacity')
        return self.take(size)

    def end(self):
        if self.pos != len(self.raw):
            raise ValueError('Trailing')

    def selection(self, kind, extent):
        fraw, rraw = self.blob(128), self.blob(192)
        marker = fn.FUNCTION+uint(11, 2)+b'layernorm_q'
        if fraw.startswith(marker):
            if len(fraw) != len(marker)+20:
                raise ValueError('Function')
            value = LayerNorm(*unpack('<HBBBBII', fraw[-14:]))
            if kind != 'norm' or function_frames(value) != (fraw, rraw):
                raise ValueError('Representation')
            return value
        f = fn.decode(fraw); r = fn.decode_representation(f, rraw)
        if kind == 'norm' and f.name == 'rmsnorm_q':
            return RMSNorm(*unpack('<HBBBII', f.params), version=f.version)
        if kind == 'exp' and f.name in ('exp_q/product', 'exp_q/nearest'):
            return Exponential(extent, *f.params[:3], r.mode, f.params[3] if r.mode == 1 else r.params[0] if r.mode == 2 else 0)
        if kind == 'activation' and f.name in ('silu_q', 'gelu_tanh_q'):
            return Activation(extent, 1 if f.name == 'silu_q' else 4, *f.params)
        raise ValueError('Function')


def decode(raw):
    t = Reader(raw)
    if t.take(len(PREFIX)) != PREFIX:
        raise ValueError('Header')
    shape_raw = t.blob(21)
    if len(shape_raw) != 21:
        raise ValueError('Shape')
    s = Shape(*unpack('<B6H2I', shape_raw)); formats = []
    for i, (_, _, dimensions) in enumerate(s.roles()):
        if t.u(2) != i or t.u(1) != len(dimensions) or tuple(t.u(4) for _ in dimensions) != dimensions:
            raise ValueError('Record')
        formats.append((t.u(1), t.u(1)))
    f0, blocks = t.u(1), []
    for _ in range(s.layers):
        n1, n2 = t.selection('norm', s.width), t.selection('norm', s.width)
        fractions = tuple(t.u(1) for _ in range(7 if s.family else 6))
        mid, out, attention = t.u(1), t.u(1), t.u(1)
        policies = tuple((t.u(1), t.u(4)) for _ in range(7))
        m, e, accumulation, drop = t.u(2), t.u(1, True), t.u(1), t.u(1)
        exp, activation = t.selection('exp', s.context), t.selection('activation', s.hidden)
        r = t.blob(128); rotation = None
        if r:
            rr = Reader(r)
            if rr.take(len(ROTATION)) != ROTATION:
                raise ValueError('Rotation')
            rotation = Rotation(rr.u(2), rr.u(4), rr.u(1), rr.u(1), rr.u(4), tuple((rr.u(8), rr.u(8)) for _ in range(4)))
            rr.end()
        blocks.append(Block(n1, n2, fractions, mid, out, attention, policies, m, e, accumulation, drop, exp, activation, rotation))
    final, final_policy, logits = t.selection('norm', s.width), (t.u(1), t.u(4)), t.u(1)
    d = Reader(t.blob(345)); mode = d.u(1); integer(mode, 0, 1, 'Mode')
    decoding = Sampled(*(d.u(4) for _ in range(4)), d.selection('exp', s.vocabulary)) if mode else None
    d.end(); t.end()
    p = Model(s, tuple(formats), f0, tuple(blocks), final, final_policy, logits, decoding)
    if encode(p) != raw:
        raise ValueError('Canonical')
    return p


def decode_expected(expected_digest, raw):
    if type(expected_digest) is not bytes or len(expected_digest) != 32:
        raise ValueError('Digest')
    result = decode(raw)
    if blake3(raw).digest() != expected_digest:
        raise ValueError('Identity')
    return result
