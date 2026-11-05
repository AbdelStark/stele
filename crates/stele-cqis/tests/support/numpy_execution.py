"""RFC-0025 §2: independent exact NumPy int64 full-model oracle.

Matrices are decoded in bounded 64-channel tiles from the unchanged Artifact;
wide dyadic/normalization glue uses Python integers and rational rounding.
Nonlinear points use the qualified independent Arb oracle, not native tables.
No original weights or activations are written to logs.
"""
from fractions import Fraction as Q
from math import isqrt
from pathlib import Path
from struct import pack
import sys
from types import MappingProxyType

import numpy as np
from blake3 import blake3

ROOT = Path(__file__).resolve().parents[4]
sys.path.insert(0, str(ROOT/'research/cqis-model-contract'))
from check_model_execution import activation, exp_point, rotate
from check_decoding_execution import draw
from numerics import LayerNorm
import artifact_codec
import attention_input_bounds
import model_codec
import model_execution
import scales_codec
import weighted_bounds


def load(model, mapping, scales_raw, raw, expected):
    """Complete independent Artifact check with bounded vectorized code scans.

    The canonical metadata helpers are unchanged. Every payload byte, scale,
    odd-nibble padding bit, extent and final digest is checked before Data exists.
    This does not replace or rerun original-source conversion qualification.
    """
    assert type(raw) is bytes and len(expected) == 32
    header, records, scales, total = artifact_codec._context(model, mapping, scales_raw)
    assert len(raw) == total, 'ArtifactLength'
    position = 0

    def expect(part):
        nonlocal position
        assert raw[position:position+len(part)] == part, 'ArtifactMetadata'
        position += len(part)

    for part in header:
        expect(part)
    scale_iter = iter(scales)
    for record in records:
        scale = next(scale_iter) if len(record.dimensions) == 2 else None
        for part, _ in artifact_codec._header(record, scale):
            expect(part)
        assert position == record.payload_offset
        for start in range(position, position+record.payload_length, 1 << 20):
            count = min(1 << 20, position+record.payload_length-start)
            codes = np.frombuffer(raw, dtype='u1', count=count, offset=start)
            if record.bits == 8:
                assert not np.any(codes == 128), 'ArtifactCode'
            if record.bits == 4:
                assert not np.any((codes & 15) == 8) and not np.any((codes >> 4) == 8), 'ArtifactCode'
        position += record.payload_length
        if record.bits == 4 and record.elements % 2:
            assert raw[position-1] >> 4 == 0, 'ArtifactPadding'
    assert position == len(raw) and blake3(raw).digest() == expected, 'ArtifactIdentity'
    s = model.shape
    for b in model.blocks:
        f, p = b.fractions, b.policies
        attention_input_bounds.derive(attention_input_bounds.Score(s.heads, s.groups, s.head_width, s.context, f[0], f[1], b.exp.F, *p[1], *p[2], b.score_m, b.score_e))
        weighted_bounds._constants(weighted_bounds.Weighted(s.heads, s.groups, s.head_width, s.context, f[2], b.exp.E, *p[3], b.accumulation, b.drop))
        assert b.activation.E <= b.activation.F, 'ActivationRange'
    ids = {(name, layer): i for i, (name, layer, _) in enumerate(s.roles())}
    if not s.family:
        ids['head', -1] = ids['token', -1]
    by_id = dict(zip((r.ordinal for r in records if len(r.dimensions) == 2), scales))
    return model_execution.Data(model, raw, records, MappingProxyType(by_id), MappingProxyType(ids),
                                (blake3(model_codec.encode(model)).digest(), blake3(scales_raw).digest(), expected))


def nearest(x):
    low = x.numerator//x.denominator
    return min((low, low+1), key=lambda k: (abs(x-k), -abs(k)))


def wide(x):
    value = nearest(x)
    if not -32768 <= value <= 32767:
        raise ValueError('Range')
    return value


def convert(values, fraction, policy):
    values = np.asarray(values, dtype=np.int64)
    magnitude = np.abs(values)
    scale = policy[1] if policy[0] else (int(magnitude.max())+126)//127
    if scale:
        quotient = magnitude//scale+(magnitude % scale >= scale-magnitude % scale)
        if np.any(quotient > 127):
            raise ValueError('RowRange')
        codes = np.where(values < 0, -quotient, quotient)
    else:
        codes = np.zeros(values.shape, dtype=np.int64)
    return codes, scale, fraction


class Oracle:
    def __init__(self, data):
        self.data = data
        self.model = data.model

    def matrix(self, name, layer, start, count):
        r = self.data.record(name, layer)
        begin, end = start*r.dimensions[1], (start+count)*r.dimensions[1]
        if r.bits == 8:
            values = np.frombuffer(self.data.raw, dtype='i1', count=end-begin,
                                   offset=r.payload_offset+begin).astype(np.int64)
        else:
            positions = np.arange(begin, end, dtype=np.int64)
            raw = np.frombuffer(self.data.raw, dtype='u1', count=(end+1)//2-begin//2,
                                offset=r.payload_offset+begin//2)
            digits = (raw[positions//2-begin//2] >> ((positions & 1)*4)) & 15
            values = np.where(digits >= 8, digits-16, digits).astype(np.int64)
        return values.reshape(count, r.dimensions[1])

    def vector(self, name, layer):
        r = self.data.record(name, layer)
        return np.frombuffer(self.data.raw, dtype='<i2', count=r.elements,
                             offset=r.payload_offset).astype(np.int64)

    def linear(self, name, layer, row, fraction):
        codes, scale, f = row
        r = self.data.record(name, layer)
        stored = self.data.scales[r.ordinal]
        mantissas = np.frombuffer(stored.mantissas, dtype='<u2')
        biases = None if self.model.shape.family or name == 'head' else self.vector(name+'.bias', layer)
        fb = 0 if biases is None else self.model.formats[self.data.record(name+'.bias', layer).ordinal][1]
        factor = Q(scale)*Q(2)**(stored.exponent-f+fraction)
        bias_factor = Q(2)**(fraction-fb)
        output = []
        for start in range(0, r.dimensions[0], 64):
            count = min(64, r.dimensions[0]-start)
            # Width<=16384 and |code|<=127 imply |dot|<2^28: exact int64.
            dots = self.matrix(name, layer, start, count) @ codes
            for j, dot in enumerate(dots, start):
                bias = 0 if biases is None else int(biases[j])
                output.append(wide(int(dot)*int(mantissas[j])*factor+bias*bias_factor))
        return np.asarray(output, dtype=np.int64)

    def norm(self, spec, values, role, layer=-1):
        d = len(values)
        mean = Q(int(values.sum()), d) if isinstance(spec, LayerNorm) else Q(0)
        variance = Q(int(values @ values), d)-mean*mean
        q = variance/Q(2)**(2*spec.F)+Q(spec.en, spec.ed)
        a = next(a for a in range(-23, 10) if 16384 <= q/Q(4)**a < 65536)
        scaled = q/Q(4)**a
        mantissa = scaled.numerator//scaled.denominator
        reciprocal = isqrt((1 << 42)//mantissa)
        reciprocal += (1 << 44) >= mantissa*(2*reciprocal+1)**2
        factor = reciprocal*Q(2)**(spec.E-spec.F-spec.G-21-a)
        gains = self.vector(role+'.gain', layer)
        biases = np.zeros(d, dtype=np.int64) if not isinstance(spec, LayerNorm) else self.vector(role+'.bias', layer)
        bias_factor = Q(0) if not isinstance(spec, LayerNorm) else Q(2)**(spec.E-spec.Gb)
        return np.asarray([wide((Q(int(x))-mean)*int(h)*factor+int(b)*bias_factor)
                           for x, h, b in zip(values, gains, biases)], dtype=np.int64)

    def full(self, tokens):
        m, s = self.model, self.model.shape
        rows = []
        for position, token in enumerate(tokens):
            code = self.matrix('token', -1, token, 1)[0]
            tm, te = self.data.scale(self.data.record('token'), token)
            if s.family:
                values = [wide(int(x)*tm*Q(2)**(te+m.f0)) for x in code]
            else:
                pc = self.matrix('position', -1, position, 1)[0]
                pm, pe = self.data.scale(self.data.record('position'), position)
                values = [wide(int(x)*tm*Q(2)**(te+m.f0)+int(y)*pm*Q(2)**(pe+m.f0)) for x, y in zip(code, pc)]
            rows.append(np.asarray(values, dtype=np.int64))
        cuts = [rows]
        cache = []
        for layer, b in enumerate(m.blocks):
            projected = []
            for position, values in enumerate(rows):
                row = convert(self.norm(b.norm1, values, 'norm1', layer), b.norm1.E, b.policies[0])
                q, k, v = [self.linear(name, layer, row, b.fractions[j]) for j, name in enumerate(('Q', 'K', 'V'))]
                q = rotate(b.rotation, tuple(map(int, q)), position, s.heads, s.head_width)
                k = rotate(b.rotation, tuple(map(int, k)), position, s.groups, s.head_width)
                projected.append(tuple(convert(value, b.fractions[j], b.policies[j+1]) for j, value in enumerate((q, k, v))))
            keys = tuple((p[1], p[2]) for p in projected)
            cache.append(keys)
            outputs = []
            for position, (values, projection) in enumerate(zip(rows, projected)):
                q, sq, _ = projection[0]
                attention = []
                for head in range(s.heads):
                    group = head//(s.heads//s.groups)
                    scores = [nearest(Q(int(q[head*s.head_width:(head+1)*s.head_width] @ k[group*s.head_width:(group+1)*s.head_width])*sq*sk*b.score_m)*Q(2)**(b.score_e-b.fractions[0]-b.fractions[1]+b.exp.F)) for (k, sk, _), _ in keys]
                    maximum = max(scores[:position+1])
                    if min(scores[:position+1])-maximum < -2**b.exp.bits:
                        raise ValueError('ExpDomain')
                    weights = [exp_point(b.exp, x-maximum) for x in scores[:position+1]]
                    for lane in range(s.head_width):
                        terms = [w*sv*int(v[group*s.head_width+lane]) for w, (_, (v, sv, _)) in zip(weights, keys)]
                        total = sum(nearest(Q(sum(terms[j:j+1024]), 2**b.drop)) for j in range(0, len(terms), 1024)) if b.accumulation else sum(terms)
                        attention.append(wide(Q(total, sum(weights))*Q(2)**(b.attention-b.fractions[2]+b.drop)))
                o = self.linear('O', layer, convert(attention, b.attention, b.policies[4]), b.fractions[3])
                incoming = m.f0 if layer == 0 else m.blocks[layer-1].out
                mid = np.asarray([wide(int(x)*Q(2)**(b.mid-incoming)+int(y)*Q(2)**(b.mid-b.fractions[3])) for x, y in zip(values, o)], dtype=np.int64)
                row = convert(self.norm(b.norm2, mid, 'norm2', layer), b.norm2.E, b.policies[5])
                up = self.linear('up', layer, row, b.fractions[4])
                gate = self.linear('gate', layer, row, b.fractions[5]) if s.family else up
                activated = np.asarray([activation(b.activation, int(t)) for t in gate], dtype=np.int64)
                product = up*activated if s.family else activated
                fraction = b.activation.E+(b.fractions[4] if s.family else 0)
                down = self.linear('down', layer, convert(product, fraction, b.policies[6]), b.fractions[-1])
                outputs.append(np.asarray([wide(int(x)*Q(2)**(b.out-b.mid)+int(y)*Q(2)**(b.out-b.fractions[-1])) for x, y in zip(mid, down)], dtype=np.int64))
            rows = outputs
            cuts.append(rows)
        logits = [self.linear('head', -1, convert(self.norm(m.final_norm, values, 'final'), m.final_norm.E, m.final_policy), m.logits_fraction) for values in rows]
        return cuts, logits, cache

    def choose(self, logits, seed, position):
        m = self.model
        maximum = int(logits.max())
        if m.decoding is None:
            return int(np.flatnonzero(logits == maximum)[0]), ((), (), (), (), None)
        d = m.decoding
        arguments = tuple(nearest(Q(int(x)-maximum)*Q(d.td, d.tn)*Q(2)**(d.exp.F-m.logits_fraction)) for x in logits)
        if min(arguments) < -2**d.exp.bits:
            raise ValueError('ExpDomain')
        weights = np.asarray([exp_point(d.exp, t) for t in arguments], dtype=np.int64)
        ids = np.arange(len(weights), dtype=np.int64)
        order = np.lexsort((ids, -weights))
        prefixes = np.cumsum(weights[order], dtype=np.int64)
        # Threshold/CDF products can exceed int64; preserve Python integer products.
        count = next(i+1 for i, x in enumerate(prefixes) if int(x)*d.pd >= int(prefixes[-1])*d.pn)
        mass = int(prefixes[count-1])
        cdf = tuple((int(x) << 32)//mass for x in prefixes[:count])
        uniform = draw(seed, position)
        token = int(order[next(i for i, endpoint in enumerate(cdf) if uniform < endpoint)])
        return token, (arguments, tuple(map(int, weights)), tuple(map(int, order)), cdf, uniform)


def full_bytes(tokens, result):
    cuts, logits, cache = result
    raw = bytearray()
    for cut in cuts:
        for row in cut:
            raw.extend(np.asarray(row, dtype='<i2').tobytes())
    for row in logits:
        raw.extend(np.asarray(row, dtype='<i2').tobytes())
    raw.extend(pack('<I', len(tokens))+pack('<'+'I'*len(tokens), *tokens))
    for layer in cache:
        for pair in layer:
            for codes, scale, fraction in pair:
                raw.extend(pack('<IB', scale, fraction)+codes.astype('i1').tobytes())
    return bytes(raw)
