"""Draft RFC-0025 collection appendix; deterministic records, no proof authority."""
from struct import pack

from blake3 import blake3

import arithmetic_bounds as arithmetic
import attention_input_bounds as attention
import decoding_bounds as decoding
import flow_bounds as flow
import function_bounds as function
import model_codec
import physical_bounds as physical
import registry_codec
import request_bounds as request
import rms_bounds as rms
import scales_codec
import weighted_bounds as weighted
from numerics import LayerNorm

PREFIX = b'stele/v0.1/cqis/bounds'
LIMIT = 1 << 29


def _records(model, scales):
    """Private layout only; callers must validate all three complete inputs."""
    s = model.shape; physical_roles = s.roles()
    ids = {(name, layer): i for i, (name, layer, _) in enumerate(physical_roles)}
    matrix_ids = [i for i, (_, _, dims) in enumerate(physical_roles) if len(dims) == 2]
    weights = {i: (model.formats[i][0], scale.exponent, max(scale.values()))
               for i, scale in zip(matrix_ids, scales)}
    slots = [('physical', i, physical.Physical(s, i, *fmt)) for i, fmt in enumerate(model.formats)]
    position = weights[ids['position', -1]] if not s.family else None
    slots.append(('embedding', -1, arithmetic.Embedding(s.vocabulary, s.context, model.f0,
                                                       *weights[0], position)))

    def projection(name, layer, kind, fraction, output, policy, *, head=False):
        i = ids[('head' if s.family else 'token', -1) if head else (name, layer)]
        bias = None if s.family or head else model.formats[ids[name+'.bias', layer]][1]
        return arithmetic.Affine(physical_roles[i][2][1], *weights[i], kind, fraction, output, *policy, bias)

    incoming = model.f0
    for layer, b in enumerate(model.blocks):
        p, f = b.policies, b.fractions
        score = attention.Score(s.heads, s.groups, s.head_width, s.context, f[0], f[1], b.exp.F,
                                *p[1], *p[2], b.score_m, b.score_e)
        score_bound = attention.derive(score)[1][22]
        value = weighted.Weighted(s.heads, s.groups, s.head_width, s.context, f[2], b.exp.E,
                                  *p[3], b.accumulation, b.drop)
        rows = [('norm1', b.norm1), ('convert.first', flow.Row(s.width, 0, b.norm1.E, *p[0]))]
        rows += [('project.'+name, projection(name, layer, 0, b.norm1.E, f[j], p[0]))
                 for j, name in enumerate(('Q', 'K', 'V'))]
        if s.family:
            r = b.rotation
            rows += [('rotate.'+name, attention.Rotation(heads, s.head_width, r.width, s.context, r.layout, f[j]))
                     for j, (name, heads) in enumerate((('Q', s.heads), ('K', s.groups)))]
        rows += [('convert.'+name, flow.Row(width, 0, f[j], *p[j+1]))
                 for j, (name, width) in enumerate((('Q', s.width), ('K', s.groups*s.head_width), ('V', s.groups*s.head_width)))]
        rows += [('attention.score', score),
                 ('attention.maximum', attention.Maximum(s.context, score_bound, b.exp.bits, b.exp.F)),
                 ('attention.exp', b.exp), ('attention.weighted', value),
                 ('attention.normalize', weighted.Normalize(value, b.attention)),
                 ('convert.attention', flow.Row(s.width, 0, b.attention, *p[4])),
                 ('project.O', projection('O', layer, 0, b.attention, f[3], p[4])),
                 ('residual.mid', flow.Residual(s.width, incoming, f[3], b.mid)),
                 ('norm2', b.norm2), ('convert.second', flow.Row(s.width, 0, b.norm2.E, *p[5])),
                 ('project.up', projection('up', layer, 0, b.norm2.E, f[4], p[5]))]
        if s.family: rows.append(('project.gate', projection('gate', layer, 0, b.norm2.E, f[5], p[5])))
        rows.append(('activation', b.activation))
        if s.family: rows.append(('gated_product', flow.Gated(s.hidden, f[4], b.activation.E)))
        fraction = b.activation.E+(f[4] if s.family else 0)
        rows += [('convert.ffn', flow.Row(s.hidden, s.family, fraction, *p[6])),
                 ('project.down', projection('down', layer, s.family, fraction, f[-1], p[6])),
                 ('residual.out', flow.Residual(s.width, b.mid, f[-1], b.out))]
        assert len(rows) == (27 if s.family else 23)
        slots.extend((name, layer, value) for name, value in rows); incoming = b.out
    slots += [('final.norm', -1, model.final_norm),
              ('convert.final', -1, flow.Row(s.width, 0, model.final_norm.E, *model.final_policy)),
              ('project.head', -1, projection('head', -1, 0, model.final_norm.E, model.logits_fraction,
                                              model.final_policy, head=True)),
              ('logits', -1, decoding.Logits(s.vocabulary, model.logits_fraction))]
    if model.decoding is not None:
        d = model.decoding
        slots += [('temperature', -1, decoding.Temperature(model.logits_fraction, d.tn, d.td, d.exp)),
                  ('sampling.exp', -1, d.exp), ('sampling', -1, decoding.Sampling(s.vocabulary, d.exp.E, d.pn, d.pd))]
    slots.append(('request', -1, request.Spec(s.vocabulary, s.context, int(model.decoding is not None))))
    expected = (36*s.layers+9 if s.family else 39*s.layers+10)+3*(model.decoding is not None)
    assert len(slots) == expected
    return tuple(slots)


def _encode(value):
    modules = {arithmetic.Affine: arithmetic, arithmetic.Embedding: arithmetic, LayerNorm: arithmetic,
               flow.Row: flow, flow.Residual: flow, flow.Gated: flow,
               attention.Rotation: attention, attention.Score: attention, attention.Maximum: attention,
               function.Exponential: function, function.Activation: function,
               weighted.Weighted: weighted, weighted.Normalize: weighted, rms.RMSNorm: rms,
               decoding.Logits: decoding, decoding.Temperature: decoding, decoding.Sampling: decoding,
               request.Spec: request, physical.Physical: physical}
    return modules[type(value)].encode(value)


def iterencode(model, scales_raw, registry_raw):
    """Complete only when exhausted; a yielded prefix grants no admission."""
    model_raw = model_codec.encode(model)
    scales = scales_codec.decode(model, scales_raw)
    registry_codec.verify(model, registry_raw)
    records = _records(model, scales)
    header = PREFIX+b''.join(blake3(raw).digest() for raw in (model_raw, scales_raw, registry_raw))+pack('<H', len(records))
    total = len(header); yield header
    for i, (_, _, value) in enumerate(records):
        raw = _encode(value); chunk = pack('<HI', i, len(raw))+raw
        total += len(chunk)
        if total > LIMIT: raise ValueError('Capacity')
        yield chunk


def encode(model, scales_raw, registry_raw):
    return b''.join(iterencode(model, scales_raw, registry_raw))


def digest(model, scales_raw, registry_raw):
    result = blake3()
    for chunk in iterencode(model, scales_raw, registry_raw): result.update(chunk)
    return result.digest()


def validate(model, scales_raw, registry_raw, raw):
    if type(raw) is not bytes or len(raw) > LIMIT:
        raise ValueError('Capacity')
    pos = 0
    for chunk in iterencode(model, scales_raw, registry_raw):
        if raw[pos:pos+len(chunk)] != chunk:
            raise ValueError('Encoding')
        pos += len(chunk)
    if pos != len(raw): raise ValueError('Trailing')
