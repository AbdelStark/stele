"""Draft RFC-0025 collection: independent selection/framing, unchanged schema oracles."""
from dataclasses import replace
from hashlib import sha256
import json
from random import Random
from struct import pack, unpack_from

from blake3 import blake3

import bound_collection as c
from check_arithmetic_bounds import rejects
from check_model_codec import oracle as model_oracle, roles
from check_registry_codec import configured, oracle as registry_oracle
from check_scales_codec import make_scales, oracle as scales_oracle
from model_codec import Sampled
from scales_codec import Scale
from source_map import Shape


def score_bound(s, b):
    def restored(policy):
        mode, scale = policy
        return 127*259 if not mode else min(127, (65536+scale)//(2*scale))*scale
    maximum = s.head_width*restored(b.policies[1])*restored(b.policies[2])*b.score_m
    shift = b.score_e-b.fractions[0]-b.fractions[1]+b.exp.F
    return maximum*2**shift if shift >= 0 else (maximum+2**(-shift-1))//2**(-shift)


def expected_records(m, scales):
    s = m.shape; physical = roles(s); table = {}; it = iter(scales)
    for i, (name, layer, dimensions) in enumerate(physical):
        table[name, layer] = (i, dimensions, next(it) if len(dimensions) == 2 else None)
    def matrix(name, layer):
        i, _, scale = table[name, layer]
        maximum = max(unpack_from('<H', scale.mantissas, j)[0] for j in range(0, len(scale.mantissas), 2))
        return m.formats[i][0], scale.exponent, maximum
    result = [('physical', i, c.physical.Physical(s, i, *m.formats[i])) for i in range(len(physical))]
    result.append(('embedding', -1, c.arithmetic.Embedding(s.vocabulary, s.context, m.f0,
                  *matrix('token', -1), matrix('position', -1) if s.family == 0 else None)))
    for l, b in enumerate(m.blocks):
        f, p = b.fractions, b.policies; ff = b.activation.E+(f[4] if s.family else 0)
        values = dict(norm1=b.norm1, norm2=b.norm2, activation=b.activation)
        for name, width, kind, fraction, policy in [
                ('first', s.width, 0, b.norm1.E, p[0]), ('Q', s.width, 0, f[0], p[1]),
                ('K', s.groups*s.head_width, 0, f[1], p[2]), ('V', s.groups*s.head_width, 0, f[2], p[3]),
                ('attention', s.width, 0, b.attention, p[4]), ('second', s.width, 0, b.norm2.E, p[5]),
                ('ffn', s.hidden, s.family, ff, p[6])]:
            values['convert.'+name] = c.flow.Row(width, kind, fraction, *policy)
        names = ('Q', 'K', 'V', 'O', 'up', 'gate', 'down') if s.family else ('Q', 'K', 'V', 'O', 'up', 'down')
        for j, name in enumerate(names):
            input_row = values['convert.'+('first' if j < 3 else 'attention' if name == 'O' else 'ffn' if name == 'down' else 'second')]
            _, dimensions, _ = table[name, l]
            bias = None if s.family else m.formats[table[name+'.bias', l][0]][1]
            values['project.'+name] = c.arithmetic.Affine(dimensions[1], *matrix(name, l), input_row.kind,
                    input_row.fraction, f[j], input_row.policy, input_row.scale, bias)
        values['attention.score'] = c.attention.Score(s.heads, s.groups, s.head_width, s.context,
                                    f[0], f[1], b.exp.F, *p[1], *p[2], b.score_m, b.score_e)
        bound = score_bound(s, b); assert bound < 2**31
        values['attention.maximum'] = c.attention.Maximum(s.context, bound, b.exp.bits, b.exp.F)
        values['attention.exp'] = b.exp
        values['attention.weighted'] = c.weighted.Weighted(s.heads, s.groups, s.head_width, s.context,
                                                         f[2], b.exp.E, *p[3], b.accumulation, b.drop)
        values['attention.normalize'] = c.weighted.Normalize(values['attention.weighted'], b.attention)
        values['residual.mid'] = c.flow.Residual(s.width, m.f0 if l == 0 else m.blocks[l-1].out, f[3], b.mid)
        values['residual.out'] = c.flow.Residual(s.width, b.mid, f[-1], b.out)
        order = 'norm1 convert.first project.Q project.K project.V'.split()
        if s.family:
            values['rotate.Q'] = c.attention.Rotation(s.heads, s.head_width, b.rotation.width, s.context, b.rotation.layout, f[0])
            values['rotate.K'] = replace(values['rotate.Q'], h=s.groups, f=f[1])
            values['gated_product'] = c.flow.Gated(s.hidden, f[4], b.activation.E)
            order += ['rotate.Q', 'rotate.K']
        order += ('convert.Q convert.K convert.V attention.score attention.maximum attention.exp attention.weighted '
                  'attention.normalize convert.attention project.O residual.mid norm2 convert.second project.up').split()
        order += (['project.gate', 'activation', 'gated_product'] if s.family else ['activation'])
        order += ['convert.ffn', 'project.down', 'residual.out']
        assert set(order) == set(values) and len(order) == len(values)
        result.extend((name, l, values[name]) for name in order)
    result += [('final.norm', -1, m.final_norm),
               ('convert.final', -1, c.flow.Row(s.width, 0, m.final_norm.E, *m.final_policy)),
               ('project.head', -1, c.arithmetic.Affine(s.width, *matrix('head' if s.family else 'token', -1),
                    0, m.final_norm.E, m.logits_fraction, *m.final_policy, None)),
               ('logits', -1, c.decoding.Logits(s.vocabulary, m.logits_fraction))]
    if m.decoding is not None:
        d = m.decoding
        result += [('temperature', -1, c.decoding.Temperature(m.logits_fraction, d.tn, d.td, d.exp)),
                   ('sampling.exp', -1, d.exp), ('sampling', -1, c.decoding.Sampling(s.vocabulary, d.exp.E, d.pn, d.pd))]
    result += [('request', -1, c.request.Spec(s.vocabulary, s.context, int(m.decoding is not None)))]
    return tuple(result)


def record_oracle(p):
    from check_arithmetic_bounds import scalar_oracle, encode_oracle
    from check_flow_bounds import encoded_oracle
    import check_layernorm_bounds as ln
    if type(p) in (c.arithmetic.Affine, c.arithmetic.Embedding): return encode_oracle(p, scalar_oracle(p)[0])
    if type(p) is c.LayerNorm: return ln.encoded_oracle(p, ln.oracle(p)[0])
    if type(p) is c.rms.RMSNorm:
        import check_rms_bounds as rm
        return encoded_oracle(rm.oracle(p)[0], pack('<H3B2I', p.d, p.F, p.G, p.E, p.en, p.ed))
    modules = ('flow', 'attention_input', 'function', 'weighted', 'decoding', 'request', 'physical')
    for name in modules:
        module = getattr(c, 'attention' if name == 'attention_input' else name)
        if type(p).__module__ == module.__name__:
            oracle = __import__('check_'+name+'_bounds').oracle
            record, params = oracle(p)[:2]
            raw = encoded_oracle(record, params)
            if name == 'weighted':
                offset = len(b'stele/v0.1/cqis/model-arithmetic')+7+len(params)+4
                raw = raw[:offset]+b'\4'+raw[offset+1:]
            return raw
    raise AssertionError(type(p))


def fixture(rng, family, shape, mode):
    m = configured(rng, family, shape, mode); blocks = []
    for b in m.blocks:
        choices = [e for e in range(-62, 31) if score_bound(shape, replace(b, score_e=e)) < 2**31]
        b = replace(b, score_e=rng.choice(choices[-21:]))
        if b.accumulation:
            row_mode, scale = b.policies[3]
            restored = 127*259 if not row_mode else min(127, (65536+scale)//(2*scale))*scale
            drop = next(k for k in range(63) if (1024*(1 << b.exp.E)*restored+(1 << k)//2)//(1 << k) <= 32767)
            b = replace(b, drop=rng.randint(drop, 62))
        blocks.append(b)
    return replace(m, blocks=tuple(blocks))


def framing(m, sr, rr, records, *, independent=False):
    header = b'stele/v0.1/cqis/bounds'+b''.join(blake3(raw).digest() for raw in (model_oracle(m), sr, rr))+pack('<H', len(records))
    parts = [header]
    for i, (_, _, value) in enumerate(records):
        raw = record_oracle(value) if independent else c._encode(value)
        parts.append(pack('<HI', i, len(raw))+raw)
    return parts


def boundaries():
    rng = Random(26860); m = fixture(rng, 0, Shape(0, 1, 2, 1, 1, 2, 8, 3, 1), 2)
    scales = tuple(Scale(-1099 if i % 2 else 1024, pack('<H', 1)*(dims[0]-1)+pack('<H', 65535))
                   for i, (_, _, dims) in enumerate(roles(m.shape)) if len(dims) == 2)
    sr, rr = c.scales_codec.encode(m, scales), c.registry_codec.encode(m)
    chunks = list(c.iterencode(m, sr, rr)); raw = b''.join(chunks); c.validate(m, sr, rr, raw)
    assert chunks == framing(m, sr, rr, expected_records(m, scales), independent=True)
    assert c.digest(m, sr, rr) == blake3(raw).digest()
    for end in (0, 1, len(chunks[0])-1, len(raw)//2, len(raw)-1): rejects(lambda: c.validate(m, sr, rr, raw[:end]), 'Encoding')
    rejects(lambda: c.validate(m, sr, rr, raw+b'\0'), 'Trailing')
    rejects(lambda: c.validate(m, sr, rr, bytearray(raw)), 'Capacity')
    for i in range(1, len(chunks)):
        for replacement, reason in ((chunks[:i]+chunks[i+1:], 'Encoding'),
                (chunks[:i]+[chunks[i], chunks[i]]+chunks[i+1:], 'Trailing' if i == len(chunks)-1 else 'Encoding')):
            rejects(lambda: c.validate(m, sr, rr, b''.join(replacement)), reason)
    for pos in (len(c.PREFIX), len(c.PREFIX)+32, len(c.PREFIX)+64, len(chunks[0])-2,
                len(chunks[0]), len(chunks[0])+2, len(chunks[0])+6, len(raw)-1):
        changed = raw[:pos]+bytes((raw[pos]^1,))+raw[pos+1:]
        rejects(lambda: c.validate(m, sr, rr, changed), 'Encoding')
    changed_scales = (replace(scales[0], mantissas=pack('<H', 2)+scales[0].mantissas[2:]),)+scales[1:]
    changed_sr = c.scales_codec.encode(m, changed_scales)
    assert c._records(m, scales) == c._records(m, changed_scales)
    rejects(lambda: c.validate(m, changed_sr, rr, raw), 'Encoding')
    assert c.encode(m, changed_sr, rr)[len(chunks[0]):] == raw[len(chunks[0]):]
    # Even a recomputed collection header cannot authorize a forged Registry data digest.
    pos = 0
    for part in c.registry_codec._parts(m):
        if type(part) is not bytes: break
        pos += len(part)
    bad_registry = rr[:pos]+bytes((rr[pos]^1,))+rr[pos+1:]
    rejects(lambda: c.digest(m, sr, bad_registry), 'TableData')
    b = m.blocks[0]
    invalid_score = replace(m, blocks=(replace(b, fractions=(0, 0)+b.fractions[2:], score_m=65535, score_e=30),))
    invalid_block = replace(m, blocks=(replace(b, accumulation=1, drop=0),))
    for bad, reason in ((invalid_score, 'ScoreBound'), (invalid_block, 'BlockBound')):
        bs, br = c.scales_codec.encode(bad, scales), c.registry_codec.encode(bad)
        rejects(lambda: c.digest(bad, bs, br), reason)
    invalid_table = replace(m, blocks=(replace(b, activation=replace(b.activation, E=14)),))
    parts = c.registry_codec._parts(invalid_table)
    forged = b''.join(part if type(part) is bytes else bytes(32) if part.name == 'gelu_tanh_q'
                      else c.registry_codec._digest(part) for part in parts)
    rejects(lambda: c.digest(invalid_table, c.scales_codec.encode(invalid_table, scales), forged), 'Overflow')
    changed_model = replace(m, formats=((12-m.formats[0][0], 0),)+m.formats[1:])
    changed_sr, changed_rr = c.scales_codec.encode(changed_model, scales), c.registry_codec.encode(changed_model)
    changed_header = next(c.iterencode(changed_model, changed_sr, changed_rr))
    rejects(lambda: c.validate(changed_model, changed_sr, changed_rr, changed_header+raw[len(chunks[0]):]), 'Encoding')
    full, corpus = [], sha256()
    for shape in (Shape(0,12,768,12,12,64,3072,50257,1024), Shape(1,32,4096,32,8,128,14336,128256,131072),
                  Shape(0,128,4096,128,128,32,16384,2**20,2**20), Shape(1,128,16384,128,128,128,16384,2**20,2**20)):
        model = fixture(rng, shape.family, shape, 1)
        model = replace(model, decoding=Sampled(1,1,1,1,replace(model.blocks[0].exp,n=shape.vocabulary)))
        values = tuple(Scale(-1099 if i % 2 else 1024, pack('<H', 65535)*dims[0])
                       for i, (_, _, dims) in enumerate(roles(shape)) if len(dims) == 2)
        # Full role/record derivation only: no fake Registry or named-model admission.
        c.model_codec.encode(model); c.scales_codec.encode(model, values)
        records = expected_records(model, values); assert records == c._records(model, values)
        size, h = 0, sha256()
        for i, (_, _, value) in enumerate(records):
            encoded = c._encode(value); assert encoded == record_oracle(value)
            framed = pack('<HI',i,len(encoded))+encoded; size += len(framed); h.update(framed)
        full.append([len(records), size, h.hexdigest()]); corpus.update(h.digest())
    assert [r[0] for r in full] == [481,1164,5005,4620]
    return dict(metadata_only_named_and_maximal_records=full, corpus_sha256=corpus.hexdigest(), mutation_slots=len(chunks)-1)


def main():
    rng, corpus, full_corpus = Random(2686), sha256(), sha256()
    maximum = [0,0]; families = [0,0]; sampled = 0; modes = [0,0,0]; frames = 0
    for i in range(10000):
        family, mode = i % 2, i % 3; h, a = rng.randint(1,4), rng.choice((2,4,8)); d = h*a
        s = Shape(family,rng.randint(1,3),d,h,h if not family else 1,a,4*d if not family else rng.randint(1,64),rng.randint(1,8),rng.randint(1,8))
        m = fixture(rng,family,s,mode); scales = make_scales(rng,m); sr = c.scales_codec.encode(m,scales); rr = c.registry_codec.encode(m)
        assert sr == scales_oracle(m,scales) and rr == registry_oracle(m)
        records = expected_records(m,scales); assert records == c._records(m,scales)
        # New work is parameter selection and assembly. Reuse qualified schemas;
        # do not repeat every earlier arithmetic campaign for every collection.
        for source in (model_oracle(m),sr,rr): corpus.update(pack('<I',len(source))+source)
        maximum[0] = max(maximum[0],len(records))
        if i < 12 or (i+1) % 1000 == 0:
            chunks = list(c.iterencode(m,sr,rr)); assert chunks == framing(m,sr,rr,records,independent=True)
            raw = b''.join(chunks); c.validate(m,sr,rr,raw)
            pos = (i*104729) % len(raw); changed = raw[:pos]+bytes((raw[pos]^1,))+raw[pos+1:]
            rejects(lambda: c.validate(m,sr,rr,changed),'Encoding')
            full_corpus.update(pack('<I',len(raw))+raw); maximum[1] = max(maximum[1],len(raw)); frames += 1
        families[family] += 1; modes[mode] += 1; sampled += m.decoding is not None
        if (i+1) % 1000 == 0: print(json.dumps(dict(completed=i+1)),flush=True)
    result = boundaries()
    print(json.dumps(dict(seed=2686,configurations=10000,families=families,modes=modes,sampled=sampled,
                         maximum_records_bytes=maximum,configuration_corpus_sha256=corpus.hexdigest(),
                         independent_complete_frames=frames,frame_corpus_sha256=full_corpus.hexdigest(),boundaries=result),sort_keys=True))


if __name__ == '__main__': main()
