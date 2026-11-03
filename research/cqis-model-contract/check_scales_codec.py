"""Independent complete Scales framing and Model-identity joins, Draft RFC-0025 §5."""
from dataclasses import replace
from hashlib import sha256
import json
from random import Random
from struct import pack, unpack_from

from blake3 import blake3

from check_arithmetic_bounds import rejects
from check_model_codec import make, oracle as model_oracle, roles
from scales_codec import Scale, decode, decode_expected, encode
from source_map import Shape


def matrices(model):
    return [(i, dims[0]) for i, (_, _, dims) in enumerate(roles(model.shape)) if len(dims) == 2]


def oracle(model, scales):
    parts = [b'stele/v0.1/cqis/scales', blake3(model_oracle(model)).digest()]
    for (i, count), scale in zip(matrices(model), scales):
        assert len(scale.mantissas) == 2*count
        parts += [pack('<Hh', i, scale.exponent), scale.mantissas]
    return b''.join(parts)


def make_scales(rng, model):
    return tuple(Scale(rng.randint(-1099, 1024), b''.join(pack('<H', rng.randint(1, 65535)) for _ in range(count)))
                 for _, count in matrices(model))


def boundaries():
    rng = Random(26830)
    shapes = [Shape(0, 12, 768, 12, 12, 64, 3072, 50257, 1024),
              Shape(1, 32, 4096, 32, 8, 128, 14336, 128256, 131072),
              Shape(0, 128, 4096, 128, 128, 32, 16384, 2**20, 2**20),
              Shape(1, 128, 16384, 128, 128, 128, 16384, 2**20, 2**20)]
    full = []
    pattern = pack('<4H', 1, 65535, 32768, 255)
    for shape in shapes:
        model = make(rng, shape.family, shape); layout = matrices(model)
        scales = tuple(Scale(-1099 if j % 2 else 1024, (pattern*((count+3)//4))[:2*count]) for j, (_, count) in enumerate(layout))
        raw = encode(model, scales)
        assert raw == oracle(model, scales) and decode(model, raw) == scales
        total = sum(count for _, count in layout)
        expected = (shape.vocabulary+shape.context+9*shape.layers*shape.width if shape.family == 0 else
                    2*shape.vocabulary+shape.layers*(3*shape.width+2*shape.groups*shape.head_width+2*shape.hidden))
        assert total == expected and total <= 2**24
        assert len(raw) == 54+4*len(layout)+2*total
        full.append((len(layout), total, len(raw)))
    assert full[-1][1] == 2**24 and full[0][0] == 74 and full[1][0] == 226
    model = make(rng, 0, Shape(0, 1, 2, 1, 1, 2, 8, 2, 2))
    scales = make_scales(rng, model); raw = encode(model, scales); header = 54
    for end in range(len(raw)):
        rejects(lambda: decode(model, raw[:end]), 'Length')
    rejects(lambda: decode(model, raw+b'\0'), 'Length')
    rejects(lambda: decode(model, bytearray(raw)), 'Capacity')
    rejects(lambda: decode(model, bytes(2**26+1)), 'Capacity')
    rejects(lambda: encode(model, scales[:-1]), 'Records')
    rejects(lambda: encode(model, scales+(scales[0],)), 'Records')
    rejects(lambda: encode(model, list(scales)), 'Records')
    for value in (-1100, 1025, True):
        bad = (replace(scales[0], exponent=value),)+scales[1:]
        rejects(lambda: encode(model, bad), 'Exponent')
    for value in (b'\0\0'+scales[0].mantissas[2:], scales[0].mantissas[:-1], bytearray(scales[0].mantissas)):
        bad = (replace(scales[0], mantissas=value),)+scales[1:]
        rejects(lambda: encode(model, bad), 'Mantissas')
    rejects(lambda: decode(model, raw[:header]+pack('<H', 1)+raw[header+2:]), 'Record')
    rejects(lambda: decode(model, raw[:header+2]+pack('<h', -1100)+raw[header+4:]), 'Exponent')
    rejects(lambda: decode(model, raw[:header+4]+b'\0\0'+raw[header+6:]), 'Mantissas')
    rejects(lambda: decode(model, b'X'+raw[1:]), 'Header')
    # Same physical layout and scale values, different full numerical Model.
    changed_model = replace(model, logits_fraction=(model.logits_fraction+1) % 31)
    rejects(lambda: decode(changed_model, raw), 'ModelIdentity')
    changed_raw = encode(changed_model, scales)
    assert changed_raw[header:] == raw[header:] and changed_raw != raw
    assert decode(changed_model, changed_raw) == scales
    # A changed valid channel is a different Scales object, even if its exponent agrees.
    word = unpack_from('<H', raw, header+4)[0]; word = word % 65535+1
    changed_raw = raw[:header+4]+pack('<H', word)+raw[header+6:]
    assert decode(model, changed_raw) != scales
    rejects(lambda: decode_expected(model, blake3(raw).digest(), changed_raw), 'Identity')
    rejects(lambda: decode_expected(model, b'\0'*31, raw), 'Digest')
    # Parsing cannot establish source-dependent minimality or zero-source policy.
    ones = tuple(Scale(1024, pack('<H', 1)*count) for _, count in matrices(model))
    assert decode(model, encode(model, ones)) == ones
    llama = make(rng, 1, Shape(1, 1, 2, 1, 1, 2, 1, 2, 1))
    llama_scales = make_scales(rng, llama); llama_raw = encode(llama, llama_scales)
    # Token and untied head share dimensions but must retain distinct ordinals.
    last = len(llama_raw)-4-len(llama_scales[-1].mantissas)
    rejects(lambda: decode(llama, llama_raw[:last]+pack('<H', 0)+llama_raw[last+2:]), 'Record')
    return full


def main():
    rng, digest = Random(2683), sha256(); families = [0, 0]; mutations = [0, 0]; maxima = [0, 0]
    for i in range(10000):
        family = i % 2; h = rng.randint(1, 4); a = rng.choice((2, 4, 8)); d = h*a
        shape = Shape(family, rng.randint(1, 4), d, h, h if not family else 1, a,
                      rng.randint(1, 128) if family else 4*d, rng.randint(1, 64), rng.randint(1, 64))
        model = make(rng, family, shape); scales = make_scales(rng, model); raw = encode(model, scales)
        assert raw == oracle(model, scales) and decode(model, raw) == scales
        expected = blake3(raw).digest(); assert decode_expected(model, expected, raw) == scales
        point = rng.randrange(len(raw)); changed = raw[:point]+bytes((raw[point] ^ 1,))+raw[point+1:]
        try: result = decode(model, changed)
        except ValueError: mutations[0] += 1
        else:
            assert result != scales and encode(model, result) == changed
            rejects(lambda: decode_expected(model, expected, changed), 'Identity'); mutations[1] += 1
        families[family] += 1; maxima = [max(maxima[0], len(raw)), max(maxima[1], sum(c for _, c in matrices(model)))]
        digest.update(pack('<I', len(raw))+raw)
    full = boundaries()
    print(json.dumps(dict(seed=2683, configurations=10000, families=families, maxima_bytes_channels=maxima,
                         mutations_structural_identity=mutations, named_and_maximal_records_channels_bytes=full,
                         corpus_sha256=digest.hexdigest()), sort_keys=True))


if __name__ == '__main__':
    main()
