"""Draft RFC-0025 encoding appendix §5; Scales parsing grants no source authority."""
from dataclasses import dataclass
from struct import iter_unpack, pack, unpack_from

from blake3 import blake3

from model_codec import encode as encode_model
from numerics import integer

PREFIX = b'stele/v0.1/cqis/scales'
LIMIT = 1 << 26


@dataclass(frozen=True)
class Scale:
    exponent: int
    # Immutable little-endian u16 words retain all channels without Python-int expansion.
    mantissas: bytes

    def values(self):
        return (m for (m,) in iter_unpack('<H', self.mantissas))


def layout(model):
    model_id = blake3(encode_model(model)).digest()
    matrices = tuple((i, dimensions[0]) for i, (_, _, dimensions) in enumerate(model.shape.roles()) if len(dimensions) == 2)
    size = len(PREFIX)+32+sum(4+2*count for _, count in matrices)
    if size > LIMIT:
        raise ValueError('Capacity')
    return model_id, matrices, size


def validate(scale, count):
    if type(scale) is not Scale:
        raise ValueError('Scale')
    integer(scale.exponent, -1099, 1024, 'Exponent')
    if type(scale.mantissas) is not bytes or len(scale.mantissas) != 2*count or any(m == 0 for m in scale.values()):
        raise ValueError('Mantissas')


def encode(model, scales):
    model_id, matrices, size = layout(model)
    if type(scales) is not tuple or len(scales) != len(matrices):
        raise ValueError('Records')
    chunks = [PREFIX, model_id]
    for (i, count), scale in zip(matrices, scales):
        validate(scale, count)
        chunks += [pack('<Hh', i, scale.exponent), scale.mantissas]
    result = b''.join(chunks)
    assert len(result) == size
    return result


def decode(model, raw):
    if type(raw) is not bytes or len(raw) > LIMIT:
        raise ValueError('Capacity')
    model_id, matrices, size = layout(model)
    if len(raw) != size:
        raise ValueError('Length')
    if raw[:len(PREFIX)] != PREFIX:
        raise ValueError('Header')
    pos = len(PREFIX)+32
    if raw[len(PREFIX):pos] != model_id:
        raise ValueError('ModelIdentity')
    result = []
    for i, count in matrices:
        record, exponent = unpack_from('<Hh', raw, pos)
        if record != i:
            raise ValueError('Record')
        scale = Scale(exponent, raw[pos+4:pos+4+2*count]); validate(scale, count)
        result.append(scale); pos += 4+2*count
    assert pos == size
    return tuple(result)


def decode_expected(model, expected_digest, raw):
    if type(expected_digest) is not bytes or len(expected_digest) != 32:
        raise ValueError('Digest')
    result = decode(model, raw)
    if blake3(raw).digest() != expected_digest:
        raise ValueError('Identity')
    return result
