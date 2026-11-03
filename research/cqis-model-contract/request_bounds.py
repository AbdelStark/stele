"""Draft RFC-0025 request/stop frame and schema18; plaintext evidence, not a verifier."""
from dataclasses import dataclass
from struct import iter_unpack, unpack_from

from blake3 import blake3

from arithmetic_bounds import CAPACITY, _column, _encode_record, _unsigned
from numerics import integer

REQUEST = b'stele/v0.1/cqis/request-boundary'
IO = b'stele/v0.1/cqis/token-io'


@dataclass(frozen=True)
class Spec:
    v: int
    n: int
    mode: int

    def __post_init__(self):
        integer(self.v, 1, 1 << 20, 'Shape')
        integer(self.n, 1, 1 << 20, 'Shape')
        integer(self.mode, 0, 1, 'Mode')


@dataclass(frozen=True)
class Request:
    prompt_length: int
    maximum_new: int
    eos: tuple[int, ...]
    seed_commitment: bytes | None


def _eos(p, eos):
    if type(eos) is not tuple or not 1 <= len(eos) <= p.v:
        raise ValueError('EOS')
    previous = -1
    for token in eos:
        integer(token, 0, p.v-1, 'Token')
        if token <= previous:
            raise ValueError('EOS')
        previous = token


def _request(p, r):
    if type(p) is not Spec or type(r) is not Request:
        raise ValueError('Parameters')
    integer(r.prompt_length, 1, p.n, 'Length')
    integer(r.maximum_new, 0, p.n-r.prompt_length, 'Length')
    _eos(p, r.eos)
    if (p.mode == 0 and r.seed_commitment is not None) or (p.mode == 1 and
            (type(r.seed_commitment) is not bytes or len(r.seed_commitment) != 32)):
        raise ValueError('Seed')


def encode_request(p, r):
    _request(p, r)
    return (REQUEST+bytes((p.mode,))+_unsigned(r.prompt_length, 4)+_unsigned(r.maximum_new, 4)
            +_unsigned(len(r.eos), 4)+b''.join(_unsigned(t, 4) for t in r.eos)
            +(r.seed_commitment if p.mode else b''))


def decode_request(p, raw):
    if type(p) is not Spec:
        raise ValueError('Parameters')
    header = len(REQUEST)+13
    if type(raw) is not bytes or len(raw) > header+4*p.v+32*p.mode:
        raise ValueError('Capacity')
    if len(raw) < header or raw[:len(REQUEST)+1] != REQUEST+bytes((p.mode,)):
        raise ValueError('Encoding')
    q, maximum, count = unpack_from('<III', raw, len(REQUEST)+1)
    if not 1 <= count <= p.v or len(raw) != header+4*count+32*p.mode:
        raise ValueError('Encoding')
    integer(q, 1, p.n, 'Length')
    integer(maximum, 0, p.n-q, 'Length')
    r = Request(q, maximum, tuple(t[0] for t in iter_unpack('<I', raw[header:header+4*count])),
                raw[-32:] if p.mode else None)
    _request(p, r)
    return r


def check_completion(p, r, prompt, sequence, reason):
    _request(p, r)
    integer(reason, 0, 1, 'Stop')
    if type(prompt) is not tuple or len(prompt) != r.prompt_length or type(sequence) is not tuple:
        raise ValueError('Length')
    if not len(prompt) <= len(sequence) <= len(prompt)+r.maximum_new:
        raise ValueError('Length')
    for token in prompt+sequence:
        integer(token, 0, p.v-1, 'Token')
    if sequence[:len(prompt)] != prompt:
        raise ValueError('Prefix')
    generated, eos = sequence[len(prompt):], frozenset(r.eos)
    if any(t in eos for t in generated[:-1]):
        raise ValueError('Stop')
    expected = int(bool(generated) and generated[-1] in eos)
    if reason != expected or (not expected and len(generated) != r.maximum_new):
        raise ValueError('Stop')
    return len(generated)


def encode_io(p, r, prompt, sequence, reason):
    g = check_completion(p, r, prompt, sequence, reason)
    return IO+_unsigned(len(prompt), 4)+_unsigned(g, 4)+bytes((reason,))+b''.join(_unsigned(t, 4) for t in sequence)


def decode_io(p, r, prompt, raw):
    _request(p, r)
    header = len(IO)+9
    if type(raw) is not bytes or len(raw) > header+4*p.n:
        raise ValueError('Capacity')
    if len(raw) < header or not raw.startswith(IO):
        raise ValueError('Encoding')
    q, g, reason = unpack_from('<IIB', raw, len(IO))
    if q != r.prompt_length or g > r.maximum_new or len(raw) != header+4*(q+g):
        raise ValueError('Encoding')
    sequence = tuple(t[0] for t in iter_unpack('<I', raw[header:]))
    check_completion(p, r, prompt, sequence, reason)
    return sequence, reason


def io_digest(p, r, prompt, sequence, reason):
    return blake3(encode_io(p, r, prompt, sequence, reason)).digest()


def mask_mle(p, eos, point):
    """Numerical sparse public-mask formula; no native public-source handle."""
    if type(p) is not Spec:
        raise ValueError('Parameters')
    _eos(p, eos)
    if type(point) is not tuple or len(point) != (p.v-1).bit_length():
        raise ValueError('Point')
    for value in point:
        integer(value, 0, 2147483646, 'Point')
    total = 0
    for token in eos:
        term = 1
        for bit, coordinate in enumerate(point):
            term = term*(coordinate if (token >> bit) & 1 else 1-coordinate) % 2147483647
        total = (total+term) % 2147483647
    return total


def derive(p):
    if type(p) is not Spec:
        raise ValueError('Parameters')
    np, vp = 1 << (p.n-1).bit_length(), 1 << (p.v-1).bit_length()
    rh, ih = len(REQUEST)+13, len(IO)+9
    scalars = (p.n, p.n-1, p.v-1, np, 2*np-1, vp, 2*vp-1, np.bit_length()-1,
               vp.bit_length()-1, rh, ih, rh+4*p.v+32*p.mode, ih+4*p.n, (1 << 32)-1)
    roles = [((1, p.n, 1), (1, p.n, 1), (1, p.n, 1)),
             ((1, p.n, 1), (1, p.n, 1)), ((1, p.n, 1), (1, p.n, 1)),
             ((1, p.n, 1), (1, p.n-1, 1)), ((1, p.n-1, 1), (1, 1, 1)),
             ((1, p.n-1, 1), (1, 1, 1)), ((1, p.n-1, 1),),
             ((p.n, 1, 1),), ((1, 1, 1),), ((1, p.n, 1),),
             ((1, p.n-1, 4),), ((1, 4*(p.n-1), 1), (1, 3, 1), (1, ih, 1)),
             ((1, p.v-1, 4),), ((1, 4*(p.v-1), 1), (1, 3, 1), (1, rh, 1)),
             tuple((1, 255, 1 << (8*i)) for i in range(4)),
             ((1, p.v-1, 1), (1, p.v-1, 1), (1, 1, 1))]
    return 18, scalars, (), tuple(_column(t) for t in roles)


def encode(p):
    record = derive(p)
    return _encode_record(_unsigned(p.v, 4)+_unsigned(p.n, 4)+bytes((p.mode,)), *record)


def validate(expected, supplied):
    if type(supplied) is not bytes or len(supplied) > CAPACITY:
        raise ValueError('Capacity')
    if supplied != encode(expected):
        raise ValueError('Encoding')
