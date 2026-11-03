"""Independent framing, stopping and public-mask evidence for Draft RFC-0025."""
from dataclasses import replace
from hashlib import sha256
import json
from random import Random
from struct import pack

from blake3 import blake3

from check_arithmetic_bounds import check_columns, column_oracle, rejects
from check_flow_bounds import check, encoded_oracle
from check_layernorm_bounds import actual
from request_bounds import (Request, Spec, check_completion, decode_io, decode_request,
                            derive, encode, encode_io, encode_request, io_digest, mask_mle, validate)


def oracle(p):
    np, vp = 2**((p.n-1).bit_length()), 2**((p.v-1).bit_length())
    rh, ih = len(b'stele/v0.1/cqis/request-boundary')+13, len(b'stele/v0.1/cqis/token-io')+9
    scalars = (p.n, p.n-1, p.v-1, np, 2*np-1, vp, 2*vp-1, np.bit_length()-1,
               vp.bit_length()-1, rh, ih, rh+4*p.v+32*p.mode, ih+4*p.n, 2**32-1)
    terms = [((1, p.n, 1), (1, p.n, 1), (1, p.n, 1)),
             ((1, p.n, 1), (1, p.n, 1)), ((1, p.n, 1), (1, p.n, 1)),
             ((1, p.n, 1), (1, p.n-1, 1)), ((1, p.n-1, 1), (1, 1, 1)),
             ((1, p.n-1, 1), (1, 1, 1)), ((1, p.n-1, 1),),
             ((p.n, 1, 1),), ((1, 1, 1),), ((1, p.n, 1),),
             ((1, p.n-1, 4),), ((1, 4*(p.n-1), 1), (1, 3, 1), (1, ih, 1)),
             ((1, p.v-1, 4),), ((1, 4*(p.v-1), 1), (1, 3, 1), (1, rh, 1)),
             tuple((1, 255, 256**i) for i in range(4)),
             ((1, p.v-1, 1), (1, p.v-1, 1), (1, 1, 1))]
    return (18, scalars, (), tuple(column_oracle(t) for t in terms)), pack('<IIB', p.v, p.n, p.mode)


def request_wire(p, r):
    return (b'stele/v0.1/cqis/request-boundary'+pack('<BIII', p.mode, r.prompt_length, r.maximum_new, len(r.eos))
            +pack('<'+'I'*len(r.eos), *r.eos)+(r.seed_commitment if p.mode else b''))


def io_wire(r, prompt, sequence, reason):
    return (b'stele/v0.1/cqis/token-io'+pack('<IIB', len(prompt), len(sequence)-len(prompt), reason)
            +pack('<'+'I'*len(sequence), *sequence))


def replay(r, prompt, offered):
    result = list(prompt); reason = 0
    for token in offered[:r.maximum_new]:
        result.append(token)
        if any(token == eos for eos in r.eos):
            reason = 1
            break
    assert reason == 1 or len(result)-len(prompt) == r.maximum_new
    return tuple(result), reason


def witness(p, r, prompt, sequence, reason, record):
    assert check_completion(p, r, prompt, sequence, reason) == len(sequence)-len(prompt)
    q, g, length = len(prompt), len(sequence)-len(prompt), len(sequence)
    remaining, has = r.maximum_new-g, int(g > 0)
    roles = record[3]
    assert check(roles[0], (q, 1), (r.maximum_new, 1), (p.n-q-r.maximum_new, 1)) == p.n
    assert check(roles[1], (q, 1), (g, 1)) == length
    assert check(roles[2], (g, 1), (remaining, 1)) == r.maximum_new
    last = g-1 if has else 0
    assert check(roles[5], (last, has), (has, 1)) == g
    assert check(roles[6], (last, 1-has)) == 0
    assert check(roles[8], (has, int(has and sequence[-1] in r.eos))) == reason
    assert check(roles[9], (remaining, 1-reason)) == 0
    membership = [(1, int(t in r.eos), int(q <= i < length-1)) for i, t in enumerate(sequence)]
    if length < p.n:
        membership.append((p.n-length, 0, 0))
    assert actual(roles[7], [membership]) == 0
    for i in range(g):
        t = check(roles[3], (q, 1), (i, 1))
        assert check(roles[4], (t-1, 1), (1, 1)) == t
    for i, token in enumerate(sequence):
        offset = check(roles[10], (i, 4))
        for lane in range(4):
            assert check(roles[11], (offset, 1), (lane, 1), (record[1][10], 1)) == record[1][10]+4*i+lane
        assert check(roles[14], *((byte, 256**j) for j, byte in enumerate(pack('<I', token)))) == token
    for i, token in enumerate(r.eos):
        offset = check(roles[12], (i, 4))
        assert check(roles[13], (offset, 1), (3, 1), (record[1][9], 1)) == record[1][9]+4*i+3
        if i:
            assert check(roles[15], (r.eos[i-1], 1), (token-r.eos[i-1]-1, 1), (1, 1)) == token


def mle_oracle(p, eos, point):
    prime = 2147483647
    values = [int(i in eos) for i in range(2**len(point))]
    for coordinate in point:
        values = [((1-coordinate)*values[i]+coordinate*values[i+1]) % prime for i in range(0, len(values), 2)]
    return values[0]


def boundaries():
    p = Spec(4, 8, 1); r = Request(2, 3, (1, 3), bytes(32)); prompt = (1, 3)
    for offered in ((0, 0, 1), (0, 3, 0), (0, 0, 0)):
        sequence, reason = replay(r, prompt, offered)
        witness(p, r, prompt, sequence, reason, derive(p))
        assert decode_io(p, r, prompt, encode_io(p, r, prompt, sequence, reason)) == (sequence, reason)
    sequence = (1, 3, 0, 0, 1)
    rejects(lambda: check_completion(p, r, prompt, sequence, 0), 'Stop')
    rejects(lambda: check_completion(p, r, prompt, (1, 3, 1, 0), 0), 'Stop')
    rejects(lambda: check_completion(p, r, prompt, (1, 3, 0), 0), 'Stop')
    rejects(lambda: check_completion(p, r, prompt, (1, 3, 0, 0, 0), 1), 'Stop')
    rejects(lambda: check_completion(p, r, prompt, (0, 3, 0, 0, 1), 1), 'Prefix')
    rejects(lambda: check_completion(p, r, prompt, sequence, True), 'Stop')
    zero = replace(r, maximum_new=0)
    witness(p, zero, prompt, prompt, 0, derive(p))
    rejects(lambda: check_completion(p, zero, prompt, prompt, 1), 'Stop')
    for bad, reason in ((replace(r, prompt_length=0), 'Length'), (replace(r, maximum_new=7), 'Length'),
                        (replace(r, eos=()), 'EOS'), (replace(r, eos=(3, 1)), 'EOS'),
                        (replace(r, eos=(1, 1)), 'EOS'), (replace(r, eos=(4,)), 'Token'),
                        (replace(r, eos=(True,)), 'Token'), (replace(r, seed_commitment=None), 'Seed')):
        rejects(lambda bad=bad: encode_request(p, bad), reason)
    rejects(lambda: encode_request(replace(p, mode=0), r), 'Seed')
    raw = encode_request(p, r); io = encode_io(p, r, prompt, sequence, 1)
    for end in range(len(raw)):
        rejects(lambda end=end: decode_request(p, raw[:end]), 'Encoding')
    for end in range(len(io)):
        rejects(lambda end=end: decode_io(p, r, prompt, io[:end]), 'Encoding')
    rejects(lambda: decode_request(p, raw+b'\0'), 'Encoding')
    rejects(lambda: decode_request(replace(p, mode=0), raw), 'Capacity')
    rejects(lambda: decode_request(replace(p, v=16, mode=0), raw), 'Encoding')
    rejects(lambda: decode_io(p, r, prompt, io+b'\0'), 'Encoding')
    rejects(lambda: decode_request(p, bytearray(raw)), 'Capacity')
    rejects(lambda: decode_io(p, r, prompt, bytearray(io)), 'Capacity')
    at = len(b'stele/v0.1/cqis/token-io')+9+4*(len(sequence)-1)
    changed = io[:at]+pack('<I', 2147483648)+io[at+4:]
    rejects(lambda: decode_io(p, r, prompt, changed), 'Token')
    public = Spec(4, 8, 0); first = Request(1, 2, (3,), None); split = replace(first, prompt_length=2, maximum_new=1)
    assert io_digest(public, first, (0,), (0, 0, 0), 0) != io_digest(public, split, (0, 0), (0, 0, 0), 0)
    extended = replace(first, maximum_new=3)
    assert io_digest(public, first, (0,), (0, 3), 1) == io_digest(public, extended, (0,), (0, 3), 1)
    assert encode_request(public, first) != encode_request(public, extended)
    malformed = raw[:len(b'stele/v0.1/cqis/request-boundary')+9]+pack('<I', 2**32-1)+raw[len(b'stele/v0.1/cqis/request-boundary')+13:]
    rejects(lambda: decode_request(p, malformed), 'Encoding')
    # Full capacity and vocabulary, without a small research entry-product cap.
    p = Spec(2**20, 2**20, 1); r = Request(1, p.n-1, tuple(range(p.v)), b's'*32)
    prompt, sequence = (p.v-1,), (p.v-1, 0)
    encoded = encode_request(p, r); assert decode_request(p, encoded) == r
    assert check_completion(p, r, prompt, sequence, 1) == 1
    assert len(encoded) == derive(p)[1][11]
    r = Request(1, p.n-1, (p.v-1,), bytes(32)); sequence = (0,)*p.n
    encoded = encode_io(p, r, (0,), sequence, 0)
    assert decode_io(p, r, (0,), encoded) == (sequence, 0)
    assert len(encoded) == derive(p)[1][12]
    record, params = oracle(p); assert derive(p) == record and encode(p) == encoded_oracle(record, params)
    check_columns(record[3])
    assert actual(record[3][7], [[(p.n, 1, 1)]]) == p.n
    for token in (0, 1, p.v-1):
        point = tuple((token >> i) & 1 for i in range(20))
        assert mask_mle(p, (0, p.v-1), point) == int(token in (0, p.v-1))
    singleton = Spec(1, 1, 0); r = Request(1, 0, (0,), None)
    assert mask_mle(singleton, (0,), ()) == 1
    witness(singleton, r, (0,), (0,), 0, derive(singleton))
    return dict(context=p.n, vocabulary=p.v, request_bytes=derive(p)[1][11], io_bytes=len(encoded))


def main():
    rng, digest = Random(2681), sha256(); stops = [0, 0]; modes = [0, 0]; maximum = [0, 0]
    prompt_eos = coincidence = 0; first = None
    for _ in range(10000):
        p = Spec(rng.choice([1, 2**20, rng.randint(2, 2**20)]), rng.choice([1, 2**20, rng.randint(2, 2**20)]), rng.randrange(2))
        q = rng.randint(1, min(16, p.n)); limit = rng.randint(0, min(16, p.n-q))
        eos = tuple(sorted(rng.sample(range(p.v), rng.randint(1, min(4, p.v)))))
        r = Request(q, limit, eos, rng.randbytes(32) if p.mode else None)
        prompt = tuple(rng.choice(eos) if rng.randrange(3)==0 else rng.randrange(p.v) for _ in range(q))
        offered = tuple(rng.choice(eos) if rng.randrange(4)==0 else rng.randrange(p.v) for _ in range(limit))
        sequence, reason = replay(r, prompt, offered)
        record, params = oracle(p); assert derive(p) == record
        data = encode(p); assert data == encoded_oracle(record, params); check_columns(record[3])
        assert len(data) < 40000
        wire = encode_request(p, r); assert wire == request_wire(p, r) and decode_request(p, wire) == r
        io = encode_io(p, r, prompt, sequence, reason)
        assert io == io_wire(r, prompt, sequence, reason) and decode_io(p, r, prompt, io) == (sequence, reason)
        assert io_digest(p, r, prompt, sequence, reason) == blake3(io_wire(r, prompt, sequence, reason)).digest()
        witness(p, r, prompt, sequence, reason, record)
        small = Spec(rng.randint(1, 32), p.n, p.mode)
        members = tuple(sorted(rng.sample(range(small.v), rng.randint(1, small.v))))
        point = tuple(rng.randrange(2147483647) for _ in range((small.v-1).bit_length()))
        assert mask_mle(small, members, point) == mle_oracle(small, members, point)
        stops[reason] += 1; modes[p.mode] += 1; prompt_eos += any(t in eos for t in prompt)
        coincidence += reason == 1 and len(sequence)-q == limit
        maximum = [max(maximum[0], len(data)), max(maximum[1], max(len(role[2]) for role in record[3]))]
        for raw in (data, wire, io): digest.update(pack('<I', len(raw))+raw)
        first = first or (p, data)
    full = boundaries(); p, data = first; validate(p, data)
    for offset in sorted({0, len(data)-1, *range(0, len(data), max(1, len(data)//64))}):
        damaged = data[:offset]+bytes([data[offset] ^ 1])+data[offset+1:]
        rejects(lambda damaged=damaged: validate(p, damaged), 'Encoding')
    rejects(lambda: validate(replace(p, mode=1-p.mode), data), 'Encoding')
    rejects(lambda: validate(p, data+b'\0'), 'Encoding')
    rejects(lambda: Spec(1, True, 0), 'Shape')
    rejects(lambda: Spec(1, 1, 2), 'Mode')
    rejects(lambda: mask_mle(Spec(3, 1, 0), (1,), (0,)), 'Point')
    rejects(lambda: mask_mle(Spec(3, 1, 0), (1,), (0, 2147483647)), 'Point')
    print(json.dumps(dict(seed=2681, configurations=10000, stop_limit_eos=stops, modes=modes,
                         prompt_contains_eos=prompt_eos, eos_at_limit=coincidence, public_mle_points=10000,
                         maxima_bytes_columns=maximum, full_domain=full, corpus_sha256=digest.hexdigest()), sort_keys=True))


if __name__ == '__main__':
    main()
