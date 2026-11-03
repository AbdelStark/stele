"""Draft RFC-0025 schema 19: independent address, column and complete-frame checks."""
from dataclasses import replace
from hashlib import sha256
import json
from random import Random
from struct import pack

from check_arithmetic_bounds import check_columns, column_oracle, rejects
from check_flow_bounds import check, encoded_oracle
from check_model_codec import roles
from physical_bounds import Physical, derive, encode, validate
from source_map import Shape


def oracle(p):
    dims = roles(p.shape)[p.record][2]; matrix = len(dims) == 2
    rows, columns = dims if matrix else (1, dims[0]); elements = rows*columns
    ci = pack('<HB', p.record, len(dims))+pack('<'+'I'*len(dims), *dims)+pack('<BB', p.bits, p.parameter)
    header = len(b'stele/v0.1/cqis/tensor')+4+len(ci)+(2+2*rows if matrix else 0)+8
    length = (elements*p.bits+7)//8; first = ((elements-1)*p.bits)//8
    full, half = 2**p.bits, 2**(p.bits-1); negative = half-1 if matrix else half
    offset = 2*negative if matrix else 65535
    lane, tail, odd = int(p.bits == 4), int(p.bits == 16), int(p.bits == 4 and elements % 2 == 1)
    scalars = (rows, columns, elements, elements-1, length, length-1, first, header, header+length,
               header+length-1, full-1, half, negative, offset, lane, tail, odd)
    terms = [((1, rows-1, columns), (1, columns-1, 1)),
             ((1, first, 2), (1, 1, 1)) if p.bits == 4 else ((1, elements-1, p.bits//8),),
             ((1, first, 1), (1, tail, 1)), ((1, length-1, 1), (1, header, 1)),
             ((1, 15, 1), (1, 15, 16)) if p.bits == 4 else
             ((1, 255, 1), (1, 255, 256)) if p.bits == 16 else ((1, 255, 1),),
             ((1, half-1, 1), (1, 1, half)),
             ((1, full-1, 1), (1, negative, 1)), ((1, offset, 1), (1, 1, full))]
    if p.bits == 4: terms.append(((1, 1, 15), (1, 1, 15)))
    if matrix:
        exponent_start = header-8-2-2*rows; mantissa_start = exponent_start+2
        last = mantissa_start+2*(rows-1)
        scalars += (exponent_start, exponent_start+1, mantissa_start, last, last+1, header-8,
                    65535, 65534, 1099, 1024, 2123, 65536, 32768)
        terms += [((1, rows-1, 2), (1, mantissa_start, 1)), ((1, last, 1), (1, 1, 1)),
                  ((1, 255, 1), (1, 255, 256)), ((1, 65534, 1), (1, 1, 1)),
                  ((1, 255, 1), (1, 255, 256)), ((1, 32767, 1), (1, 1, 32768)),
                  ((1, 65535, 1), (1, 1099, 1)), ((1, 2123, 1), (1, 1, 65536))]
    s = p.shape
    params = pack('<B6H2I', s.family, s.layers, s.width, s.heads, s.groups, s.head_width, s.hidden, s.vocabulary, s.context)+ci
    return (19, scalars, (), tuple(column_oracle(t) for t in terms)), params


def witness(p, r, c, x, m, e, record):
    s, roles = record[1], record[3]
    rows, columns, count, _, length, _, _, header = s[:8]
    assert 0 <= r < rows and 0 <= c < columns
    index = check(roles[0], (r, columns), (c, 1))
    assert index == r*columns+c < count
    first, lane = divmod(index, 2) if p.bits == 4 else (index*(p.bits//8), 0)
    if p.bits == 4: assert check(roles[1], (first, 2), (lane, 1)) == index
    else: assert check(roles[1], (index, p.bits//8)) == first
    last = check(roles[2], (first, 1), (int(p.bits == 16), 1))
    assert last < length and check(roles[3], (last, 1), (header, 1)) == header+last < header+length
    full, half, negative, maximum = 2**p.bits, s[11], s[12], s[13]
    assert -negative <= x <= half-1
    u, sign = x % full, int(x < 0)
    if p.bits == 4:
        other = 15 if u != 15 else 7
        low, high = (other, u) if lane else (u, other)
        if s[16] and index == count-1: high = 0
        byte = check(roles[4], (low, 1), (high, 16))
        assert (byte >> (4*lane)) & 15 == u
        assert check(roles[8], (1-lane, low), (lane, high)) == u
        if s[16] and index == count-1: assert lane == 0 and high == 0
    elif p.bits == 8: assert check(roles[4], (u, 1)) == int.from_bytes(pack('<b', x), 'little')
    else: assert check(roles[4], (u % 256, 1), (u//256, 256)) == int.from_bytes(pack('<h', x), 'little')
    assert check(roles[5], (u % half, 1), (sign, half)) == u
    assert 0 <= x+negative <= maximum
    assert check(roles[6], (u, 1), (negative, 1)) == check(roles[7], (x+negative, 1), (sign, full))
    if p.bits != 16:
        offset = 9 if p.bits == 4 else 8; ms = s[19]
        assert check(roles[offset], (r, 2), (ms, 1)) == ms+2*r
        assert check(roles[offset+1], (ms+2*r, 1), (1, 1)) < header-8
        assert check(roles[offset+2], (m % 256, 1), (m//256, 256)) == check(roles[offset+3], (m-1, 1), (1, 1)) == m
        word, sign = e % 65536, int(e < 0)
        assert check(roles[offset+4], (word % 256, 1), (word//256, 256)) == word
        assert check(roles[offset+5], (word % 32768, 1), (sign, 32768)) == word
        assert check(roles[offset+6], (word, 1), (1099, 1)) == check(roles[offset+7], (e+1099, 1), (sign, 65536))
    return index, header+last


def boundaries():
    p = Physical(Shape(1, 128, 16384, 128, 128, 128, 16384, 2**20, 2**20), 0, 8, 0)
    record = derive(p); a, address = witness(p, 2**20-1, 16383, -127, 65535, -1099, record)
    assert a == 2**34-1 and address == 2**34+2**21+48 and len(record[3][0][2]) == 5
    # A field-congruent address is a distinct integer; source/column consumers must keep all bytes.
    changed = a-2147483647; assert changed >= 0 and changed % 2147483647 == a % 2147483647 and changed != a
    fixtures = [p, replace(p, bits=4), Physical(Shape(0, 1, 1, 1, 1, 1, 4, 3, 1), 0, 4, 0),
                Physical(Shape(0, 1, 1, 1, 1, 1, 4, 3, 1), 2, 16, 30)]
    for p in fixtures:
        record = derive(p); expected, params = oracle(p); assert record == expected
        raw = encode(p); assert raw == encoded_oracle(expected, params); validate(p, raw)
        r, c = record[1][0]-1, record[1][1]-1
        for x in (-record[1][12], 0, record[1][11]-1):
            for e in (-1099, 0, 1024): witness(p, r, c, x, 1 if e == 0 else 65535, e, record)
    p = fixtures[-1]; raw = encode(p)
    for end in (0, 1, len(raw)//2, len(raw)-1): rejects(lambda: validate(p, raw[:end]), 'Encoding')
    rejects(lambda: validate(p, raw+b'\0'), 'Encoding')
    rejects(lambda: validate(p, bytearray(raw)), 'Capacity')
    rejects(lambda: validate(p, bytes(36000)), 'Capacity')
    rejects(lambda: validate(replace(p, parameter=29), raw), 'Encoding')
    rejects(lambda: replace(p, bits=8), 'Format')
    rejects(lambda: replace(p, record=True), 'Record')
    rejects(lambda: replace(p, parameter=True), 'Format')
    rejects(lambda: replace(fixtures[0], parameter=1), 'Format')
    rejects(lambda: replace(p, record=len(p.shape.roles())), 'Record')
    counts, digest = [], sha256()
    for shape in (Shape(0,12,768,12,12,64,3072,50257,1024),
                  Shape(1,32,4096,32,8,128,14336,128256,131072),
                  Shape(0,128,4096,128,128,32,16384,2**20,2**20), fixtures[0].shape):
        expected_roles = roles(shape); assert len(expected_roles) == len(shape.roles())
        counts.append(len(expected_roles))
        for i, (_, _, dimensions) in enumerate(expected_roles):
            bits = 16 if len(dimensions) == 1 else 4 if i % 2 else 8
            p = Physical(shape,i,bits,30 if bits == 16 else 0); record = derive(p); expected, params = oracle(p)
            assert record == expected; raw = encode(p); assert raw == encoded_oracle(expected,params)
            witness(p,record[1][0]-1,record[1][1]-1,-record[1][12],65535,-1099,record)
            digest.update(pack('<I',len(raw))+raw)
    assert counts == [196,291,2052,1155]
    for bits in (4,8):
        half = 2**(bits-1); forbidden_offset = half+(half-1)-2**bits
        assert forbidden_offset == -1  # Excluded minimum matrix code cannot have a ranged offset.
    return dict(maximum_index=a, maximum_record_byte=address, high_word_counterexample=changed,
                odd_int4_elements=3, complete_named_and_maximal_roles=counts, complete_role_corpus_sha256=digest.hexdigest())


def main():
    rng, digest = Random(2685), sha256(); kinds = {4:0, 8:0, 16:0}; maximum = [0,0]; high = 0
    for i in range(10000):
        family = i % 2; h = rng.choice((1, 2, 16, 128)); width = rng.randint(1, (16384 if family else 4096)//h)
        d = h*width; g = h if family == 0 else rng.choice([x for x in range(1,h+1) if h%x == 0])
        shape = Shape(family,rng.randint(1,128),d,h,g,width,rng.randint(1,16384) if family else 4*d,
                      rng.choice((1,2**20,rng.randint(1,2**20))),rng.choice((1,2**20,rng.randint(1,2**20))))
        index = rng.randrange(len(roles(shape))); dimensions = roles(shape)[index][2]
        bits, parameter = (16, rng.randrange(31)) if len(dimensions) == 1 else (rng.choice((4,8)),0)
        p = Physical(shape,index,bits,parameter); record = derive(p); expected, params = oracle(p)
        assert record == expected; check_columns(record[3]); raw = encode(p); assert raw == encoded_oracle(expected,params); validate(p,raw)
        rows, columns = record[1][:2]; r, c = rng.randrange(rows),rng.randrange(columns)
        x = rng.randint(-record[1][12],record[1][11]-1)
        a, address = witness(p,r,c,x,rng.randint(1,65535),rng.randint(-1099,1024),record)
        high += address >= 2147483647; kinds[bits] += 1
        pos = rng.randrange(len(raw)); changed = raw[:pos]+bytes((raw[pos]^1,))+raw[pos+1:]
        rejects(lambda: validate(p,changed),'Encoding')
        maximum = [max(maximum[0],len(raw)),max(maximum[1],*(len(role[2]) for role in record[3]))]
        digest.update(pack('<I',len(raw))+raw)
    result = boundaries()
    print(json.dumps(dict(seed=2685,configurations=10000,formats=kinds,addresses_above_field=high,
                         maxima_bytes_columns=maximum,boundaries=result,corpus_sha256=digest.hexdigest()),sort_keys=True))


if __name__ == '__main__': main()
