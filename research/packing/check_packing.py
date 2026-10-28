"""Q28 exact packing/counterexample checks; no production NC or performance credit."""
from itertools import product
import random
from packing import MASK, pack, unpack

P = (1 << 31)-1


def rejects(reason, call):
    try:
        call()
    except ValueError as error:
        assert str(error) == reason, (reason, str(error))
    else:
        raise AssertionError(f'accepted instead of {reason}')


def reference(values, width, columns):
    # Independent oracle: canonical signed little-endian bytes, then one integer.
    raw = b''.join(x.to_bytes(width//8, 'little', signed=True) for x in values)
    integer = int.from_bytes(raw, 'little')
    return tuple((integer >> (30*i)) & MASK for i in range(columns))


def check_obstructions():
    for width, zero, colliding in ((8, (0,)*4, (-1, -1, -1, 127)),
                                    (16, (0,)*2, (-1, 32767))):
        raw0 = b''.join(x.to_bytes(width//8, 'little', signed=True) for x in zero)
        raw1 = b''.join(x.to_bytes(width//8, 'little', signed=True) for x in colliding)
        assert int.from_bytes(raw0, 'little') == 0
        assert int.from_bytes(raw1, 'little') == P
        assert int.from_bytes(raw0, 'little') % P == int.from_bytes(raw1, 'little') % P
        assert pack(zero, width, 2, 2) != pack(colliding, width, 2, 2)
    assert 256**4 == 65536**2 == 1 << 32 and 1 << 32 > P
    assert 1 << 31 > P and (1 << 31)-1 == P
    assert MASK < P//2+1 and 2**15-1+2**15*(2**15-1) == MASK
    # A field recombination equality alone cannot distinguish an invalid digit.
    assert 0+256*1 == 256+256*0 == 256
    assert unpack((256,), 8, 2, 1, 1) == (0, 1)
    rejects('SourceRange', lambda: pack((256, 0), 8, 1, 1))
    # Legal packing still changes the original functional and fused row.
    ma = ((0, 1), (0, 0)); mb = ((0, 0), (1, 0))
    inv = pow(257, -1, P)
    r = 256*inv % P
    a = ((1-r) % P, r)
    original = lambda m: tuple(sum(a[i]*m[i][j] for i in range(2)) % P for j in range(2))
    folded_packed = lambda m: sum(a[i]*pack(row, 8, 1, 1)[0] for i, row in enumerate(m)) % P
    assert folded_packed(ma) == folded_packed(mb) == r
    assert original(ma)[0] == 0 and original(mb)[0] == r != 0
    for m in (ma, mb):
        b = original(m)
        assert folded_packed(m) == (b[0]+256*b[1]) % P
    # For linear decoding of the first lane, a=1 is forced by (1,0), but then
    # the packed image of (0,1) maps to 256 rather than the required zero.
    assert pack((1, 0), 8, 1, 1) == (1,)
    assert pack((0, 1), 8, 1, 1) == (256,)
    print('obstructions: 32-bit/M31 collisions, out-of-range decomposition and fused-row mismatch verified')


def check_codec():
    count = 0
    # Every signed value, including the endpoints, with exact canonical re-encoding.
    for width in (8, 16):
        for value in range(-(1 << (width-1)), 1 << (width-1)):
            actual = pack((value,), width, 1, 1)
            assert actual == reference((value,), width, 1)
            assert unpack(actual, width, 1, 1, 1) == (value,)
            count += 1
    rng = random.Random(280028)
    for width in (8, 16):
        for case in range(10_000):
            length = 1+case % 128
            values = tuple(rng.randrange(-(1 << (width-1)), 1 << (width-1)) for _ in range(length))
            used = (length*width+29)//30
            columns = 1 << (used-1).bit_length()
            if case % 3 == 0:
                columns *= 2
            actual = pack(values, width, columns, columns)
            assert actual == reference(values, width, columns)
            assert unpack(actual, width, length, columns, columns) == values
            assert pack(unpack(actual, width, length, columns, columns), width, columns, columns) == actual
            count += 1
    # Exhaust complete short rows, sharing neither packing nor decoding logic.
    for width in (8, 16):
        for values in product((-(1 << (width-1)), -1, 0, 1, (1 << (width-1))-1), repeat=4):
            columns = 2 if width == 8 else 4
            actual = pack(values, width, columns, columns)
            assert actual == reference(values, width, columns)
            assert unpack(actual, width, 4, columns, columns) == values
            count += 1
    print(f'codec: {count} independent byte-oracle/round-trip cases; both widths and cross-word tails checked')


def check_rejections():
    for width in (0, 4, 30, 31, 32, True):
        rejects('Width', lambda: pack((0,), width, 1, 1))
    for values in ((), None, '0'):
        rejects('Shape', lambda: pack(values, 8, 1, 1))
    for width in (8, 16):
        for value in (True, -(1 << (width-1))-1, 1 << (width-1)):
            rejects('SourceRange', lambda: pack((value,), width, 1, 1))
    for columns in (0, 3, True):
        rejects('Shape', lambda: pack((0,), 8, columns, 4))
    rejects('Shape', lambda: pack((0,)*4, 8, 1, 1))
    for budget in (0, -1, True):
        rejects('Capacity', lambda: pack((0,), 8, 1, budget))
    rejects('Capacity', lambda: unpack((0, 0), 8, 1, 2, 1))
    for word in (-1, MASK+1, P, True):
        rejects('PackedRange', lambda: unpack((word,), 8, 1, 1, 1))
    for count in (0, -1, True):
        rejects('Shape', lambda: unpack((0,), 8, count, 1, 1))
    rejects('Shape', lambda: unpack((), 8, 1, 1, 1))
    rejects('Shape', lambda: unpack((0, 0, 0), 8, 1, 3, 3))
    rejects('Shape', lambda: unpack((0,), 16, 2, 1, 1))
    rejects('Shape', lambda: unpack((0, 0), 8, 1, 1, 2))
    rejects('Shape', lambda: unpack((0,), 8, 1, 2, 2))
    # Mutate exactly one unused high bit or one padding word of canonical data.
    tails = 0
    for width in (8, 16):
        for count in range(1, 61):
            used = (count*width+29)//30
            columns = 2 << (used-1).bit_length()
            words = pack((0,)*count, width, columns, columns)
            remainder = count*width % 30
            if remainder:
                altered = list(words); altered[used-1] = 1 << remainder
                rejects('Tail', lambda: unpack(altered, width, count, columns, columns))
                tails += 1
            altered = list(words); altered[used] = 1
            rejects('Padding', lambda: unpack(altered, width, count, columns, columns))
    assert tails == 112
    print('rejections: malformed ranges/shapes/budgets; 112 tail-bit and 120 padding-word mutations rejected')


if __name__ == '__main__':
    check_obstructions()
    check_codec()
    check_rejections()
    print('Q28 research only; no private range consumer, NC credit, PCS/profile, ZK or native performance claim')
