"""Q24: independent circle-transform algebra, not a PCS or size benchmark."""
import random
from pathlib import Path

P = 2**31-1
G = (1717986917, 1288490189)
HALF = (P+1)//2


def multiply(a, b):
    return ((a[0]*b[0]-a[1]*b[1]) % P, (a[0]*b[1]+a[1]*b[0]) % P)


def power(a, n):
    result = (1, 0)
    while n:
        if n & 1:
            result = multiply(result, a)
        a, n = multiply(a, a), n//2
    return result


def point(log_size, index):
    if not 0 <= log_size <= 30 or not 0 <= index < 2**log_size:
        raise ValueError('domain')
    return power(G, (2*index+1)*2**(30-log_size))


def domain(log_size):
    first = point(log_size, 0)
    step = power(G, 2**(31-log_size))
    result = [first]
    for _ in range(1, 2**log_size):
        result.append(multiply(result[-1], step))
    return result


def x_transform(values, xs, inverse):
    if len(values) == 1:
        return list(values)
    half = len(values)//2
    next_x = [(2*x*x-1) % P for x in xs[:half]]
    if inverse:
        even = [(values[j]+values[-1-j])*HALF % P for j in range(half)]
        assert all(xs[j] for j in range(half))
        odd = [(values[j]-values[-1-j])*HALF*pow(xs[j], P-2, P) % P for j in range(half)]
        a, b = x_transform(even, next_x, True), x_transform(odd, next_x, True)
        return [v for pair in zip(a, b) for v in pair]
    a = x_transform(values[::2], next_x, False)
    b = x_transform(values[1::2], next_x, False)
    result = [0]*len(values)
    for j in range(half):
        result[j], result[-1-j] = (a[j]+xs[j]*b[j]) % P, (a[j]-xs[j]*b[j]) % P
    return result


def transform(values, points, inverse=False):
    n = len(values)
    assert n == len(points) and n and not n & (n-1)
    if n == 1:
        return list(values)
    half = n//2
    xs, ys = zip(*points[:half])
    assert all(ys)
    if inverse:
        even = [(values[j]+values[-1-j])*HALF % P for j in range(half)]
        odd = [(values[j]-values[-1-j])*HALF*pow(ys[j], P-2, P) % P for j in range(half)]
        a, b = x_transform(even, xs, True), x_transform(odd, xs, True)
        return [v for pair in zip(a, b) for v in pair]
    a, b = x_transform(values[::2], xs, False), x_transform(values[1::2], xs, False)
    result = [0]*n
    for j in range(half):
        result[j], result[-1-j] = (a[j]+ys[j]*b[j]) % P, (a[j]-ys[j]*b[j]) % P
    return result


def direct(coefficients, pt):
    x, y = pt
    factors = [y]
    for _ in range((len(coefficients)-1).bit_length()-1):
        factors.append(x)
        x = (2*x*x-1) % P
    total = 0
    for j, coefficient in enumerate(coefficients):
        value = coefficient
        for bit, factor in enumerate(factors):
            if j >> bit & 1:
                value = value*factor % P
        total = (total+value) % P
    return total


def encode(row, log_blowup):
    m = (len(row)-1).bit_length()
    if not row or len(row) != 2**m or log_blowup not in (1, 2) or m+log_blowup > 30:
        raise ValueError('shape')
    coefficients = transform(row, domain(m), True)
    return transform(coefficients+[0]*(2**(m+log_blowup)-len(row)), domain(m+log_blowup))


def vectors():
    rows = []
    for m in range(6):
        coefficients = [(37+19*j*j-11*j) % P for j in range(2**m)]
        row = [direct(coefficients, pt) for pt in domain(m)]
        for b in (1, 2):
            word = [direct(coefficients, pt) for pt in domain(m+b)]
            rows.append(f'{m} {b} ' + ','.join(map(str, row)) + ' ' + ','.join(map(str, word)))
    return '\n'.join(rows) + '\n'


def checks():
    assert Path(__file__).with_name('vectors.txt').read_text() == vectors(), 'circle vectors drift'
    assert G == ((-3*pow(5, P-2, P)) % P, (4*pow(5, P-2, P)) % P)
    assert (G[0]*G[0]+G[1]*G[1]) % P == 1
    assert power(G, 2**30) == (P-1, 0) and power(G, 2**31) == (1, 0)
    for log_size in range(31):
        assert point(log_size, 0) != (1, 0)
        assert point(log_size, 2**log_size-1) == (point(log_size, 0)[0], -point(log_size, 0)[1] % P)
    rng, count = random.Random(402), 0
    for m in range(7):
        pts = domain(m)
        assert len(set(pts)) == 2**m
        assert pts == [point(m, j) for j in range(2**m)]
        for boundary in ([0]*len(pts), [1]*len(pts), [P-1]*len(pts),
                         [j % 2 for j in range(len(pts))]):
            values = transform(boundary, pts)
            assert values == [direct(boundary, pt) for pt in pts]
            assert transform(values, pts, True) == boundary
        for _ in range(10):
            coefficients = [rng.randrange(P) for _ in pts]
            values = transform(coefficients, pts)
            assert values == [direct(coefficients, pt) for pt in pts]
            assert transform(values, pts, True) == coefficients
            for blowup in (1, 2):
                encoded = encode(values, blowup)
                assert encoded == [direct(coefficients, pt) for pt in domain(m+blowup)]
                other = [rng.randrange(P) for _ in pts]
                scale = rng.randrange(P)
                assert encode([(a+scale*b) % P for a, b in zip(values, other)], blowup) == [
                    (a+scale*b) % P for a, b in zip(encoded, encode(other, blowup))]
                count += 1
    # Vanishing top basis function: the full degree space has an extra dimension.
    for m in range(1, 7):
        def top(pt):
            x = pt[0]
            for _ in range(m-1):
                x = (2*x*x-1) % P
            return x
        assert all(top(pt) == 0 for pt in domain(m))
        assert any(top(pt) != 0 for pt in domain(m+1))
    # Direct basis evaluation must detect both order and normalization mistakes.
    coefficients = list(range(8))
    values = transform(coefficients, domain(3))
    assert values != list(reversed(values))
    assert transform([8*v % P for v in values], domain(3), True) != coefficients
    # This FFT subspace is not an ordinary [N,k] MDS Reed--Solomon code.
    y0 = domain(2)[0][1]
    word = encode([(y-y0) % P for _, y in domain(1)], 1)
    assert word == [(y-y0) % P for _, y in domain(2)]
    assert sum(x != 0 for x in word) == 2  # N-k, smaller than N-k+1.
    for args in [([], 1), ([1, 2, 3], 1), ([1], 0), ([1], 3)]:
        try:
            encode(*args)
        except ValueError:
            pass
        else:
            raise AssertionError('invalid shape accepted')
    try:
        point(31, 0)
    except ValueError:
        pass
    else:
        raise AssertionError('unsupported twin-coset size accepted')
    print(f'{count} seeded rate-1/2 and rate-1/4 encodings match direct evaluation; 28 boundary round trips agree.')
    print('Generator order, domain endpoint formulas through log 30, inverse normalization and size rejection checked.')
    print('Vanishing top polynomial demonstrates the extra full-space dimension for logs 1..6.')
    print('A length-four, dimension-two word has weight two: do not import the ordinary RS MDS formula.')
    print('Research only: no 2^30 allocation, performance ledger, PCS parameter or GPU parity claim.')
    print('Twelve shared canonical M31 vectors match independent direct evaluation.')


if __name__ == '__main__':
    checks()
