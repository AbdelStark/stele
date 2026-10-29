"""Q26 candidate quantiser policy; research only, not an Accepted CQIS kernel."""
from fractions import Fraction as Q


def require(condition, reason):
    if not condition:
        raise ValueError(reason)


def round_away(x):
    require(type(x) is Q, 'Scalar')
    n, d = abs(x.numerator), x.denominator
    q, r = divmod(n, d)
    return (q+int(2*r >= d))*(-1 if x < 0 else 1)


def ceiling(x):
    return -((-x.numerator)//x.denominator)


def ceil_log2(x):
    require(type(x) is Q and x > 0, 'Magnitude')
    n, d = x.numerator, x.denominator
    e = n.bit_length()-d.bit_length()
    above = (n > (d << e)) if e >= 0 else ((n << -e) > d)
    if above:
        e += 1
    return e


def weights(channels, bits):
    """Explicit int4/int8 selection; one exponent, per-output-channel mantissas."""
    require(type(bits) is int and bits in (4, 8), 'Format')
    require(type(channels) is list and len(channels) > 0, 'Shape')
    require(type(channels[0]) is list and len(channels[0]) > 0, 'Shape')
    width = len(channels[0])
    require(all(type(row) is list and len(row) == width for row in channels), 'Shape')
    for row in channels:
        for x in row:
            require(type(x) is Q, 'Scalar')
            # Bound this candidate to values obtainable from finite binary64.
            require(x.denominator & (x.denominator-1) == 0, 'Scalar')
            require(x.denominator <= 1 << 1074 and abs(x) < Q(2)**1024, 'Scalar')
            n = abs(x.numerator)
            while n and n % 2 == 0:
                n //= 2
            require(n < 1 << 53, 'Scalar')
    limit = (1 << (bits-1))-1
    maxima = [max(map(abs, row)) for row in channels]
    peak = max(maxima)
    exponent = ceil_log2(peak/(limit*65535)) if peak else 0
    unit = Q(2)**exponent
    mantissas = [max(1, ceiling(m/(limit*unit))) for m in maxima]
    require(all(1 <= m <= 65535 for m in mantissas), 'Scale')
    output = [[round_away(x/(m*unit)) for x in row]
              for row, m in zip(channels, mantissas)]
    require(all(abs(v) <= limit for row in output for v in row), 'Overflow')
    return dict(bits=bits, exponent=exponent, mantissas=mantissas, output=output)


def row_input(row):
    require(type(row) is list and len(row) > 0, 'Shape')
    require(all(type(x) is int and -32768 <= x <= 32767 for x in row), 'Domain')


def dynamic(row):
    """Keep the exact ceiling, including zero; never divide an all-zero row."""
    row_input(row)
    maximum = max(map(abs, row))
    scale = (maximum+126)//127
    output = [round_away(Q(x, scale)) for x in row] if scale else [0]*len(row)
    require(all(abs(x) <= 127 for x in output), 'Overflow')
    return dict(scale=scale, output=output)


def static(row, scale):
    """Explicit selected scale in source integer units; no automatic mode switch."""
    row_input(row)
    require(type(scale) is int and 1 <= scale <= 65535, 'Scale')
    output = [round_away(Q(x, scale)) for x in row]
    require(all(abs(x) <= 127 for x in output), 'Overflow')
    return dict(scale=scale, output=output)
