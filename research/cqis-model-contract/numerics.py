"""Q26 / Draft RFC-0025: exact new model relations, not a proof consumer."""
from dataclasses import dataclass
from math import gcd, isqrt


def integer(x, low, high, reason):
    if type(x) is not int or not low <= x <= high:
        raise ValueError(reason)


def row(values, d):
    if type(values) is not list or len(values) != d:
        raise ValueError('Shape')
    for value in values:
        integer(value, -32768, 32767, 'Input')


def round_ratio(numerator, denominator):
    if type(numerator) is not int or type(denominator) is not int or denominator <= 0:
        raise ValueError('Ratio')
    q, r = divmod(abs(numerator), denominator)
    return (-1 if numerator < 0 else 1)*(q+int(2*r >= denominator))


def checked_output(value):
    integer(value, -32768, 32767, 'Range')
    return value


def shifted_pair(left, le, right, re):
    shift = max(0, -le, -re)
    return (left << (le+shift))+(right << (re+shift)), 1 << shift


def affine(acc, mantissa, scale, exponent, fraction, output_fraction, bias, bias_fraction):
    """One rounding after the exact scaled dot and learned bias are added."""
    integer(acc, -(1 << 31), (1 << 31)-1, 'Accumulator')
    integer(mantissa, 1, 65535, 'WeightScale')
    integer(scale, 0, 8454661, 'RowScale')
    integer(exponent, -1099, 1024, 'WeightExponent')
    integer(fraction, 0, 44, 'Units')
    for value in (output_fraction, bias_fraction):
        integer(value, 0, 30, 'Units')
    integer(bias, -32768, 32767, 'Input')
    if scale == 0 and acc != 0:
        raise ValueError('ZeroScale')
    n, d = shifted_pair(acc*mantissa*scale, exponent-fraction+output_fraction,
                        bias, output_fraction-bias_fraction)
    return checked_output(round_ratio(n, d))


def embedding(token, tm, te, position, pm, pe, output_fraction):
    """One rounding after token and learned-position contributions."""
    for value in (token, position):
        integer(value, -127, 127, 'Input')
    for value in (tm, pm):
        integer(value, 1, 65535, 'WeightScale')
    for value in (te, pe):
        integer(value, -1099, 1024, 'WeightExponent')
    integer(output_fraction, 0, 30, 'Units')
    n, d = shifted_pair(token*tm, te+output_fraction, position*pm, pe+output_fraction)
    return checked_output(round_ratio(n, d))


@dataclass(frozen=True)
class LayerNorm:
    d: int
    F: int
    G: int
    E: int
    Gb: int
    en: int
    ed: int

    def __post_init__(self):
        integer(self.d, 1, 16384, 'Dimension')
        for value in (self.F, self.G, self.Gb):
            integer(value, 0, 30, 'Units')
        integer(self.E, 0, 14, 'Units')
        for value in (self.en, self.ed):
            integer(value, 1, (1 << 32)-1, 'Epsilon')
        if gcd(self.en, self.ed) != 1:
            raise ValueError('Epsilon')


def bounds(p):
    """Exact shape/parameter-only maxima; no observed row is an input."""
    if type(p) is not LayerNorm:
        raise ValueError('Parameters')
    d = p.d
    n = p.ed*d*d*(1 << 30)+p.en*d*d*(1 << (2*p.F))
    denominator = p.ed*d*d*(1 << (2*p.F))
    t = 65535*(d-1)*32768*16384
    branches = {}
    for a in range(-23, 10):
        e = p.F+p.G+21+a-p.E
        k = max(e, p.Gb-p.E, 0)
        branches[a] = dict(A=n << max(-2*a, 0), D=denominator << max(2*a, 0),
                           U=(t << (k-e))+(d*32768 << (k+p.E-p.Gb)),
                           D_out=d << k)
    return dict(S=32768*d, Q=d*(1 << 30), V=d*d*(1 << 30),
                C=65535*(d-1), N=n, P=denominator, T=t, branches=branches)


def layer_norm(p, values, gains, biases):
    if type(p) is not LayerNorm:
        raise ValueError('Parameters')
    for values_row in (values, gains, biases):
        row(values_row, p.d)
    s = sum(values)
    q = sum(x*x for x in values)
    v = p.d*q-s*s
    centered = [p.d*x-s for x in values]
    n = p.ed*v+p.en*p.d*p.d*(1 << (2*p.F))
    denominator = p.ed*p.d*p.d*(1 << (2*p.F))
    a = (n.bit_length()-denominator.bit_length()-14)//2
    aa, dd = n << max(-2*a, 0), denominator << max(2*a, 0)
    if aa < 16384*dd:
        a -= 1
        aa, dd = n << max(-2*a, 0), denominator << max(2*a, 0)
    m, remainder = divmod(aa, dd)
    if not (-23 <= a <= 9 and 16384 <= m <= 65535):
        raise ValueError('Normalization')
    j = isqrt((1 << 42)//m)
    j += int((1 << 44) >= m*(2*j+1)**2)
    e = p.F+p.G+21+a-p.E
    k = max(e, p.Gb-p.E, 0)
    products = [c*h*j for c, h in zip(centered, gains)]
    numerators = [(t << (k-e))+(p.d*b << (k+p.E-p.Gb))
                  for t, b in zip(products, biases)]
    divisor = p.d << k
    output = [checked_output(round_ratio(u, divisor)) for u in numerators]
    return dict(S=s, Q=q, V=v, C=centered, N=n, P=denominator, a=a, A=aa, D=dd,
                M=m, remainder=remainder, J=j, e=e, k=k, T=products,
                U=numerators, D_out=divisor, output=output)
