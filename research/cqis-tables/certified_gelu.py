"""Q25 / Draft RFC-0004 A2: GeLU real-variant enclosures with exact constants."""
from fractions import Fraction as Q
from functools import lru_cache
from math import isqrt
from certified_exp import require
from certified_activations import strict_exp


def atan_bounds(x,bits):
    lower,upper,partial,power = Q(0),x,x,x
    for n in range(1,513):
        power *= x*x
        partial += power/(2*n+1)*(-1 if n % 2 else 1)
        if n % 2:
            lower = partial
        else:
            upper = partial
        if upper-lower < Q(1,1 << bits):
            return lower,upper
    raise ValueError('Precision')


@lru_cache(maxsize=16,typed=True)
def normalizer(bits):
    """Strict rational bounds on 1/sqrt(2*pi), using Machin and integer sqrt."""
    require(type(bits) is int and 32 <= bits <= 272,'Precision')
    a,b = atan_bounds(Q(1,5),bits+8),atan_bounds(Q(1,239),bits+8)
    low,high = 16*a[0]-4*b[1],16*a[1]-4*b[0]
    require(3 < low < high < 4,'Interval')
    unit = 1 << bits

    def floor_root(value):
        k = isqrt((value.numerator*unit*unit)//value.denominator)
        require(k*k*value.denominator <= value.numerator*unit*unit
                < (k+1)**2*value.denominator,'Interval')
        return k

    return Q(floor_root(1/(2*high)),unit),Q(floor_root(1/(2*low))+1,unit)


def normal_tail(a,bits):
    """Strict enclosure for Phi(-a), a>0; never substitutes the zero limit."""
    if a >= 8:
        # Integral from a to infinity is < exp(-a²/2)/a; sqrt(2*pi)>2.
        return Q(0),strict_exp(a*a/2,bits)[1]/(2*a)
    c0,c1 = normalizer(bits+8)
    lower,upper,partial,term = Q(0),a,a,a
    for n in range(1,513):
        term *= a*a*(2*n-1)/(2*n*(2*n+1))
        partial += term*(-1 if n % 2 else 1)
        if n >= a*a/2:  # All following alternating magnitudes decrease.
            if n % 2:
                lower = max(Q(0),partial)
            else:
                upper = min(a,partial)
            if upper-lower < Q(1,1 << (bits+8)):
                break
    else:
        raise ValueError('Precision')
    return max(Q(0),Q(1,2)-c1*upper),min(Q(1,2),Q(1,2)-c0*lower)


def gaussian_interval(kind,x,bits):
    require(type(kind) is str and kind in ('gelu','gelu_tanh'),'Parameters')
    require(type(x) is Q and abs(x) <= 32768,'Argument')
    require(type(bits) is int and bits in (32,64,128,256),'Precision')
    if x == 0:
        return Q(0),Q(0),0
    a = abs(x)
    if kind == 'gelu':
        low,high = normal_tail(a,bits)
    else:
        c0,c1 = normalizer(bits+8)
        cubic = a+Q(8943,200000)*a**3
        # sqrt(2/pi)=2*c. tanh(v) uses exp(-2*v), hence factor four.
        z0 = strict_exp(4*c1*cubic,bits)[0]
        z1 = strict_exp(4*c0*cubic,bits)[1]
        low,high = z0/(1+z0),z1/(1+z1)
    require(0 <= low < high <= Q(1,2),'Interval')
    lo,hi = (a*(1-high),a*(1-low)) if x > 0 else (-a*high,-a*low)
    return lo,hi,1
