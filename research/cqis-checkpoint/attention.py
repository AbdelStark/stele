"""Q26 / Draft RFC-0004 A6: exact attention units, not an admitted kernel."""
from dataclasses import dataclass
from fractions import Fraction as Q
from functools import lru_cache
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]/'cqis-tables'))
import certified_exp as exp
import function_identity as fn
from quantiser import require, dynamic, static


def integer(x, low, high, reason):
    require(type(x) is int and low <= x <= high, reason)


def policy(mode, scale):
    require(type(mode) is str and mode in ('dynamic', 'static'), 'Mode')
    integer(scale, 0 if mode == 'dynamic' else 1, 0 if mode == 'dynamic' else 65535, 'Scale')


def rounded(n, d):
    """Signed nearest, ties away; positive d is established by the caller."""
    q, r = divmod(abs(n), d)
    return (-1 if n < 0 else 1)*(q+int(2*r >= d))


@dataclass(frozen=True)
class Config:
    function: fn.Function
    fv: int
    fo: int
    value_mode: str
    value_scale: int
    output_mode: str
    output_scale: int
    accumulation: str
    drop: int

    def __post_init__(self):
        require(type(self.function) is fn.Function and self.function.name in
                ('exp_q/product', 'exp_q/nearest'), 'Function')
        integer(self.fv, 0, 30, 'Units'); integer(self.fo, 0, 30, 'Units')
        policy(self.value_mode, self.value_scale); policy(self.output_mode, self.output_scale)
        require(type(self.accumulation) is str and self.accumulation in ('exact', 'block1024'), 'Mode')
        integer(self.drop, 0, 62, 'Drop')
        if self.accumulation == 'exact': require(self.drop == 0, 'Drop')
        else: require(self.drop >= minimum_drop(self), 'BlockBound')


def restored_max(p):
    if p.value_mode == 'dynamic': return 127*259
    s = p.value_scale
    return s*min(127, (65536+s)//(2*s))


def minimum_drop(p):
    maximum = 1024*(1 << p.function.params[2])*restored_max(p)
    return next(c for c in range(63) if rounded(maximum, 1 << c) <= 32767)


def bounds(p, n, *, position_span=None):
    require(type(p) is Config, 'Config'); integer(n, 1, 1 << 20, 'Shape')
    if position_span is None: position_span = n
    integer(position_span, n, 1 << 20, 'Shape')
    probability = 1 << p.function.params[2]
    block_max = 1024*probability*restored_max(p)
    total = n*probability*restored_max(p)
    if p.accumulation == 'block1024':
        blocks = min(n, (position_span+1023)//1024)
        total = blocks*rounded(block_max, 1 << p.drop)
    exponent = p.fo-p.fv+p.drop
    return dict(restored_max=restored_max(p), probability_max=probability,
                block_max=block_max, sum_max=total, z_max=n*probability,
                numerator_max=total << max(exponent, 0),
                denominator_max=(n*probability) << max(-exponent, 0))


@dataclass(frozen=True)
class Cache:
    fv: int
    mode: str
    parameter: int
    codes: tuple
    scales: tuple


def shape(rows, kind):
    require(type(rows) is kind and 1 <= len(rows) <= 1 << 20, 'Shape')
    require(type(rows[0]) is kind and 1 <= len(rows[0]) <= 16384, 'Shape')
    width = len(rows[0])
    require(len(rows)*width <= 1 << 20, 'Capacity')
    require(all(type(r) is kind and len(r) == width for r in rows), 'Shape')
    return width


def convert(p, values, output=False):
    mode = p.output_mode if output else p.value_mode
    scale = p.output_scale if output else p.value_scale
    return dynamic(values) if mode == 'dynamic' else static(values, scale)


def prepare(p, values):
    require(type(p) is Config, 'Config'); shape(values, list)
    require(all(type(x) is int and -32768 <= x <= 32767 for v in values for x in v), 'Input')
    converted = [convert(p, v) for v in values]
    return Cache(p.fv, p.value_mode, p.value_scale,
                 tuple(tuple(v['output']) for v in converted), tuple(v['scale'] for v in converted))


def validate(p, cache):
    require(type(cache) is Cache, 'Cache')
    require(type(cache.fv) is int and type(cache.parameter) is int and
            (cache.fv, cache.mode, cache.parameter) == (p.fv, p.value_mode, p.value_scale), 'CacheScope')
    width = shape(cache.codes, tuple)
    require(type(cache.scales) is tuple and len(cache.scales) == len(cache.codes), 'Shape')
    for codes, scale in zip(cache.codes, cache.scales):
        integer(scale, 0 if cache.mode == 'dynamic' else p.value_scale,
                259 if cache.mode == 'dynamic' else p.value_scale, 'Scale')
        limit = min(127, (65536+scale)//(2*scale)) if scale else 127
        require(all(type(x) is int and abs(x) <= limit for x in codes), 'Code')
        require(scale != 0 or all(x == 0 for x in codes), 'ZeroScale')
    return width


@lru_cache(maxsize=8192)
def probability(function, delta):
    b, f, e = function.params[:3]
    require(0 <= delta <= 1 << b, 'Domain')
    if function.name == 'exp_q/nearest': return exp.certify(Q(delta, 1 << f), e)['value']
    high, low = divmod(delta, 1 << function.params[3])
    a = exp.certify(Q(high << function.params[3], 1 << f), e)['value']
    z = exp.certify(Q(low, 1 << f), e)['value']
    return (a*z) >> e


def wide_row(p, scores, allowed, cache, *, positions=None):
    require(type(p) is Config, 'Config'); width = validate(p, cache)
    n = len(cache.codes)
    if positions is None: positions = tuple(range(n))
    require(type(positions) is tuple and len(positions)==n and
            all(type(j) is int and 0<=j<1 << 20 for j in positions) and
            all(x<y for x,y in zip(positions,positions[1:])), 'Positions')
    require(type(scores) is list and len(scores) == n, 'Shape')
    require(type(allowed) is list and len(allowed) == n and all(type(x) is bool for x in allowed), 'Mask')
    require(all(type(x) is int and -(1 << 31) <= x < 1 << 31 for x in scores), 'Score')
    require(any(allowed), 'EmptyRow')
    selected = max((j for j in range(n) if allowed[j]), key=lambda j: scores[j])
    maximum = scores[selected]
    weights = [probability(p.function, maximum-x) if bit else 0 for x, bit in zip(scores, allowed)]
    z = sum(weights)
    # P(0)=2^E and the selected maximum is allowed, so z is positive.
    require(z >= 1 << p.function.params[2], 'Divisor')
    total = [0]*width; partial = [0]*width
    for j, (codes, scale, weight) in enumerate(zip(cache.codes, cache.scales, weights)):
        for c, code in enumerate(codes): partial[c] += weight*scale*code
        if p.accumulation == 'block1024' and (j+1 == n or positions[j]//1024 != positions[j+1]//1024):
            for c, value in enumerate(partial):
                small = rounded(value, 1 << p.drop)
                require(-32768 <= small <= 32767, 'BlockBound')
                total[c] += small
            partial = [0]*width
    if p.accumulation == 'exact': total = partial
    exponent = p.fo-p.fv+p.drop
    division = [(abs(x) << max(exponent, 0), z << max(-exponent, 0)) for x in total]
    wide = [(-1 if x < 0 else 1)*rounded(u, d) for x, (u, d) in zip(total, division)]
    require(all(-32768 <= x <= 32767 for x in wide), 'Overflow')
    return dict(maximum=maximum, selected=positions[selected], z=z, total=total, wide=wide, division=division)


def row(p, scores, allowed, cache, *, positions=None):
    result = wide_row(p, scores, allowed, cache, positions=positions)
    converted = convert(p, result['wide'], output=True)
    return dict(result, scale=converted['scale'], codes=converted['output'])
