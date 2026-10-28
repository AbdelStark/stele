"""RFC-0010 A3 / Q27 conditional tensor parameters, not admitted PCS parameters."""
from fractions import Fraction
from identity import parameters
from recursive import sc


def require(condition, reason):
    if not condition:
        raise ValueError(reason)


def queries(n, hit):
    require(type(n) is int and 1 <= n <= 1 << 31 and type(hit) is int and 1 <= hit <= n,
            'InvalidParameters')

    def passes(q):
        return ((n-hit)**q << 130) <= n**q

    lo, hi = 1, 1
    while hi < 16384 and not passes(hi):
        hi *= 2
    require(passes(hi), 'UnsupportedParameters')
    while lo < hi:
        middle = (lo+hi)//2
        if passes(middle):
            hi = middle
        else:
            lo = middle+1
    return lo


def tensor_parameters(raw_id, field, rows_log):
    require(type(field) is int and field in (4,8) and type(rows_log) is int and rows_log >= 0,
            'UnsupportedParameters')
    info = parameters(raw_id, field)
    n, distance = info['codeword_len'], info['distance']
    radius = (distance-1)//3
    hit = radius+1
    return dict(radius=radius, hit=hit, queries=queries(n,hit),
                gap=Fraction(2*rows_log*hit,sc.P**field), miss=Fraction(n-hit,n),
                setup=info['setup_loss'])
