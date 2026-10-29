"""Q25 / Draft RFC-0004 A2 candidate: rational certificates, no host floats."""
from dataclasses import dataclass
from fractions import Fraction as Q
from functools import lru_cache


def require(condition, reason):
    if not condition:
        raise ValueError(reason)


def round_nonnegative(value):
    require(value >= 0,'Magnitude')
    return (2*value.numerator+value.denominator)//(2*value.denominator)


@lru_cache(maxsize=65536,typed=True)
def enclosure(x, bits):
    """Alternating Taylor on [0,1/2], then outward-rounded dyadic squaring."""
    require(type(x) is Q and 0 <= x <= 32768,'Argument')
    require(type(bits) is int and bits in (32,64,128,256),'Precision')
    y, squarings = x,0
    while y > Q(1,2):
        y /= 2
        squarings += 1
    precision = bits+squarings+4
    unit = 1 << precision
    if x == 0:
        return unit,unit,precision
    lower,upper,partial,term = Q(0),Q(1),Q(1),Q(1)
    for n in range(1,513):
        term *= y/n
        partial += term if n % 2 == 0 else -term
        if n % 2:
            lower = partial
        else:
            upper = partial
        if upper-lower <= Q(1,unit):
            break
    else:
        raise ValueError('Precision')
    low = (lower.numerator*unit)//lower.denominator
    high = -((-upper.numerator*unit)//upper.denominator)
    for _ in range(squarings):
        low = (low*low)//unit
        high = (high*high+unit-1)//unit
    require(0 <= low <= high <= unit,'Interval')
    require(Q(high-low,unit) < Q(1,1 << bits),'Interval')
    return low,high,precision


def certify(x,e):
    require(type(e) is int and 0 <= e <= 14,'Parameters')
    for bits in (32,64,128,256):
        low,high,precision = enclosure(x,bits)
        lower = round_nonnegative(Q((1 << e)*low,1 << precision))
        upper = round_nonnegative(Q((1 << e)*high,1 << precision))
        if lower == upper:
            return dict(value=lower,lower=low,upper=high,precision=precision,bits=bits)
    raise ValueError('Precision')


@dataclass(frozen=True)
class Parameters:
    B: int
    F: int
    E: int

    def __post_init__(self):
        require(all(type(x) is int for x in (self.B,self.F,self.E))
                and 7 <= self.B <= 15 and 0 <= self.F <= 30 and 0 <= self.E <= 14,'Parameters')


def generate(p):
    return dict(parameters=[p.B,p.F,p.E],
        high=[certify(Q(128*i,1 << p.F),p.E) for i in range((1 << (p.B-7))+1)],
        low=[certify(Q(i,1 << p.F),p.E) for i in range(128)])


def verify(p,table):
    require(type(table) is dict and set(table) == {'parameters','high','low'},'TableShape')
    require(type(table['parameters']) is list and all(type(v) is int for v in table['parameters'])
            and table['parameters'] == [p.B,p.F,p.E],'Parameters')
    for tag,count,multiplier in [('high',(1 << (p.B-7))+1,128),('low',128,1)]:
        require(type(table[tag]) is list and len(table[tag]) == count,'TableShape')
        for i,cert in enumerate(table[tag]):
            expected = certify(Q(i*multiplier,1 << p.F),p.E)
            require(type(cert) is dict and set(cert) == set(expected)
                    and all(type(v) is int for v in cert.values()) and cert == expected,'Certificate')


def evaluate(p,table,t):
    """The fixed-table caller must first validate all certificates with verify."""
    require(type(t) is int and -(1 << p.B) <= t <= 0,'Domain')
    high,low = divmod(-t,128)
    return (table['high'][high]['value']*table['low'][low]['value'])//(1 << p.E)


def corrected(p):
    """Same exact real target for direct and decomposed evaluation; full correction cost."""
    base = generate(p)
    direct = [certify(Q(-t,1 << p.F),p.E) for t in range(-(1 << p.B),1)]
    corrections = [cert['value']-evaluate(p,base,t) for t,cert in zip(range(-(1 << p.B),1),direct)]
    require(all(-1 <= c <= 2 for c in corrections),'Correction')
    return dict(base=base,direct=direct,corrections=corrections)


def verify_corrected(p,table):
    require(type(table) is dict and set(table) == {'base','direct','corrections'},'TableShape')
    verify(p,table['base'])
    require(all(type(table[k]) is list and len(table[k]) == (1 << p.B)+1
                for k in ('direct','corrections')),'TableShape')
    for i,t in enumerate(range(-(1 << p.B),1)):
        cert,c = table['direct'][i],table['corrections'][i]
        expected = certify(Q(-t,1 << p.F),p.E)
        require(type(cert) is dict and set(cert) == set(expected)
                and all(type(v) is int for v in cert.values()) and cert == expected,'Certificate')
        require(type(c) is int and -1 <= c <= 2
                and evaluate(p,table['base'],t)+c == expected['value'],'Correction')


def evaluate_corrected(p,table,t):
    return evaluate(p,table['base'],t)+table['corrections'][t+(1 << p.B)]
