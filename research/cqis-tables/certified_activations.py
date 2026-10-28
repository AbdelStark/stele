"""Q25 / Draft RFC-0004 A2: strict rational activation candidates, research only."""
from dataclasses import dataclass
from fractions import Fraction as Q
from certified_exp import enclosure, require, round_nonnegative


def round_endpoint(value,side):
    """Signed half-away at value (0), from below (-1), or from above (+1)."""
    require(type(value) is Q and type(side) is int and side in (-1,0,1),'Endpoint')
    magnitude = abs(value)
    result = round_nonnegative(magnitude)*(-1 if value < 0 else 1)
    tie = (2*magnitude.numerator) % (2*magnitude.denominator) == magnitude.denominator
    if tie and side < 0 and value > 0:
        result -= 1
    if tie and side > 0 and value < 0:
        result += 1
    return result


def strict_exp(x,bits):
    """For x>0 both endpoints are excluded; x=0 is an exact singleton."""
    require(type(x) is Q and x >= 0,'Argument')
    require(type(bits) is int and bits in (32,64,128,256),'Precision')
    if x == 0:
        return Q(1),Q(1),0
    if x >= bits:
        # exp(1)>2 proves 0<exp(-x)<2^-bits, with no zero substitution.
        return Q(0),Q(1,1 << bits),1
    low,high,p = enclosure(x,bits)
    # Alternating Taylor bounds are strict for positive x. Outward rounding and
    # monotone squaring preserve strictness, including a rounded zero endpoint.
    return Q(low,1 << p),Q(high,1 << p),1


@dataclass(frozen=True)
class Parameters:
    kind: str
    F: int
    E: int
    cap_m: int = 0
    cap_f: int = 0

    def __post_init__(self):
        require(type(self.kind) is str and self.kind in ('sigmoid','silu','softcap')
                and all(type(v) is int for v in (self.F,self.E,self.cap_m,self.cap_f))
                and 0 <= self.F <= 30 and 0 <= self.E <= 14,'Parameters')
        if self.kind == 'softcap':
            require(1 <= self.cap_m <= 65535 and 0 <= self.cap_f <= 30
                    and (self.cap_f == 0 or self.cap_m % 2 == 1),'Parameters')
        else:
            require(self.cap_m == self.cap_f == 0,'Parameters')

    def metadata(self):
        return [self.kind,self.F,self.E,self.cap_m,self.cap_f]


def interval(p,t,bits):
    require(type(t) is int and -32768 <= t <= 32767,'Domain')
    x,scale = Q(t,1 << p.F),1 << p.E
    cap = Q(p.cap_m,1 << p.cap_f) if p.kind == 'softcap' else Q(1)
    exponent = 2*abs(x)/cap if p.kind == 'softcap' else abs(x)
    lo,hi,strict = strict_exp(exponent,bits)
    if p.kind == 'sigmoid':
        low,high = (1/(1+hi),1/(1+lo)) if x >= 0 else (lo/(1+lo),hi/(1+hi))
    elif p.kind == 'silu':
        low,high = (x/(1+hi),x/(1+lo)) if x >= 0 else (x*hi/(1+hi),x*lo/(1+lo))
    else:
        low,high = cap*(1-hi)/(1+hi),cap*(1-lo)/(1+lo)
        if x < 0:
            low,high = -high,-low
    return low*scale,high*scale,strict


def certify(p,t):
    for bits in (32,64,128,256):
        low,high,strict = interval(p,t,bits)
        a,b = round_endpoint(low,strict),round_endpoint(high,-strict)
        if a == b:
            require(-32768 <= a <= 32767,'Overflow')
            return dict(value=a,bits=bits,lower=[low.numerator,low.denominator],
                        upper=[high.numerator,high.denominator],strict=strict)
    raise ValueError('Precision')


def generate(p):
    """Complete signed order, -32768 through 32767; any row failure rejects all."""
    return dict(parameters=p.metadata(),rows=[certify(p,t) for t in range(-32768,32768)])


def verify(p,table):
    require(type(table) is dict and set(table) == {'parameters','rows'},'TableShape')
    metadata = table['parameters']
    require(type(metadata) is list and len(metadata) == 5 and type(metadata[0]) is str
            and all(type(v) is int for v in metadata[1:]) and metadata == p.metadata(),'Parameters')
    require(type(table['rows']) is list and len(table['rows']) == 65536,'TableShape')
    for t,cert in zip(range(-32768,32768),table['rows']):
        expected = certify(p,t)
        require(type(cert) is dict and set(cert) == set(expected)
                and all(type(cert[k]) is int for k in ('value','bits','strict'))
                and all(type(cert[k]) is list and len(cert[k]) == 2
                        and all(type(v) is int for v in cert[k]) for k in ('lower','upper'))
                and cert == expected,'Certificate')
