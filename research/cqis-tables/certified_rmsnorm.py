"""Q25 / Draft RFC-0004 A2: total normalization, checked integer RMSNorm candidate."""
from dataclasses import dataclass
from fractions import Fraction as Q
from math import gcd, isqrt
from certified_exp import require

DELTA = Q(1,1 << 15)+Q(1,1 << 14)+Q(1,1 << 29)
# Version 1: int16 inputs (RFC-0021 §2.3). Version 2: int24 inputs, d <= 8192 (RFC-0021 A4).
# Per version: input magnitude bound, largest exponent a, largest shift, largest |X*H*J|.
LIMITS = {1: (1 << 15,9,90,1 << 44),2: (1 << 23,16,97,1 << 52)}


@dataclass(frozen=True)
class Parameters:
    d: int
    F: int
    G: int
    E: int
    en: int
    ed: int
    version: int = 1

    def __post_init__(self):
        require(type(self.version) is int and self.version in LIMITS
                and self.d <= (16384 if self.version == 1 else 8192),'Parameters')
        require(all(type(v) is int for v in self.metadata()) and 1 <= self.d <= 16384
                and 0 <= self.F <= 30 and 0 <= self.G <= 30 and 0 <= self.E <= 14
                and 1 <= self.en < 1 << 32 and 1 <= self.ed < 1 << 32
                and gcd(self.en,self.ed) == 1,'Parameters')

    def metadata(self):
        return [self.d,self.F,self.G,self.E,self.en,self.ed]


def rsqrt_certificate(m):
    require(type(m) is int and 16384 <= m < 65536,'Mantissa')
    k = isqrt((1 << 42)//m)
    j = k+int((1 << 44) >= m*(2*k+1)**2)
    return dict(value=j,lower_gap=(1 << 44)-m*(2*j-1)**2,
                upper_gap=m*(2*j+1)**2-(1 << 44))


def verify_entry(m,cert):
    require(type(m) is int and 16384 <= m < 65536,'Mantissa')
    require(type(cert) is dict and set(cert) == {'value','lower_gap','upper_gap'}
            and all(type(v) is int for v in cert.values()),'TableCertificate')
    j = cert['value']
    require(8192 <= j <= 16384 and cert['lower_gap'] == (1 << 44)-m*(2*j-1)**2
            and cert['upper_gap'] == m*(2*j+1)**2-(1 << 44)
            and cert['lower_gap'] >= 0 and cert['upper_gap'] > 0,'TableCertificate')


def generate_table():
    return dict(rows=[rsqrt_certificate(m) for m in range(16384,65536)])


def verify_table(table):
    require(type(table) is dict and set(table) == {'rows'} and type(table['rows']) is list
            and len(table['rows']) == 49152,'TableShape')
    for m,cert in zip(range(16384,65536),table['rows']):
        verify_entry(m,cert)


def scaled_ratio(n,p,a):
    return (n << (-2*a),p) if a < 0 else (n,p << (2*a))


def statistic_ratio(p,s):
    require(type(s) is int and 0 <= s <= p.d*LIMITS[p.version][0]**2,'Statistic')
    denominator = p.ed*p.d*(1 << (2*p.F))
    return p.ed*s+p.en*p.d*(1 << (2*p.F)),denominator


def normalize(p,s):
    n,denominator = statistic_ratio(p,s)
    a = (n.bit_length()-denominator.bit_length()-14)//2
    A,D = scaled_ratio(n,denominator,a)
    if A < 16384*D:
        a -= 1;A,D = scaled_ratio(n,denominator,a)
    m,r = divmod(A,D)
    require(-23 <= a <= LIMITS[p.version][1] and 16384 <= m < 65536,'Normalization')
    return dict(S=s,N=n,P=denominator,a=a,M=m,R=r,J=rsqrt_certificate(m)['value'])


def verify_normalization(p,s,w):
    require(type(w) is dict and set(w) == {'S','N','P','a','M','R','J'},'Normalization')
    n,denominator = statistic_ratio(p,s)
    require(all(type(w[k]) is int for k in ('S','N','P'))
            and (w['S'],w['N'],w['P']) == (s,n,denominator),'Statistic')
    require(all(type(w[k]) is int for k in ('a','M','R'))
            and -23 <= w['a'] <= LIMITS[p.version][1] and 16384 <= w['M'] < 65536,'Normalization')
    A,D = scaled_ratio(n,denominator,w['a'])
    require(0 <= w['R'] < D and A == w['M']*D+w['R'],'Normalization')
    j,m = w['J'],w['M']
    require(type(j) is int and 8192 <= j <= 16384
            and m*(2*j-1)**2 <= 1 << 44 < m*(2*j+1)**2,'TableCertificate')


def round_shift(value,shift,version=1):
    _,_,highest,product = LIMITS[version]
    require(type(value) is int and abs(value) <= product,'Product')
    require(type(shift) is int and -16 <= shift <= highest,'Shift')
    if shift < 0:
        return value << -shift
    magnitude = (abs(value)+(1 << (shift-1) if shift else 0)) >> shift
    return -magnitude if value < 0 else magnitude


def inputs(p,xs,gs):
    require(type(xs) is list and type(gs) is list and len(xs) == len(gs) == p.d,'Shape')
    x = LIMITS[p.version][0]
    require(all(type(v) is int and -x <= v < x for v in xs)
            and all(type(v) is int and -32768 <= v <= 32767 for v in gs),'Domain')


def evaluate(p,xs,gs):
    inputs(p,xs,gs)
    w = normalize(p,sum(x*x for x in xs))
    shift = p.F+p.G+21+w['a']-p.E
    ys = [round_shift(x*g*w['J'],shift,p.version) for x,g in zip(xs,gs)]
    require(all(-32768 <= y <= 32767 for y in ys),'Overflow')
    return dict(parameters=p.metadata(),norm=w,shift=shift,output=ys)


def verify(p,xs,gs,result):
    inputs(p,xs,gs)
    require(type(result) is dict and set(result) == {'parameters','norm','shift','output'},'Shape')
    require(type(result['parameters']) is list and all(type(v) is int for v in result['parameters'])
            and result['parameters'] == p.metadata(),'Parameters')
    w = result['norm'];verify_normalization(p,sum(x*x for x in xs),w)
    shift = p.F+p.G+21+w['a']-p.E
    require(type(result['shift']) is int and result['shift'] == shift
            and type(result['output']) is list and len(result['output']) == p.d,'Output')
    for x,g,y in zip(xs,gs,result['output']):
        require(type(y) is int and -32768 <= y <= 32767
                and y == round_shift(x*g*w['J'],shift,p.version),'Output')


def ceil_root(n):
    k = isqrt(n)
    return k+int(k*k < n)


def bounds(p):
    """Research static magnitudes, not native field-faithfulness certificates."""
    x,amax,_,product = LIMITS[p.version]
    s = p.d*x*x
    n,denominator = statistic_ratio(p,s)
    low,high = p.F+p.G-2-p.E,p.F+p.G+21+amax-p.E
    record = dict(S=s,N=n,P=denominator,scaled_N=n << 46,scaled_P=denominator << (2*amax),
        hh=p.d*128**2,hl_abs=p.d*128*255,ll=p.d*255**2,product=product,
        biased=product+(1 << (high-1) if high > 0 else 0),
        left_product=product << max(0,-low),shift_min=low,shift_max=high)
    return record if p.version == 1 else dict(record,version=2)


def verify_bounds(p,record):
    require(type(record) is dict and all(type(v) is int for v in record.values())
            and record == bounds(p),'Bounds')
