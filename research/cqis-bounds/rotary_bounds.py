"""Q26 / Draft RFC-0004 A3/A6/A7: rotary envelope arithmetic, no source authentication."""
from dataclasses import asdict, dataclass
from math import isqrt
from requant import same
from encoding import unsigned

P=2**31-1
UNIT=1<<14
# A7: |C|+|S| <= UNIT*sqrt(2)+1; the integer sum is at most 23171.
ENVELOPE=isqrt(2*UNIT*UNIT)+1
TAG=b'stele/research/q26/rotary-bounds/v1\0'
SCALARS=('row_width','pair_count','passthrough_count','input_max','coefficient_max','coefficient_l1_max',
         'product_max','numerator_max','divisor','bias','biased_max','quotient_max','remainder_max','division_max','output_max')
FIELDS=('numerator','sign','magnitude','quotient','remainder')


@dataclass(frozen=True)
class Spec:
    heads: int
    width: int
    rotary: int
    layout: str
    fraction: int
    length: int


def derive(p):
    if (type(p) is not Spec or type(p.layout) is not str or p.layout not in ('adjacent','split') or
            any(type(getattr(p,k)) is not int for k in ('heads','width','rotary','fraction','length')) or
            not 1<=p.heads<=128 or not 1<=p.width<=16384//p.heads or
            not 0<=p.rotary<=p.width or p.rotary%2 or not 0<=p.fraction<=30 or
            not 1<=p.length<=1<<20 or p.length*max(1,p.rotary//2)>1<<20): raise ValueError('Spec')
    maximum=32768*ENVELOPE
    c=dict(asdict(p),prime=P,row_width=p.heads*p.width,pair_count=p.heads*(p.rotary//2),
           passthrough_count=p.heads*(p.width-p.rotary),input_max=32768,coefficient_max=UNIT,
           coefficient_l1_max=ENVELOPE,product_max=32768*UNIT,numerator_max=maximum,
           divisor=UNIT,bias=UNIT//2,biased_max=maximum+UNIT//2,quotient_max=32768,
           remainder_max=UNIT-1,division_max=32768*UNIT+UNIT-1,output_max=32768)
    if any(2*c[k]>=P for k in ('input_max','coefficient_max','product_max','numerator_max',
                               'biased_max','division_max','output_max')): raise ValueError('FieldBound')
    return c


def validate(p,record):
    expected=derive(p)
    if not same(record,expected): raise ValueError('Certificate')
    return expected


def inputs(p,position,xs,coefficients):
    c=derive(p)
    if type(position) is not int or not 0<=position<p.length: raise ValueError('Position')
    if (type(xs) is not tuple or len(xs)!=c['row_width'] or
            any(type(x) is not int or not -32768<=x<=32767 for x in xs)): raise ValueError('Input')
    if (type(coefficients) is not tuple or len(coefficients)!=p.rotary//2 or
            any(type(pair) is not tuple or len(pair)!=2 or any(type(v) is not int or abs(v)>UNIT for v in pair)
                for pair in coefficients)): raise ValueError('Coefficients')
    # This is a fixed source-domain obligation, not a bound selected from observed data.
    if any(abs(cosine)+abs(sine)>ENVELOPE for cosine,sine in coefficients): raise ValueError('CoefficientEnvelope')


def pairs(p):
    for h in range(p.heads):
        for j in range(p.rotary//2):
            left=2*j if p.layout=='adjacent' else j
            right=left+1 if p.layout=='adjacent' else j+p.rotary//2
            yield h*p.width+left,h*p.width+right,j


def witness(p,position,xs,coefficients):
    inputs(p,position,xs,coefficients); output=list(xs); entries=[]
    for left,right,j in pairs(p):
        cosine,sine=coefficients[j]; x,y=xs[left],xs[right]; pair=[]
        for index,numerator in zip((left,right),(x*cosine-y*sine,x*sine+y*cosine)):
            magnitude=abs(numerator); q,remainder=divmod(magnitude+UNIT//2,UNIT)
            output[index]=-q if numerator<0 else q
            if not -32768<=output[index]<=32767: raise ValueError('OutputRange')
            pair.append(dict(numerator=numerator,sign=int(numerator<0),magnitude=magnitude,quotient=q,remainder=remainder))
        entries.append(tuple(pair))
    return dict(position=position,entries=tuple(entries),output=tuple(output))


def check_relations(p,record,position,xs,coefficients,w):
    """Plaintext sources/ranges; envelope membership is not canonical coefficient identity."""
    c=validate(p,record); inputs(p,position,xs,coefficients)
    if (type(w) is not dict or set(w)!={'position','entries','output'} or type(w['entries']) is not tuple or
            len(w['entries'])!=c['pair_count'] or type(w['output']) is not tuple or len(w['output'])!=c['row_width']):
        raise ValueError('Witness')
    if type(w['position']) is not int or w['position']!=position: raise ValueError('Position')
    if any(type(v) is not int or not -32768<=v<=32767 for v in w['output']): raise ValueError('Range')
    for (left,right,j),pair in zip(pairs(p),w['entries']):
        if type(pair) is not tuple or len(pair)!=2: raise ValueError('Witness')
        cosine,sine=coefficients[j]; x,y=xs[left],xs[right]
        for index,numerator,e in zip((left,right),(x*cosine-y*sine,x*sine+y*cosine),pair):
            if type(e) is not dict or set(e)!=set(FIELDS) or any(type(e[k]) is not int for k in FIELDS): raise ValueError('Witness')
            bounds=dict(sign=1,magnitude=c['numerator_max'],quotient=32768,remainder=UNIT-1)
            if any(not 0<=e[k]<=v for k,v in bounds.items()) or not -c['numerator_max']<=e['numerator']<=c['numerator_max']:
                raise ValueError('Range')
            # Range of magnitude-sign enforces canonical zero without an inverse.
            if e['sign']>e['magnitude']: raise ValueError('Sign')
            # The coupled coefficient envelope bounds the entire signed RHS, not a loose offset sum.
            if (e['numerator']-numerator)%P: raise ValueError('Numerator')
            if (e['numerator']-(1-2*e['sign'])*e['magnitude'])%P: raise ValueError('SourceSign')
            if (e['magnitude']+UNIT//2-e['quotient']*UNIT-e['remainder'])%P: raise ValueError('Rounding')
            if (w['output'][index]-(1-2*e['sign'])*e['quotient'])%P: raise ValueError('OutputRelation')
    for h in range(p.heads):
        for j in range(p.rotary,p.width):
            index=h*p.width+j
            if (w['output'][index]-xs[index])%P: raise ValueError('Passthrough')
    return w['output']


def encode(p):
    c=derive(p)
    raw=TAG+b''.join(unsigned(v,2) for v in (p.heads,p.width,p.rotary))
    raw+=bytes([('adjacent','split').index(p.layout),p.fraction])+unsigned(p.length,4)
    raw+=unsigned(P,4)+bytes([len(SCALARS)])+b''.join(unsigned(c[k],4) for k in SCALARS)
    if len(raw)>128: raise ValueError('Capacity')
    return raw


def validate_bytes(p,raw):
    expected=encode(p)
    if type(raw) is not bytes or len(raw)>128 or raw!=expected: raise ValueError('Encoding')
