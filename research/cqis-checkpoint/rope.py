"""Q26 / Draft RFC-0004 A6: integer-certified rotary coefficient candidate."""
from dataclasses import dataclass
from fractions import Fraction as Q
from functools import lru_cache
from pathlib import Path
import struct
import sys
from blake3 import blake3
from flint import fmpz
from quantiser import require, round_away
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'cqis-tables'))
from certified_gelu import atan_bounds

TAG = b'stele/research/rope/v1\0'
MODES = ('base','linear','llama3')
LAYOUTS = ('adjacent','split')


@dataclass(frozen=True)
class Parameters:
    width: int
    length: int
    base: Q
    mode: str = 'base'
    layout: str = 'adjacent'
    factor: Q = Q(1)
    low: Q = Q(0)
    high: Q = Q(0)
    original: int = 0

    def __post_init__(self):
        require(type(self.width) is int and 2<=self.width<=16384 and self.width%2==0,'Parameters')
        require(type(self.length) is int and 1<=self.length<=1 << 20,'Parameters')
        require(type(self.mode) is str and self.mode in MODES and
                type(self.layout) is str and self.layout in LAYOUTS,'Parameters')
        for value in (self.base,self.factor,self.low,self.high):
            require(type(value) is Q and 0<=value<=1 << 32 and
                    0<=value.numerator<1 << 64 and value.denominator<1 << 64,'Parameters')
        require(self.base>=1 and self.factor>=1 and type(self.original) is int,'Parameters')
        if self.mode=='llama3':
            require(0<self.low<self.high and 1<=self.original<=1 << 20,'Parameters')
        else:
            require(self.low==self.high==self.original==0,'Parameters')
            if self.mode=='base': require(self.factor==1,'Parameters')


def encode(p):
    require(type(p) is Parameters,'Parameters')
    header=struct.pack('<HIBBI',p.width,p.length,MODES.index(p.mode),LAYOUTS.index(p.layout),p.original)
    return TAG+header+b''.join(struct.pack('<QQ',v.numerator,v.denominator) for v in (p.base,p.factor,p.low,p.high))


def decode(raw):
    require(type(raw) is bytes and len(raw)==len(TAG)+76 and raw.startswith(TAG),'Descriptor')
    try:
        width,length,mode,layout,original=struct.unpack_from('<HIBBI',raw,len(TAG))
        require(mode<len(MODES) and layout<len(LAYOUTS),'Descriptor')
        values=[Q(*struct.unpack_from('<QQ',raw,len(TAG)+12+16*i)) for i in range(4)]
        p=Parameters(width,length,values[0],MODES[mode],LAYOUTS[layout],*values[1:],original)
        require(encode(p)==raw,'Descriptor')
        return p
    except (ValueError,ZeroDivisionError,struct.error): raise ValueError('Descriptor') from None


def identity(p): return blake3(encode(p)).digest()


def verify_expected(expected,raw):
    require(type(expected) is Parameters,'Parameters')
    require(decode(raw)==expected,'Identity')


@lru_cache(maxsize=3,typed=True)
def pi_interval(bits):
    require(type(bits) is int and bits in (128,256,512),'Precision')
    a,b=atan_bounds(Q(1,5),bits+16),atan_bounds(Q(1,239),bits+16)
    return 16*a[0]-4*b[1],16*a[1]-4*b[0]


@lru_cache(maxsize=3*8192,typed=True)
def frequency(p,j,bits):
    require(type(p) is Parameters,'Parameters')
    require(type(j) is int and 0<=j<p.width//2,'Pair')
    require(type(bits) is int and bits in (128,256,512),'Precision')
    exponent=Q(2*j,p.width);num,den=exponent.numerator,exponent.denominator
    unit=1 << bits
    numerator=(fmpz(unit)**den)*(fmpz(p.base.denominator)**num)
    divisor=fmpz(p.base.numerator)**num
    radicand=numerator//divisor; root=radicand.root(den)
    require(root**den<=radicand<(root+1)**den,'Root')
    low=Q(int(root),unit)
    high=low if root**den*divisor==numerator else Q(int(root)+1,unit)
    if p.mode=='linear': return low/p.factor,high/p.factor
    if p.mode=='llama3':
        pl,ph=pi_interval(bits)
        def clamp(x): return max(Q(0),min(Q(1),x))
        gl=clamp((p.original*low/(2*ph)-p.low)/(p.high-p.low))
        gh=clamp((p.original*high/(2*pl)-p.low)/(p.high-p.low))
        low*=1/p.factor+(1-1/p.factor)*gl
        high*=1/p.factor+(1-1/p.factor)*gh
    require(0<=low<=high<=1,'Interval')
    return low,high


def small(y,parity,bits):
    """Alternating Taylor enclosure for sin/cos at 0<=y<=1/8."""
    require(type(y) is Q and 0<=y<=Q(1,8) and type(parity) is int and parity in (0,1),'Argument')
    require(type(bits) is int and bits in (128,256,512),'Precision')
    total=term=y if parity else Q(1)
    for k in range(1,129):
        term=-term*y*y/((2*k-1+parity)*(2*k+parity))
        if abs(term)<=Q(1,1 << (bits+8)): return min(total,total+term),max(total,total+term)
        total+=term
    raise ValueError('Precision')


def enclosure(p,position,j,bits):
    require(type(p) is Parameters,'Parameters')
    require(type(position) is int and 0<=position<p.length,'Position')
    require(type(j) is int and 0<=j<p.width//2,'Pair')
    require(type(bits) is int and bits in (128,256,512),'Precision')
    unit=1 << bits
    if position==0: return (unit,unit),(0,0)
    low,high=frequency(p,j,bits);low*=position;high*=position;doublings=0
    while high>Q(1,8): low/=2;high/=2;doublings+=1
    midpoint=(low+high)/2;radius=(high-low)/2
    def integer_interval(pair):
        lo,hi=pair[0]-radius,pair[1]+radius
        return lo.numerator*unit//lo.denominator,-((-hi.numerator*unit)//hi.denominator)
    s=integer_interval(small(midpoint,1,bits));c=integer_interval(small(midpoint,0,bits))
    def clip(pair): return max(-unit,pair[0]),min(unit,pair[1])
    for _ in range(doublings):
        products=[x*y for x in s for y in c]
        sn=clip((2*min(products)//unit,-((-2*max(products))//unit)))
        squares=[x*x for x in c]
        lower=0 if c[0]<=0<=c[1] else min(squares)
        cn=clip((2*lower//unit-unit,-((-2*max(squares))//unit)-unit))
        s,c=sn,cn
        require(-unit<=s[0]<=s[1]<=unit and -unit<=c[0]<=c[1]<=unit,'Interval')
    return c,s


def certify(p,position,j):
    for bits in (128,256,512):
        c,s=enclosure(p,position,j,bits);unit=1 << bits
        values=[tuple(round_away(Q(v*16384,unit)) for v in pair) for pair in (c,s)]
        if all(low==high for low,high in values):
            return dict(cos=values[0][0],sin=values[1][0],bits=bits,cos_interval=c,sin_interval=s)
    raise ValueError('Precision')


def verify_entry(p,position,j,certificate):
    expected=certify(p,position,j)
    require(type(certificate) is dict and set(certificate)==set(expected),'Certificate')
    require(all(type(certificate[k]) is int for k in ('cos','sin','bits')),'Certificate')
    require(all(type(certificate[k]) is tuple and len(certificate[k])==2 and
                all(type(x) is int for x in certificate[k]) for k in ('cos_interval','sin_interval')),'Certificate')
    require(certificate==expected,'Certificate')


def generate(p):
    require(type(p) is Parameters,'Parameters')
    require(p.length*(p.width//2)<=1 << 16,'Capacity')
    out=bytearray()
    for position in range(p.length):
        for j in range(p.width//2):
            cert=certify(p,position,j);out+=struct.pack('<hh',cert['cos'],cert['sin'])
    return bytes(out)


def verify_table(p,raw):
    require(type(p) is Parameters,'Parameters')
    require(type(raw) is bytes and len(raw)==2*p.length*p.width,'Table')
    require(raw==generate(p),'Table')
