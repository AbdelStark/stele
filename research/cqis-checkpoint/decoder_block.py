"""Q26 / Draft RFC-0004 A8: complete dense block numerical composition only."""
from dataclasses import dataclass
from functools import lru_cache
import projected_attention as pa
import records
from alignment import residual
from quantiser import require
import certified_rmsnorm as norm
import certified_activations as activation

GATE_SCALE_MAX = ((1 << 30)+126)//127


@dataclass(frozen=True)
class Row:
    codes: tuple
    scale: int
    fraction: int

    def __post_init__(self):
        require(type(self.codes) is tuple and 1<=len(self.codes)<=16384 and
                all(type(x) is int and abs(x)<=127 for x in self.codes),'Row')
        pa.a.integer(self.scale,0,GATE_SCALE_MAX,'Scale'); pa.a.integer(self.fraction,0,44,'Units')
        require(self.scale!=0 or all(x==0 for x in self.codes),'ZeroScale')


def quantize(values, fraction, policy, *, product=False):
    require(type(product) is bool and type(values) is list and 1<=len(values)<=16384,'Shape')
    low,high = (-(1 << 30),1 << 30) if product else (-32768,32767)
    require(all(type(x) is int and low<=x<=high for x in values),'Domain')
    require(type(policy) is tuple and len(policy)==2,'Policy'); pa.a.policy(*policy)
    scale = (max(map(abs,values))+126)//127 if policy[0]=='dynamic' else policy[1]
    codes = tuple(pa.a.rounded(x,scale) for x in values) if scale else (0,)*len(values)
    require(all(abs(x)<=127 for x in codes),'Overflow')
    return Row(codes,scale,fraction)


@dataclass(frozen=True)
class Matrix:
    bits: int
    exponent: int
    mantissas: tuple
    codes: tuple

    def __post_init__(self):
        require(type(self.bits) is int and self.bits in (4,8),'Format')
        pa.a.integer(self.exponent,-1099,1024,'Exponent'); pa.a.shape(self.codes,tuple)
        require(type(self.mantissas) is tuple and len(self.mantissas)==len(self.codes) and
                all(type(m) is int and 1<=m<=65535 for m in self.mantissas),'Scale')
        limit = (1 << (self.bits-1))-1
        require(all(type(x) is int and abs(x)<=limit for row in self.codes for x in row),'Code')


def from_record(spec, raw):
    records.config(spec)
    require(spec.bits in (4,8) and len(spec.shape)==2 and spec.parameter==0,'Record')
    require(records.count(spec)<=1 << 20 and max(spec.shape)<=16384,'Capacity')
    parsed = records.parse(spec,raw); n,k = spec.shape
    return Matrix(spec.bits,parsed['exponent'],tuple(parsed['mantissas']),
                  tuple(tuple(parsed['values'][i*k:(i+1)*k]) for i in range(n)))


def linear(w, x, fraction):
    require(type(w) is Matrix and type(x) is Row,'Weights')
    require(len(w.codes[0])==len(x.codes),'Shape'); pa.a.integer(fraction,0,30,'Units')
    result = []
    for codes,m in zip(w.codes,w.mantissas):
        # d<=16384: |dot|<2^28, scale<=ceil(2^30/127); |numerator|<2^68.
        numerator = sum(a*b for a,b in zip(codes,x.codes))*m*x.scale
        shift = x.fraction-w.exponent-fraction
        if shift>=69: value = 0
        elif shift>=0: value = pa.a.rounded(numerator,1 << shift)
        elif numerator==0: value = 0
        else:
            require(-shift<=15,'Overflow'); value = numerator << -shift
        require(-32768<=value<=32767,'Overflow'); result.append(value)
    return result


@dataclass(frozen=True)
class Params:
    norm1: norm.Parameters
    norm2: norm.Parameters
    gains1: tuple
    gains2: tuple
    weights: tuple  # Q,K,V,O,up,gate,down, each output-channel major.
    attention: pa.Params
    silu: pa.a.fn.Function
    fu: int
    fo: int
    fd: int
    fout: int
    first: tuple
    second: tuple
    gated: tuple

    def __post_init__(self):
        require(type(self.norm1) is norm.Parameters and type(self.norm2) is norm.Parameters,'Norm')
        require(self.norm1.d==self.norm2.d,'Shape'); d = self.norm1.d
        for gs in (self.gains1,self.gains2):
            require(type(gs) is tuple,'Shape'); pa.wide_row(list(gs),d)
        require(type(self.attention) is pa.Params,'Config'); p = self.attention
        require(type(self.weights) is tuple and len(self.weights)==7 and
                all(type(w) is Matrix for w in self.weights),'Weights')
        hidden = len(self.weights[4].codes)
        pa.a.integer(hidden,1,16384,'Shape')
        shapes = [(p.heads*p.width,d),(p.groups*p.width,d),(p.groups*p.width,d),
                  (d,p.heads*p.width),(hidden,d),(hidden,d),(d,hidden)]
        require(all((len(w.codes),len(w.codes[0]))==shape for w,shape in zip(self.weights,shapes)),'Shape')
        require(sum(n*k for n,k in shapes)<=1 << 20,'Capacity')
        require(type(self.silu) is pa.a.fn.Function and self.silu.name=='silu_q','Function')
        # RFC-0021 §2.2 requires the whole table. SiLU is total in int16 iff E<=F;
        # positive maximum is at 32767, and negative outputs are >=-2^E.
        require(self.silu.params[1]<=self.silu.params[0],'Overflow')
        for f in (self.fu,self.fo,self.fd,self.fout): pa.a.integer(f,0,30,'Units')
        for policy in (self.first,self.second,self.gated):
            require(type(policy) is tuple and len(policy)==2,'Policy'); pa.a.policy(*policy)


@lru_cache(maxsize=8192,typed=True)
def silu(function, value):
    return activation.certify(activation.Parameters('silu',*function.params),value)['value']


def project(p, row):
    pa.wide_row(row,p.norm1.d)
    x1 = quantize(norm.evaluate(p.norm1,row,list(p.gains1))['output'],p.norm1.E,p.first)
    wq,wk,wv = p.weights[:3]
    return dict(x1=x1,q=linear(wq,x1,p.attention.fq),k=linear(wk,x1,p.attention.fk),
                v=linear(wv,x1,p.attention.attention.fv))


def finish(p, row, position, projected, cache):
    r = dict(projected); wo,wu,wg,wd = p.weights[3:]
    r['attention'] = pa.query(p.attention,position,r['q'],cache,[j<=position for j in cache.positions])
    at = r['attention']; x = Row(tuple(at['codes']),at['scale'],p.attention.attention.fo)
    r['o'] = linear(wo,x,p.fo)
    r['mid'] = [residual(x,p.norm1.F,y,p.fo,p.norm2.F) for x,y in zip(row,r['o'])]
    r['x2'] = quantize(norm.evaluate(p.norm2,r['mid'],list(p.gains2))['output'],p.norm2.E,p.second)
    r['up'] = linear(wu,r['x2'],p.fu); r['gate'] = linear(wg,r['x2'],p.silu.params[0])
    r['silu'] = [silu(p.silu,v) for v in r['gate']]
    r['product'] = [x*y for x,y in zip(r['up'],r['silu'])]
    # No intermediate int16 requant: both factor units and the exact product survive.
    r['h'] = quantize(r['product'],p.fu+p.silu.params[1],p.gated,product=True)
    r['down'] = linear(wd,r['h'],p.fd)
    r['output'] = [residual(x,p.norm2.F,y,p.fd,p.fout) for x,y in zip(r['mid'],r['down'])]
    return r


@dataclass(frozen=True)
class Cached:
    scope: Params
    attention: pa.Cached


def full(p, rows, positions):
    require(type(p) is Params,'Config'); require(pa.a.shape(rows,list)==p.norm1.d,'Shape')
    cells = 16*p.norm1.d+16*p.attention.heads*p.attention.width+8*p.attention.groups*p.attention.width
    cells += 8*len(p.weights[4].codes)+8*p.attention.heads
    require(len(rows)*cells<=1 << 22,'Capacity')  # Retained integer payloads; Python object overhead is additional.
    require(type(positions) is list and len(positions)==len(rows),'Positions')
    pa.positions(p.attention,tuple(positions))
    projected = [project(p,row) for row in rows]
    cache = pa.prepare(p.attention,positions,[r['k'] for r in projected],[r['v'] for r in projected])
    outputs = [finish(p,row,pos,r,cache) for row,pos,r in zip(rows,positions,projected)]
    return dict(rows=outputs,cache=Cached(p,cache))


def step(p, row, position, cache=None):
    require(type(p) is Params,'Config'); pa.position(p.attention,position)
    if cache is not None:
        require(type(cache) is Cached and type(cache.scope) is Params and cache.scope==p,'CacheScope')
        old = cache.attention
        require(type(old) is pa.Cached and type(old.scope) is pa.Params and old.scope==p.attention,'CacheScope')
        pa.positions(p.attention,old.positions); require(position>old.positions[-1],'Positions')
        pa.a.validate(pa.conversion(p.attention),old.keys); pa.a.validate(p.attention.attention,old.values)
    r = project(p,row)
    current = pa.prepare(p.attention,[position],[r['k']],[r['v']])
    if cache is not None:
        def append(left, right):
            return pa.a.Cache(right.fv,right.mode,right.parameter,left.codes+right.codes,left.scales+right.scales)
        current = pa.Cached(p.attention,old.positions+(position,),append(old.keys,current.keys),append(old.values,current.values))
    # Construct new immutable state, but expose it only after the whole row succeeds.
    output = finish(p,row,position,r,current)
    return output,Cached(p,current)
