"""Q26 / Draft RFC-0004 A6: projected attention with explicit integer units."""
from dataclasses import dataclass
import attention as a
from quantiser import require


def shift(value, exponent):
    return value << exponent if exponent >= 0 else a.rounded(value, 1 << -exponent)


@dataclass(frozen=True)
class Params:
    heads: int
    groups: int
    width: int
    rotary: int
    layout: str
    fq: int
    fk: int
    q_mode: str
    q_scale: int
    k_mode: str
    k_scale: int
    score_m: int
    score_e: int
    attention: a.Config
    rotations: tuple

    def __post_init__(self):
        a.integer(self.heads,1,128,'Heads'); a.integer(self.groups,1,self.heads,'Heads')
        require(self.heads%self.groups == 0,'Heads')
        a.integer(self.width,1,16384//self.heads,'Shape')
        a.integer(self.rotary,0,self.width,'Rotation'); require(self.rotary%2 == 0,'Rotation')
        require(type(self.layout) is str and self.layout in ('adjacent','split'),'Rotation')
        a.integer(self.fq,0,30,'Units'); a.integer(self.fk,0,30,'Units')
        a.policy(self.q_mode,self.q_scale); a.policy(self.k_mode,self.k_scale)
        a.integer(self.score_m,1,65535,'ScoreScale'); a.integer(self.score_e,-62,30,'ScoreScale')
        require(type(self.attention) is a.Config,'Config')
        require(type(self.rotations) is tuple and 1<=len(self.rotations)<=1 << 20,'Rotation')
        require(len(self.rotations)*max(1,self.rotary//2)<=1 << 20,'Capacity')
        for row in self.rotations:
            require(type(row) is tuple and len(row)==self.rotary//2,'Rotation')
            for pair in row:
                require(type(pair) is tuple and len(pair)==2,'Rotation')
                for v in pair: a.integer(v,-16384,16384,'Rotation')
        require(bounds(self)['score_abs_max'] < 1 << 31,'ScoreBound')


def conversion(p, query=False):
    return a.Config(p.attention.function,p.fq if query else p.fk,0,
                    p.q_mode if query else p.k_mode,p.q_scale if query else p.k_scale,
                    'dynamic',0,'exact',0)


def bounds(p):
    sq = a.restored_max(conversion(p,True)); sk = a.restored_max(conversion(p))
    product = p.width*sq*sk*p.score_m
    exponent = p.score_e-p.fq-p.fk+p.attention.function.params[1]
    return dict(rotation_numerator_max=1 << 30,score_product_max=product,
                score_shift=exponent,score_abs_max=shift(product,exponent))


def position(p, value):
    a.integer(value,0,len(p.rotations)-1,'Position')


def positions(p, values):
    require(type(values) is tuple and 1<=len(values)<=1 << 20,'Positions')
    require(all(type(j) is int and 0<=j<len(p.rotations) for j in values),'Positions')
    require(all(left<right for left,right in zip(values,values[1:])),'Positions')


def wide_row(values, width):
    require(type(values) is list and len(values)==width,'Shape')
    require(all(type(v) is int and -32768<=v<=32767 for v in values),'Input')


def rotate(p, pos, values, count):
    position(p,pos); wide_row(values,count*p.width)
    result = values.copy()
    for h in range(count):
        for j,(c,s) in enumerate(p.rotations[pos]):
            left = 2*j if p.layout=='adjacent' else j
            right = left+1 if p.layout=='adjacent' else j+p.rotary//2
            left += h*p.width; right += h*p.width
            x,y = values[left],values[right]
            result[left] = a.rounded(x*c-y*s,16384)
            result[right] = a.rounded(x*s+y*c,16384)
    require(all(-32768<=v<=32767 for v in result),'Overflow')
    return result


@dataclass(frozen=True)
class Cached:
    scope: Params
    positions: tuple
    keys: a.Cache
    values: a.Cache


def prepare(p, absolute_positions, keys, values):
    require(type(p) is Params,'Config')
    require(type(absolute_positions) is list,'Positions'); pos = tuple(absolute_positions)
    positions(p,pos)
    require(a.shape(keys,list)==p.groups*p.width and len(keys)==len(pos),'Shape')
    require(a.shape(values,list)==p.groups*p.width and len(values)==len(pos),'Shape')
    rotated = [rotate(p,j,k,p.groups) for j,k in zip(pos,keys)]
    return Cached(p,pos,a.prepare(conversion(p),rotated),a.prepare(p.attention,values))


def query(p, absolute_position, values, cache, allowed):
    require(type(p) is Params,'Config')
    require(type(cache) is Cached and type(cache.scope) is Params and cache.scope==p,'CacheScope')
    positions(p,cache.positions)
    position(p,absolute_position)
    require(a.validate(conversion(p),cache.keys)==p.groups*p.width,'Shape')
    require(a.validate(p.attention,cache.values)==p.groups*p.width,'Shape')
    require(len(cache.keys.codes)==len(cache.positions)==len(cache.values.codes),'Shape')
    require(type(allowed) is list and len(allowed)==len(cache.positions) and
            all(type(bit) is bool for bit in allowed),'Mask')
    require(any(allowed),'EmptyRow')
    rotated = rotate(p,absolute_position,values,p.heads)
    q = a.convert(conversion(p,True),rotated); qs = q['scale']; qc = q['output']
    score_bounds = bounds(p); wide,heads = [],[]
    for h in range(p.heads):
        group = h//(p.heads//p.groups); start = group*p.width; end = start+p.width
        query_codes = qc[h*p.width:(h+1)*p.width]
        scores = []
        for key,ks in zip(cache.keys.codes,cache.keys.scales):
            dot = sum(x*y for x,y in zip(query_codes,key[start:end]))
            score = shift(dot*qs*ks*p.score_m,score_bounds['score_shift'])
            require(abs(score)<=score_bounds['score_abs_max'],'ScoreBound')
            scores.append(score)
        sliced = a.Cache(cache.values.fv,cache.values.mode,cache.values.parameter,
                         tuple(v[start:end] for v in cache.values.codes),cache.values.scales)
        result = a.wide_row(p.attention,scores,allowed,sliced,positions=cache.positions)
        # Normalize all heads before one conversion of the assembled O-projection input.
        heads.append({key:result[key] for key in ('maximum','selected','z','total','wide')})
        wide.extend(result['wide'])
    output = a.convert(p.attention,wide,output=True)
    return dict(query_scale=qs,heads=heads,wide=wide,scale=output['scale'],codes=output['output'])
