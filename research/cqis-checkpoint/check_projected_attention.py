# /// script
# requires-python = ">=3.12"
# dependencies = ["numpy==2.3.4", "blake3==1.0.11"]
# ///
"""Q26 projected attention oracle; numerical evidence, not native/proof parity."""
from dataclasses import replace
from fractions import Fraction as Q
import hashlib
import json
import random
import numpy as np
from projected_attention import Params, Cached, prepare, query, bounds, rotate, a
from check_attention import rounded, convert, reject


def rotation(p, position, values, count):
    result = list(values)
    for h in range(count):
        for j, (c, s) in enumerate(p.rotations[position]):
            left = 2*j if p.layout == 'adjacent' else j
            right = left+1 if p.layout == 'adjacent' else j+p.rotary//2
            left += h*p.width; right += h*p.width
            x, y = values[left], values[right]
            result[left] = rounded(Q(x*c-y*s, 16384))
            result[right] = rounded(Q(x*s+y*c, 16384))
    if any(not -32768<=v<=32767 for v in result): raise ValueError('Overflow')
    return result


def probability(p, difference):
    b, f, e = p.attention.function.params[:3]
    if not 0<=difference<=1 << b: raise ValueError('Domain')
    if p.attention.function.name.endswith('nearest'):
        return a.exp.certify(Q(difference, 1 << f), e)['value']
    split = p.attention.function.params[3]; high, low = divmod(difference, 1 << split)
    return (a.exp.certify(Q(high << split, 1 << f), e)['value']*
            a.exp.certify(Q(low, 1 << f), e)['value'])//(1 << e)


def oracle(p, position, q, positions, keys, values, allowed):
    ks = [convert(rotation(p, j, k, p.groups), p.k_mode, p.k_scale) for j,k in zip(positions,keys)]
    vs = [convert(v, p.attention.value_mode, p.attention.value_scale) for v in values]
    sq, qc = convert(rotation(p, position, q, p.heads), p.q_mode, p.q_scale)
    wide, heads = [], []
    for h in range(p.heads):
        group = h//(p.heads//p.groups); lo = group*p.width; hi = lo+p.width
        matrix = np.asarray([k[lo:hi] for _,k in ks], dtype=np.int64)
        dots = matrix @ np.asarray(qc[h*p.width:(h+1)*p.width], dtype=np.int64)
        scores = [rounded(Q(int(dot)*sq*sk*p.score_m)*Q(2)**(
                  p.score_e-p.fq-p.fk+p.attention.function.params[1])) for dot,(sk,_) in zip(dots,ks)]
        assert all(abs(s)<=bounds(p)['score_abs_max'] for s in scores)
        maximum = max(s for s,bit in zip(scores,allowed) if bit)
        selected = min(j for j,s,bit in zip(positions,scores,allowed) if bit and s==maximum)
        weights = [probability(p, maximum-s) if bit else 0 for s,bit in zip(scores,allowed)]
        z = sum(weights); partial = {}
        for j,w,(scale,codes) in zip(positions,weights,vs):
            block = j//1024 if p.attention.accumulation == 'block1024' else 0
            partial.setdefault(block,[0]*p.width)
            for c in range(p.width): partial[block][c] += w*scale*codes[lo+c]
        total = [sum(rounded(Q(v[c],1 << p.attention.drop)) for v in partial.values()) for c in range(p.width)]
        output = [rounded(Q(t,z)*Q(2)**(p.attention.fo-p.attention.fv+p.attention.drop)) for t in total]
        if any(not -32768<=x<=32767 for x in output): raise ValueError('Overflow')
        heads.append(dict(maximum=maximum, selected=selected, z=z, total=total, wide=output))
        wide += output
    scale,codes = convert(wide,p.attention.output_mode,p.attention.output_scale)
    return dict(query_scale=sq, heads=heads, wide=wide, scale=scale, codes=codes)


def config(heads=2, groups=1, width=2, n=8):
    att = a.Config(a.fn.Function('exp_q/nearest',1,bytes([15,7,4])),0,0,
                   'dynamic',0,'dynamic',0,'exact',0)
    return Params(heads,groups,width,0,'adjacent',8,8,'dynamic',0,'dynamic',0,
                  1,0,att,tuple(() for _ in range(n)))


def check():
    rng = random.Random(2628); digest = hashlib.sha256(); success = 0
    for case in range(10000):
        h = rng.choice((1,2,4)); g = rng.choice([v for v in (1,2,4) if h%v==0])
        d = rng.choice((2,4,6)); n = rng.randrange(1,6); p = config(h,g,d,n)
        rotary = rng.choice((0,2,d)); layout = rng.choice(('adjacent','split'))
        rotations = tuple(tuple(rng.choice(((16384,0),(0,16384),(9830,13107),(-16384,0)))
                                for _ in range(rotary//2)) for _ in range(n))
        mode = 'dynamic' if case%3 else 'static'; scale = 0 if mode=='dynamic' else rng.randrange(64,1025)
        function = a.fn.Function('exp_q/product' if case%2 else 'exp_q/nearest',1,
                                bytes([15,7,case%15])+(bytes([7]) if case%2 else b''))
        att = replace(p.attention,function=function,value_mode=mode,value_scale=scale)
        if case%2: att = replace(att,accumulation='block1024',drop=a.minimum_drop(att))
        p = replace(p,rotary=rotary,layout=layout,rotations=rotations,
                    fq=rng.randrange(8,16),fk=rng.randrange(8,16),
                    q_mode=mode,q_scale=scale,k_mode=mode,k_scale=scale,
                    score_m=rng.randrange(1,4),score_e=rng.randrange(-2,1),attention=att)
        keys = [[rng.randrange(-2000,2001) for _ in range(g*d)] for _ in range(n)]
        values = [[rng.randrange(-32768,32768) for _ in range(g*d)] for _ in range(n)]
        q = [rng.randrange(-2000,2001) for _ in range(h*d)]
        allowed = [bool(rng.randrange(2)) for _ in range(n)]; allowed[case%n] = True
        positions = list(range(n)); position = case%n
        assert rotate(p,position,q,p.heads) == rotation(p,position,q,p.heads)
        try: expected = oracle(p,position,q,positions,keys,values,allowed)
        except ValueError as error:
            reject(str(error),lambda: query(p,position,q,prepare(p,positions,keys,values),allowed))
            digest.update(b'reject'); continue
        cached = prepare(p,positions,keys,values)
        expected_keys = [convert(rotation(p,j,k,g),mode,scale) for j,k in zip(positions,keys)]
        assert cached.keys.scales == tuple(s for s,_ in expected_keys)
        assert cached.keys.codes == tuple(tuple(k) for _,k in expected_keys)
        actual = query(p,position,q,cached,allowed)
        assert actual == expected
        digest.update(json.dumps(actual,sort_keys=True,separators=(',',':')).encode()); success += 1
    # Whole projection scales and GQA views: per-head conversion would change codes.
    p = config(4,2); keys = [[127,0,254,0]]; values = [[127,0,254,0]]; q = [127,0,254,0,127,0,254,0]
    cached = prepare(p,[0],keys,values); result = query(p,0,q,cached,[True])
    assert cached.keys.scales == (2,) and cached.keys.codes == ((64,0,127,0),)
    assert result['wide'] == [128,0,128,0,254,0,254,0] and result['scale'] == 2
    assert result['codes'] == [64,0,64,0,127,0,127,0] and result['query_scale'] == 2
    # Full causal, prefix and evicted window use the same absolute block positions.
    cache_cases = 0
    for accumulation in ('exact','block1024'):
        p = config(4,2,n=1031); att = replace(p.attention,accumulation=accumulation,
                   drop=0 if accumulation=='exact' else a.minimum_drop(p.attention))
        p = replace(p,attention=att)
        keys = [[(j%11)*37,0,(j%7)*67,0] for j in range(1031)]
        values = [[(j%13)*173,0,-(j%17)*151,0] for j in range(1031)]
        full = prepare(p,list(range(1031)),keys,values); q = [64,0]*4
        for end in (0,1,1023,1024,1030):
            start = max(0,end-4); mask = [start<=j<=end for j in range(1031)]
            expected = oracle(p,end,q,list(range(1031)),keys,values,mask)
            assert query(p,end,q,full,mask) == expected
            prefix = prepare(p,list(range(end+1)),keys[:end+1],values[:end+1])
            evicted = prepare(p,list(range(start,end+1)),keys[start:end+1],values[start:end+1])
            assert query(p,end,q,prefix,mask[:end+1]) == expected
            assert query(p,end,q,evicted,[True]*(end-start+1)) == expected
            cache_cases += 1
    # Output conversion belongs after head assembly, including its rejection order.
    p = config(2,2,n=2); p = replace(p,attention=replace(p.attention,output_mode='static',output_scale=1))
    cached = prepare(p,[0,1],[[0,0,30000,0],[0,0,-30000,0]],[[1000,0,0,0]]*2)
    reject('Domain',lambda: query(p,0,[0,0,30000,0],cached,[True,True]))
    reject('Overflow',lambda: query(p,0,[0,0,0,0],cached,[True,True]))
    # Occupied absolute blocks cannot be bounded from cache row count alone.
    att = a.Config(a.fn.Function('exp_q/nearest',1,bytes([7,7,0])),0,0,
                   'static',1,'dynamic',0,'block1024',2)
    sparse = tuple(1024*j for j in range(1024)); values = a.prepare(att,[[127]]*1024)
    result = a.row(att,[0]*1024,[True]*1024,values,positions=sparse)
    assert result['total'] == [32768] and result['wide'] == [128]
    assert result['total'][0] > a.bounds(att,1024)['sum_max']
    assert result['total'][0] <= a.bounds(att,1024,position_span=sparse[-1]+1)['sum_max']
    reject('Shape',lambda: a.bounds(att,2,position_span=1))
    reject('Positions',lambda: a.row(att,[0]*1024,[True]*1024,values,positions=(0,)*1024))
    # A nonzero absolute attained index must survive eviction.
    assert a.row(att,[0],[True],a.prepare(att,[[1]]),positions=(1024,))['selected']==1024
    p = config(1,1,4); p = replace(p,rotary=4,rotations=tuple(((0,16384),)*2 for _ in range(8)))
    assert rotate(p,0,[1,2,3,4],1)==[-2,1,-4,3]
    assert rotate(replace(p,layout='split'),0,[1,2,3,4],1)==[-3,-4,1,2]
    p = config(1,1,3); p = replace(p,rotary=2,rotations=tuple(((0,16384),) for _ in range(8)))
    assert rotate(p,0,[1,2,300],1)==[-2,1,300]
    p = config(1,1,2); p = replace(p,rotary=2,rotations=tuple(((8192,0),) for _ in range(8)))
    assert rotate(p,0,[-1,1],1)==[-1,1]
    # Legal position syntax does not authenticate the cached rotation/source relation.
    p = config(1,1,2,n=2); p = replace(p,rotary=2,rotations=(((16384,0),),((0,16384),)))
    original = prepare(p,[0],[[127,0]],[[1,0]])
    substituted = replace(original,positions=(1,))
    honest = prepare(p,[1],[[127,0]],[[1,0]])
    assert query(p,1,[127,0],substituted,[True])['heads'][0]['maximum']==0
    assert query(p,1,[127,0],honest,[True])['heads'][0]['maximum']==32
    p = config(); cached = prepare(p,[0],[[1,2]],[[3,4]])
    reject('CacheScope',lambda: query(replace(p,score_e=-1),0,[1,2,3,4],cached,[True]))
    reject('Positions',lambda: prepare(p,[1,1],[[1,2]]*2,[[3,4]]*2))
    reject('Position',lambda: query(p,8,[1,2,3,4],cached,[True]))
    reject('Shape',lambda: prepare(p,[0],[[1]],[[3,4]]))
    reject('Mask',lambda: query(p,0,[1,2,3,4],cached,[1]))
    reject('EmptyRow',lambda: query(p,0,[1,2,3,4],cached,[False]))
    reject('ScoreBound',lambda: replace(p,fq=0,fk=0))
    reject('Heads',lambda: replace(p,heads=3,groups=2))
    p = replace(p,rotary=2,rotations=tuple(((16384,16384),) for _ in range(8)))
    reject('Overflow',lambda: prepare(p,[0],[[32767,32767]],[[0,0]]))
    print(json.dumps(dict(seed=2628,cases=10000,accepted=success,rejected=10000-success,
                         cache_cases=cache_cases,sha256=digest.hexdigest()),sort_keys=True))
    print('Candidate only: supplied rotation tables, no native forward/proof/fidelity admission.')


if __name__ == '__main__': check()
