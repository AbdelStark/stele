# /// script
# requires-python = ">=3.12"
# dependencies = ["numpy==2.3.4", "blake3==1.0.11", "python-flint==0.9.0"]
# ///
"""Q26 complete block composition: independent integer/Fraction arithmetic."""
from dataclasses import asdict, replace
from fractions import Fraction as Q
import hashlib
import json
import random
import numpy as np
import decoder_block as d
import rope
from check_projected_attention import oracle as attention_oracle
from check_attention import rounded, reject
from check_rmsnorm import reference as norm_oracle


def quantized(xs, fraction, policy):
    mode, parameter = policy
    maximum = max(abs(x) for x in xs)
    scale = -(-maximum//127) if mode == 'dynamic' else parameter
    codes = [rounded(Q(x, scale)) for x in xs] if scale else [0]*len(xs)
    if any(abs(x)>127 for x in codes): raise ValueError('Overflow')
    return d.Row(tuple(codes), scale, fraction)


def linear(w, x, fraction):
    dots = np.asarray(w.codes, dtype=np.int64) @ np.asarray(x.codes, dtype=np.int64)
    ys = [rounded(Q(int(v)*m*x.scale)*Q(2)**(w.exponent-x.fraction+fraction))
          for v,m in zip(dots,w.mantissas)]
    if any(not -32768<=v<=32767 for v in ys): raise ValueError('Overflow')
    return ys


def norm(p, xs, gs):
    ys = norm_oracle(p, xs, list(gs))[3]
    if any(not -32768<=v<=32767 for v in ys): raise ValueError('Overflow')
    return ys


def residual(xs, fx, ys, fy, fo):
    out = [rounded((Q(x)*Q(2)**-fx+Q(y)*Q(2)**-fy)*Q(2)**fo) for x,y in zip(xs,ys)]
    if any(not -32768<=v<=32767 for v in out): raise ValueError('Overflow')
    return out


def reference(p, xs, positions):
    wq,wk,wv,wo,wu,wg,wd = p.weights
    records = []
    for row in xs:
        x1 = quantized(norm(p.norm1,row,p.gains1),p.norm1.E,p.first)
        records.append(dict(x1=x1,q=linear(wq,x1,p.attention.fq),
                            k=linear(wk,x1,p.attention.fk),v=linear(wv,x1,p.attention.attention.fv)))
    for pos,row,r in zip(positions,xs,records):
        r['attention'] = attention_oracle(p.attention,pos,r['q'],positions,
            [v['k'] for v in records],[v['v'] for v in records],[j<=pos for j in positions])
        at = r['attention']; x = d.Row(tuple(at['codes']),at['scale'],p.attention.attention.fo)
        r['o'] = linear(wo,x,p.fo)
        r['mid'] = residual(row,p.norm1.F,r['o'],p.fo,p.norm2.F)
        r['x2'] = quantized(norm(p.norm2,r['mid'],p.gains2),p.norm2.E,p.second)
        r['up'] = linear(wu,r['x2'],p.fu); r['gate'] = linear(wg,r['x2'],p.silu.params[0])
        # Shared certified table primitive; this tests composition, not transcendental independence.
        r['silu'] = [d.activation.certify(d.activation.Parameters('silu',*p.silu.params),v)['value'] for v in r['gate']]
        r['product'] = [x*y for x,y in zip(r['up'],r['silu'])]
        r['h'] = quantized(r['product'],p.fu+p.silu.params[1],p.gated)
        r['down'] = linear(wd,r['h'],p.fd)
        r['output'] = residual(r['mid'],p.norm2.F,r['down'],p.fd,p.fout)
    return records


def configuration(rng, case, length=4):
    heads = 1+case%2; groups = 1 if case%3 else heads; width = 2; dim = heads*width; hidden = 3+case%4
    att = d.pa.a.Config(d.pa.a.fn.Function('exp_q/nearest',1,bytes([15,7,8])),8,8,
                       'dynamic',0,'dynamic',0,'exact',0)
    if case%2: att = replace(att,accumulation='block1024',drop=d.pa.a.minimum_drop(att))
    rotation = rope.Parameters(width,length,Q(10000),layout='split' if case%2 else 'adjacent')
    rotations = tuple(tuple((v['cos'],v['sin']) for v in [rope.certify(rotation,t,j)
                      for j in range(width//2)]) for t in range(length))
    ap = d.pa.Params(heads,groups,width,width,rotation.layout,8,8,'dynamic',0,'dynamic',0,1,0,att,rotations)
    shapes = [(dim,dim),(groups*width,dim),(groups*width,dim),(dim,dim),
              (hidden,dim),(hidden,dim),(dim,hidden)]
    weights = []
    for i,(n,k) in enumerate(shapes):
        bits = 4 if (case+i)%2 else 8
        spec = d.records.Spec('w'+str(i),'binary32',(n,k),bits,0)
        values = [rng.randrange(-7,8) for _ in range(n*k)]
        raw = d.records.encode(spec,-14,[rng.randrange(800,1601) for _ in range(n)],values)
        weights.append(d.from_record(spec,raw))
    norm1 = d.norm.Parameters(dim,8,8,8,1,100000)
    return d.Params(norm1,norm1,tuple([256]*dim),tuple([256]*dim),tuple(weights),ap,
                    d.pa.a.fn.Function('silu_q',1,bytes([8,8])),8,8,8,8,
                    ('dynamic',0),('static',4) if case%4==0 else ('dynamic',0),('dynamic',0))


def check():
    rng = random.Random(2630); digest = hashlib.sha256(); accepted = rejected = cache_cases = 0
    base = configuration(random.Random(2630),0)
    reject('Overflow',lambda: replace(base,silu=d.pa.a.fn.Function('silu_q',1,bytes([0,1]))))
    for f in range(31):
        for e in range(15):
            function = d.pa.a.fn.Function('silu_q',1,bytes([f,e]))
            if e>f:
                reject('Overflow',lambda: d.activation.certify(d.activation.Parameters('silu',f,e),32767))
                reject('Overflow',lambda: replace(base,silu=function))
            else:
                assert replace(base,silu=function).silu==function
                assert -32768<=d.activation.certify(d.activation.Parameters('silu',f,e),32767)['value']<=32767
    for case in range(10000):
        p = configuration(rng,case); n = 1+case%3; positions = list(range(n))
        p = replace(p,norm1=replace(p.norm1,F=6+case%5,E=6+(case//5)%5),
                    norm2=replace(p.norm2,F=7+case%5,E=6+(case//7)%5),
                    fu=5+case%8,fo=6+(case//3)%5,fd=6+(case//9)%5,
                    fout=20 if case%17==0 else 6+(case//11)%7,
                    silu=d.pa.a.fn.Function('silu_q',1,bytes([6+case%7,min(6+case%7,4+(case//13)%7)])),
                    gated=('static',1) if case%41==0 else p.gated)
        ap = p.attention
        p = replace(p,attention=replace(ap,fq=6+case%5,fk=6+(case//2)%5,
                    attention=replace(ap.attention,fv=6+case%5,fo=6+(case//7)%5)))
        rows = [[rng.randrange(-900,901) for _ in range(p.norm1.d)] for _ in positions]
        try: expected = reference(p,rows,positions)
        except ValueError as error:
            reject(str(error),lambda: d.full(p,rows,positions)); rejected += 1; digest.update(b'reject'); continue
        actual = d.full(p,rows,positions); assert actual['rows']==expected
        cache = None
        for row,pos,want in zip(rows,positions,expected):
            one,cache = d.step(p,row,pos,cache); assert one==want
        assert cache == actual['cache']; cache_cases += 1
        digest.update(json.dumps([{k:asdict(v) if isinstance(v,d.Row) else v
                       for k,v in r.items()} for r in expected],sort_keys=True,separators=(',',':')).encode())
        accepted += 1
    assert (accepted,rejected,cache_cases)==(8058,1942,8058)
    assert digest.hexdigest()=='bdce1edd1a5b7e216a53c49276e66d3c82162a71d99e64dc568a7754e46f836a'
    # The gate product is exact int32; int16 conversion cannot represent this row.
    product = [32767*32767,-32768*32767,1 << 30,0]
    h = d.quantize(product,44,('dynamic',0),product=True)
    assert h==quantized(product,44,('dynamic',0)) and h.scale>65535
    reject('Domain',lambda: d.quantize(product,44,('dynamic',0)))
    reject('Overflow',lambda: d.quantize(product,44,('static',1),product=True))
    # The combined exact numerator exceeds int64 even though the final int16 fits.
    w = d.Matrix(8,-64,(65535,),((127,)*16384,)); x = d.Row((127,)*16384,h.scale,0)
    assert 16384*127**2*65535*h.scale > 1 << 63
    assert d.linear(w,x,0)==linear(w,x,0)
    reject('Overflow',lambda: d.linear(replace(w,exponent=0),x,0))
    reject('Row',lambda: d.Row((True,),1,0))
    reject('ZeroScale',lambda: d.Row((1,),0,0))
    reject('Shape',lambda: d.full(p,[[1]], [0]))
    reject('Positions',lambda: d.full(p,[rows[0],rows[0]],[0,0]))
    reject('Weights',lambda: replace(p,weights=p.weights[:-1]))
    reject('Function',lambda: replace(p,silu=d.pa.a.fn.Function('sigmoid_q',1,bytes([8,8]))))
    reject('Shape',lambda: replace(p,gains1=p.gains1[:-1]))
    # Whole-block scope and failure atomicity: a different down projection invalidates the old cache.
    p = configuration(rng,12); rows = [[100,-200],[300,200]]
    first,cache = d.step(p,rows[0],0,None); saved = cache
    changed = replace(p,weights=p.weights[:-1]+(replace(p.weights[-1],exponent=1024),))
    reject('CacheScope',lambda: d.step(changed,rows[1],1,cache))
    reject('Positions',lambda: d.step(p,rows[1],0,cache))
    reject('Overflow',lambda: d.step(replace(p,fout=30),rows[0],0,None))
    assert cache==saved
    failing = replace(p,gated=('static',1))
    _,stable = d.step(failing,[0,0],0,None)
    reject('Overflow',lambda: d.step(failing,rows[1],1,stable))
    zero,next_cache = d.step(failing,[0,0],1,stable)
    assert zero['output']==[0,0] and stable.attention.positions==(0,) and next_cache.attention.positions==(0,1)
    # Every matrix and unit remains part of local scope, even if shapes agree.
    for i in range(7):
        weights = list(p.weights); weights[i] = replace(weights[i],exponent=weights[i].exponent+1)
        reject('CacheScope',lambda: d.step(replace(p,weights=tuple(weights)),rows[1],1,cache))
    reject('CacheScope',lambda: d.step(replace(p,fu=p.fu+1),rows[1],1,cache))
    reject('Units',lambda: replace(p,fout=True))
    reject('Code',lambda: d.Matrix(4,0,(1,),((-8,),)))
    reject('ZeroScale',lambda: d.Row((1,),0,0))
    assert d.linear(d.Matrix(8,1024,(65535,),((127,),)),d.Row((0,),0,44),30)==[0]
    # Compose two complete blocks; caches remain per layer and preserve causal equality.
    for mode in ('exact','block1024'):
        p = configuration(rng,1,length=1026)
        att = replace(p.attention.attention,accumulation=mode,
                      drop=0 if mode=='exact' else d.pa.a.minimum_drop(p.attention.attention))
        p = replace(p,attention=replace(p.attention,attention=att))
        pos = [0,1023,1024,1025]; rows = [[rng.randrange(-500,501) for _ in range(p.norm1.d)] for _ in pos]
        one = d.full(p,rows,pos); two = d.full(p,[r['output'] for r in one['rows']],pos)
        assert one['rows']==reference(p,rows,pos)
        assert two['rows']==reference(p,[r['output'] for r in one['rows']],pos)
        c1 = c2 = None
        for row,j,want in zip(rows,pos,two['rows']):
            r,c1 = d.step(p,row,j,c1); r,c2 = d.step(p,r['output'],j,c2); assert r==want
        assert c1==one['cache'] and c2==two['cache']
    print(json.dumps(dict(seed=2630,accepted=accepted,rejected=rejected,cache_cases=cache_cases,
                          sha256=digest.hexdigest()),sort_keys=True))


if __name__ == '__main__': check()
