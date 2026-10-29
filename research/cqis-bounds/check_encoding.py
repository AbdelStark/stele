# /// script
# requires-python = ">=3.12"
# dependencies = ["numpy==2.3.4"]
# ///
"""Q26: closed static record framing, independent bounds and exact mutations."""
from dataclasses import replace
import hashlib
import json
from math import gcd
from pathlib import Path
from random import Random
import struct
import sys
import encoding as e
import limbs
import requant as q
import norm_bounds as n
from check_limbs import oracle, rejects


def expected(p):
    """Independent scalar/role derivation; no candidate constants or column_specs."""
    if type(p) is q.Spec:
        v,h,d = 2**31,2**(p.bits-1),2**p.shift
        bias = d//2 if p.shift else 0
        a = v*p.mantissa
        limit = min(h,(a+bias)//d)
        scalars = [d,bias,a,limit,h,4*h-1,2*h]
        roles = [(2,2**32-1,2),(2,v,1),(1,v,p.mantissa),
                 (2,max(a,bias),1),(1,limit,d),(2,max(limit*d,d-1),1)]
        return 1,struct.pack('<HBB',p.mantissa,p.shift,p.bits),scalars,[],roles
    unit,stat = p.d*4**p.F,p.d*2**30
    numerator,denominator = p.ed*stat+p.en*unit,p.ed*unit
    low,high = p.F+p.G-2-p.E,p.F+p.G+30-p.E
    divisor,bias,left = 2**max(0,high),2**(high-1) if high>0 else 0,2**max(0,-low)
    dmax = denominator*4**9
    scalars = [unit,stat,numerator,denominator,numerator*4**23,dmax,65535*dmax,
               divisor,bias,left,131071,65536]
    roles = [(p.d,32768,32768),(2,max(stat,unit),max(p.ed,p.en)),
             (1,numerator,4**23),(1,65535,dmax),(2,65535*dmax,1),
             (1,32768,32768),(1,2**30,16384),(2,max(2**44,bias),1),
             (1,32768,divisor),(2,32768*divisor,1),(1,2**44,left)]
    return 2,struct.pack('<HBBBII',p.d,p.F,p.G,p.E,p.en,p.ed),scalars,[low,high],roles


def inspect(p,raw):
    tag,params,scalars,shifts,roles = expected(p)
    cursor,fields,blocks = 0,[],[]
    def take(length):
        nonlocal cursor
        assert 0<=length<=len(raw)-cursor
        value = raw[cursor:cursor+length];cursor += length
        return value
    def integer(width,signed=False):
        fields.append((cursor,width,signed))
        return int.from_bytes(take(width),'little',signed=signed)
    assert len(raw)<=8192
    assert take(22)==b'stele/v0.1/cqis/bounds'
    assert integer(4)==1 and integer(1)==tag and integer(2)==len(params)
    assert take(len(params))==params
    assert integer(4)==2**31-1 and integer(1)==8
    assert integer(1)==len(scalars)
    assert [integer(20) for _ in scalars]==scalars
    assert integer(1)==len(shifts)
    assert [integer(2,True) for _ in shifts]==shifts
    assert integer(1)==len(roles)
    for index,(count,a,b) in enumerate(roles,1):
        start = cursor
        cert = oracle(limbs.Spec(count,a,b,8))
        assert 2*max(cert['lhs']+cert['rhs'])<2**31-1
        assert integer(1)==index and integer(4)==count
        assert [integer(20) for _ in range(3)]==[a,b,count*a*b]
        la,lb,k = [integer(1) for _ in range(3)]
        assert (la,lb,k)==tuple(len(cert[key]) for key in ('left_caps','right_caps','result_caps'))
        assert 1<=min(la,lb,k)<=max(la,lb,k)<=20
        for key,length in [('left_caps',la),('right_caps',lb),('result_caps',k)]:
            assert tuple(integer(1) for _ in range(length))==cert[key]
        for key,length in [('carry_caps',k+1),('lhs',k),('rhs',k)]:
            assert tuple(integer(4) for _ in range(length))==cert[key]
        assert cursor-start<=372
        blocks.append((start,cursor))
    assert cursor==len(raw)
    return fields,blocks


def rejects_changed_record(p,raw):
    assert e.validate(p,raw) is None
    fields,blocks = inspect(p,raw)
    for i in range(len(raw)):
        bad = bytearray(raw);bad[i] ^= 1
        rejects('Encoding',lambda: e.validate(p,bytes(bad)))
        rejects('Encoding',lambda: e.validate(p,raw[:i]))
    for bad in [raw+b'\0',b'\0'*8193,bytearray(raw),None]:
        rejects('Encoding',lambda: e.validate(p,bad))
    for offset,width,signed in fields:
        if width not in (4,20) or signed:
            continue
        value = int.from_bytes(raw[offset:offset+width],'little')+(2**31-1)
        if value<2**(8*width):
            bad = raw[:offset]+value.to_bytes(width,'little')+raw[offset+width:]
            rejects('Encoding',lambda: e.validate(p,bad))
    first,second = blocks[:2]
    bad = raw[:first[0]]+raw[second[0]:second[1]]+raw[first[0]:first[1]]+raw[second[1]:]
    rejects('Encoding',lambda: e.validate(p,bad))
    other = replace(p,mantissa=p.mantissa%65535+1) if type(p) is q.Spec else replace(p,E=(p.E+1)%15)
    rejects('Encoding',lambda: e.validate(other,raw))
    rejects('Encoding',lambda: e.validate(p,e.encode(other)))


def report():
    rng,checksum = Random(2612),hashlib.sha256()
    sizes = {1:[8192,0],2:[8192,0]}
    goldens = [q.Spec(1,0,8),q.Spec(65535,62,16),q.Spec(3,2,8),
               n.Spec(1,0,0,14,1,2**32-1),n.Spec(16384,30,30,14,2**32-1,2**32-2),
               n.Spec(3,8,14,8,1,100000)]
    for p in goldens:
        rejects_changed_record(p,e.encode(p))
    for bad in [q.Spec(0,0,8),q.Spec(65536,0,8),q.Spec(1,63,8),q.Spec(1,1,32),
                q.Spec(True,0,8),n.Spec(0,0,0,0,1,1),n.Spec(16385,0,0,0,1,1),
                n.Spec(1,31,0,0,1,1),n.Spec(1,0,0,0,2,2),n.Spec(1,0,0,0,0,1),{},None]:
        rejects('Spec',lambda: e.encode(bad))
    for bad in [-1,2**160,True]:
        rejects('Capacity',lambda: e.unsigned(bad,20))
    for width in [0,21,2**31,True]:
        rejects('Capacity',lambda: e.unsigned(0,width))
    for i in range(10000):
        a,b = rng.randrange(1,2**32),rng.randrange(1,2**32)
        g = gcd(a,b)
        specs = [q.Spec(rng.randrange(1,65536),rng.randrange(63),(8,16)[i%2]),
                 n.Spec(rng.randrange(1,16385),rng.randrange(31),rng.randrange(31),rng.randrange(15),a//g,b//g)]
        for kind,p in enumerate(specs,1):
            raw = e.encode(p)
            inspect(p,raw)
            assert e.validate(p,raw) is None
            sizes[kind] = [min(sizes[kind][0],len(raw)),max(sizes[kind][1],len(raw))]
            checksum.update(struct.pack('<I',len(raw))+raw)
    assert 22+4+1+2+13+4+1+1+12*20+1+2*2+1+11*372==4386<8192
    return dict(cases=20000,seed=2612,capacity=8192,length_bounds=sizes,sha256=checksum.hexdigest(),
                goldens=[dict(schema=expected(p)[0],parameters=expected(p)[1].hex(),bytes=e.encode(p).hex()) for p in goldens])


if __name__=='__main__':
    value = report()
    path = Path(__file__).with_name('encoding.json')
    if sys.argv[1:]==['--write']:
        with path.open('x') as output:
            json.dump(value,output,indent=2);output.write('\n')
    else:
        assert not sys.argv[1:] and json.loads(path.read_text())==json.loads(json.dumps(value))
    print(json.dumps({k:v for k,v in value.items() if k!='goldens'},sort_keys=True))
