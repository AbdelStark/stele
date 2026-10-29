# /// script
# requires-python = ">=3.12"
# dependencies = ["python-flint==0.9.0", "blake3==1.0.11"]
# ///
"""Q26: exact rotary coefficients against independent Arb real intervals."""
from dataclasses import replace
from fractions import Fraction as Q
import hashlib
import json
import random
import struct
from flint import arb, ctx
import rope


def reject(reason, f):
    try: f()
    except ValueError as e: assert str(e)==reason,(reason,str(e))
    else: raise AssertionError('accepted '+reason)


def nearest(x):
    lo = x.numerator//x.denominator
    return min((lo,lo+1),key=lambda v:(abs(x-v),-abs(v)))


def real(q): return arb(q.numerator)/q.denominator


def oracle(p,position,j,minimum=256):
    for precision in (minimum,2*minimum,4*minimum):
        with ctx.workprec(precision):
            frequency = (real(p.base).log()*(-arb(2*j)/p.width)).exp()
            if p.mode == 'linear': frequency /= real(p.factor)
            if p.mode == 'llama3':
                wavelength = 2*arb.pi()/frequency
                if wavelength > p.original/real(p.low): frequency /= real(p.factor)
                elif wavelength < p.original/real(p.high): pass
                elif wavelength <= p.original/real(p.low) and wavelength >= p.original/real(p.high):
                    blend = (p.original/wavelength-real(p.low))/real(p.high-p.low)
                    frequency *= (1-blend)/real(p.factor)+blend
                else: continue
            s,c = (position*frequency).sin_cos()
            result = []
            for v in (c,s):
                lo,hi = Q(str(v.lower().fmpq())),Q(str(v.upper().fmpq()))
                a,b = nearest(lo*16384),nearest(hi*16384)
                if a!=b: break
                result.append((a,lo,hi))
            if len(result)==2: return result
    raise AssertionError('oracle precision')


def check():
    rng = random.Random(2629); digest = hashlib.sha256(); precisions = {}
    base = rope.Parameters(128,1 << 20,Q(500000),'base','adjacent')
    for case in range(10000):
        width = rng.choice((2,6,32,64,80,128,256,1024))
        if case%100 == 0: width = rng.choice((8192,16384))
        mode = ('base','linear','llama3')[case%3]
        p = rope.Parameters(width,1 << 20,rng.choice((Q(10000),Q(500000),Q(3,2),Q(1))),mode,
                            'adjacent' if case%2 else 'split',Q(1) if mode=='base' else Q(8),
                            Q(1) if mode=='llama3' else Q(0),Q(4) if mode=='llama3' else Q(0),
                            8192 if mode=='llama3' else 0)
        position = rng.randrange(p.length); j = rng.randrange(width//2)
        if case%127==0: position=0
        cert = rope.certify(p,position,j); expected = oracle(p,position,j)
        assert (cert['cos'],cert['sin']) == tuple(v[0] for v in expected)
        unit = 1 << cert['bits']
        for name,(_,low,high) in zip(('cos','sin'),expected):
            a,b = cert[name+'_interval']
            assert Q(a,unit)<=low<=high<=Q(b,unit)
            assert abs(Q(cert[name],16384)-low)<=Q(1,32768) and abs(Q(cert[name],16384)-high)<=Q(1,32768)
        precisions[cert['bits']]=precisions.get(cert['bits'],0)+1
        digest.update(rope.encode(p)+struct.pack('<IHHhh',position,width,j,cert['cos'],cert['sin']))
    # Complete finite table and canonical descriptor/data checks.
    p = replace(base,width=8,length=33,mode='llama3',factor=Q(8),low=Q(1),high=Q(4),original=8192)
    raw = rope.generate(p); expected = b''.join(struct.pack('<hh',*(v[0] for v in oracle(p,i,j)))
                                               for i in range(p.length) for j in range(p.width//2))
    assert raw==expected and len(raw)==4*p.length*(p.width//2)
    rope.verify_table(p,raw); assert rope.decode(rope.encode(p))==p
    assert rope.identity(replace(p,layout='split'))!=rope.identity(p)
    assert rope.generate(replace(p,layout='split'))==raw
    changed=bytearray(raw);changed[0]^=1
    reject('Table',lambda:rope.verify_table(p,bytes(changed)))
    reject('Descriptor',lambda:rope.decode(rope.encode(p)+b'\0'))
    reject('Descriptor',lambda:rope.decode(rope.encode(p)[:-1]))
    reject('Identity',lambda:rope.verify_expected(replace(p,base=Q(10000)),rope.encode(p)))
    # A nonreduced rational is not a second encoding of the same parameters.
    encoded=bytearray(rope.encode(p));offset=len(rope.TAG)+12
    encoded[offset:offset+16]=struct.pack('<QQ',1000000,2)
    reject('Descriptor',lambda:rope.decode(bytes(encoded)))
    cert=rope.certify(p,1,1);changed=dict(cert);changed['cos']+=1
    reject('Certificate',lambda:rope.verify_entry(p,1,1,changed))
    changed=dict(cert);changed['bits']=True
    reject('Certificate',lambda:rope.verify_entry(p,1,1,changed))
    reject('Position',lambda:rope.certify(p,p.length,0))
    reject('Pair',lambda:rope.certify(p,0,p.width//2))
    reject('Parameters',lambda:replace(p,width=3))
    reject('Parameters',lambda:replace(p,base=Q(0)))
    reject('Parameters',lambda:replace(p,low=p.high))
    reject('Parameters',lambda:replace(base,factor=Q(8)))
    reject('Parameters',lambda:replace(base,mode='ntk'))
    reject('Capacity',lambda:rope.generate(base))
    # All scaling regions, then adjacent bounded-denominator thresholds around 1/(2*pi).
    regions=set()
    with ctx.workprec(512):
        for j in range(64):
            ratio=8192*(arb(500000).log()*(-arb(2*j)/128)).exp()/(2*arb.pi())
            regions.add('low' if ratio<1 else 'high' if ratio>4 else 'blend')
        assert regions=={'low','blend','high'}
        target=1/(2*arb.pi());middle=Q(str(target.mid().fmpq()));left,right=Q(0),Q(1)
        while left.denominator+right.denominator < 1 << 64:
            mediant=Q(left.numerator+right.numerator,left.denominator+right.denominator)
            if mediant<middle:left=mediant
            else:right=mediant
        assert real(left)<target<real(right)
    difficult=rope.Parameters(2,1 << 20,Q(1),'llama3','adjacent',Q(8),left,right,1)
    refined=rope.certify(difficult,(1 << 20)-1,0)
    assert refined['bits']>128
    for bits in (128,256,512):
        enclosure=rope.enclosure(difficult,(1 << 20)-1,0,bits)
        for pair,(_,lo,hi) in zip(enclosure,oracle(difficult,(1 << 20)-1,0,minimum=bits+256)):
            assert Q(pair[0],1 << bits)<=lo<=hi<=Q(pair[1],1 << bits)
    assert (refined['cos'],refined['sin'])==tuple(v[0] for v in oracle(difficult,(1 << 20)-1,0))
    endpoint=replace(base,width=16384,base=Q((1 << 64)-1,(1 << 64)-2))
    cert=rope.certify(endpoint,(1 << 20)-1,8191)
    assert (cert['cos'],cert['sin'])==tuple(v[0] for v in oracle(endpoint,(1 << 20)-1,8191))
    for i in range(len(rope.encode(p))):
        changed=bytearray(rope.encode(p));changed[i]^=1
        try:rope.verify_expected(p,bytes(changed))
        except ValueError as e:assert str(e) in ('Descriptor','Identity')
        else:raise AssertionError('descriptor mutation accepted')
    reject('Precision',lambda:rope.frequency(base,0,1024))
    rope.frequency(base,1,128)  # Populate the integer key before testing a bool alias.
    reject('Pair',lambda:rope.frequency(base,True,128))
    reject('Parameters',lambda:replace(base,length=True))
    # Frequencies must not be quantised to Q14 before multiplying by position.
    p=replace(base,width=4,base=Q(10000));position=100000;j=1
    rounded_frequency=Q(nearest(Q(1,100)*16384),16384)
    with ctx.workprec(256):
        s,c=(position*real(rounded_frequency)).sin_cos()
        premature=tuple(nearest(Q(str(v.mid().fmpq()))*16384) for v in (c,s))
    cert=rope.certify(p,position,j)
    assert premature!=(cert['cos'],cert['sin'])
    # Feed generated coefficients to the actual projected-attention candidate.
    import projected_attention as pa
    ap=pa.a.Config(pa.a.fn.Function('exp_q/nearest',1,bytes([15,7,4])),0,0,'dynamic',0,'dynamic',0,'exact',0)
    rp=rope.Parameters(4,6,Q(500000),'llama3','split',Q(8),Q(1),Q(4),8192)
    data=rope.generate(rp);pairs=list(struct.iter_unpack('<hh',data))
    rotations=tuple(tuple(pairs[2*i:2*i+2]) for i in range(6))
    pp=pa.Params(2,1,4,4,'split',8,8,'dynamic',0,'dynamic',0,1,0,ap,rotations)
    keys=[[37*i,-19*i,11*i,5*i] for i in range(6)];values=[[173*i,-11*i,19*i,7*i] for i in range(6)]
    full=pa.prepare(pp,list(range(6)),keys,values)
    for end in range(6):
        q=[31,-19,27,5]*2;mask=[j<=end for j in range(6)]
        assert pa.query(pp,end,q,full,mask)==pa.query(pp,end,q,pa.prepare(pp,list(range(end+1)),keys[:end+1],values[:end+1]),mask[:end+1])
    print(json.dumps(dict(seed=2629,cases=10000,precision_counts=precisions,table_pairs=132,
                         composed_prefixes=6,refined_bits=refined['bits'],scaling_regions=sorted(regions),
                         premature_pair=premature,correct_pair=(cert['cos'],cert['sin']),sha256=digest.hexdigest()),sort_keys=True))
    print('Research coefficients only: native registry/forward/proof consumers and fidelity remain open.')


if __name__=='__main__':check()
