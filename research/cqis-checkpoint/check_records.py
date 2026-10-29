# /// script
# requires-python = ">=3.12"
# dependencies = ["numpy==2.3.4"]
# ///
"""Q26 physical record evidence; no checkpoint/PCS acceptance or NC credit."""
from dataclasses import replace
from fractions import Fraction as Q
import hashlib
import itertools
import json
from pathlib import Path
import random
import struct
import sys
import numpy as np
import records as r
from scalars import FORMATS, decode
from check_scalars import rejects, value, encode_exact
from check_quantiser import nearest, reference
from check_alignment import numpy_shift


def independent(spec, raw):
    """Cartesian indexing and struct packing, independent of candidate strides/codec."""
    width = FORMATS[spec.source][0]
    pairs = [decode(spec.source,raw[i:i+width]) for i in range(0,len(raw),width)]
    source = [value(pair) for pair in pairs]
    if spec.bits == 16:
        result = [nearest(x*2**spec.parameter) for x in source]
        n,e = np.array(pairs,dtype=np.int64).T
        ny,ok = numpy_shift(n,-e-spec.parameter)
        assert list(map(bool,ok)) == [-32768 <= x <= 32767 for x in result]
        assert all(int(y) == x for y,x,valid in zip(ny,result,ok) if valid)
        if not all(-32768 <= x <= 32767 for x in result):
            return None
        exponent,mantissas = None,[]
    else:
        coordinates = list(itertools.product(*(range(d) for d in spec.shape)))
        groups = [[x for pos,x in zip(coordinates,source) if pos[spec.parameter] == j]
                  for j in range(spec.shape[spec.parameter])]
        out = reference(groups,spec.bits)
        exponent,mantissas = out['exponent'],out['mantissas']
        result = [nearest(x/(mantissas[pos[spec.parameter]]*Q(2)**exponent))
                  for pos,x in zip(coordinates,source)]
    name = spec.name.encode('ascii')
    config = (r.CONFIG+struct.pack('<H',len(name))+name+
              struct.pack('<BB',tuple(FORMATS).index(spec.source)+1,len(spec.shape))+
              b''.join(struct.pack('<I',d) for d in spec.shape)+
              struct.pack('<BB',spec.bits,spec.parameter))
    payload = bytearray()
    if spec.bits == 4:
        for i in range(0,len(result),2):
            lo = result[i]%16
            hi = result[i+1]%16 if i+1 < len(result) else 0
            payload.append(lo+16*hi)
    else:
        payload.extend(struct.pack('<' + ('b' if spec.bits == 8 else 'h')*len(result),*result))
    scales = b'' if spec.bits == 16 else struct.pack('<h',exponent)+b''.join(struct.pack('<H',m) for m in mantissas)
    encoded = r.DATA+struct.pack('<I',len(config))+config+scales+struct.pack('<Q',len(payload))+payload
    return encoded,dict(exponent=exponent,mantissas=mantissas,values=result)


def report():
    rng,checksum = random.Random(2604),hashlib.sha256()
    counts,examples = [],[]
    for bits in (4,8,16):
        success,overflow = 0,0
        for case in range(10000):
            shape = tuple(rng.randrange(1,4) for _ in range(rng.randrange(1,4)))
            source = tuple(FORMATS)[case%4]
            parameter = rng.randrange(31) if bits == 16 else rng.randrange(len(shape))
            spec = r.Spec('layer.'+str(case%11),source,shape,bits,parameter)
            size,eb,fb = FORMATS[source]
            words = []
            for _ in range(r.count(spec)):
                word = rng.getrandbits(size*8)
                if (word >> fb) & ((1 << eb)-1) == (1 << eb)-1:
                    word ^= 1 << fb  # Finite, retaining sign and significand.
                words.append(word)
            if case%100 == 0: words = [0]*len(words)
            raw = b''.join(word.to_bytes(size,'little') for word in words)
            expected = independent(spec,raw)
            checksum.update(r.config(spec)+raw)
            if expected is None:
                rejects('Overflow',lambda: r.prepare(spec,raw)); overflow += 1
                checksum.update(b'overflow')
            else:
                encoded,parsed = expected
                actual = r.prepare(spec,raw)
                assert actual == encoded
                assert r.parse(spec,actual) == parsed
                assert r.encode(spec,**parsed) == actual
                checksum.update(actual); success += 1
                if case == 0: examples.append(dict(bits=bits,config=r.config(spec).hex(),record=actual.hex()))
        counts.append(dict(bits=bits,tensors=10000,accepted=success,overflow=overflow))
    spec = r.Spec('w','binary16',(1,3),4,0)
    # Exact hand vector: config + e=-17, m=56174 + payload [2,5,7].
    raw = bytes.fromhex('003c00400042')  # 1,2,3 in binary16.
    encoded = r.prepare(spec,raw)
    assert r.parse(spec,encoded) == dict(exponent=-17,mantissas=[56174],values=[2,5,7])
    assert encoded[-2:] == bytes.fromhex('5207')
    offset = len(r.DATA)+4+len(r.config(spec))
    mutations = [(0,encoded[0]^1,'Prefix'),
                 (len(r.DATA),encoded[len(r.DATA)]+1,'Config'),
                 (offset+1,0x7f,'Exponent'),
                 (len(encoded)-1,0x17,'Padding'),
                 (len(encoded)-2,0x58,'Range')]
    for index,byte,reason in mutations:
        changed = bytearray(encoded); changed[index] = byte
        rejects(reason,lambda: r.parse(spec,bytes(changed)))
    changed = bytearray(encoded); changed[offset:offset+2] = (1025).to_bytes(2,'little',signed=True)
    rejects('Exponent',lambda: r.parse(spec,bytes(changed)))
    changed = bytearray(encoded); changed[offset+2:offset+4] = b'\0\0'
    rejects('Scale',lambda: r.parse(spec,bytes(changed)))
    changed = bytearray(encoded); changed[offset+4:offset+12] = (3).to_bytes(8,'little')
    rejects('PayloadLength',lambda: r.parse(spec,bytes(changed)))
    for k in range(len(encoded)):
        rejects('Truncated',lambda: r.parse(spec,encoded[:k]))
    rejects('Trailing',lambda: r.parse(spec,encoded+b'\0'))
    for other in (replace(spec,name='v'),replace(spec,source='bfloat16'),
                  replace(spec,shape=(3,1)),replace(spec,parameter=1),replace(spec,bits=8)):
        rejects('Config',lambda: r.parse(other,encoded))
    for bad,reason in [(replace(spec,name=''),'Name'),(replace(spec,name='é'),'Name'),
                       (replace(spec,source='float'),'Source'),(replace(spec,shape=()),'Shape'),
                       (replace(spec,shape=(True,)),'Shape'),(replace(spec,shape=(1<<32,)),'Shape'),
                       (replace(spec,shape=((1<<32)-1,)*3),'Capacity'),
                       (replace(spec,shape=((1<<32)-1,)*2),'Capacity'),
                       (replace(spec,shape=(1,)*256),'Shape'),(replace(spec,bits=True),'Format'),
                       (replace(spec,parameter=2),'Parameter')]:
        rejects(reason,lambda: r.config(bad))
    # Huge legal shapes reject source size without allocating their tensor storage.
    rejects('SourceLength',lambda: r.prepare(replace(spec,shape=((1<<32)-1,1)),b''))
    rejects('SourceLength',lambda: r.prepare(spec,raw+b'\0'))
    rejects('SourceLength',lambda: r.prepare(spec,bytearray(raw)))
    for source,(size,eb,fb) in FORMATS.items():
        bad = (((1<<eb)-1)<<fb).to_bytes(size,'little')
        rejects('Nonfinite',lambda: r.prepare(r.Spec('g',source,(1,),16,0),bad))
    # A valid one-value mutation stays a different record: parsing is not source binding.
    changed = encoded[:-2]+bytes.fromhex('5107')
    assert r.parse(spec,changed)['values'] == [1,5,7] and changed != r.prepare(spec,raw)
    # int4 packing is continuous across row/channel boundaries, not row-padded.
    matrix = r.Spec('w','binary16',(2,3),4,0)
    packed = r.encode(matrix,-1,[1,2],[1,2,3,4,5,6])
    assert packed[-3:] == bytes.fromhex('214365')
    gain = r.Spec('g','binary16',(3,),16,0)
    assert r.parse(gain,r.prepare(gain,bytes.fromhex('003800b80000')))['values'] == [1,-1,0]
    for bits in (4,8):
        rejects('Range',lambda: r.encode(replace(spec,bits=bits),0,[1],[-(1<<(bits-1)),0,0]))
    rejects('Format',lambda: r.encode(spec,0,[1],[True,0,0]))
    rejects('Scale',lambda: r.encode(spec,0,[True],[0,0,0]))
    rejects('Scale',lambda: r.encode(gain,0,[],[0,0,0]))
    rejects('Bytes',lambda: r.parse(spec,bytearray(encoded)))
    large = replace(spec,shape=((1<<32)-1,1))
    header = r.DATA+len(r.config(large)).to_bytes(4,'little')+r.config(large)+b'\0\0'
    rejects('Truncated',lambda: r.parse(large,header))
    for nibble in range(1,16):
        rejects('Padding',lambda: r.parse(spec,encoded[:-1]+bytes([7+16*nibble])))
    maximum_rank = r.Spec('w','binary16',(1,)*255,4,254)
    assert r.parse(maximum_rank,r.prepare(maximum_rank,b'\0\0'))['values'] == [0]
    byte_spec = replace(spec,bits=8)
    byte_record = r.encode(byte_spec,0,[1],[0,0,0])
    rejects('Range',lambda: r.parse(byte_spec,byte_record[:-1]+b'\x80'))
    for fractional in (0,15,30):
        single = r.Spec('g','binary64',(1,),16,fractional)
        for numerator in (-65537,-65536,-65535,-1,0,1,65533,65534,65535):
            x = Q(numerator,2)*Q(2)**-fractional
            source = encode_exact('binary64',x)
            y = nearest(x*2**fractional)
            if -32768 <= y <= 32767:
                assert r.parse(single,r.prepare(single,source))['values'] == [y]
            else:
                rejects('Overflow',lambda: r.prepare(single,source))
    return dict(question='Q26',counts=counts,examples=examples,sha256=checksum.hexdigest(),
                evidence='Research physical bytes and arithmetic; no PCS/source proof or performance result')


if __name__ == '__main__':
    result = report()
    path = Path(__file__).with_name('record-candidates.json')
    data = json.dumps(result,indent=2,sort_keys=True)+'\n'
    if sys.argv[1:] == ['--write']: path.write_text(data)
    else: assert path.read_text() == data
    print(data,end='')
