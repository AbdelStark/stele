"""RFC-0025 source §2: bounded structural fixtures from the qualified parser."""
from hashlib import sha256
import json
from math import gcd
from pathlib import Path
from random import Random
import sys

root=Path(__file__).resolve().parents[4]
sys.path.insert(0,str(root/'research/cqis-checkpoint'))
import source

data=bytearray(); cases=[]
def add(label,header,payload=b'',error=None,raw=None):
    if raw is None:
        if isinstance(header,dict): header=json.dumps(header,ensure_ascii=True,separators=(',',':')).encode()
        raw=len(header).to_bytes(8,'little')+header+payload
    try:
        parsed=source.parse(raw)
    except (ValueError,OverflowError):
        assert error is not None,label
        tensors=[]
    else:
        assert error is None,label
        size=int.from_bytes(raw[:8],'little'); original=json.loads(raw[8:8+size])
        tensors=[dict(name=n,dtype=t['dtype'],shape=t['shape'],offset=8+size+original[n]['data_offsets'][0],length=len(t['data'])) for n,t in sorted(parsed['tensors'].items())]
    cases.append(dict(label=label,offset=len(data),length=len(raw),sha256=sha256(raw).hexdigest(),error=error,tensors=tensors))
    data.extend(raw)

def tensor(dtype='F32',shape=None,offsets=None):
    return dict(dtype=dtype,shape=[1] if shape is None else shape,data_offsets=[0,4] if offsets is None else offsets)

for dtype,bits in source.BITS.items():
    count=8//gcd(bits,8); length=count*bits//8
    add(dtype,{'__metadata__':{'original':'annotation'},'z':tensor(dtype,[count],[0,length]),'empty':tensor('U8',[0],[0,0]),'tail':tensor('U8',[0],[length,length])},bytes(range(length)))
add('empty',{})
add('metadata only',{'__metadata__':{'':'\0\n\t\\"/é😀'}})
add('scalar nonfinite',{'scalar':tensor('F32',[],[0,4])},b'\0\0\x80\x7f')
add('empty full u64',{'':tensor('U8',[0,(1<<64)-1],[0,0])})
add('negative zero',b'{"a":{"dtype":"F32","shape":[-0],"data_offsets":[-0,0]}}')
add('escaped names and dtype',b'{"\\ud83d\\ude00":{"data_offsets":[0,4],"shape":[],"dtyp\\u0065":"F\\u0033\\u0032"}}',b'abcd')
add('raw unicode',json.dumps({'é😀':tensor()},ensure_ascii=False).encode(),b'abcd')
rng=Random(50400)
for i in range(32):
    header={'__metadata__':{'fixture':str(i)}}; payload=bytearray()
    names=[f'tensor-{j:02d}-é' for j in range(rng.randrange(1,25))];rng.shuffle(names)
    for name in names:
        dtype=rng.choice(list(source.BITS));bits=source.BITS[dtype]
        shape=[rng.randrange(5),8//gcd(bits,8)];length=shape[0]*shape[1]*bits//8
        header[name]=tensor(dtype,shape,[len(payload),len(payload)+length]);payload.extend(rng.randrange(256) for _ in range(length))
    items=list(header.items());rng.shuffle(items)
    add('random '+str(i),dict(items),bytes(payload))
for length in [65527,65528,65529,131064]:
    header=b'{"__metadata__":{"long":"'+b'x'*(length-30)+b'"}}'
    header+=b' '*(length-len(header))
    assert len(header)==length
    add('header boundary '+str(length),header)

base=b'{"a":{"dtype":"F32","shape":[1],"data_offsets":[0,4]}}'
for label,header,error in [
    ('leading space',b' '+base,'SourceHeader'),('empty header',b'','SourceHeader'),
    ('UTF8',b'{"\xff":{}}','SourceJson'),('trailing JSON',base+b'{}','SourceJson'),
    ('trailing comma',base[:-1]+b',}','SourceJson'),
    ('duplicate tensor',base[:-1]+b','+base[1:],'SourceDuplicate'),
    ('escaped duplicate tensor',base[:-1]+b','+base[1:].replace(b'"a"',b'"\\u0061"'),'SourceDuplicate'),
    ('duplicate field',base.replace(b'"dtype":"F32"',b'"dtype":"F32","dtyp\\u0065":"F32"'),'SourceDuplicate'),
    ('unknown field',base.replace(b'"dtype":"F32"',b'"extra":0,"dtype":"F32"'),'SourceContainer'),
    ('missing field',base.replace(b'"dtype":"F32",',b''),'SourceContainer'),
    ('unknown dtype',base.replace(b'F32',b'F33'),'SourceContainer'),
    ('high surrogate',base.replace(b'"a"',b'"\\ud800"'),'SourceJson'),
    ('low surrogate',base.replace(b'"a"',b'"\\udc00"'),'SourceJson'),
    ('raw control',base.replace(b'"a"',b'"\x01"'),'SourceJson'),
    ('bad escape',base.replace(b'"a"',b'"\\q"'),'SourceJson'),
    ('bad unicode digits',base.replace(b'"a"',b'"\\u0x00"'),'SourceJson'),
    ('bad surrogate pair',base.replace(b'"a"',b'"\\ud800\\u0061"'),'SourceJson'),
    ('vertical tab suffix',base+b'\x0b','SourceJson'),
    ('wrong rank syntax',base.replace(b'[1]',b'1'),'SourceJson'),
    ('wrong offsets count',base.replace(b'[0,4]',b'[0,4,4]'),'SourceContainer'),
    ('reversed offsets',base.replace(b'[0,4]',b'[4,0]'),'SourceContainer'),
    ('size mismatch',base.replace(b'[1]',b'[2]'),'SourceContainer'),
    ('dimension overflow',base.replace(b'[1]',b'[18446744073709551615,2]'),'SourceContainer'),
    ('bit overflow',base.replace(b'[1]',b'[18446744073709551615]'),'SourceContainer'),
    ('subbyte alignment',base.replace(b'F32',b'F4'),'SourceContainer'),
    ('nonstring annotation',b'{"__metadata__":{"x":0}}','SourceJson'),
    ('duplicate annotation',b'{"__metadata__":{"x":"a","\\u0078":"b"}}','SourceDuplicate'),
    ('duplicate metadata',b'{"__metadata__":{},"__metadata__":{}}','SourceDuplicate'),
]: add(label,header,b'abcd',error)
for number in [b'true',b'false',b'null',b'1.0',b'1e0',b'NaN',b'Infinity',b'-1',b'01',b'-00',b'18446744073709551616']:
    add('invalid number '+number.decode(),base.replace(b'[1]',b'['+number+b']'),b'abcd','SourceJson')
add('hole',{'a':tensor(offsets=[1,5])},b'abcde','SourceCoverage')
add('overlap',{'a':tensor(),'b':tensor()},b'abcd','SourceCoverage')
add('payload suffix',{'a':tensor()},b'abcde','SourceCoverage')
add('empty inside span',{'a':tensor(),'b':tensor('U8',[0],[2,2])},b'abcd','SourceCoverage')
add('short file',b'',error='SourceHeader',raw=b'1234567')
add('header past EOF',b'',error='SourceHeader',raw=(100).to_bytes(8,'little')+b'{}')
add('header limit',b'',error='SourceHeader',raw=(100000001).to_bytes(8,'little')+b'{}')
out=Path(__file__).resolve().parents[1]/'fixtures'
(out/'source-containers.bin').write_bytes(data)
(out/'source-containers.json').write_text(json.dumps(dict(cases=cases),ensure_ascii=True,separators=(',',':'))+'\n')
print(json.dumps(dict(cases=len(cases),valid=sum(c['error'] is None for c in cases),bytes=len(data))))
