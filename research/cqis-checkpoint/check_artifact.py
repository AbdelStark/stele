# /// script
# requires-python = ">=3.12"
# dependencies = ["blake3==1.0.11"]
# ///
"""Q26 ordered artifact framing and identity evidence; not passport admission."""
from dataclasses import replace
import hashlib
import json
from pathlib import Path
import random
import struct
import sys
from blake3 import blake3
import artifact as a
import records as r
from check_scalars import rejects


def reference(specs, records):
    ordered = sorted(specs,key=lambda x:x.name.encode('ascii'))
    configs = [r.config(spec) for spec in ordered]
    preparation = (b'stele/research/q26/quantiser/v1'+struct.pack('<I',len(specs))+
                   b''.join(struct.pack('<I',len(c))+c for c in configs))
    identity = blake3(preparation).digest()
    framed = [struct.pack('<Q',len(records[s.name]))+records[s.name] for s in ordered]
    encoded = b'stele/research/q26/weights/v1'+identity+struct.pack('<I',len(specs))+b''.join(framed)
    return preparation,identity,encoded,blake3(encoded).digest()


def report():
    rng,checksum = random.Random(2605),hashlib.sha256()
    for case in range(10000):
        specs,source = [],{}
        for i in range(1+case%5):
            bits = (4,8,16)[(case+i)%3]
            shape = (rng.randrange(1,5),rng.randrange(1,5))
            parameter = rng.randrange(5) if bits == 16 else rng.randrange(2)
            # All sources finite/exact; varied physical dtype and policy metadata.
            dtype = ('binary16','bfloat16')[i%2]
            spec = r.Spec('tensor.'+str(i),dtype,shape,bits,parameter)
            specs.append(spec)
            choices = ('0000','003c','00bc','0040') if dtype == 'binary16' else ('0000','803f','80bf','0040')
            source[spec.name] = b''.join(bytes.fromhex(rng.choice(choices)) for _ in range(r.count(spec)))
        records = {s.name:r.prepare(s,source[s.name]) for s in specs}
        expected = reference(specs,records)
        rng.shuffle(specs)
        source = dict(reversed(tuple(source.items())))
        assert a.configuration(specs) == expected[0]
        assert a.quantiser_id(specs) == expected[1]
        actual = a.prepare(specs,source)
        assert actual == expected[2] == a.assemble(specs,records)
        assert a.digest(specs,actual) == expected[3]
        assert a.parse(specs,actual) == records
        assert b''.join(a.chunks(specs,records)) == actual
        checksum.update(actual)
    specs = [r.Spec('z','binary16',(1,3),4,0),r.Spec('a','binary16',(1,),16,0)]
    source = {'z':bytes.fromhex('003c00400042'),'a':bytes.fromhex('003c')}
    records = {s.name:r.prepare(s,source[s.name]) for s in specs}
    encoded = a.prepare(specs,source)
    qid = a.quantiser_id(specs)
    offset = len(a.DATA)+32+4
    size = len(records['a'])
    for index,reason in [(0,'Prefix'),(len(a.DATA),'Quantiser'),
                         (len(a.DATA)+32,'Count'),(offset,'RecordLength')]:
        changed = bytearray(encoded); changed[index] ^= 1
        rejects(reason,lambda: a.parse(specs,bytes(changed)))
    # Swap entire independently framed records; the expected first length differs.
    left,right = encoded[offset:offset+8+size],encoded[offset+8+size:]
    rejects('RecordLength',lambda: a.parse(specs,encoded[:offset]+right+left))
    rejects('Trailing',lambda: a.parse(specs,encoded+left))
    rejects('Truncated',lambda: a.parse(specs,encoded[:offset]+left))
    for k in range(len(encoded)):
        rejects('Truncated',lambda: a.parse(specs,encoded[:k]))
    rejects('Duplicate',lambda: a.configuration(specs+[specs[0]]))
    rejects('Count',lambda: a.configuration([]))
    rejects('Count',lambda: a.configuration(tuple(specs)))
    rejects('Bytes',lambda: a.parse(specs,bytearray(encoded)))
    for mapping in ({'a':source['a']},{**source,'extra':b''}):
        rejects('SourceSet',lambda: a.prepare(specs,mapping))
    rejects('RecordSet',lambda: a.assemble(specs,{'a':records['a']}))
    rejects('RecordSet',lambda: a.assemble(specs,{**records,'extra':b''}))
    changed_spec = specs[0]
    for changed in (replace(changed_spec,name='y'),replace(changed_spec,source='bfloat16'),
                    replace(changed_spec,shape=(3,1)),replace(changed_spec,bits=8),
                    replace(changed_spec,parameter=1)):
        other = [changed,specs[1]]
        assert a.quantiser_id(other) != qid
        rejects('Quantiser',lambda: a.parse(other,encoded))
    assert a.quantiser_id([specs[0],replace(specs[1],parameter=1)]) != qid
    # A semantic value mutation changes digest, but it is not syntactically invalid.
    altered = dict(records)
    altered['z'] = records['z'][:-2]+bytes.fromhex('5107')
    saved = a.chunks(specs,records)
    records['z'] = altered['z']
    assert b''.join(saved) == encoded  # Snapshot survives caller dictionary mutation.
    invalid = dict(records); invalid['z'] = invalid['z'][:-1]+b'\x17'
    rejects('Padding',lambda: a.chunks(specs,invalid))  # Checked before any iterator escapes.
    different = a.assemble(specs,altered)
    assert a.parse(specs,different) == altered
    assert a.digest(specs,different) != a.digest(specs,encoded)
    assert a.quantiser_id(specs) == qid  # Same algorithm/config, different content.
    # Identical-sized named records still cannot be substituted or duplicated.
    twins = [r.Spec('a','binary16',(1,),8,0),r.Spec('b','binary16',(1,),8,0)]
    records2 = {s.name:r.prepare(s,b'\0\0') for s in twins}
    other = a.assemble(twins,records2)
    frame = other[offset:offset+8+len(records2['a'])]
    rejects('Config',lambda: a.parse(twins,other[:offset]+frame+frame))
    return dict(question='Q26',artifacts=10000,sha256=checksum.hexdigest(),
                example=dict(configuration=a.configuration(specs).hex(),quantiser_id=qid.hex(),
                             artifact=encoded.hex(),digest=a.digest(specs,encoded).hex()),
                evidence='Research framing/identity; no source authentication, PCS, ZK or performance claim')


if __name__ == '__main__':
    result = report()
    path = Path(__file__).with_name('artifact-candidates.json')
    data = json.dumps(result,indent=2,sort_keys=True)+'\n'
    if sys.argv[1:] == ['--write']: path.write_text(data)
    else: assert path.read_text() == data
    print(data,end='')
