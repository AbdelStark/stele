"""RFC-0025 source §2: original index fixtures from the pinned strict parser."""
from hashlib import sha256
import json
from pathlib import Path
from random import Random
import sys

root=Path(__file__).resolve().parents[4]
sys.path.insert(0,str(root/'research/cqis-checkpoint'))
import shards

cases=[]; data=bytearray()
def add(label,raw,error=None):
    if isinstance(raw,dict): raw=json.dumps(raw,ensure_ascii=True,separators=(',',':')).encode()
    try: index=shards.parse_index(raw)
    except ValueError:
        assert error is not None,label
        entries=[];total=None
    else:
        assert error is None,label
        entries=[dict(name=n,file_name=f) for n,f in sorted(index['weight_map'].items())]
        total=index['metadata']['total_size']
    cases.append(dict(label=label,offset=len(data),length=len(raw),sha256=sha256(raw).hexdigest(),error=error,entries=entries,total_size=total))
    data.extend(raw)

base=b'{"metadata":{"total_size":4},"weight_map":{"a":"one.safetensors"}}'
add('minimal',base)
add('leading whitespace',b' \t\r\n'+base+b' \t\r\n')
add('negative zero',base.replace(b'":4',b'":-0'))
add('full u64 total',{'metadata':{'total_size':(1<<64)-1},'weight_map':{'':'one.safetensors','\0é😀':'two.safetensors'}})
add('annotations',{'weight_map':{'a':'one.safetensors','b':'one.safetensors'},'metadata':{'label':'original\n\t\0é😀','total_size':0,'':'empty key'}})
add('maximum basename',{'metadata':{'total_size':0},'weight_map':{'a':'x'*(65535-12)+'.safetensors'}})
add('escaped keys',b'{"metad\\u0061ta":{"total_siz\\u0065":4},"weight_map":{"\\ud83d\\ude00":"one\\u002esafetensors"}}')
rng=Random(50420)
for i in range(32):
    names=[f'tensor-{j}-é' for j in range(rng.randrange(1,100))];rng.shuffle(names)
    mapping={n:f'shard-{rng.randrange(8)}.safetensors' for n in names}
    value={'metadata':{'total_size':rng.randrange(1<<64),'original':str(i)},'weight_map':mapping}
    if i%2: value=dict(reversed(list(value.items())))
    add('random '+str(i),value)
for length in [65535,65536,65537,131072]:
    raw=base+b' '*(length-len(base));assert len(raw)==length
    add('chunk boundary '+str(length),raw)
for label,raw,error in [
    ('empty',b'','SourceJson'),('not object',b'[]','SourceJson'),
    ('trailing',base+b'{}','SourceJson'),('trailing comma',base[:-1]+b',}','SourceJson'),
    ('UTF8',base.replace(b'"a"',b'"\xff"'),'SourceJson'),
    ('unknown field',base[:-1]+b',"extra":0}','SourceIndex'),
    ('missing mapping',b'{"metadata":{"total_size":0}}','SourceIndex'),
    ('missing metadata',b'{"weight_map":{"a":"one.safetensors"}}','SourceIndex'),
    ('missing total',b'{"metadata":{},"weight_map":{"a":"one.safetensors"}}','SourceIndex'),
    ('empty mapping',b'{"metadata":{"total_size":0},"weight_map":{}}','SourceIndex'),
    ('duplicate root',base[:-1]+b',"metadata":{"total_size":4}}','SourceDuplicate'),
    ('duplicate total',base.replace(b'"total_size":4',b'"total_size":4,"total_siz\\u0065":4'),'SourceDuplicate'),
    ('duplicate annotation',base.replace(b'"total_size":4',b'"total_size":4,"x":"a","\\u0078":"b"'),'SourceDuplicate'),
    ('duplicate tensor',base.replace(b'"a":"one.safetensors"',b'"a":"one.safetensors","\\u0061":"two.safetensors"'),'SourceDuplicate'),
    ('nonstring annotation',base.replace(b'"total_size":4',b'"total_size":4,"label":true'),'SourceJson'),
    ('nonstring label',base.replace(b'"one.safetensors"',b'0'),'SourceJson'),
    ('surrogate name',base.replace(b'"a"',b'"\\ud800"'),'SourceJson'),
    ('surrogate label',base.replace(b'one.safetensors',b'\\udc00.safetensors'),'SourceJson'),
]: add(label,raw,error)
for number in [b'true',b'false',b'null',b'4.0',b'4e0',b'-1',b'01',b'-00',b'NaN',b'Infinity',b'18446744073709551616']:
    add('invalid total '+number.decode(),base.replace(b'":4',b'":'+number),'SourceJson')
for name in ['', '.', '..', '/one.safetensors', 'a/one.safetensors', 'a\\one.safetensors', '\0.safetensors', 'x'*(65536-12)+'.safetensors']:
    add('invalid basename '+repr(name[:24]),{'metadata':{'total_size':0},'weight_map':{'a':name}},'FileName')
add('wrong suffix',{'metadata':{'total_size':0},'weight_map':{'a':'one.bin'}},'SourceFiles')
out=Path(__file__).resolve().parents[1]/'fixtures'
(out/'source-index.bin').write_bytes(data)
(out/'source-index.json').write_text(json.dumps(dict(seed=50420,cases=cases),separators=(',',':'))+'\n')
print(json.dumps(dict(cases=len(cases),valid=sum(c['error'] is None for c in cases),bytes=len(data))))
