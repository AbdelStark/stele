# /// script
# requires-python = ">=3.12"
# dependencies = ["blake3==1.0.11", "safetensors==0.6.2"]
# ///
"""Q26 source-container differential checks, not checkpoint-proof controls."""
from dataclasses import replace
import hashlib
import json
from pathlib import Path
import random
import sys
import safetensors
from blake3 import blake3
import artifact as a
import records as r
import source as s
from check_scalars import rejects


def pack(header, payload=b'', spaces=0):
    data = json.dumps(header,separators=(',',':'),ensure_ascii=False).encode()+b' '*spaces
    return len(data).to_bytes(8,'little')+data+payload


def header_raw(header, payload=b''):
    return len(header).to_bytes(8,'little')+header+payload


def tensor(dtype='F16',shape=None,offsets=None):
    return dict(dtype=dtype,shape=[1] if shape is None else shape,
                data_offsets=[0,2] if offsets is None else offsets)


def report():
    rng,checksum = random.Random(2606),hashlib.sha256()
    formats = [('F16','float16','binary16','003c'),('BF16','bfloat16','bfloat16','803f'),
               ('F32','float32','binary32','0000803f'),('F64','float64','binary64','000000000000f03f')]
    for case in range(10000):
        info,expected,specs = {},{},[]
        for i in range(1+case%4):
            dtype,api,source,one = formats[(i+case)%4]
            shape = (rng.randrange(1,5),rng.randrange(1,5))
            name = 'weight.'+str(i)
            values = [bytes.fromhex(one) if rng.randrange(2) else bytes(len(bytes.fromhex(one)))
                      for _ in range(shape[0]*shape[1])]
            raw = b''.join(values)
            info[name] = dict(dtype=api,shape=list(shape),data=raw)
            expected[name] = dict(dtype=dtype,shape=shape,data=raw)
            bits = (4,8,16)[(i+case)%3]
            specs.append(r.Spec(name,source,shape,bits,rng.randrange(5) if bits == 16 else i%2))
        info['unused.counter'] = dict(dtype='int64',shape=[],data=(case).to_bytes(8,'little'))
        expected['unused.counter'] = dict(dtype='I64',shape=(),data=(case).to_bytes(8,'little'))
        raw = safetensors.serialize(info,metadata={'case':str(case)})
        upstream = {name:dict(dtype=v['dtype'],shape=tuple(v['shape']),data=bytes(v['data']))
                    for name,v in safetensors.deserialize(raw)}
        actual = s.parse(raw)
        assert actual['tensors'] == expected == upstream
        assert actual['metadata'] == {'case':str(case)}
        digest = hashlib.sha256(raw).digest()
        result = s.prepare(specs,['unused.counter'],raw,digest)
        assert result['digest_hf'] == digest
        assert result['artifact'] == a.prepare(specs,{x.name:expected[x.name]['data'] for x in specs})
        assert result['digest_cqis'] == a.digest(specs,result['artifact'])
        checksum.update(raw+result['source_preparation_id']+result['artifact'])
    structural = []
    for dtype,bits in s.BITS.items():
        # Use an integral number of bytes for sub-byte encodings.
        count = 8 if bits < 8 else 1
        raw = pack({'v':tensor(dtype,[count],[0,count*bits//8])},bytes(count*bits//8))
        assert s.parse(raw)['tensors']['v']['data'] == bytes(dict(safetensors.deserialize(raw))['v']['data'])
        structural.append(dtype)
    for shape in ([],[0],[2,0,3]):
        n = 1 if not shape else 0
        raw = pack({'v':tensor('F16',shape,[0,2*n])},bytes(2*n))
        assert s.parse(raw)['tensors']['v']['shape'] == tuple(dict(safetensors.deserialize(raw))['v']['shape'])
    raw = pack({'z':tensor('U8',[1],[2,3]),'empty':tensor('F16',[0],[2,2]),
                'a':tensor('F16',[1],[0,2])},bytes(3),7)
    assert set(s.parse(raw)['tensors']) == set(dict(safetensors.deserialize(raw)))
    base = pack({'w':tensor()},bytes.fromhex('003c'))
    spec = r.Spec('w','binary16',(1,),8,0)
    digest = hashlib.sha256(base).digest()
    original = s.prepare([spec],[],base,digest)
    padded = pack({'w':tensor()},bytes.fromhex('003c'),8)
    assert s.prepare([spec],[],padded,hashlib.sha256(padded).digest())['artifact'] == original['artifact']
    rejects('SourceDigest',lambda: s.prepare([spec],[],padded,digest))
    first = pack({'__metadata__':{'a':'1','b':'2'},'w':tensor()},bytes.fromhex('003c'))
    second = pack({'w':tensor(),'__metadata__':{'b':'2','a':'1'}},bytes.fromhex('003c'))
    assert dict(safetensors.deserialize(first)) == dict(safetensors.deserialize(second))
    assert s.parse(first) == s.parse(second)
    assert hashlib.sha256(first).digest() != hashlib.sha256(second).digest()
    assert s.prepare([spec],[],first,hashlib.sha256(first).digest())['artifact'] == original['artifact']
    assert s.prepare([spec],[],second,hashlib.sha256(second).digest())['artifact'] == original['artifact']
    rejects('Digest',lambda: s.prepare([spec],[],base,b''))
    for bad in (replace(spec,source='bfloat16'),replace(spec,shape=(1,1))):
        rejects('SourceMetadata',lambda: s.prepare([bad],[],base,digest))
    rejects('Selection',lambda: s.prepare([spec],['w'],base,digest))
    rejects('Selection',lambda: s.prepare([spec],['absent'],base,digest))
    rejects('Ignored',lambda: s.selection([spec],['x','x']))
    rejects('Ignored',lambda: s.selection([spec],[True]))
    rejects('Unicode',lambda: s.selection([spec],['\ud800']))
    expected_selection = (b'stele/research/q26/source/v1'+a.quantiser_id([spec])+bytes.fromhex('02000000')+
                          bytes.fromhex('01000000')+b'a'+bytes.fromhex('01000000')+b'b')
    assert s.selection([spec],['a','b']) == expected_selection == s.selection([spec],['b','a'])
    assert original['source_preparation_id'] == blake3(s.selection([spec],[])).digest()
    assert s.selection([spec],[]) != s.selection([spec],['unused'])
    extra = pack({'w':tensor(),'x':tensor('U8',[1],[2,3])},bytes(3))
    rejects('Selection',lambda: s.prepare([spec],[],extra,hashlib.sha256(extra).digest()))
    nonfinite = pack({'w':tensor()},bytes.fromhex('007c'))
    assert s.parse(nonfinite)['tensors']['w']['data'] == bytes.fromhex('007c')
    rejects('Nonfinite',lambda: s.prepare([spec],[],nonfinite,hashlib.sha256(nonfinite).digest()))
    bad_headers = [({'w':tensor(offsets=[1,3])},bytes(3),'Offsets'),
                   ({'w':tensor(offsets=[0,1])},bytes(1),'Size'),
                   ({'w':tensor(),'x':tensor()},bytes(2),'Offsets'),
                   ({'w':tensor()},bytes(3),'Coverage'),
                   ({'w':tensor('F4',[1],[0,1])},bytes(1),'Alignment'),
                   ({'w':tensor('unknown')},bytes(2),'Dtype'),
                   ({'w':tensor(shape=[True])},bytes(2),'Shape'),
                   ({'w':tensor(shape=[1<<64])},bytes(2),'Shape'),
                   ({'w':tensor(shape=[1<<63,2])},bytes(2),'Capacity'),
                   ({'w':tensor(offsets=[False,2])},bytes(2),'Offsets'),
                   ({'w':{**tensor(),'extra':1}},bytes(2),'TensorSchema'),
                   ({'__metadata__':{'x':1}},b'','Metadata')]
    for header,payload,reason in bad_headers:
        rejects(reason,lambda: s.parse(pack(header,payload)))
    for header in (b'{"w":{},"w":{}}',b'{"w":{"dtype":"F16","dtype":"BF16"}}',
                   b'{"__metadata__":{"x":"a","x":"b"}}'):
        rejects('Duplicate',lambda: s.parse(header_raw(header)))
    for header,reason in [(b' {}','HeaderStart'),(b'{','JSON'),(b'{"x":NaN}','JSON'),
                          (b'{"x":1.0}','JSON'),(b'{"\\ud800":{}}','Unicode'),(b'{\xff}','UTF8')]:
        rejects(reason,lambda: s.parse(header_raw(header)))
    for k in range(len(base)):
        rejects('Truncated' if k < 8+int.from_bytes(base[:8],'little') else 'Offsets',lambda: s.parse(base[:k]))
    rejects('HeaderLimit',lambda: s.parse((s.MAX_HEADER+1).to_bytes(8,'little')))
    rejects('Bytes',lambda: s.parse(bytearray(base)))
    return dict(question='Q26',files=10000,upstream=safetensors.__version__,dtypes=structural,
                sha256=checksum.hexdigest(),example=dict(file=base.hex(),digest_hf=digest.hex(),
                source_preparation_id=original['source_preparation_id'].hex(),digest_cqis=original['digest_cqis'].hex()),
                evidence='Research file adaptation; no publisher authentication or commitment/source proof')


def checkpoint(path):
    revision = '71034c5d8bde858ff824298bdedc65515b97d2b9'
    expected_hash = bytes.fromhex('8111d5afb0715dbf5a31396d31432cb56370ba23f6650a035ea0fc8a20b4e500')
    raw = Path(path).read_bytes()
    assert hashlib.sha256(raw).digest() == expected_hash and len(raw) == 453864
    # Fixed fixture expectations, not dimensions/roles selected by its own header.
    specs = [r.Spec('transformer.wte.weight','binary32',(1000,32),8,0),
             r.Spec('transformer.wpe.weight','binary32',(512,32),8,0)]
    for suffix in ('weight','bias'):
        specs.append(r.Spec('transformer.ln_f.'+suffix,'binary32',(32,),16,8))
    for layer in range(5):
        prefix = 'transformer.h.'+str(layer)+'.'
        for role in ('ln_1','ln_2'):
            for suffix in ('weight','bias'):
                specs.append(r.Spec(prefix+role+'.'+suffix,'binary32',(32,),16,8))
        for role,shape in [('attn.c_attn',(32,96)),('attn.c_proj',(32,32)),
                           ('mlp.c_fc',(32,128)),('mlp.c_proj',(128,32))]:
            specs.append(r.Spec(prefix+role+'.weight','binary32',shape,8,1))
            specs.append(r.Spec(prefix+role+'.bias','binary32',(shape[1],),16,8))
    upstream = {name:dict(dtype=v['dtype'],shape=tuple(v['shape']),data=bytes(v['data']))
                for name,v in safetensors.deserialize(raw)}
    assert s.parse(raw)['tensors'] == upstream
    assert set(upstream) == {spec.name for spec in specs}
    assert all(upstream[x.name]['shape'] == x.shape and upstream[x.name]['dtype'] == 'F32' for x in specs)
    result = s.prepare(specs,[],raw,expected_hash)
    assert result['artifact'] == a.prepare(specs,{name:v['data'] for name,v in upstream.items()})
    return dict(repository='hf-internal-testing/tiny-random-gpt2',revision=revision,
                file='model.safetensors',bytes=len(raw),tensors=len(specs),ignored=0,
                parameters=sum(r.count(x) for x in specs),artifact_bytes=len(result['artifact']),
                **{key:result[key].hex() for key in ('digest_hf','source_preparation_id','quantiser_id','digest_cqis')},
                evidence='Complete parameter preparation under candidate precisions; no forward pass/fidelity/proof')


if __name__ == '__main__':
    args = sys.argv[1:]
    if args[:1] == ['--checkpoint']:
        assert len(args) in (2,3)
        result = checkpoint(args[1]); filename = 'source-checkpoint.json'; args = args[2:]
    else:
        result = report(); filename = 'source-candidates.json'
    path = Path(__file__).with_name(filename)
    data = json.dumps(result,indent=2,sort_keys=True)+'\n'
    if args == ['--write']: path.write_text(data)
    else:
        assert args == []
        assert path.read_text() == data
    print(data,end='')
