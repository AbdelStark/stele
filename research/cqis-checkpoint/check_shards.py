# /// script
# requires-python = ">=3.12"
# dependencies = ["blake3==1.0.11", "safetensors==0.6.2"]
# ///
"""Q26 indexed source checks; research, not passport/proof acceptance."""
from dataclasses import replace
import hashlib
import json
from pathlib import Path
import random
import struct
import sys
from blake3 import blake3
import safetensors
import artifact as a
import records as r
import source as s
import shards as h
from check_scalars import rejects


def sha(raw):
    return hashlib.sha256(raw).digest()


def encode(index):
    return json.dumps(index,separators=(',',':')).encode()


def partition(tensors, groups):
    files,mapping = {},{}
    for i,names in enumerate(groups):
        filename = f'model-{i+1:05d}-of-{len(groups):05d}.safetensors'
        files[filename] = safetensors.serialize({name:tensors[name] for name in names},metadata={'format':'pt'})
        mapping.update((name,filename) for name in names)
    index = encode(dict(metadata=dict(total_size=sum(len(x['data']) for x in tensors.values())),weight_map=mapping))
    return index,files


def run(specs,ignored,index,files):
    return h.prepare(specs,ignored,index,files,sha(index),{name:sha(raw) for name,raw in files.items()})


def manifest(index, files):
    entries = []
    for name in sorted(files,key=lambda x:x.encode()):
        raw,label = files[name],name.encode()
        entries.append(struct.pack('<H',len(label))+label+struct.pack('<Q',len(raw))+sha(raw))
    return (b'stele/research/q26/checkpoint-bundle/v1'+struct.pack('<Q',len(index))+sha(index)+
            struct.pack('<I',len(files))+b''.join(entries))


def report():
    rng,checksum = random.Random(2607),hashlib.sha256()
    formats = [('float16','binary16','003c'),('bfloat16','bfloat16','803f'),
               ('float32','binary32','0000803f'),('float64','binary64','000000000000f03f')]
    for case in range(10000):
        tensors,specs = {},[]
        count = 2+case%9
        for i in range(count):
            api,source,one = formats[(i+case)%4]
            name = 'w.'+str(i)
            shape = (rng.randrange(1,4),rng.randrange(1,4))
            unit = bytes.fromhex(one)
            raw = b''.join(unit if rng.randrange(2) else bytes(len(unit)) for _ in range(shape[0]*shape[1]))
            tensors[name] = dict(dtype=api,shape=list(shape),data=raw)
            bits = (4,8,16)[(case+i)%3]
            specs.append(r.Spec(name,source,shape,bits,i%5 if bits == 16 else i%2))
        tensors['ignored'] = dict(dtype='int64',shape=[],data=case.to_bytes(8,'little'))
        names = list(tensors); rng.shuffle(names)
        groups = [names[i::1+case%5] for i in range(min(1+case%5,len(names)))]
        index,files = partition(tensors,groups)
        files = dict(reversed(tuple(files.items())))
        actual = run(specs,['ignored'],index,files)
        expected = a.prepare(specs,{x.name:tensors[x.name]['data'] for x in specs})
        assert actual['artifact'] == expected
        assert actual['source_manifest'] == manifest(index,files)
        assert actual['source_bundle_id'] == blake3(manifest(index,files)).digest()
        assert actual['source_identity'] == b'\x01'+actual['source_bundle_id']
        assert actual['digest_cqis'] == a.digest(specs,expected)
        checksum.update(actual['source_manifest']+actual['artifact'])
    specs = [r.Spec(name,'binary16',(1,),8,0) for name in ('a','b')]
    tensors = {name:dict(dtype='float16',shape=[1],data=bytes.fromhex('003c')) for name in ('a','b')}
    index,files = partition(tensors,[['a'],['b']]); original = run(specs,[],index,files)
    repacked,onefile = partition(tensors,[['a','b']]); changed = run(specs,[],repacked,onefile)
    assert original['artifact'] == changed['artifact'] and original['source_bundle_id'] != changed['source_bundle_id']
    assert original['source_preparation_id'] == changed['source_preparation_id']
    assert h.single_identity(sha(next(iter(onefile.values()))))[0] == 0
    assert h.single_identity(original['source_bundle_id']) != original['source_identity']
    selection = s.selection(specs,[])
    prepared = b'stele/research/q26/sharded-source/v1'+struct.pack('<Q',len(selection))+selection
    assert original['source_preparation_id'] == blake3(prepared).digest()
    obj = json.loads(index); labels = list(files)
    annotated = json.loads(index); annotated['metadata']['annotation'] = 'not an alias'
    assert run(specs,[],encode(annotated),files)['artifact'] == original['artifact']
    nonfinite = {name:dict(v) for name,v in tensors.items()}; nonfinite['a']['data'] = bytes.fromhex('007c')
    bad_index,bad_files = partition(nonfinite,[['a'],['b']])
    rejects('Nonfinite',lambda: run(specs,[],bad_index,bad_files))
    def reject_index(value, reason):
        rejects(reason,lambda: run(specs,[],encode(value),files))
    wrong = json.loads(index); wrong['weight_map']['a'] = labels[1]
    reject_index(wrong,'FileSet')  # First shard is now unreferenced.
    wrong = json.loads(index); wrong['weight_map'] = {'a':labels[1],'b':labels[0]}
    reject_index(wrong,'ShardContents')
    wrong = json.loads(index); wrong['metadata']['total_size'] += 1
    reject_index(wrong,'TotalSize')
    wrong = json.loads(index); wrong['weight_map']['extra'] = labels[0]
    reject_index(wrong,'ShardContents')
    missing = dict(files); del missing[labels[0]]
    rejects('FileSet',lambda: run(specs,[],index,missing))
    extra = {**files,'extra.safetensors':files[labels[0]]}
    rejects('FileSet',lambda: run(specs,[],index,extra))
    duplicate = dict(files); duplicate[labels[1]] = safetensors.serialize(tensors)
    rejects('DuplicateTensor',lambda: run(specs,[],index,duplicate))
    hashes = {name:sha(raw) for name,raw in files.items()}
    rejects('IndexDigest',lambda: h.prepare(specs,[],index+b' ',files,sha(index),hashes))
    mutated = dict(files); mutated[labels[0]] = mutated[labels[0]][:-1]+b'\x01'
    rejects('ShardDigest',lambda: h.prepare(specs,[],index,mutated,sha(index),hashes))
    rejects('Digest',lambda: h.prepare(specs,[],index,files,b'',hashes))
    rejects('Digest',lambda: h.prepare(specs,[],index,files,sha(index),{**hashes,labels[0]:b''}))
    rejects('FileSet',lambda: h.prepare(specs,[],index,files,sha(index),{}))
    rejects('Selection',lambda: run(specs,['absent'],index,files))
    rejects('SourceMetadata',lambda: run([replace(specs[0],source='bfloat16'),specs[1]],[],index,files))
    rejects('SourceMetadata',lambda: run([replace(specs[0],shape=(1,1)),specs[1]],[],index,files))
    rejects('Digest',lambda: h.single_identity(b''))
    rejects('Bytes',lambda: h.parse_index(bytearray(index)))
    for name in ('../x.safetensors','/x.safetensors','x\\y.safetensors','x\0.safetensors','x.bin',''):
        wrong = json.loads(index); wrong['weight_map']['a'] = name
        reject_index(wrong,'Filename')
    for metadata in ({},{'total_size':True},{'total_size':-1},{'total_size':1<<64},{'total_size':4,'extra':1}):
        wrong = json.loads(index); wrong['metadata'] = metadata
        reject_index(wrong,'IndexMetadata')
    rejects('IndexSchema',lambda: h.parse_index(encode({'metadata':{'total_size':0},'weight_map':{}})))
    rejects('Duplicate',lambda: h.parse_index(b'{"weight_map":{},"weight_map":{}}'))
    rejects('Duplicate',lambda: h.parse_index(b'{"weight_map":{"a":"x","a":"y"}}'))
    for raw,reason in [(b'{','JSON'),(b'{"x":1.0}','JSON'),(b'{\xff}','UTF8'),
                       (b'{}'+b' '*(s.MAX_HEADER-1),'IndexLimit')]:
        rejects(reason,lambda: h.parse_index(raw))
    reordered = json.dumps(obj,sort_keys=True,indent=2).encode()
    other = run(specs,[],reordered,files)
    assert other['artifact'] == original['artifact'] and other['source_bundle_id'] != original['source_bundle_id']
    return dict(question='Q26',bundles=10000,sha256=checksum.hexdigest(),
                example={k:v.hex() for k,v in original.items() if k not in ('artifact',)},
                evidence='Research indexed source framing; no full inference, passport or source proof')


def checkpoint(path):
    from check_source import checkpoint as source_checkpoint
    expected = source_checkpoint(path)
    raw = Path(path).read_bytes()
    upstream = dict(safetensors.deserialize(raw))
    tensors = {name:dict(dtype='float32',shape=v['shape'],data=bytes(v['data'])) for name,v in upstream.items()}
    # The exact file hash and prior fixture quantiser id pin this test configuration.
    specs = [r.Spec(name,'binary32',tuple(v['shape']),8 if len(v['shape']) == 2 else 16,
                    (0 if name in ('transformer.wte.weight','transformer.wpe.weight') else 1)
                    if len(v['shape']) == 2 else 8) for name,v in upstream.items()]
    assert a.quantiser_id(specs).hex() == expected['quantiser_id']
    unsharded = a.prepare(specs,{name:v['data'] for name,v in tensors.items()})
    results = []
    for count in (2,3,7,64):
        names = sorted(tensors)
        index,files = partition(tensors,[names[i::count] for i in range(count)])
        actual = run(specs,[],index,files)
        assert actual['artifact'] == unsharded
        assert actual['digest_cqis'].hex() == expected['digest_cqis']
        results.append(dict(shards=count,source_bundle_id=actual['source_bundle_id'].hex(),
                            digest_cqis=actual['digest_cqis'].hex()))
    return dict(question='Q26',original_digest_hf=expected['digest_hf'],tensors=64,ignored=0,
                repartitions=results,evidence='Locally repartitioned pinned checkpoint; no published sharded-source claim')


if __name__ == '__main__':
    args = sys.argv[1:]
    if args[:1] == ['--checkpoint']:
        assert len(args) in (2,3)
        result = checkpoint(args[1]); filename = 'shard-checkpoint.json'; args = args[2:]
    else:
        result = report(); filename = 'shard-candidates.json'
    path = Path(__file__).with_name(filename)
    data = json.dumps(result,indent=2,sort_keys=True)+'\n'
    if args == ['--write']: path.write_text(data)
    else:
        assert args == []
        assert path.read_text() == data
    print(data,end='')
