"""Draft RFC-0025 source appendix: exact files, containers, views and asset frames."""
from dataclasses import replace
from hashlib import sha256
import json
from random import Random
from struct import pack

from blake3 import blake3
import safetensors

import source_codec as c
from check_arithmetic_bounds import rejects
from check_source_map import fixture
from source_map import Entry, Shape, SourceMap

DTYPES={1:'float16',2:'bfloat16',3:'float32',4:'float64'}


def file_frame(f):
    name=f.name.encode('utf8'); return pack('<H',len(name))+name+pack('<Q',f.length)+f.sha256


def source_frame(s):
    return b'stele/v0.1/cqis/source'+bytes((s.kind,))+(file_frame(s.files[0]) if not s.kind else
            file_frame(s.index)+pack('<I',len(s.files))+b''.join(file_frame(f) for f in s.files))


def assets_frame(a):
    return (b'stele/v0.1/cqis/source-assets'+file_frame(a.config)+pack('<I',len(a.tokenizers))+
            b''.join(file_frame(f) for f in a.tokenizers)+bytes((int(a.generation is not None),))+
            (file_frame(a.generation) if a.generation is not None else b''))


def auxiliary(generation):
    files={'config.json':b'{"family":"fixture"}', 'tokens-e\u0301.json':b'{"a":1}', 'tokens-\u00e9.bin':b'\0\xff'}
    if generation: files['generation_config.json']=b'{"eos_token_id":0}'
    return c.describe_assets('config.json',('tokens-e\u0301.json','tokens-\u00e9.bin'),
            'generation_config.json' if generation else None,files),files


def package(mapping, sources, groups):
    tensors={name:dict(dtype=DTYPES[value[0]],shape=list(value[1]),data=value[2])
             for name,value in sources.items() if name!='buffer'}
    tensors['buffer']=dict(dtype='int64',shape=[],data=bytes(8))
    names=list(tensors); files={}; locations={}
    for i in range(groups):
        selected=names[i::groups]; label=f'model-{i}.safetensors'
        files[label]=safetensors.serialize({name:tensors[name] for name in selected},metadata={'format':'pt'})
        locations.update((name,label) for name in selected)
    index=None
    if groups>1:
        index='model.safetensors.index.json'
        files[index]=json.dumps(dict(metadata=dict(total_size=sum(len(t['data']) for t in tensors.values())),
                                    weight_map=locations),separators=(',',':')).encode()
    return c.describe_source(files,index),files,tensors


def check(mapping,source,assets,files,tensors,physical):
    sr,ar=c.encode_source(source),c.encode_assets(assets)
    assert sr==source_frame(source) and ar==assets_frame(assets)
    assert c.decode_source(sr)==source and c.decode_assets(ar)==assets
    out=c.verify(mapping,source,assets,files)
    assert out.source_identity==(b'\0'+source.files[0].sha256 if not source.kind else b'\1'+blake3(sr).digest())
    assert out.assets_id==blake3(ar).digest()
    actual={}
    for name,t in out.tensors.items():
        expected=tensors[name]; assert t.shape==tuple(expected['shape']) and bytes(t.data)==expected['data']
        assert t.data.readonly and any(t.data.obj is raw for raw in files.values())
        if name!='buffer': actual[name]=(next(k for k,v in DTYPES.items() if v==expected['dtype']),t.shape,bytes(t.data))
    actual['buffer']=('opaque',)
    assert mapping.extract(actual)==physical
    for f in (assets.config,)+assets.tokenizers+((assets.generation,) if assets.generation else ()):
        assert out.assets[f.name] is files[f.name]
    return out,sr,ar


def structural():
    def container(info,payload=b''):
        header=json.dumps(info,separators=(',',':')).encode()
        return pack('<Q',len(header))+header+payload
    cases=0
    for dtype,bits in c.legacy.BITS.items():
        # Sub-byte formats need complete bytes; empty tensors retain their dtype.
        for shape,count in (([8],8),([0],0)):
            raw=container({'x':dict(dtype=dtype,shape=shape,data_offsets=[0,count*bits//8])},bytes(count*bits//8))
            actual=c._tensors(raw)['x']; reference=c.legacy.parse(raw)['tensors']['x']
            assert (actual.dtype,actual.shape,bytes(actual.data))==(reference['dtype'],reference['shape'],reference['data'])
            assert actual.data.readonly and actual.data.obj is raw
            cases+=1
    raw=container({'x':dict(dtype='F64',shape=[],data_offsets=[0,8])},bytes(8))
    assert c._tensors(raw)['x'].shape==()
    invalid=[({'x':dict(dtype='F4',shape=[1],data_offsets=[0,1])},bytes(1),'Alignment'),
             ({'x':dict(dtype='F16',shape=[2**63,2],data_offsets=[0,0])},b'','Capacity'),
             ({'x':dict(dtype='F16',shape=[1],data_offsets=[1,3])},bytes(3),'Offsets'),
             ({'x':dict(dtype='F16',shape=[1],data_offsets=[0,2])},bytes(3),'Coverage'),
             ({'x':dict(dtype='F16',shape=[1],data_offsets=[0,2]),
               'y':dict(dtype='F16',shape=[1],data_offsets=[0,2])},bytes(2),'Offsets'),
             ({'__metadata__':{'a':1}},b'','Metadata')]
    for info,payload,reason in invalid:
        raw=container(info,payload)
        rejects(lambda:c._tensors(raw),reason)
        rejects(lambda:c.legacy.parse(raw),reason)
    return dict(dtype_cases=cases,scalar_cases=1,malformed_cases=len(invalid))


def boundaries():
    rng=Random(26880); mapping,sources,physical=fixture(rng,Shape(0,1,2,1,1,2,8,3,2),True)
    source,files,tensors=package(mapping,sources,2); assets,af=auxiliary(True); files.update(af)
    out,sr,ar=check(mapping,source,assets,files,tensors,physical)
    for decoder,raw in ((c.decode_source,sr),(c.decode_assets,ar)):
        for end in (0,1,len(raw)//2,len(raw)-1):
            try: decoder(raw[:end])
            except ValueError: pass
            else: raise AssertionError('Truncated')
        rejects(lambda:decoder(raw+b'\0'),'Trailing')
        rejects(lambda:decoder(bytearray(raw)),'Capacity')
    rejects(lambda:c.decode_source(sr[:len(c.SOURCE)]+b'\2'+sr[len(c.SOURCE)+1:]),'Kind')
    rejects(lambda:c.encode_source(replace(source,files=source.files[::-1])),'Order')
    rejects(lambda:c.encode_assets(replace(assets,tokenizers=assets.tokenizers[::-1])),'Order')
    rejects(lambda:c.encode_assets(replace(assets,tokenizers=(assets.config,))),'FileSet')
    rejects(lambda:c.decode_source(c.SOURCE+b'\1'+file_frame(source.index)+pack('<I',2**32-1)),'Capacity')
    rejects(lambda:c.decode_assets(c.ASSETS+file_frame(assets.config)+pack('<I',2**32-1)),'Capacity')
    for name in ('','.', '..','a/b','a\\b','a\0b'):
        rejects(lambda:c.File(name,0,bytes(32)).encode(),'Filename')
    rejects(lambda:c.encode_source(replace(source,index=replace(source.index,length=100000001))),'Capacity')
    labels=tuple(files); missing=dict(files); del missing[labels[0]]
    rejects(lambda:c.verify(mapping,source,assets,missing),'FileSet')
    rejects(lambda:c.verify(mapping,source,assets,{**files,'extra':b''}),'FileSet')
    changed=dict(files); changed[labels[0]]=changed[labels[0]]+b'\0'
    rejects(lambda:c.verify(mapping,source,assets,changed),'FileLength')
    for name in (source.files[0].name,source.index.name,assets.config.name,assets.tokenizers[0].name,assets.generation.name):
        changed=dict(files); raw=changed[name]; changed[name]=bytes((raw[0]^1,))+raw[1:]
        rejects(lambda:c.verify(mapping,source,assets,changed),'FileDigest')
    mutable=dict(files); mutable[source.files[0].name]=bytearray(mutable[source.files[0].name])
    rejects(lambda:c.verify(mapping,source,assets,mutable),'Bytes')
    before=bytes(out.tensors[next(iter(out.tensors))].data)
    replaced=dict(files); snap=c.verify(mapping,source,assets,replaced); replaced.clear()
    assert bytes(snap.tensors[next(iter(snap.tensors))].data)==before
    rejects(lambda:c.verify(replace(mapping,ignored=()),source,assets,files),'Selection')
    first=mapping.entries[0]; wrong=replace(mapping,entries=(replace(first,dtype=first.dtype%4+1),)+mapping.entries[1:])
    rejects(lambda:c.verify(wrong,source,assets,files),'SourceMetadata')
    index=json.loads(files[source.index.name]); keys=list(index['weight_map'])
    name=keys[0]; index['weight_map'][name]=next(f.name for f in source.files if f.name!=index['weight_map'][name])
    changed={f.name:files[f.name] for f in source.files}; changed[source.index.name]=json.dumps(index).encode()
    forged=c.describe_source(changed,source.index.name)
    rejects(lambda:c.verify(mapping,forged,assets,{**changed,**af}),'ShardContents')
    index=json.loads(files[source.index.name]); index['metadata']['total_size']+=1
    changed[source.index.name]=json.dumps(index).encode(); forged=c.describe_source(changed,source.index.name)
    rejects(lambda:c.verify(mapping,forged,assets,{**changed,**af}),'TotalSize')
    index=json.loads(files[source.index.name]); first,second=source.files[:2]
    duplicated=next(n for n,label in index['weight_map'].items() if label==first.name)
    selected={n:tensors[n] for n,label in index['weight_map'].items() if label==second.name}
    selected[duplicated]=tensors[duplicated]
    changed={f.name:files[f.name] for f in source.files}; changed[source.index.name]=files[source.index.name]
    changed[second.name]=safetensors.serialize(selected,metadata={'format':'pt'})
    forged=c.describe_source(changed,source.index.name)
    rejects(lambda:c.verify(mapping,forged,assets,{**changed,**af}),'DuplicateTensor')
    # Hash-valid but structurally invalid source containers still reject.
    def raw_header(header,payload=b''): return pack('<Q',len(header))+header+payload
    for raw,reason in ((raw_header(b'{"x":{},"x":{}}'),'Duplicate'),
                       (raw_header(b'{"x":{"dtype":"F16","shape":[true],"data_offsets":[0,2]}}',bytes(2)),'Shape'),
                       (raw_header(b'{"x":{"dtype":"F16","shape":[2],"data_offsets":[0,2]}}',bytes(2)),'Size'),
                       (pack('<Q',100000001),'HeaderLimit')):
        fs={'bad.safetensors':raw}; forged=c.describe_source(fs)
        rejects(lambda:c.verify(mapping,forged,assets,{**fs,**af}),reason)
    # Exact raw index bytes and file labels remain observable across repartitioning.
    single,sf,_=package(mapping,sources,1); a=c.verify(mapping,single,assets,{**sf,**af})
    assert all(bytes(a.tensors[n].data)==bytes(out.tensors[n].data) for n in a.tensors)
    assert a.source_identity!=out.source_identity
    changed={f.name:files[f.name] for f in source.files}; changed[source.index.name]=files[source.index.name]+b' '
    other=c.describe_source(changed,source.index.name); b=c.verify(mapping,other,assets,{**changed,**af})
    assert b.source_identity!=out.source_identity and b.assets_id==out.assets_id
    renamed={'renamed.safetensors':next(iter(sf.values()))}; rs=c.describe_source(renamed)
    assert c.identity(rs)==c.identity(single) and c.encode_source(rs)!=c.encode_source(single)
    # Alias equality covers the original bytes, even under updated file digests.
    if not mapping.aliases:
        mapping=replace(mapping,aliases=(('head.alias',0),)); sources['head.alias']=sources[mapping.entries[0].name]
    alias=mapping.aliases[0][0]; dtype,shape,raw=sources[alias]
    sources=dict(sources); sources[alias]=(dtype,shape,bytes((raw[0]^1,))+raw[1:])
    forged,fs,_=package(mapping,sources,1)
    rejects(lambda:c.verify(mapping,forged,assets,{**fs,**af}),'AliasData')
    # No old 2^22-element conversion cap is imposed on source structure.
    shape=Shape(0,1,8,1,1,8,32,600000,1); entries=[]; data={}; total=0
    for name,layer,dims in shape.roles():
        label=f'{layer}.{name}'; count=dims[0]*(dims[1] if len(dims)==2 else 1)
        entries.append(Entry(label,1,dims,0)); data[label]=(1,dims,bytes(2*count)); total+=count
    large=SourceMap(shape,tuple(entries),(),('buffer',)); ls,lf,ts=package(large,data,1)
    snapshot=c.verify(large,ls,assets,{**lf,**af}); token=snapshot.tensors['-1.token']
    assert len(token.data)==9600000 and token.data.obj is next(iter(lf.values())) and token.data.readonly
    # Full u64 descriptor fields are retained without pretending to hold such files.
    meta=c.Source(0,None,(c.File('maximum.safetensors',2**64-1,bytes(32)),))
    assert c.decode_source(c.encode_source(meta))==meta
    return dict(large_selected_elements=4800000,large_file_bytes=len(next(iter(lf.values()))),
                all_large_source_elements=total,source_frame_bytes=len(sr),assets_frame_bytes=len(ar),
                maximum_file_length=meta.files[0].length,structural=structural())


def main():
    rng,corpus=Random(2688),sha256(); kinds=[0,0]; families=[0,0]; count=0; maximum=[0,0]
    for i in range(10000):
        family=i%2; h=rng.randint(1,3); a=rng.randint(2,4); d=h*a
        shape=Shape(family,rng.randint(1,3),d,h,h if not family else 1,a,4*d if not family else rng.randint(1,16),rng.randint(1,7),rng.randint(1,5))
        mapping,sources,physical=fixture(rng,shape,not family and i%4==0)
        source,files,tensors=package(mapping,sources,1 if i%3==0 else rng.randint(2,4))
        assets,af=auxiliary(i%2==0); files.update(af)
        out,sr,ar=check(mapping,source,assets,files,tensors,physical)
        for f in source.files:
            upstream={n:(v['dtype'],tuple(v['shape']),bytes(v['data'])) for n,v in safetensors.deserialize(files[f.name])}
            assert all((out.tensors[n].dtype,out.tensors[n].shape,bytes(out.tensors[n].data))==value for n,value in upstream.items())
        selected=rng.choice(tuple(files)); bad=dict(files); raw=bad[selected]; pos=rng.randrange(len(raw))
        bad[selected]=raw[:pos]+bytes((raw[pos]^1,))+raw[pos+1:]
        rejects(lambda:c.verify(mapping,source,assets,bad),'FileDigest')
        for raw in (sr,ar,mapping.encode()): corpus.update(pack('<I',len(raw))+raw)
        kinds[source.kind]+=1; families[family]+=1; count+=len(out.tensors); maximum=[max(maximum[0],len(sr)),max(maximum[1],len(ar))]
        if (i+1)%2000==0: print(json.dumps(dict(completed=i+1)),flush=True)
    print(json.dumps(dict(seed=2688,configurations=10000,kinds=kinds,families=families,tensors=count,
                         maximum_source_assets_bytes=maximum,corpus_sha256=corpus.hexdigest(),boundaries=boundaries()),sort_keys=True))


if __name__=='__main__': main()
