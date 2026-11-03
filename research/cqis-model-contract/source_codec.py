"""Draft RFC-0025 source appendix: canonical identities and immutable byte slices."""
from dataclasses import dataclass
from hashlib import sha256
import json
from pathlib import Path
from struct import pack
import sys
from types import MappingProxyType

from blake3 import blake3

from numerics import integer
from source_map import SourceMap

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'cqis-checkpoint'))
import source as legacy
import shards as legacy_shards

SOURCE=b'stele/v0.1/cqis/source'
ASSETS=b'stele/v0.1/cqis/source-assets'
LIMIT=1<<29


def filename(name):
    raw=legacy.utf8(name)
    if not 1<=len(raw)<=65535 or name in ('.','..') or any(c in name for c in ('/','\\','\0')):
        raise ValueError('Filename')
    return raw


@dataclass(frozen=True)
class File:
    name: str
    length: int
    sha256: bytes

    def encode(self):
        name=filename(self.name); integer(self.length,0,legacy.MAX_U64,'Length')
        if type(self.sha256) is not bytes or len(self.sha256)!=32: raise ValueError('Digest')
        return pack('<H',len(name))+name+pack('<Q',self.length)+self.sha256


def _files(values):
    if type(values) is not tuple or any(type(v) is not File for v in values): raise ValueError('Files')
    raw=tuple(v.encode() for v in values); names=[filename(v.name) for v in values]
    if len(set(names))!=len(names): raise ValueError('FileSet')
    if names!=sorted(names): raise ValueError('Order')
    integer(sum(v.length for v in values),0,legacy.MAX_U64,'Length')
    return raw


@dataclass(frozen=True)
class Source:
    kind: int
    index: File | None
    files: tuple[File,...]


@dataclass(frozen=True)
class Assets:
    config: File
    tokenizers: tuple[File,...]
    generation: File | None


def _bounded(parts):
    if sum(map(len,parts))>LIMIT: raise ValueError('Capacity')
    return b''.join(parts)


def encode_source(value):
    if type(value) is not Source: raise ValueError('Source')
    integer(value.kind,0,1,'Kind'); files=_files(value.files)
    if not files or any(not f.name.endswith('.safetensors') for f in value.files): raise ValueError('Files')
    prefix=SOURCE+bytes((value.kind,))
    if not value.kind:
        if value.index is not None or len(files)!=1: raise ValueError('Source')
        return _bounded((prefix,files[0]))
    index=value.index
    if type(index) is not File or not index.name.endswith('.json'): raise ValueError('Index')
    ir=index.encode()
    if index.length>legacy.MAX_HEADER or len(files)>index.length//16 or sum(len(filename(f.name)) for f in value.files)>index.length:
        raise ValueError('Capacity')
    if index.name in {f.name for f in value.files}: raise ValueError('FileSet')
    integer(index.length+sum(f.length for f in value.files),0,legacy.MAX_U64,'Length')
    return _bounded((prefix,ir,pack('<I',len(files)),*files))


def _asset_files(value):
    if type(value) is not Assets or type(value.config) is not File: raise ValueError('Assets')
    tokenizers=_files(value.tokenizers)
    if not tokenizers or not value.config.name.endswith('.json'): raise ValueError('Assets')
    if value.generation is not None and (type(value.generation) is not File or not value.generation.name.endswith('.json')):
        raise ValueError('Generation')
    files=(value.config,)+value.tokenizers+((value.generation,) if value.generation else ())
    _files(tuple(sorted(files,key=lambda f:filename(f.name))))
    return files


def encode_assets(value):
    _asset_files(value)
    return _bounded((ASSETS,value.config.encode(),pack('<I',len(value.tokenizers)),
                     *(f.encode() for f in value.tokenizers),bytes((int(value.generation is not None),)),
                     value.generation.encode() if value.generation else b''))


class Reader:
    def __init__(self,raw,prefix):
        if type(raw) is not bytes or len(raw)>LIMIT: raise ValueError('Capacity')
        self.raw,self.pos=raw,0
        if self.take(len(prefix))!=prefix: raise ValueError('Header')
    def take(self,n):
        if n>len(self.raw)-self.pos: raise ValueError('Truncated')
        result=self.raw[self.pos:self.pos+n]; self.pos+=n; return result
    def u(self,n): return int.from_bytes(self.take(n),'little')
    def file(self):
        try: name=self.take(self.u(2)).decode('utf8')
        except UnicodeError as error: raise ValueError('Filename') from error
        return File(name,self.u(8),self.take(32))
    def files(self,maximum=None,names_limit=None):
        count=self.u(4)
        if count>(len(self.raw)-self.pos)//43 or (maximum is not None and count>maximum): raise ValueError('Capacity')
        result=[]; size=0
        for _ in range(count):
            f=self.file(); size+=len(filename(f.name))
            if names_limit is not None and size>names_limit: raise ValueError('Capacity')
            result.append(f)
        return tuple(result)
    def end(self):
        if self.pos!=len(self.raw): raise ValueError('Trailing')


def decode_source(raw):
    r=Reader(raw,SOURCE); kind=r.u(1); integer(kind,0,1,'Kind')
    if kind:
        index=r.file()
        if index.length>legacy.MAX_HEADER: raise ValueError('Capacity')
        value=Source(kind,index,r.files(index.length//16,index.length))
    else: value=Source(0,None,(r.file(),))
    r.end()
    if encode_source(value)!=raw: raise ValueError('Canonical')
    return value


def decode_assets(raw):
    r=Reader(raw,ASSETS); config,tokenizers,present=r.file(),r.files(),r.u(1)
    integer(present,0,1,'Generation'); value=Assets(config,tokenizers,r.file() if present else None); r.end()
    if encode_assets(value)!=raw: raise ValueError('Canonical')
    return value


def identity(value):
    raw=encode_source(value)
    return bytes((value.kind,))+(blake3(raw).digest() if value.kind else value.files[0].sha256)


def _snapshot(files):
    if type(files) is not dict: raise ValueError('Bytes')
    snapshot=files.copy()
    if any(type(raw) is not bytes for raw in snapshot.values()): raise ValueError('Bytes')
    return snapshot


def _describe(name,files): return File(name,len(files[name]),sha256(files[name]).digest())


def describe_source(files,index=None):
    files=_snapshot(files)
    value=Source(int(index is not None),_describe(index,files) if index is not None else None,
                 tuple(_describe(n,files) for n in sorted(files,key=filename) if n!=index))
    encode_source(value); return value


def describe_assets(config,tokenizers,generation,files):
    files=_snapshot(files)
    if type(tokenizers) is not tuple: raise ValueError('Assets')
    value=Assets(_describe(config,files),tuple(_describe(n,files) for n in tokenizers),
                 _describe(generation,files) if generation is not None else None)
    encode_assets(value)
    if set(files)!={f.name for f in _asset_files(value)}: raise ValueError('FileSet')
    return value


@dataclass(frozen=True)
class Tensor:
    dtype: str
    shape: tuple[int,...]
    data: memoryview


def _tensors(raw):
    """Pinned complete structural rules; payload slices retain immutable backing."""
    if len(raw)<8: raise ValueError('Truncated')
    size=int.from_bytes(raw[:8],'little')
    if size>legacy.MAX_HEADER: raise ValueError('HeaderLimit')
    if size>len(raw)-8: raise ValueError('Truncated')
    header=raw[8:8+size]
    if not header.startswith(b'{'): raise ValueError('HeaderStart')
    try: text=header.decode('utf8')
    except UnicodeError as error: raise ValueError('UTF8') from error
    try: content=json.loads(text,object_pairs_hook=legacy.unique,parse_float=legacy.no_number,parse_constant=legacy.no_number)
    except legacy.SourceError: raise
    except (ValueError,RecursionError) as error: raise ValueError('JSON') from error
    if type(content) is not dict: raise ValueError('JSON')
    metadata=content.pop('__metadata__',{})
    if type(metadata) is not dict or any(type(v) is not str for v in metadata.values()): raise ValueError('Metadata')
    for k,v in metadata.items(): legacy.utf8(k); legacy.utf8(v)
    entries=[]; payload=len(raw)-8-size
    for name,info in content.items():
        legacy.utf8(name)
        if type(info) is not dict or set(info)!={'dtype','shape','data_offsets'}: raise ValueError('TensorSchema')
        dtype,shape,offsets=info['dtype'],info['shape'],info['data_offsets']
        if type(dtype) is not str or dtype not in legacy.BITS: raise ValueError('Dtype')
        if type(shape) is not list or not all(legacy.unsigned(d) for d in shape): raise ValueError('Shape')
        if type(offsets) is not list or len(offsets)!=2 or not all(legacy.unsigned(d) for d in offsets): raise ValueError('Offsets')
        start,end=offsets
        if not start<=end<=payload: raise ValueError('Offsets')
        count=1
        for d in shape: count*=d; integer(count,0,legacy.MAX_U64,'Capacity')
        bits=count*legacy.BITS[dtype]; integer(bits,0,legacy.MAX_U64,'Capacity')
        if bits%8: raise ValueError('Alignment')
        if end-start!=bits//8: raise ValueError('Size')
        entries.append((start,end,name,dtype,tuple(shape)))
    cursor=0
    for start,end,*_ in sorted(entries):
        if start!=cursor: raise ValueError('Offsets')
        cursor=end
    if cursor!=payload: raise ValueError('Coverage')
    return {name:Tensor(dtype,shape,memoryview(raw)[8+size+start:8+size+end]) for start,end,name,dtype,shape in entries}


@dataclass(frozen=True)
class Package:
    source_identity: bytes
    assets_id: bytes
    tensors: object
    assets: object


def verify(mapping,source,assets,files):
    if type(mapping) is not SourceMap: raise ValueError('Map')
    mapping.encode(); encode_source(source); ar=encode_assets(assets); files=_snapshot(files)
    expected=source.files+((source.index,) if source.index else ())+_asset_files(assets)
    _files(tuple(sorted(expected,key=lambda f:filename(f.name))))
    if set(files)!={f.name for f in expected}: raise ValueError('FileSet')
    for f in expected:
        if len(files[f.name])!=f.length: raise ValueError('FileLength')
        if sha256(files[f.name]).digest()!=f.sha256: raise ValueError('FileDigest')
    index=legacy_shards.parse_index(files[source.index.name]) if source.kind else None
    if index and set(index['weight_map'].values())!={f.name for f in source.files}: raise ValueError('FileSet')
    by_file={f.name:set() for f in source.files}
    if index:
        for name,label in index['weight_map'].items(): by_file[label].add(name)
    tensors={}; total=0
    for f in source.files:
        current=_tensors(files[f.name])
        if set(tensors)&set(current): raise ValueError('DuplicateTensor')
        if index and set(current)!=by_file[f.name]: raise ValueError('ShardContents')
        total+=sum(len(t.data) for t in current.values()); integer(total,0,legacy.MAX_U64,'Capacity'); tensors.update(current)
    if index and total!=index['metadata']['total_size']: raise ValueError('TotalSize')
    if set(tensors)!={e.name for e in mapping.entries}|{n for n,_ in mapping.aliases}|set(mapping.ignored): raise ValueError('Selection')
    for e in mapping.entries:
        if (tensors[e.name].dtype,tensors[e.name].shape)!=(('F16','BF16','F32','F64')[e.dtype-1],e.shape): raise ValueError('SourceMetadata')
    for name,target in mapping.aliases:
        if tensors[name]!=tensors[mapping.entries[target].name]: raise ValueError('AliasData')
    auxiliary={f.name:files[f.name] for f in _asset_files(assets)}
    return Package(identity(source),blake3(ar).digest(),MappingProxyType(tensors),MappingProxyType(auxiliary))
