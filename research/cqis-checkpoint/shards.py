"""Q26 indexed checkpoint candidate; no admitted passport/source proof."""
import hashlib
import json
from blake3 import blake3
import artifact as a
import source as s
from quantiser import require

MANIFEST = b'stele/research/q26/checkpoint-bundle/v1'
PREPARATION = b'stele/research/q26/sharded-source/v1'


def digest_bytes(value):
    require(type(value) is bytes and len(value) == 32, 'Digest')
    return value


def single_identity(file_sha256):
    return b'\0'+digest_bytes(file_sha256)


def filename(name):
    require(type(name) is str, 'Filename')
    encoded = s.utf8(name)
    require(1 <= len(encoded) <= 65535 and name.endswith('.safetensors') and
            not any(x in name for x in ('/','\\','\0')), 'Filename')
    return encoded


def parse_index(raw):
    require(type(raw) is bytes, 'Bytes')
    require(len(raw) <= s.MAX_HEADER, 'IndexLimit')
    try:
        text = raw.decode('utf8')
    except UnicodeError as error:
        raise s.SourceError('UTF8') from error
    try:
        index = json.loads(text,object_pairs_hook=s.unique,parse_float=s.no_number,parse_constant=s.no_number)
    except s.SourceError:
        raise
    except (ValueError,RecursionError) as error:
        raise s.SourceError('JSON') from error
    require(type(index) is dict and set(index) == {'metadata','weight_map'}, 'IndexSchema')
    metadata,mapping = index['metadata'],index['weight_map']
    require(type(metadata) is dict and 'total_size' in metadata and s.unsigned(metadata['total_size']), 'IndexMetadata')
    for key,value in metadata.items():
        s.utf8(key)
        if key != 'total_size':
            require(type(value) is str, 'IndexMetadata')
            s.utf8(value)
    require(type(mapping) is dict and 1 <= len(mapping) < 1 << 32, 'IndexSchema')
    for name,label in mapping.items():
        s.utf8(name)
        filename(label)
    return index


def prepare(specs, ignored, index_raw, files, expected_index, expected_files):
    specs = a.ordered(specs)
    require(type(ignored) is list, 'Ignored')
    ignored = ignored.copy()
    selection = s.selection(specs,ignored)
    require(type(index_raw) is bytes, 'Bytes')
    require(len(index_raw) <= s.MAX_HEADER, 'IndexLimit')
    index_hash = hashlib.sha256(index_raw).digest()
    require(index_hash == digest_bytes(expected_index), 'IndexDigest')
    index = parse_index(index_raw)
    mapping = index['weight_map']
    names = sorted(set(mapping.values()),key=filename)
    require(type(files) is dict and type(expected_files) is dict and
            set(files) == set(expected_files) == set(names), 'FileSet')
    # Snapshot immutable bytes before checking; caller dictionary updates cannot
    # substitute a different value between hash validation and tensor parsing.
    snapshot = tuple((name,files[name],expected_files[name]) for name in names)
    framed = [MANIFEST+len(index_raw).to_bytes(8,'little')+index_hash+len(names).to_bytes(4,'little')]
    total_files = 0
    for name,raw,expected in snapshot:
        require(type(raw) is bytes, 'Bytes')
        total_files += len(raw)
        require(total_files <= s.MAX_U64, 'Capacity')
        actual_hash = hashlib.sha256(raw).digest()
        require(actual_hash == digest_bytes(expected), 'ShardDigest')
        label = filename(name)
        framed.append(len(label).to_bytes(2,'little')+label+len(raw).to_bytes(8,'little')+actual_hash)
    by_file = {name:set() for name in names}
    for name,label in mapping.items(): by_file[label].add(name)
    tensors,total_payload = {},0
    for name,raw,_ in snapshot:
        current = s.parse(raw)['tensors']
        require(not (set(current) & set(tensors)), 'DuplicateTensor')
        require(set(current) == by_file[name], 'ShardContents')
        total_payload += sum(len(tensor['data']) for tensor in current.values())
        require(total_payload <= s.MAX_U64, 'Capacity')
        tensors.update(current)
    require(total_payload == index['metadata']['total_size'], 'TotalSize')
    require(set(tensors) == {spec.name for spec in specs} | set(ignored), 'Selection')
    source = {}
    for spec in a.ordered(specs):
        found = tensors[spec.name]
        require((found['dtype'],found['shape']) == (s.SOURCE[spec.source],spec.shape), 'SourceMetadata')
        source[spec.name] = found['data']
    artifact = a.prepare(specs,source)
    manifest = b''.join(framed)
    bundle = blake3(manifest).digest()
    prepared = PREPARATION+len(selection).to_bytes(8,'little')+selection
    return dict(source_manifest=manifest,source_bundle_id=bundle,source_identity=b'\x01'+bundle,
                index_sha256=index_hash,source_preparation_id=blake3(prepared).digest(),
                quantiser_id=a.quantiser_id(specs),artifact=artifact,digest_cqis=a.digest(specs,artifact))
