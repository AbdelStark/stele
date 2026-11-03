"""Independent byte framing/coordinate checks for Draft RFC-0025's source map."""
from dataclasses import replace
from hashlib import sha256
import json
from random import Random
from struct import pack

from blake3 import blake3

from source_map import Entry, Shape, SourceMap, decode


def rejects(call, reason=None):
    try:
        call()
    except ValueError as error:
        if reason is not None:
            assert str(error) == reason, (error, reason)
    else:
        raise AssertionError('accepted a required rejection')


def role_oracle(s):
    """Literal architecture order; no calls to the candidate's role expansion."""
    d, f, k = s.width, s.hidden, s.groups*s.head_width
    if s.family == 0:
        block = [('norm1.gain', (d,)), ('norm1.bias', (d,)),
                 ('Q', (d, d)), ('Q.bias', (d,)), ('K', (d, d)), ('K.bias', (d,)),
                 ('V', (d, d)), ('V.bias', (d,)), ('O', (d, d)), ('O.bias', (d,)),
                 ('up', (f, d)), ('up.bias', (f,)), ('down', (d, f)), ('down.bias', (d,)),
                 ('norm2.gain', (d,)), ('norm2.bias', (d,))]
        edges = [('position', -1, (s.context, d))]
        end = [('final.gain', -1, (d,)), ('final.bias', -1, (d,))]
    else:
        block = [('norm1.gain', (d,)), ('Q', (d, d)), ('K', (k, d)), ('V', (k, d)),
                 ('O', (d, d)), ('up', (f, d)), ('gate', (f, d)), ('down', (d, f)),
                 ('norm2.gain', (d,))]
        edges = []
        end = [('final.gain', -1, (d,)), ('head', -1, (s.vocabulary, d))]
    return tuple([('token', -1, (s.vocabulary, d))]+edges+
                 [(role, layer, shape) for layer in range(s.layers) for role, shape in block]+end)


def encode_oracle(mapping):
    def name(s):
        raw = s.encode('utf8')
        return pack('<H', len(raw))+raw

    s = mapping.shape
    shape = pack('<B6H2I', s.family, s.layers, s.width, s.heads, s.groups,
                 s.head_width, s.hidden, s.vocabulary, s.context)
    data = [b'stele/v0.1/cqis/source-map', pack('<I', len(shape)), shape]
    for entry in mapping.entries:
        data.extend([name(entry.name), pack('<BB', entry.dtype, len(entry.shape)),
                     pack('<'+'I'*len(entry.shape), *entry.shape), pack('<B', entry.transform)])
        if entry.transform in (2, 3):
            data.append(pack('<B', entry.part))
    data.append(pack('<I', len(mapping.aliases)))
    for source, target in mapping.aliases:
        data.extend([name(source), pack('<H', target)])
    data.append(pack('<I', len(mapping.ignored)))
    data.extend(name(source) for source in mapping.ignored)
    return b''.join(data)


def fixture(rng, shape, fused):
    entries, sources, expected = [], {}, []
    for role, layer, target in role_oracle(shape):
        name = f'{layer}.{role}'
        part = None
        dtype = rng.randrange(1, 5)
        if fused and role.removesuffix('.bias') in ('Q', 'K', 'V'):
            part = ('Q', 'K', 'V').index(role.removesuffix('.bias'))
            tag = 3 if role.endswith('.bias') else 2
            source_shape = (3*shape.width,) if tag == 3 else (shape.width, 3*shape.width)
            name = f'{layer}.fused.{tag}'
            if name in sources:
                dtype = sources[name][0]
        elif len(target) == 2 and role not in ('token', 'position') and rng.randrange(2):
            tag, source_shape = 1, target[::-1]
        else:
            tag, source_shape = 0, target
        size = {1: 2, 2: 2, 3: 4, 4: 8}[dtype]
        count = source_shape[0]*(source_shape[1] if len(source_shape) == 2 else 1)
        if name not in sources:
            raw = b''.join(rng.randrange(4096).to_bytes(size, 'little') for _ in range(count))
            sources[name] = dtype, source_shape, raw
        raw = sources[name][2]
        scalars = [raw[i:i+size] for i in range(0, len(raw), size)]
        if tag == 0:
            output = scalars
        elif tag == 3:
            output = scalars[part*shape.width:(part+1)*shape.width]
        else:
            rows = [scalars[i:i+source_shape[1]] for i in range(0, count, source_shape[1])]
            if tag == 2:
                rows = [row[part*shape.width:(part+1)*shape.width] for row in rows]
            output = [value for column in zip(*rows) for value in column]
        expected.append(b''.join(output))
        entries.append(Entry(name, dtype, source_shape, tag, part))
    aliases = (('published_head', 0),) if shape.family == 0 and rng.randrange(2) else ()
    if aliases:
        sources['published_head'] = sources[entries[0].name]
    sources['buffer'] = ('opaque',)  # Structural validation belongs to the container parser.
    mapping = SourceMap(shape, tuple(entries), aliases, ('buffer',))
    return mapping, sources, tuple(expected)


def controls(mapping, sources):
    raw = mapping.encode()
    for i in range(len(raw)):
        rejects(lambda i=i: decode(raw[:i]))
    rejects(lambda: decode(raw+b'\0'), 'Noncanonical')
    rejects(lambda: decode(b'X'+raw[1:]), 'Header')
    rejects(lambda: replace(mapping, entries=mapping.entries[:-1]).encode(), 'Roles')
    rejects(lambda: replace(mapping, entries=mapping.entries+(mapping.entries[-1],)).encode(), 'Roles')
    rejects(lambda: replace(mapping, ignored=('buffer', 'buffer')).encode(), 'Ignored')
    rejects(lambda: replace(mapping, ignored=('z', 'a')).encode(), 'Ignored')
    rejects(lambda: replace(mapping, ignored=(mapping.entries[0].name,)).encode(), 'Ignored')
    rejects(lambda: replace(mapping, aliases=(('head', 1),)).encode(), 'Alias')
    rejects(lambda: replace(mapping, aliases=((mapping.entries[0].name, 0),)).encode(), 'Alias')
    rejects(lambda: replace(mapping.shape, family=True), 'Family')
    rejects(lambda: replace(mapping.entries[0], name='\ud800').encode(), 'Name')
    rejects(lambda: replace(mapping.entries[0], part=0).encode(), 'InactivePart')
    rejects(lambda: replace(mapping.entries[0], dtype=True).encode(), 'Dtype')
    rejects(lambda: mapping.extract({**sources, 'extra': sources[mapping.entries[0].name]}), 'SourceSet')
    missing = dict(sources)
    del missing[mapping.entries[0].name]
    rejects(lambda: mapping.extract(missing), 'SourceSet')
    for index, entry in enumerate(mapping.entries):
        if entry.transform in (2, 3):
            changed = list(mapping.entries)
            changed[index] = replace(entry, part=(entry.part+1) % 3)
            rejects(lambda: replace(mapping, entries=tuple(changed)).encode(), 'PartRole')
            changed[index] = replace(entry, name=entry.name+'.split')
            rejects(lambda: replace(mapping, entries=tuple(changed)).encode(), 'Partition')
            changed[index] = replace(entry, dtype=entry.dtype % 4+1)
            rejects(lambda: replace(mapping, entries=tuple(changed)).encode(), 'Partition')
    with_alias = replace(mapping, aliases=(('published_head', 0),))
    token = sources[mapping.entries[0].name]
    alias_sources = {**sources, 'published_head': token}
    assert with_alias.extract(alias_sources) == mapping.extract(sources)
    changed = bytes([token[2][0] ^ 1])+token[2][1:]
    rejects(lambda: with_alias.extract({**alias_sources, 'published_head': (*token[:2], changed)}), 'AliasData')
    rejects(lambda: with_alias.extract({**alias_sources, 'published_head': (float(token[0]), *token[1:])}), 'AliasData')
    # A valid whole-field change creates a distinct map identity, not an authenticated old map.
    changed = replace(mapping, entries=(replace(mapping.entries[0], name='another_token'),)+mapping.entries[1:])
    assert decode(changed.encode()) == changed
    assert blake3(changed.encode()).digest() != blake3(raw).digest()


def main():
    rng, corpus = Random(2671), sha256()
    counts = {'GPT2': 0, 'Llama': 0, 'fused': 0, 'alias': 0}
    first = None
    for i in range(10000):
        family, heads, head_width = rng.randrange(2), rng.randrange(1, 4), rng.randrange(1, 4)
        width = heads*head_width
        groups = heads if family == 0 else rng.choice([g for g in range(1, heads+1) if heads % g == 0])
        shape = Shape(family, rng.randrange(1, 4), width, heads, groups, head_width,
                      4*width if family == 0 else rng.randrange(1, 17), rng.randrange(1, 9), rng.randrange(1, 9))
        fused = family == 0 and bool(rng.randrange(2))
        mapping, sources, expected = fixture(rng, shape, fused)
        assert shape.roles() == role_oracle(shape)
        raw = mapping.encode()
        assert raw == encode_oracle(mapping)
        assert decode(raw) == mapping
        assert mapping.extract(sources) == expected
        counts['GPT2' if family == 0 else 'Llama'] += 1
        counts['fused'] += fused
        counts['alias'] += bool(mapping.aliases)
        corpus.update(pack('<I', len(raw))+raw)
        for output in expected:
            corpus.update(pack('<I', len(output))+output)
        if first is None and fused:
            first = mapping, sources
    controls(*first)
    # Exact named architecture roles only: no checkpoint, inference or proof run.
    named = [Shape(0, 12, 768, 12, 12, 64, 3072, 50257, 1024),
             Shape(1, 32, 4096, 32, 8, 128, 14336, 128256, 131072)]
    assert [len(s.roles()) for s in named] == [196, 291]
    for shape in named:
        assert shape.roles() == role_oracle(shape)
    max_shape = Shape(1, 128, 16384, 128, 128, 128, 16384, 1 << 20, 1 << 20)
    assert len(max_shape.roles()) == 1155
    print(json.dumps({'seed': 2671, 'cases': 10000, 'counts': counts,
                      'corpus_sha256': corpus.hexdigest()}, sort_keys=True))


if __name__ == '__main__':
    main()
