"""Draft RFC-0025 encoding §§1–2: closed physical roles and raw source transforms."""
from dataclasses import dataclass

from numerics import integer

PREFIX = b'stele/v0.1/cqis/source-map'
LIMIT = 1 << 24


def name_bytes(name):
    if type(name) is not str or '\0' in name:
        raise ValueError('Name')
    try:
        value = name.encode('utf8')
    except UnicodeError as error:
        raise ValueError('Name') from error
    if not 1 <= len(value) <= 4096:
        raise ValueError('Name')
    return value


def uint(value, size):
    integer(value, 0, (1 << (8*size))-1, 'Integer')
    return value.to_bytes(size, 'little')


def named(value):
    raw = name_bytes(value)
    return uint(len(raw), 2)+raw


@dataclass(frozen=True)
class Shape:
    family: int
    layers: int
    width: int
    heads: int
    groups: int
    head_width: int
    hidden: int
    vocabulary: int
    context: int

    def __post_init__(self):
        integer(self.family, 0, 1, 'Family')
        for value, maximum in ((self.layers, 128), (self.width, 16384),
                               (self.heads, 128), (self.groups, 128),
                               (self.head_width, 16384), (self.hidden, 16384),
                               (self.vocabulary, 1 << 20), (self.context, 1 << 20)):
            integer(value, 1, maximum, 'Shape')
        if self.heads*self.head_width != self.width or self.heads % self.groups:
            raise ValueError('Heads')
        if self.family == 0 and (self.groups != self.heads or self.hidden != 4*self.width):
            raise ValueError('GPT2')

    def encode(self):
        return uint(self.family, 1)+b''.join(uint(x, 2) for x in (
            self.layers, self.width, self.heads, self.groups, self.head_width, self.hidden)
        )+uint(self.vocabulary, 4)+uint(self.context, 4)

    def roles(self):
        """Each tuple is (role label, layer, shape); no caller-provided role set."""
        d, f, g, a = self.width, self.hidden, self.groups, self.head_width
        roles = [('token', -1, (self.vocabulary, d))]
        if self.family == 0:
            roles.append(('position', -1, (self.context, d)))
        for layer in range(self.layers):
            roles.append(('norm1.gain', layer, (d,)))
            if self.family == 0:
                roles.append(('norm1.bias', layer, (d,)))
            matrices = [('Q', d, d), ('K', g*a, d), ('V', g*a, d), ('O', d, d), ('up', f, d)]
            if self.family == 1:
                matrices.append(('gate', f, d))
            matrices.append(('down', d, f))
            for role, output, inner in matrices:
                roles.append((role, layer, (output, inner)))
                if self.family == 0:
                    roles.append((role+'.bias', layer, (output,)))
            roles.append(('norm2.gain', layer, (d,)))
            if self.family == 0:
                roles.append(('norm2.bias', layer, (d,)))
        roles.append(('final.gain', -1, (d,)))
        roles.append(('final.bias', -1, (d,)) if self.family == 0 else
                     ('head', -1, (self.vocabulary, d)))
        return tuple(roles)


@dataclass(frozen=True)
class Entry:
    name: str
    dtype: int
    shape: tuple
    transform: int
    part: int | None = None

    def encode(self):
        name_bytes(self.name)
        integer(self.dtype, 1, 4, 'Dtype')
        integer(self.transform, 0, 3, 'Transform')
        if type(self.shape) is not tuple or len(self.shape) not in (1, 2):
            raise ValueError('SourceShape')
        count = 1
        for dimension in self.shape:
            integer(dimension, 1, (1 << 32)-1, 'SourceShape')
            count *= dimension
        if count*(2, 2, 4, 8)[self.dtype-1] >= 1 << 64:
            raise ValueError('SourceLength')
        raw = (named(self.name)+uint(self.dtype, 1)+uint(len(self.shape), 1)+
               b''.join(uint(d, 4) for d in self.shape)+uint(self.transform, 1))
        if self.transform in (2, 3):
            integer(self.part, 0, 2, 'Part')
            return raw+uint(self.part, 1)
        if self.part is not None:
            raise ValueError('InactivePart')
        return raw


@dataclass(frozen=True)
class SourceMap:
    shape: Shape
    entries: tuple
    aliases: tuple = ()
    ignored: tuple = ()

    def encode(self):
        if type(self.shape) is not Shape or type(self.entries) is not tuple:
            raise ValueError('Map')
        roles = self.shape.roles()
        if len(self.entries) != len(roles):
            raise ValueError('Roles')
        selected = {}
        chunks = [PREFIX, uint(len(self.shape.encode()), 4), self.shape.encode()]
        for entry, (role, layer, dimensions) in zip(self.entries, roles):
            if type(entry) is not Entry:
                raise ValueError('Entry')
            chunks.append(entry.encode())
            selected.setdefault(entry.name, []).append((entry, role, layer))
            if entry.transform == 0:
                expected = dimensions
            elif entry.transform == 1 and len(dimensions) == 2 and role not in ('token', 'position'):
                expected = dimensions[::-1]
            elif self.shape.family == 0 and entry.transform in (2, 3):
                matrix = role.removesuffix('.bias')
                if matrix not in ('Q', 'K', 'V') or entry.part != ('Q', 'K', 'V').index(matrix):
                    raise ValueError('PartRole')
                if (entry.transform == 3) != role.endswith('.bias'):
                    raise ValueError('PartRole')
                expected = ((self.shape.width, 3*self.shape.width) if entry.transform == 2 else
                            (3*self.shape.width,))
            else:
                raise ValueError('TransformRole')
            if entry.shape != expected:
                raise ValueError('SourceShape')
        for uses in selected.values():
            first = uses[0][0]
            if first.transform in (2, 3):
                if (len(uses) != 3 or {e.part for e, _, _ in uses} != {0, 1, 2} or
                    any((e.dtype, e.shape, e.transform, layer) !=
                        (first.dtype, first.shape, first.transform, uses[0][2]) for e, _, layer in uses)):
                    raise ValueError('Partition')
            elif len(uses) != 1:
                raise ValueError('Alias')
        if type(self.aliases) is not tuple or len(self.aliases) > (1 if self.shape.family == 0 else 0):
            raise ValueError('Alias')
        chunks.append(uint(len(self.aliases), 4))
        used = set(selected)
        for alias in self.aliases:
            if type(alias) is not tuple or len(alias) != 2:
                raise ValueError('Alias')
            name, target = alias
            name_bytes(name)
            integer(target, 0, 0, 'Alias')
            if name in used or self.entries[0].transform != 0:
                raise ValueError('Alias')
            used.add(name)
            chunks.append(named(name)+uint(target, 2))
        if type(self.ignored) is not tuple:
            raise ValueError('Ignored')
        raw_names = [name_bytes(name) for name in self.ignored]
        if raw_names != sorted(set(raw_names)) or used.intersection(self.ignored):
            raise ValueError('Ignored')
        chunks.append(uint(len(self.ignored), 4))
        chunks.extend(named(name) for name in self.ignored)
        if sum(map(len, chunks)) > LIMIT:
            raise ValueError('Capacity')
        return b''.join(chunks)

    def extract(self, sources):
        """Prototype retains bytes; no streaming, native-resource or proof claim."""
        self.encode()
        if type(sources) is not dict:
            raise ValueError('Sources')
        expected = {e.name for e in self.entries} | {n for n, _ in self.aliases} | set(self.ignored)
        if set(sources) != expected:
            raise ValueError('SourceSet')
        output = []
        for entry, (_, _, target) in zip(self.entries, self.shape.roles()):
            source = sources[entry.name]
            if type(source) is not tuple or len(source) != 3 or source[:2] != (entry.dtype, entry.shape):
                raise ValueError('SourceMetadata')
            # Reject bool/float aliases even when Python tuple equality would accept them.
            dtype, dimensions, raw = source
            if (type(dtype) is not int or type(dimensions) is not tuple or
                any(type(d) is not int for d in dimensions) or type(raw) is not bytes):
                raise ValueError('SourceMetadata')
            size = (2, 2, 4, 8)[entry.dtype-1]
            count = 1
            for dimension in entry.shape:
                count *= dimension
            if len(raw) != count*size:
                raise ValueError('SourceLength')
            if entry.transform == 0:
                result = raw
            elif entry.transform == 3:
                offset = entry.part*target[0]*size
                result = raw[offset:offset+target[0]*size]
            else:
                columns = entry.shape[1]
                start = entry.part*target[0] if entry.transform == 2 else 0
                result = b''.join(raw[(i*columns+start+o)*size:(i*columns+start+o+1)*size]
                                  for o in range(target[0]) for i in range(target[1]))
            output.append(result)
        for name, target in self.aliases:
            alias = sources[name]
            original = sources[self.entries[target].name]
            if (type(alias) is not tuple or len(alias) != 3 or type(alias[0]) is not int or
                type(alias[1]) is not tuple or any(type(d) is not int for d in alias[1]) or
                type(alias[2]) is not bytes or alias != original):
                raise ValueError('AliasData')
        return tuple(output)


def decode(raw):
    if type(raw) is not bytes or len(raw) > LIMIT:
        raise ValueError('Capacity')
    offset = 0

    def take(n):
        nonlocal offset
        if n > len(raw)-offset:
            raise ValueError('Truncated')
        result = raw[offset:offset+n]
        offset += n
        return result

    def number(size):
        return int.from_bytes(take(size), 'little')

    def name():
        length = number(2)
        if not 1 <= length <= 4096:
            raise ValueError('Name')
        try:
            return take(length).decode('utf8')
        except UnicodeError as error:
            raise ValueError('Name') from error

    if take(len(PREFIX)) != PREFIX or number(4) != 21:
        raise ValueError('Header')
    shape = Shape(number(1), *(number(2) for _ in range(6)), number(4), number(4))
    entries = []
    for _ in shape.roles():
        source, dtype, rank = name(), number(1), number(1)
        if rank not in (1, 2):
            raise ValueError('SourceShape')
        dimensions = tuple(number(4) for _ in range(rank))
        transform = number(1)
        part = number(1) if transform in (2, 3) else None
        entries.append(Entry(source, dtype, dimensions, transform, part))
    count = number(4)
    if count > (1 if shape.family == 0 else 0):
        raise ValueError('Alias')
    aliases = tuple((name(), number(2)) for _ in range(count))
    count = number(4)
    if count > (len(raw)-offset)//3:
        raise ValueError('Capacity')
    ignored = tuple(name() for _ in range(count))
    result = SourceMap(shape, tuple(entries), aliases, ignored)
    if result.encode() != raw:
        raise ValueError('Noncanonical')
    return result
