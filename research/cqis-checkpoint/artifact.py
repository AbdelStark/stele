"""Q26 research-only ordered weight artifact, not an admitted passport format."""
from blake3 import blake3
import records as r
from quantiser import require

CONFIG = b'stele/research/q26/quantiser/v1'
DATA = b'stele/research/q26/weights/v1'


def ordered(specs):
    require(type(specs) is list and 1 <= len(specs) < 1 << 32, 'Count')
    for spec in specs: r.config(spec)
    result = sorted(specs,key=lambda spec:spec.name.encode('ascii'))
    require(all(a.name != b.name for a,b in zip(result,result[1:])), 'Duplicate')
    return result


def configuration(specs):
    entries = [r.config(spec) for spec in ordered(specs)]
    return CONFIG+len(entries).to_bytes(4,'little')+b''.join(len(c).to_bytes(4,'little')+c for c in entries)


def quantiser_id(specs):
    """Identity of this exact candidate offline conversion algorithm/configuration."""
    return blake3(configuration(specs)).digest()


def record_size(spec):
    descriptor = r.config(spec)
    scales = 0 if spec.bits == 16 else 2+2*spec.shape[spec.parameter]
    total = len(r.DATA)+4+len(descriptor)+scales+8+r.length(spec)
    require(total <= r.MAX_LENGTH, 'Capacity')
    return total


def chunks(specs, records):
    """Validate/snapshot all records before returning an iterator of immutable bytes."""
    specs = ordered(specs)
    require(type(records) is dict and set(records) == {s.name for s in specs}, 'RecordSet')
    values = tuple(records[s.name] for s in specs)
    segments = [DATA+quantiser_id(specs)+len(specs).to_bytes(4,'little')]
    total = len(segments[0])
    for spec,raw in zip(specs,values):
        expected = record_size(spec)
        r.parse(spec,raw)
        require(len(raw) == expected, 'RecordLength')
        total += 8+expected
        require(total <= r.MAX_LENGTH, 'Capacity')
        segments.extend([expected.to_bytes(8,'little'),raw])
    return iter(segments)


def assemble(specs, records):
    """Join valid physical records; this does not check source provenance/minimality."""
    return b''.join(chunks(specs,records))


def prepare(specs, source):
    """Derive every record from exactly the selected raw source tensors."""
    specs = ordered(specs)
    require(type(source) is dict and set(source) == {s.name for s in specs}, 'SourceSet')
    records = {spec.name:r.prepare(spec,source[spec.name]) for spec in specs}
    return assemble(specs,records)


def parse(specs, raw):
    specs = ordered(specs)
    require(type(raw) is bytes, 'Bytes')
    require(len(raw) <= r.MAX_LENGTH, 'Capacity')
    position = 0

    def take(n):
        nonlocal position
        require(n <= len(raw)-position, 'Truncated')
        out = raw[position:position+n]
        position += n
        return out

    require(take(len(DATA)) == DATA, 'Prefix')
    require(take(32) == quantiser_id(specs), 'Quantiser')
    require(int.from_bytes(take(4),'little') == len(specs), 'Count')
    records = {}
    for spec in specs:
        expected = record_size(spec)
        require(int.from_bytes(take(8),'little') == expected, 'RecordLength')
        record = take(expected)
        r.parse(spec,record)
        records[spec.name] = record
    require(position == len(raw), 'Trailing')
    return records


def digest(specs, raw):
    """Content hash only after canonical syntax/configuration checks."""
    parse(specs,raw)
    return blake3(raw).digest()
