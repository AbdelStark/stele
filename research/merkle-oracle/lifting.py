"""Q27 classical hash-log model, never imported by a native verifier."""
import struct
from blake3 import blake3


class RecordedHash:
    """Record distinct full-input calls; symbolic functions isolate bad events."""

    def __init__(self, function=None):
        self.function = function or (lambda data: blake3(data).digest())
        self.log = {}

    def __call__(self, data):
        if data not in self.log:
            value = self.function(data)
            assert isinstance(value, bytes) and len(value) == 32
            self.log[data] = value
        return self.log[data]


def frames(spec, level, index, payload):
    """Exact RFC-0012 A3 column-domain bytes, including absent tree padding."""
    if spec.kind != 0:
        raise ValueError('InvalidTree')
    header = spec.header()
    if level == 0:
        return b'\x00'+header+struct.pack('<QB', index, index < spec.count)+payload
    return b'\x01'+header+struct.pack('<IQ', level, index)+payload


def field_column(payload):
    if not payload or len(payload) % 4:
        raise ValueError('InvalidLeaf')
    values = tuple(int.from_bytes(payload[i:i+4], 'little') for i in range(0, len(payload), 4))
    if any(x >= 2**31-1 for x in values):
        raise ValueError('NoncanonicalField')
    return values


def complete(spec, root, frozen):
    """Define a fixed total oracle without new hash queries; proof device only."""
    height = spec.height()
    if spec.kind != 0 or spec.width % 4:
        raise ValueError('InvalidTree')
    inverse = {value: data for data, value in frozen.items()}
    if len(inverse) != len(frozen):
        raise ValueError('Collision')
    columns = [(0,)*(spec.width//4) for _ in range(spec.count)]
    frontier = set()

    def visit(digest, level, index):
        if index << level >= spec.count:
            return
        data = inverse.get(digest)
        if data is None:
            frontier.add(digest)
            return
        prefix = frames(spec, level, index, b'')
        size = spec.width if level == 0 else 64
        if not data.startswith(prefix) or len(data) != len(prefix)+size:
            return
        payload = data[len(prefix):]
        if level:
            visit(payload[:32], level-1, 2*index)
            visit(payload[32:], level-1, 2*index+1)
        else:
            try:
                columns[index] = field_column(payload)
            except ValueError:
                pass  # A malformed known leaf is zero only in this proof device.

    visit(root, height, 0)
    return tuple(columns), frontier


def verify(spec, root, index, payload, siblings, h):
    """Small authenticated-column model; no missing-column or decode fallback."""
    height = spec.height()
    if not 0 <= index < spec.count:
        raise ValueError('InvalidIndex')
    if len(payload) != spec.width:
        raise ValueError('InvalidLeaf')
    if len(root) != 32 or len(siblings) != height or any(len(s) != 32 for s in siblings):
        raise ValueError('InvalidPath')
    column = field_column(payload)
    digest = h(frames(spec, 0, index, payload))
    for level, sibling in enumerate(siblings, 1):
        pair = sibling+digest if index & 1 else digest+sibling
        index >>= 1
        digest = h(frames(spec, level, index, pair))
    if digest != root:
        raise ValueError('RootMismatch')
    return column
