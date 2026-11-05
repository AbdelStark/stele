"""RFC-0021 A3: golden metadata from the qualified RFC-0025 Python helpers.

Run with Python 3.12 and blake3==1.0.11; stdout is layernorm-descriptors.json.
Only pure framing/table helpers run, never a historical campaign main.
"""
from hashlib import sha256
import json
from pathlib import Path
from struct import pack
import sys

from blake3 import blake3

if not __debug__:
    raise RuntimeError('reference assertions must remain enabled')

ROOT = Path(__file__).resolve().parents[4]
sys.path.insert(0, str(ROOT / 'research/cqis-model-contract'))
from check_model_codec import selection
from model_codec import function_frames, fn
from numerics import LayerNorm
from rms_bounds import RMSNorm

cases = [(1, 0, 0, 0, 0, 1, 1), (768, 8, 8, 8, 8, 1, 100000),
         (16384, 30, 30, 14, 30, 4294967295, 4294967294),
         (8, 8, 8, 8, 30, 1, 100000)]
vectors = []
for parameters in cases:
    value = LayerNorm(*parameters)
    descriptor, representation = function_frames(value)
    assert selection(value) == (pack('<I', len(descriptor)) + descriptor
                               + pack('<I', len(representation)) + representation)
    vectors.append(dict(parameters=pack('<HBBBBII', *parameters).hex(),
                        descriptor=descriptor.hex(), function_id=blake3(descriptor).hexdigest(),
                        representation=representation.hex(),
                        representation_id=blake3(representation).hexdigest()))

norms = [LayerNorm(*cases[1]), RMSNorm(768, 8, 8, 8, 1, 100000)]
frames = sorted((function_frames(n) for n in norms), key=lambda pair: blake3(pair[0]).digest())
manifest = fn.MANIFEST + pack('<I', len(frames))
for pair in frames:
    for raw in pair:
        manifest += pack('<H', len(raw)) + raw
table = fn.table.Descriptor('rsqrt_q', 1, b'')
raw = fn.table.encode(table)
manifest += pack('<IH', 1, len(raw)) + raw + blake3(fn.table.encode_data(table)).digest()
sources = ['research/cqis-model-contract/' + p for p in
           ('check_model_codec.py', 'model_codec.py', 'numerics.py', 'rms_bounds.py')]
print(json.dumps(dict(sources={p: sha256((ROOT / p).read_bytes()).hexdigest() for p in sources},
                      vectors=vectors, manifest=manifest.hex()), indent=2))
