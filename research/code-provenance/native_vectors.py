"""RFC-0010 A4 native KATs from the materialized map, not bounded traversal.

Run: uv run --with blake3==1.0.11 python3 research/code-provenance/native_vectors.py
The row is full-K canonical limbs (17*i+29*limb+1) mod p; seed is J || 31 zeros.
Digests cover every output limb in canonical little-endian order.
"""
import struct
from blake3 import blake3
from sampler import manifest, materialize
from recursive import encode_row, sc

print('# RFC-0010 A4: J degree BLAKE3(canonical complete codeword)')
for j in (3, 4, 5):
    setup, _ = materialize(manifest(bytes([j])+bytes(31), j))
    for d in (1, 4, 8):
        row = [tuple((17*i+29*k+1) % sc.P for k in range(d)) for i in range(4**j)]
        word, _ = encode_row(setup, row)
        raw = b''.join(struct.pack('<I', limb) for value in word for limb in value)
        print(j, d, blake3(raw).hexdigest())
