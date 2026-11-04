"""RFC-0025 encoding §4: complete independent canonical rotary-data digests.

Python 3.12, python-flint==0.9.0 and blake3==1.0.11; no campaign main runs.
"""
from fractions import Fraction as Q
from hashlib import sha256
import json
from pathlib import Path
from struct import pack
import sys
from blake3 import blake3

if not __debug__:
    raise RuntimeError('reference assertions must remain enabled')
ROOT = Path(__file__).resolve().parents[4]
sys.path.insert(0, str(ROOT/'research/cqis-checkpoint'))
from check_rope import oracle
from rope import Parameters

cases = []
for mode in range(3):
    payloads = []
    for layout in range(2):
        p = Parameters(8, 33, Q(500000), ('base', 'linear', 'llama3')[mode],
            ('adjacent', 'split')[layout], Q(1 if mode == 0 else 8),
            Q(1 if mode == 2 else 0), Q(4 if mode == 2 else 0), 8192 if mode == 2 else 0)
        descriptor = b'stele/v0.1/cqis/rotation'+pack('<HIBBI', p.width, p.length, mode, layout, p.original)
        descriptor += b''.join(pack('<QQ', v.numerator, v.denominator) for v in (p.base, p.factor, p.low, p.high))
        payload = b''.join(pack('<hh', *(v[0] for v in oracle(p, t, j)))
                           for t in range(p.length) for j in range(p.width//2))
        payloads.append(payload)
        frame = b'stele/v0.1/cqis/rotation-data'+blake3(descriptor).digest()+payload
        cases.append(dict(descriptor=descriptor.hex(), digest=blake3(frame).hexdigest(), pairs=132))
    assert payloads[0] == payloads[1]
descriptor = b'stele/v0.1/cqis/rotation'+pack('<HIBBI', 16384, 1, 0, 0, 0)
descriptor += b''.join(pack('<QQ', n, d) for n, d in ((500000, 1), (1, 1), (0, 1), (0, 1)))
frame = b'stele/v0.1/cqis/rotation-data'+blake3(descriptor).digest()+pack('<hh', 16384, 0)*8192
cases.append(dict(descriptor=descriptor.hex(), digest=blake3(frame).hexdigest(), pairs=8192))
receipt = dict(cases=cases, oracle_source_sha256=sha256((ROOT/'research/cqis-checkpoint/check_rope.py').read_bytes()).hexdigest())
(ROOT/'crates/stele-cqis/tests/fixtures/rotary-data.json').write_text(json.dumps(receipt, indent=2)+'\n')
print(json.dumps(receipt))
