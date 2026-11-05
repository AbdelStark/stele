"""RFC-0025 static/flow appendices: bounded native fixture generation.

Calls only the qualified pure derivations; no historical campaign main.
Python 3.12 and blake3==1.0.11. Records are metadata, not proof admission.
"""
from dataclasses import asdict
from hashlib import sha256
import json
from math import gcd
from pathlib import Path
from random import Random
from struct import pack
import sys
from blake3 import blake3

ROOT = Path(__file__).resolve().parents[4]
sys.path.insert(0, str(ROOT/'research/cqis-model-contract'))
from arithmetic_bounds import Affine, Embedding, encode as arithmetic
from flow_bounds import Row, Residual, Gated, encode as flow
from numerics import LayerNorm
from rms_bounds import RMSNorm, encode as rms

rng = Random(50337)
cases, complete = [], bytearray()


def add(p, full=False):
    encoder = arithmetic if type(p) in (Affine, Embedding, LayerNorm) else rms if type(p) is RMSNorm else flow
    raw = encoder(p)
    cases.append(dict(kind=type(p).__name__, parameters=asdict(p),
                      length=len(raw), digest=blake3(raw).hexdigest(), complete=full))
    if full:
        complete.extend(pack('<I', len(raw)))
        complete.extend(raw)


for kind in (0, 1):
    for policy in (0, 1):
        scale = (8454661 if kind else 65535) if policy else 0
        add(Row(16384, kind, 44 if kind else 30, policy, scale), True)
        for biased in (None, 30):
            add(Affine(16384, 8, -1099, 65535, kind, 44 if kind else 30,
                       0, policy, scale, biased), True)
add(Affine(1, 4, 1024, 1, 0, 0, 30, 1, 1, 0), True)
for position in (None, (8, 1024, 65535), (4, -1099, 1)):
    add(Embedding(1 << 20, 1 << 20, 30, 8, -1099, 65535, position), True)
for p in (Residual(1, 0, 30, 14), Residual(16384, 30, 30, 0),
          Residual(1, 0, 0, 0), Gated(1, 0, 0), Gated(16384, 30, 14)):
    add(p, True)

for _ in range(256):
    kind, policy = rng.randrange(2), rng.randrange(2)
    scale = rng.randint(1, 8454661 if kind else 65535) if policy else 0
    add(Affine(rng.randint(1, 16384), rng.choice((4, 8)), rng.randint(-1099, 1024),
               rng.randint(1, 65535), kind, rng.randint(0, 44 if kind else 30),
               rng.randint(0, 30), policy, scale, rng.choice((None, rng.randint(0, 30)))))
    weight = lambda: (rng.choice((4, 8)), rng.randint(-1099, 1024), rng.randint(1, 65535))
    add(Embedding(rng.randint(1, 1 << 20), rng.randint(1, 1 << 20), rng.randint(0, 30),
                  *weight(), rng.choice((None, weight()))))
    add(Row(rng.randint(1, 16384), kind, rng.randint(0, 44 if kind else 30), policy, scale))
    add(Residual(rng.randint(1, 16384), *(rng.randint(0, 30) for _ in range(3))))
    add(Gated(rng.randint(1, 16384), rng.randint(0, 30), rng.randint(0, 14)))

for d in (1, 16384):
    for F, G, E, Gb in ((0, 0, 14, 30), (30, 30, 0, 0)):
        add(LayerNorm(d, F, G, E, Gb, (1 << 32)-1, (1 << 32)-2), True)
        add(RMSNorm(d, F, G, E, (1 << 32)-1, (1 << 32)-2), True)
for _ in range(128):
    d, F, G, E = rng.randint(1, 16384), rng.randint(0, 30), rng.randint(0, 30), rng.randint(0, 14)
    en, ed = rng.randint(1, (1 << 32)-1), rng.randint(1, (1 << 32)-1)
    divisor = gcd(en, ed); en //= divisor; ed //= divisor
    add(LayerNorm(d, F, G, E, rng.randint(0, 30), en, ed))
    add(RMSNorm(d, F, G, E, en, ed))

out = ROOT/'crates/stele-cqis/tests/fixtures'
paths = ['research/cqis-model-contract/'+p for p in ('arithmetic_bounds.py', 'flow_bounds.py', 'numerics.py', 'rms_bounds.py')]
receipt = dict(seed=50337, sources={p:sha256((ROOT/p).read_bytes()).hexdigest() for p in paths},
               complete_sha256=sha256(complete).hexdigest(), cases=cases)
(out/'arithmetic-records.bin').write_bytes(complete)
(out/'arithmetic-records.json').write_text(json.dumps(receipt, separators=(',', ':'))+'\n')
print(json.dumps(dict(records=len(cases), complete=sum(c['complete'] for c in cases),
                     bytes=len(complete), sha256=receipt['complete_sha256'])))
