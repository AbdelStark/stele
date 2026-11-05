"""RFC-0025 schemas7–13/15–19: bounded fixtures from qualified pure derivations.

Python3.12, blake3==1.0.11; no historical campaign mains or proof admission.
"""
from dataclasses import replace
from hashlib import sha256
import json
from math import gcd
from pathlib import Path
from random import Random
from struct import pack, unpack_from
import sys
from blake3 import blake3

ROOT = Path(__file__).resolve().parents[4]
sys.path.insert(0, str(ROOT/'research/cqis-model-contract'))
import attention_input_bounds as attention
import function_bounds as function
import weighted_bounds as weighted
import decoding_bounds as decoding
import request_bounds as request
import physical_bounds as physical
from source_map import Shape

rng = Random(50339)
cases, rejected, complete = [], [], bytearray()
prefix = b'stele/v0.1/cqis/model-arithmetic'


def rejection_parameters(p):
    if type(p) is attention.Score:
        return 8, pack('<3HI4BHBHHb', p.h, p.g, p.w, p.n, p.fq, p.fk, p.f, p.qm, p.qs, p.km, p.ks, p.m, p.e)
    s = p.source if type(p) is weighted.Normalize else p
    raw = pack('<3HI3BH2B', s.h, s.g, s.w, s.n, s.f, s.E, s.policy, s.scale, s.mode, s.drop)
    return (13, raw+bytes((p.fo,))) if type(p) is weighted.Normalize else (12, raw)


def add(module, p, full=False):
    try:
        raw = module.encode(p)
    except ValueError as error:
        assert str(error) in ('ScoreBound', 'BlockBound')
        schema, params = rejection_parameters(p)
        rejected.append(dict(schema=schema, parameters=params.hex(), error=str(error)))
        return
    schema = raw[len(prefix)+4]
    length = unpack_from('<H', raw, len(prefix)+5)[0]
    params = raw[len(prefix)+7:len(prefix)+7+length]
    case = dict(schema=schema, parameters=params.hex(), length=len(raw), digest=blake3(raw).hexdigest(), complete=full)
    if schema == 8: case['score_bound'] = module.derive(p)[1][22]
    cases.append(case)
    if full: complete.extend(pack('<I', len(raw))+raw)


for layout in (0, 1):
    add(attention, attention.Rotation(1, 16384, 16384, 1 << 20, layout, 30), True)
    add(attention, attention.Rotation(128, 3, 2, 1, layout, 0), True)
for scale in (32767, 32768):
    add(attention, attention.Score(1, 1, 1, 1, 0, 0, 0, 1, scale, 1, scale, 2, 0), True)
for bound in (0, (1 << 31)-1):
    add(attention, attention.Maximum(1 << 20, bound, 31, 30), True)
for mode, bits, k in ((0, 15, 0), (1, 31, 16), (1, 7, 1), (2, 15, 15)):
    add(function, function.Exponential(1 << 20, bits, 30, 14, mode, k), True)
for kind in range(5):
    add(function, function.Activation(16384, kind, 30, 14, 65535 if kind == 2 else 0, 30 if kind == 2 else 0), True)
for n, scale, mode, drop in ((1, 32767, 1, 10), (1, 32768, 1, 10), (1024, 32768, 1, 10),
                              (1 << 20, 65535, 0, 0), (1025, 65535, 1, 62)):
    p = weighted.Weighted(128, 8, 128, n, 30, 0 if drop == 10 else 14, 1, scale, mode, drop)
    add(weighted, p, True)
    add(weighted, weighted.Normalize(p, 0 if mode == 0 else 30), True)
for v in (1, 1 << 20):
    add(decoding, decoding.Logits(v, 30), True)
    add(decoding, decoding.Sampling(v, 14, (1 << 32)-2, (1 << 32)-1), True)
    for mode in (0, 1): add(request, request.Spec(v, 1 << 20, mode), True)
for tn, td in ((1, (1 << 32)-1), ((1 << 32)-1, 1)):
    add(decoding, decoding.Temperature(30, tn, td, function.Exponential(1 << 20, 31, 30, 14, 1, 16)), True)

for _ in range(128):
    h = rng.randint(1, 128); g = rng.choice([v for v in range(1, h+1) if h % v == 0])
    w, n = rng.randint(2, 16384//h), rng.randint(1, 1 << 20)
    add(attention, attention.Rotation(h, w, 2*rng.randint(1, w//2), n, rng.randrange(2), rng.randint(0, 30)))
    policy = lambda: (1, rng.randint(1, 65535)) if rng.randrange(2) else (0, 0)
    qm, qs = policy(); km, ks = policy()
    add(attention, attention.Score(h, g, w, n, rng.randint(0, 30), rng.randint(0, 30), rng.randint(0, 30), qm, qs, km, ks, rng.randint(1, 65535), rng.randint(-62, 30)))
    add(attention, attention.Maximum(n, rng.randrange(1 << 31), rng.randint(7, 31), rng.randint(0, 30)))
    mode = rng.randrange(3); bits = rng.randint(7, 31 if mode == 1 else 15)
    exp = function.Exponential(n, bits, rng.randint(0, 30), rng.randint(0, 14), mode,
                               rng.randint(max(1, bits-15), min(16, bits)) if mode else 0)
    add(function, exp)
    kind = rng.randrange(5)
    add(function, function.Activation(rng.randint(1, 16384), kind, rng.randint(0, 30), rng.randint(0, 14),
                                     2*rng.randrange(32768)+1 if kind == 2 else 0, rng.randint(0, 30) if kind == 2 else 0))
    mode = rng.randrange(2); pm, ps = policy()
    p = weighted.Weighted(h, g, w, n, rng.randint(0, 30), rng.randint(0, 14), pm, ps, mode, rng.randint(0, 62) if mode else 0)
    add(weighted, p); add(weighted, weighted.Normalize(p, rng.randint(0, 30)))
    a, b = rng.randint(1, (1 << 32)-1), rng.randint(1, (1 << 32)-1)
    divisor = gcd(a, b); a //= divisor; b //= divisor
    add(decoding, decoding.Logits(n, rng.randint(0, 30)))
    add(decoding, decoding.Temperature(rng.randint(0, 30), a, b, exp))
    add(decoding, decoding.Sampling(n, rng.randint(0, 14), min(a, b), max(a, b)))
    add(request, request.Spec(n, rng.randint(1, 1 << 20), rng.randrange(2)))

shapes = [Shape(0, 12, 768, 12, 12, 64, 3072, 50257, 1024),
          Shape(1, 32, 4096, 32, 8, 128, 14336, 128256, 131072),
          Shape(0, 128, 4096, 128, 128, 32, 16384, 1 << 20, 1 << 20),
          Shape(1, 128, 16384, 128, 128, 128, 16384, 1 << 20, 1 << 20),
          Shape(0, 1, 1, 1, 1, 1, 4, 3, 3), Shape(1, 1, 1, 1, 1, 1, 3, 3, 3)]
for index, shape in enumerate(shapes):
    roles = shape.roles()
    ordinals = range(len(roles)) if index < 2 or index >= 4 else [0, 1, 2, len(roles)-1]
    for ordinal in ordinals:
        matrix = len(roles[ordinal][2]) == 2
        for bits in ((4, 8) if matrix else (16,)):
            p = physical.Physical(shape, ordinal, bits, 0 if matrix else 30)
            add(physical, p, index >= 2 and ordinal == 0)
    add(physical, physical.Physical(shape, next(i for i, r in enumerate(roles) if len(r[2]) == 1), 16, 0), index >= 2)

out = ROOT/'crates/stele-cqis/tests/fixtures'
names = ['arithmetic_bounds.py','attention_input_bounds.py','function_bounds.py','weighted_bounds.py',
         'decoding_bounds.py','request_bounds.py','physical_bounds.py','source_map.py','numerics.py']
receipt = dict(seed=50339, sources={'research/cqis-model-contract/'+p:sha256((ROOT/'research/cqis-model-contract'/p).read_bytes()).hexdigest() for p in names},
               complete_sha256=sha256(complete).hexdigest(), cases=cases, rejected=rejected)
(out/'extended-arithmetic.bin').write_bytes(complete)
(out/'extended-arithmetic.json').write_text(json.dumps(receipt, separators=(',', ':'))+'\n')
print(json.dumps(dict(records=len(cases), rejected=len(rejected), complete=sum(c['complete'] for c in cases), bytes=len(complete))))
