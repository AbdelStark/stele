"""RFC-0025 encoding §5: frozen native fixtures, without campaign main execution.

Run with Python 3.12 and blake3==1.0.11. Large cases store expected digests only.
"""
from hashlib import sha256
import json
from pathlib import Path
from random import Random
from struct import pack, unpack_from
import sys

from blake3 import blake3

if not __debug__:
    raise RuntimeError('reference assertions must remain enabled')
ROOT = Path(__file__).resolve().parents[4]
sys.path.insert(0, str(ROOT / 'research/cqis-model-contract'))
from check_scales_codec import make_scales, matrices, oracle
from check_model_codec import make
from model_codec import decode as decode_model, encode as encode_model
from scales_codec import Scale, decode, encode
from source_map import Shape

out = ROOT / 'crates/stele-cqis/tests/fixtures'
data = (out / 'models.bin').read_bytes()
pos = 0


def take(n):
    global pos
    result = data[pos:pos+n]
    assert len(result) == n
    pos += n
    return result


def number(fmt):
    size = {'<I': 4, '<H': 2, '<B': 1}[fmt]
    return unpack_from(fmt, take(size))[0]


def blob():
    return take(number('<I'))


rng = Random(50332)
count = number('<I')
small = pack('<I', 66)
large = []
small_models = []
pattern = pack('<4H', 1, 65535, 32768, 255)
for case in range(count):
    model = decode_model(blob())
    take(32)
    for _ in range(number('<H')):
        blob(); take(2); take(4*number('<B'))
    if case >= 4:
        if case >= count-2:
            small_models.append(model)
        continue
    layout = matrices(model)
    scales = tuple(Scale(-1099 if j % 2 else 1024,
                    (pattern*((channels+3)//4))[:2*channels])
                    for j, (_, channels) in enumerate(layout))
    raw = encode(model, scales)
    assert raw == oracle(model, scales) and decode(model, raw) == scales
    identity = blake3(raw).digest()
    large.append(dict(case=case, matrices=len(layout),
                      channels=sum(n for _, n in layout),
                      length=len(raw), identity=identity.hex()))
assert pos == len(data)
for case in range(64):
    family = case % 2
    h = rng.randint(1, 4); a = rng.choice((2, 4, 8)); d = h*a
    shape = Shape(family, rng.randint(1, 4), d, h, h if family == 0 else 1, a,
                  4*d if family == 0 else rng.randint(1, 128),
                  rng.randint(1, 64), rng.randint(1, 64))
    small_models.append(make(rng, family, shape))
for model in small_models:
    model_raw = encode_model(model)
    scales = make_scales(rng, model)
    raw = encode(model, scales)
    assert raw == oracle(model, scales) and decode(model, raw) == scales
    small += pack('<I', len(model_raw)) + model_raw + pack('<I', len(raw)) + raw + blake3(raw).digest()
(out / 'scales.bin').write_bytes(small)
paths = ['research/cqis-model-contract/'+p for p in
         ('check_scales_codec.py', 'scales_codec.py', 'model_codec.py', 'check_model_codec.py')]
receipt = dict(seed=50332, small=len(small_models), large=large,
               sources={p: sha256((ROOT/p).read_bytes()).hexdigest() for p in paths},
               models_sha256=sha256(data).hexdigest(),
               fixture_sha256=sha256(small).hexdigest())
(out / 'scales.json').write_text(json.dumps(receipt, indent=2)+'\n')
print(json.dumps(receipt))
