# /// script
# requires-python = "==3.12.*"
# dependencies = ["blake3==1.0.11", "python-flint==0.9.0"]
# ///
"""RFC-0026 task E16-10: deterministic synthetic family-1 (Llama-shaped) models.

Emits canonical Model, Preparation, Scales and Artifact bytes for the development
end-to-end prover tests (`crates/stele-prover/tests/fixtures/synthetic-e2e.{json,bin}`).
Parameters follow `check_model_execution.fixture` for family 1 with a fixed shape,
dynamic row policies and small weight codes so the int16 stream does not saturate.
No oracle runs here: the Rust executor is the reference. Run:
`uv run --script research/cqis-model-contract/synthetic_e2e.py <out-dir>`.
"""
from dataclasses import replace
import json
from pathlib import Path
from random import Random
from struct import pack
import sys

from blake3 import blake3

from check_artifact_codec import artifact, mapping, preparation
from check_model_codec import make, roles
from function_bounds import Activation, Exponential
from model_codec import Rotation, encode as encode_model
from scales_codec import Scale, encode as encode_scales
from source_map import Shape


def synthetic(seed, layers, d, heads, hidden, vocabulary, context, group=False):
    """One family-1 model; `group` gives every dynamic affine-input row RFC-0004 A15 groups."""
    rng = Random(seed); width = d // heads
    s = Shape(1, layers, d, heads, heads, width, hidden, vocabulary, context)
    m = make(rng, 1, s)
    exp = Exponential(s.context, 15, 6, 6, 0, 0)
    norm = lambda n, fraction: replace(n, F=fraction, G=6, E=6, en=1, ed=100000)
    g = lambda n: (2, n // 2) if group else (0, 0)
    blocks = []; f0 = 7; incoming = f0
    for b in m.blocks:
        rotation = Rotation(width, s.context, 0, 0, 0, ((500000, 1), (1, 1), (0, 1), (0, 1)))
        policies = (g(d), (0, 0), (0, 0), (0, 0), g(d), g(d), (0, 0))
        fractions = (7,) * 7
        blocks.append(replace(b, norm1=norm(b.norm1, incoming), norm2=norm(b.norm2, 7), fractions=fractions,
                              mid=7, out=7, attention=7, policies=policies, score_m=1, score_e=-4,
                              accumulation=0, drop=0, exp=exp, activation=Activation(s.hidden, 1, 7, 6),
                              rotation=rotation))
        incoming = 7
    formats = tuple((8, 0) if len(ds) == 2 else (16, 6) for _, _, ds in roles(s))
    m = replace(m, formats=formats, f0=f0, blocks=tuple(blocks), final_norm=norm(m.final_norm, incoming),
                final_policy=g(d), logits_fraction=7, decoding=None)
    scales = []; payload = []
    for (name, layer, ds), (bits, _) in zip(roles(s), formats):
        n = ds[0] * (ds[1] if len(ds) == 2 else 1)
        if len(ds) == 2:
            codes = [rng.randint(-3, 3) for _ in range(n)]
            e = -3 if name == 'token' else -5
            mantissas = [rng.randint(1, 3) for _ in range(ds[0])]
            scales.append(Scale(e, b''.join(pack('<H', x) for x in mantissas)))
            payload.append(b''.join(pack('<b', x) for x in codes))
        else:
            codes = [rng.randint(48, 80) for _ in range(n)]
            payload.append(b''.join(pack('<h', x) for x in codes))
    mp = mapping(m, rng, False); sr = encode_scales(m, tuple(scales)); raw = artifact(m, mp, tuple(scales), payload)
    return dict(model=encode_model(m), preparation=preparation(m, mp), scales=sr, artifact=raw)


CASES = (
    ('one-layer', dict(seed=1, layers=1, d=64, heads=4, hidden=128, vocabulary=256, context=16)),
    ('one-layer-grouped', dict(seed=2, layers=1, d=64, heads=4, hidden=128, vocabulary=256, context=16, group=True)),
    ('eight-layer', dict(seed=8, layers=8, d=64, heads=4, hidden=128, vocabulary=256, context=64)),
)


FIXTURES = Path(__file__).resolve().parents[2] / 'crates/stele-prover/tests/fixtures'


def build():
    """The fixture's `.bin` and `.json` bytes; the JSON pins the `.bin` BLAKE3 digest."""
    blob = bytearray(); cases = []
    for name, params in CASES:
        parts = synthetic(**params); entry = dict(name=name, params=params)
        for key in ('model', 'preparation', 'scales', 'artifact'):
            entry[key] = dict(offset=len(blob), length=len(parts[key])); blob += parts[key]
        entry['artifact_id'] = blake3(parts['artifact']).hexdigest()
        cases.append(entry)
    text = json.dumps(dict(source='research/cqis-model-contract/synthetic_e2e.py',
                           blake3=blake3(bytes(blob)).hexdigest(), cases=cases), indent=1) + '\n'
    return bytes(blob), text.encode()


def check():
    """Regenerate and compare with the committed fixture; drift fails."""
    blob, text = build()
    assert (FIXTURES / 'synthetic-e2e.bin').read_bytes() == blob, 'synthetic-e2e.bin drifted'
    assert (FIXTURES / 'synthetic-e2e.json').read_bytes() == text, 'synthetic-e2e.json drifted'
    return dict(cases=len(CASES), bytes=len(blob))


def main(out):
    blob, text = build()
    (Path(out) / 'synthetic-e2e.bin').write_bytes(blob)
    (Path(out) / 'synthetic-e2e.json').write_bytes(text)


if __name__ == '__main__':
    main(sys.argv[1] if len(sys.argv) > 1 else FIXTURES)
