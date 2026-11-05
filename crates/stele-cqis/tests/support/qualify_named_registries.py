"""Manual full named-geometry Registry qualification, not a performance benchmark.

Build the model_registry example in the test profile. Run this script with
Python 3.12, python-flint==0.9.0 and blake3==1.0.11. Full native and independent
Arb regeneration run on the same complete Model; no campaign main is invoked.
These numerical configurations do not establish original-source/fidelity credit.
"""
import argparse
from dataclasses import replace
from hashlib import sha256
import json
from pathlib import Path
from random import Random
from struct import pack, unpack_from
import subprocess
import sys

from blake3 import blake3

if not __debug__:
    raise RuntimeError('reference assertions must remain enabled')
ROOT = Path(__file__).resolve().parents[4]
sys.path.insert(0, str(ROOT/'research/cqis-model-contract'))
from check_registry_codec import configured, oracle
from model_codec import Rotation, encode as encode_model
from source_map import Shape


def digest(path): return sha256(path.read_bytes()).hexdigest()


parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--family', choices=('gpt2-small', 'llama-3.1-8b'), required=True)
parser.add_argument('--native', type=Path, required=True)
parser.add_argument('--output-dir', type=Path, required=True)
args = parser.parse_args()
native = args.native.resolve(strict=True)
output = args.output_dir.resolve()
output.mkdir(parents=True, exist_ok=False)
family = int(args.family == 'llama-3.1-8b')
shape = (Shape(1, 32, 4096, 32, 8, 128, 14336, 128256, 131072) if family else
         Shape(0, 12, 768, 12, 12, 64, 3072, 50257, 1024))
model = configured(Random(50335+family), family, shape, 2)
blocks = []
for b in model.blocks:
    fractions = list(b.fractions); fractions[5 if family else 4] = 7
    rotation = (Rotation(128, shape.context, 2, 1, 8192,
                ((500000, 1), (8, 1), (1, 1), (4, 1))) if family else None)
    blocks.append(replace(b, fractions=tuple(fractions),
        activation=replace(b.activation, F=7, E=7), exp=replace(b.exp, F=7, E=7), rotation=rotation))
decoding = model.decoding
if decoding is not None: decoding = replace(decoding, exp=replace(decoding.exp, F=7, E=7))
model = replace(model, blocks=tuple(blocks), decoding=decoding)
model_raw = encode_model(model)
(output/'model.bin').write_bytes(model_raw)
(output/'input.bin').write_bytes(pack('<I', len(model_raw))+model_raw)
sources = [p for p in sorted((ROOT/'crates/stele-cqis/src').rglob('*.rs'))]
sources += [ROOT/'crates/stele-cqis/examples/model_registry.rs', Path(__file__).resolve(),
            ROOT/'Cargo.toml', ROOT/'Cargo.lock', ROOT/'rust-toolchain.toml',
            ROOT/'crates/stele-cqis/Cargo.toml']
for directory in ('cqis-model-contract', 'cqis-checkpoint', 'cqis-tables'):
    sources += sorted((ROOT/'research'/directory).glob('*.py'))
receipt = dict(family=args.family, seed=50335+family,
    scope='Complete named-geometry numerical Registry only; no original-source, fidelity, inference or proof credit.',
    head=subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip(),
    native_sha256=digest(native), model_id=blake3(model_raw).hexdigest(),
    shape=vars(shape), rotation_pairs=8388608 if family else 0,
    sources={str(p.relative_to(ROOT)):digest(p) for p in sources})
with (output/'input.bin').open('rb') as inp, (output/'native.bin').open('xb') as out, (output/'native.stderr').open('xb') as err:
    process = subprocess.Popen([str(native)], stdin=inp, stdout=out, stderr=err)
    receipt['native_pid'] = process.pid
    (output/'running.json').write_text(json.dumps(receipt, indent=2)+'\n')
    try:
        expected = oracle(model)
        (output/'reference.bin').write_bytes(expected)
        (output/'reference-complete.json').write_text(json.dumps(dict(length=len(expected),
            registry_id=blake3(expected).hexdigest()), indent=2)+'\n')
        code = process.wait()
        assert code == 0, ('NativeFailure', code)
    except BaseException:
        if process.poll() is None:
            process.terminate(); process.wait()
        raise
actual = (output/'native.bin').read_bytes()
assert len(actual) >= 4 and unpack_from('<I', actual)[0] == len(actual)-4
assert actual[4:] == expected, 'RegistryMismatch'
assert all(digest(ROOT/p) == h for p,h in receipt['sources'].items()), 'SourceChanged'
receipt.update(status='passed', registry_id=blake3(expected).hexdigest(), registry_length=len(expected),
               artifacts={p:digest(output/p) for p in ('model.bin','input.bin','native.bin','reference.bin','native.stderr')})
(output/'results.json').write_text(json.dumps(receipt, indent=2)+'\n')
print(json.dumps({k:receipt[k] for k in ('family','status','registry_id','registry_length','rotation_pairs')}), flush=True)
