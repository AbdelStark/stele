"""RFC-0025 execution: new bounded native fixtures from qualified pure oracles.

Python 3.12, blake3==1.0.11, numpy==1.26.4, python-flint==0.9.0,
safetensors==0.6.2. Does not invoke a historical campaign entry point.
"""
from hashlib import sha256
import json
from pathlib import Path
from random import Random
from struct import pack
import sys
from blake3 import blake3

ROOT = Path(__file__).resolve().parents[4]
sys.path.insert(0, str(ROOT/'research/cqis-model-contract'))
from check_model_execution import fixture, reference, generation_reference
from check_model_codec import oracle as model_frame
from check_artifact_codec import preparation
import model_execution as execution
import request_bounds as request

binary = bytearray()
cases = []
rng = Random(50426)


def store(raw):
    at = dict(offset=len(binary), length=len(raw))
    binary.extend(raw)
    return at


def shorts(values):
    return pack('<'+'h'*len(values), *values)


for i in range(64):
    m, mp, sr, raw, arrays = fixture(rng, i % 2)
    tokens = tuple(rng.randrange(m.shape.vocabulary) for _ in range(m.shape.context))
    try:
        cuts, logits, cache = reference(m, arrays, tokens)
    except ValueError as error:
        assert str(error) in ('Range', 'RowRange', 'ExpDomain')
        expected = str(error)
    else:
        data = execution.load(m, mp, sr, raw, blake3(raw).digest())
        check = execution.full(data, tokens)
        assert (cuts, logits) == (check.cuts, check.logits)
        expected = dict(cuts=store(b''.join(shorts(row) for cut in cuts for row in cut)),
                        logits=store(b''.join(shorts(row) for row in logits)),
                        cache=store(b''.join(pack('<IB', scale, fraction)+bytes(x % 256 for x in codes)
                            for layer in cache for pair in layer for codes, scale, fraction in pair)))
    generations = []
    if isinstance(expected, dict):
        for limit, eos in ((0, (m.shape.vocabulary-1,)),
                           (1, tuple(range(m.shape.vocabulary))),
                           (m.shape.context-1, (m.shape.vocabulary-1,))):
            seed = None if m.decoding is None else rng.randbytes(32)
            boundary = request.Request(1, limit, eos, None if seed is None else blake3(b'stele/v0.1/cqis/sample-seed'+seed).digest())
            prompt = tokens[:1]
            try:
                sequence, reason, _ = generation_reference(m, arrays, boundary, prompt, seed)
            except ValueError as error:
                result = str(error)
                assert result in ('Range', 'RowRange', 'ExpDomain')
            else:
                result = dict(tokens=sequence, reason=reason)
            spec = request.Spec(m.shape.vocabulary, m.shape.context, int(m.decoding is not None))
            generations.append(dict(request=store(request.encode_request(spec, boundary)), prompt=prompt,
                                    seed=None if seed is None else seed.hex(), expected=result))
    cases.append(dict(model=store(model_frame(m)), preparation=store(preparation(m, mp)),
                      scales=store(sr), artifact=store(raw), artifact_id=blake3(raw).hexdigest(),
                      tokens=tokens, expected=expected, generations=generations))

out = ROOT/'crates/stele-cqis/tests/fixtures'
(out/'model-execution.bin').write_bytes(binary)
paths = ['research/cqis-model-contract/'+name for name in
         ('check_model_execution.py', 'check_model_codec.py', 'check_artifact_codec.py', 'model_execution.py')]
receipt = dict(seed=50426, cases=cases, fixture_sha256=sha256(binary).hexdigest(),
               sources={p: sha256((ROOT/p).read_bytes()).hexdigest() for p in paths})
(out/'model-execution.json').write_text(json.dumps(receipt, separators=(',', ':'))+'\n')
print(json.dumps(dict(cases=len(cases), accepted=sum(isinstance(c['expected'], dict) for c in cases), bytes=len(binary))))
