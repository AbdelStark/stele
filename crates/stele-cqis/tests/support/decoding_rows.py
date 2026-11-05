"""RFC-0025 decoding: 10000 original-logit rows for each selection mode.

New bounded corpus; only imports qualified pure helpers, never old campaigns.
Python 3.12, numpy 1.26.4, blake3 1.0.11, python-flint 0.9.0,
safetensors 0.6.2. NumPy sorting and independent Arb selection must agree.
"""
from dataclasses import replace
from hashlib import sha256
import json
from pathlib import Path
from random import Random
from struct import pack

from blake3 import blake3
import numpy as np

from numpy_execution import Oracle, load
from check_model_execution import fixture
from check_decoding_execution import oracle, seed_hash
from check_artifact_codec import preparation
from function_bounds import Exponential
from model_codec import Sampled, encode
from request_bounds import Request
from scales_codec import decode, encode as encode_scales


class Words:
    def __init__(self, seed): self.state = seed
    def next(self):
        self.state = (self.state*6364136223846793005+1442695040888963407) % 2**64
        return self.state >> 32


ROOT = Path(__file__).resolve().parents[4]
binary = bytearray()


def store(raw):
    span = dict(offset=len(binary), length=len(raw))
    binary.extend(raw)
    return span


groups = []
for mode in range(-1, 3):
    for group in range(8):
        rng = Random(504290+mode*8+group)
        base, mapping, scales, artifact, _ = fixture(rng, group % 2, layers=1, context=64)
        # Keep forward static bounds independently valid. Decoding is its own
        # selected function (different extent), including the product B=31 domain.
        bits = 31 if mode == 1 and group == 7 else (7 if group % 2 else 15)
        ef = (0, 1, 7, 15, 30, 7, 0, 30)[group]
        lf = (0, 1, 7, 15, 30, 0, 15, 14)[group]
        e = Exponential(base.shape.vocabulary, bits, ef, 14 if group % 2 else 4,
                        max(mode, 0), min(16, bits) if mode > 0 else 0)
        sampling = None if mode < 0 else Sampled(1 if group % 2 else 3,
            1 if group % 2 else 5, 1 if group % 3 else 9, 1 if group % 3 else 10, e)
        m = replace(base, decoding=sampling, logits_fraction=lf)
        sr = encode_scales(m, decode(base, scales))
        data = load(m, mapping, sr, artifact, blake3(artifact).digest())
        numpy = Oracle(data)
        seed = 504300+32*(mode+1)+group
        words = Words(seed)
        digest = blake3()
        accepted = 0
        for i in range(1250):
            values = [words.next() % 65536-32768 for _ in range(m.shape.vocabulary)]
            if i % 7 == 0: values = [values[0]]*len(values)  # first maximum/tied mass
            if i % 11 == 0: values = [0]+[-32768]*(len(values)-1)  # zero-weight suffix
            original_seed = b''.join(pack('<I', words.next()) for _ in range(8))
            position = 1+words.next() % 63
            prefix = (m.shape.vocabulary-1,)+(0,)*(position-1)
            supplied = None if mode < 0 else original_seed
            request = Request(1, 63, (m.shape.vocabulary-1,), None if supplied is None else seed_hash(supplied))
            try:
                selected, parts = numpy.choose(np.asarray(values, dtype=np.int64), supplied, position)
            except ValueError as error:
                assert str(error) == 'ExpDomain'
                try: oracle(m, request, prefix, tuple(values), supplied)
                except ValueError as other: assert str(other) == 'ExpDomain'
                else: raise AssertionError('missing independent rejection')
                digest.update(b'\0')
            else:
                expected = oracle(m, request, prefix, tuple(values), supplied)
                assert (selected, parts) == (expected.token, (expected.arguments, expected.weights,
                    expected.order, expected.cdf, expected.draw))
                accepted += 1
                arguments, weights, order, cdf, draw = parts
                digest.update(b'\1'+pack('<II', position, selected))
                for values, fmt in ((arguments, 'i'), (weights, 'I'), (order, 'I'), (cdf, 'Q')):
                    digest.update(pack('<I', len(values))+pack('<'+fmt*len(values), *values))
                digest.update(bytes((draw is not None,))+(b'' if draw is None else pack('<I', draw)))
        groups.append(dict(mode=mode, seed=seed, count=1250, accepted=accepted,
            digest=digest.hexdigest(), model=store(encode(m)), preparation=store(preparation(m, mapping)),
            scales=store(sr), artifact=store(artifact), artifact_id=blake3(artifact).hexdigest()))
    print(json.dumps(dict(mode=mode, complete=10000)), flush=True)

directory = ROOT/'crates/stele-cqis/tests/fixtures'
(directory/'decoding-rows.bin').write_bytes(binary)
paths = ('crates/stele-cqis/tests/support/numpy_execution.py',
         'research/cqis-model-contract/check_decoding_execution.py',
         'research/cqis-model-contract/check_decoding.py',
         'research/cqis-model-contract/check_model_execution.py')
(directory/'decoding-rows.json').write_text(json.dumps(dict(groups=groups,
    fixture_sha256=sha256(binary).hexdigest(),
    sources={p: sha256((ROOT/p).read_bytes()).hexdigest() for p in paths}), separators=(',', ':'))+'\n')
