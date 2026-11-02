"""RFC-0023 independent verification transcript over the existing reference engines."""
from contextlib import contextmanager
import importlib
from pathlib import Path
import struct
import sys
from types import SimpleNamespace

STATEMENT = b'stele/v0.1/requant/statement'
CONSTRAINTS = b'stele/v0.1/requant/constraints'
CLAIMS = b'stele/v0.1/requant/claims'
WEIGHT = b'stele/v0.1/requant/weight'


@contextmanager
def load(root):
    sys.dont_write_bytecode = True
    root = Path(root).resolve()
    paths = ['tests/negative-controls', 'research/cqis-bounds', 'research/zerocheck',
             'research/batching', 'research/stacked-gkr']
    old_path = sys.path[:]
    for path in paths:
        sys.path.insert(0, str(root/path))
    o = importlib.import_module('lookup_corpus')
    zc = importlib.import_module('check_zerocheck')
    req = importlib.import_module('requant')
    encoding = importlib.import_module('encoding')
    public = importlib.import_module('weighted_mle')
    pcs, sc, ft = o.pcs, o.sc, o.ft
    expected = [(o, 'tests/negative-controls/lookup_corpus.py'),
                (zc, 'research/zerocheck/check_zerocheck.py'),
                (req, 'research/cqis-bounds/requant.py'),
                (encoding, 'research/cqis-bounds/encoding.py'),
                (public, 'research/stacked-gkr/weighted_mle.py'),
                (pcs, 'research/merkle-oracle/field_wire.py'),
                (sc, 'research/sumcheck/check_sumcheck.py'),
                (ft, 'research/logup-characteristic/fraction.py')]
    for module, path in expected:
        assert Path(module.__file__).resolve() == root/path
    assert zc.sc is sc is pcs.sc is ft.sc
    old_pcs_transcript, old_lookup_transcript = pcs.Transcript, o.Transcript

    class Transcript(old_lookup_transcript):
        def __init__(self, public_bytes, degree):
            super().__init__(public_bytes, degree)
            self.draw_trace = []

        def absorb(self, label, payload):
            if label in (STATEMENT, CONSTRAINTS, CLAIMS, zc.ZERO, zc.SKIP, zc.FINAL):
                self.state = o.raw_hash(pcs.frame(self.state, 0, label, payload)).digest()
                self.usage['hash_evaluations'] += 1
                self.usage['state_updates'] += 1
                self.public_bytes += len(payload)
            else:
                super().absorb(label, payload)

        def challenge(self, label=pcs.CHALLENGE):
            if label in (WEIGHT, zc.WEIGHT):
                old = self.state
                raw = o.raw_hash(pcs.frame(old, 1, label, bytes([self.degree]))).digest(length=256)
                self.usage['xof_requests'] += 1
                self.usage['xof_bytes'] += 256
                try:
                    value, consumed = pcs.sample(raw, self.degree)
                except ValueError as error:
                    assert str(error) == 'SamplingExhausted'
                    self.usage['candidate_words'] += 64
                    raise
                self.usage['candidate_words'] += consumed
                payload = bytes([self.degree])+struct.pack('<I', consumed)+value
                self.state = o.raw_hash(pcs.frame(old, 2, label, payload)).digest()
                self.usage['hash_evaluations'] += 1
                self.usage['state_updates'] += 1
                self.draws[label] = self.draws.get(label, 0)+1
            else:
                value, consumed = super().challenge(label)
            self.draw_trace.append((label, struct.unpack('<'+'I'*self.degree, value)))
            return value, consumed

    pcs.Transcript = o.Transcript = Transcript
    try:
        yield SimpleNamespace(o=o, pcs=pcs, sc=sc, ft=ft, ti=o.ti, zc=zc,
                              req=req, encoding=encoding, public=public, Transcript=Transcript)
    finally:
        pcs.Transcript, o.Transcript = old_pcs_transcript, old_lookup_transcript
        sys.path[:] = old_path
