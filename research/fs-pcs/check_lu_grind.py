# /// script
# requires-python = ">=3.12"
# dependencies = ["blake3==1.0.11"]
# ///
"""RFC-0008 A8: standard-profile LU (β, α) grinding bits and wire, from the RFC text.

1. Bits. One (β, α) round (RFC-0012 A17 item 3, fs-composition.md Lemma 4) has error
   a/|K| with a = (c−1)(N+t) + N+t−1. Its nonce takes the least k ≥ 0 with
   a·2^108 ≤ p^d·2^k (A17 (C1), standard λ+g = 108); k > 32 is UnsupportedParameters.
   Rows "c N t d k" (k = none when unsupported) are pinned in lu-grind-bits.txt.
2. Wire. The unchanged independent A5 producer of tests/negative-controls/lookup_corpus.py
   is run with Policy 2 originals and multiplicity sources (research/merkle-oracle/check_policy2_wire.py)
   and the A8 nonce: after Repetition(id, j, 0), before Beta; on the wire after the
   registrations. Its bytes and continuation are pinned in lu-standard-wire.txt for
   the native Descriptor::standard. No native code is imported.

  uv run --locked --script research/fs-pcs/check_lu_grind.py [--write-vectors]
"""
from hashlib import sha256

from blake3 import blake3
from pathlib import Path
import struct
import sys

ROOT = Path(__file__).resolve().parents[2]
FIXTURES = ROOT/'crates/stele-reductions/tests/fixtures'
P = 2**31 - 1
sys.dont_write_bytecode = True


def bits(c, n, t, d):
    a = (c-1)*(n+t) + n+t-1
    k = 0
    while a*2**108 > P**d*2**k:
        k += 1
    return k if k <= 32 else None


def rows():
    out = []
    for d in (4, 8):
        for c in (1, 2):
            for t in (1, 256, 4096, 65535, 65536):
                for m in (0, 1, 15, 16, 17, 20, 27, 40, 59):
                    k = bits(c, 2**m, t, d)
                    out.append(f'{c} {2**m} {t} {d} {"none" if k is None else k}')
    return ('\n'.join(out)+'\n').encode()


def standard_wire():
    """Run lookup_corpus.reference unchanged, routing mu sources to Policy 2 and adding A8."""
    sys.path.insert(0, str(ROOT/'tests/negative-controls'))
    import lookup_corpus as lc
    import check_policy2_wire as p2
    base = lc.pcs
    nonces, certificates = [], []

    class Pcs:
        """field_wire, except every source carries Policy 2 (RFC-0008 A8 item 3)."""
        def __getattr__(self, name):
            return getattr(base, name)

        def commit(self, matrix, ell, m, blowup, d, identity):
            return p2.commit(matrix, ell, m, blowup, d, identity)

        def open_functional(self, t, identity, verified, witness, a, b, value):
            policy2 = isinstance(verified.source, p2.Source)
            return (p2 if policy2 else base).open_functional(t, identity, verified, witness, a, b, value)

    class Transcript(lc.Transcript):
        grind = 0

        def field(self, label):
            # A8 item 4: the nonce immediately follows Repetition(id, j, 0) and precedes Beta.
            if label == lc.BETA and Transcript.grind:
                nonces.append(p2.grind(self, Transcript.grind))
            return super().field(label)

    def register(source, witness):
        assert isinstance(source, p2.Source)
        proof = p2.certify(source, witness)
        if source.identity >= 20:  # multiplicity registrations only; originals are caller-owned
            certificates.append(len(proof))
        return p2.verify_certificate(source, proof), proof, None, 0

    saved = lc.pcs, lc.register, lc.Transcript, base.Transcript
    lc.pcs, lc.register, lc.Transcript, base.Transcript = Pcs(), register, Transcript, lc.Transcript
    out = []
    try:
        for d, table, t, value, r in ((4, 'range_8', 256, 7, 1), (8, 'range_8', 256, 7, 1),
                                      (4, 'range_16', 65536, 9, 1), (4, 'range_16', 65536, 9, 2)):
            case = dict(name=f'standard-{table}-{d}', degree=d, public_hex=lc.PUBLIC.hex(), lookup_id=7,
                        m=0, b=0, table=dict(name=table, version=1, params_hex=''), selector=[1],
                        originals=[dict(id=10, ell=0, blowup=1, message=[value])],
                        multiplicities=[dict(id=20+j, ell=4, blowup=1+j) for j in range(r)])
            Transcript.grind = bits(1, 1, t, d)
            nonces.clear()
            certificates.clear()
            result = lc.reference(case)
            assert result['outcome'] == 'produced', result
            assert len(nonces) == r*int(Transcript.grind > 0) and len(certificates) == r
            raw = bytes.fromhex(result['proof'])
            # A8 item 5: nonce j sits at 2 + sum(32 + C_i) + 8j, after every registration packet.
            at = 2+sum(32+c for c in certificates)
            proof = raw[:at]+b''.join(struct.pack('<Q', n) for n in nonces)+raw[at:]
            # Plain rows for the native test: degree table value r k offset nonces bytes blake3 continuation.
            out.append(' '.join(map(str, (d, table, value, r, Transcript.grind, at,
                                          ','.join(map(str, nonces)) or '-', len(proof),
                                          blake3(proof).hexdigest(), result['continuation']))))
    finally:
        lc.pcs, lc.register, lc.Transcript, base.Transcript = saved
    return ('\n'.join(out)+'\n').encode()


def main():
    # Spot checks from the text: OM31 never grinds; range_8 at 2^27 positions is the
    # recorded proof's worst LU round at 12 bits (fs-composition.md §6); c = 2,
    # t = 2^16 at N = 1 needs 2 bits; N = 2^59 at c = 2 exceeds 32 bits.
    assert bits(2, 2**59, 65536, 8) == 0
    assert bits(1, 2**27, 256, 4) == 12
    assert bits(2, 1, 65536, 4) == 2 and bits(1, 1, 65536, 4) == 1 and bits(1, 1, 256, 4) == 0
    assert bits(2, 2**59, 65536, 4) is None
    table, wire = rows(), standard_wire()
    pins = ((FIXTURES/'lu-grind-bits.txt', table), (FIXTURES/'lu-standard-wire.txt', wire))
    if sys.argv[1:] == ['--write-vectors']:
        for path, raw in pins:
            path.write_bytes(raw)
    for path, raw in pins:
        assert path.read_bytes() == raw, f'native fixture drift: {path.name}'
    count = table.count(b'\n')
    print(f'{count} LU (beta, alpha) grind-bit rows; 4 standard A5 wires (k = 0, 0, 1, 1; r = 2 last); '
          f'SHA256 {sha256(wire).hexdigest()}')


if __name__ == '__main__':
    main()
