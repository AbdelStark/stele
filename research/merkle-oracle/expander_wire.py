"""RFC-0010 A3 item 2: version-2 source byte oracle. Research only; imports no
native implementation. Everything except the source bytes, code map and Policy 1
table is field_wire.py's A9 wire, reused unchanged (that file is digest-pinned)."""
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
import struct
import sys

import field_wire as wire
from check_expander_policy import CERT, OPEN

sys.path.append(str(Path(__file__).resolve().parents[1] / 'code-provenance'))
from recursive import encode_row  # noqa: E402
from sampler import manifest, materialize  # noqa: E402

require = wire.require


@lru_cache(None)
def setup(raw):
    return materialize(raw)[0]


@dataclass(frozen=True)
class Source(wire.Source):
    """Version 2: m=2J (C=4^J), blowup 1 (N=2C), 55-byte v2 manifest, J=3..14."""
    seed: bytes = bytes(32)

    def counts(self):
        j = self.m//2
        require(type(self.seed) is bytes and len(self.seed) == 32 and self.blowup == 1
                and self.m == 2*j and 3 <= j <= 14, 'UnsupportedSource')
        return CERT[j-3], OPEN[j-3]

    def bytes(self):
        require(self.degree in (4, 8) and type(self.identity) is int
                and 0 <= self.identity < 2**64 and type(self.ell) is int
                and 0 <= self.ell <= 30 and len(self.root) == 32, 'UnsupportedSource')
        self.counts()
        return (b'stele/v0.1/field-source'+struct.pack('<BBQB', 2, self.degree, self.identity, self.ell)
                +manifest(self.seed, self.m//2)+struct.pack('<QQBB', 1 << self.ell, 1 << self.m, 0, 1)
                +self.root)

    def encode(self, values):
        # The v2 map is base-linear; encode_row takes rows of 1-, 4- or 8-limb tuples.
        return encode_row(setup(manifest(self.seed, self.m//2)), values)[0]


def commit(matrix, ell, j, degree, identity, seed):
    source = Source(degree, identity, ell, 2*j, 1, bytes(32), seed)
    require(len(matrix) == 1 << ell and all(len(r) == 1 << (2*j) for r in matrix), 'ProofShape')
    require(all(type(x) is int and 0 <= x < wire.P for r in matrix for x in r), 'NoncanonicalField')
    encoded = [[x[0] for x in source.encode([(x,) for x in r])] for r in matrix]
    payloads = [struct.pack('<'+'I'*len(matrix), *column) for column in zip(*encoded)]
    levels = wire.merkle.build(source.tree(), payloads)
    return Source(degree, identity, ell, 2*j, 1, levels[-1][0], seed), (matrix, payloads, levels)


def verify_responses(transcript, source, a, u, block, label, count):
    tree = source.tree()
    stride = tree.width+32*tree.height()
    expected = source.encode(u)
    for q in range(count):
        index = transcript.column(label, tree.count)
        response = block[q*stride:(q+1)*stride]
        payload = response[:tree.width]
        siblings = [response[i:i+32] for i in range(tree.width, stride, 32)]
        wire.merkle.verify(tree, source.root, index, payload, siblings)
        column = [wire.scalar(x[0], source.degree) for x in wire.fields(payload, 1)]
        require(expected[index] == wire.dot(a, column, source.degree), 'ColumnMismatch')


def certify(source, witness):
    transcript, a = wire.certificate_transcript(source)
    t = wire.row(witness[0], a, source.degree)
    transcript.absorb(wire.CERT_ROW, wire.field_bytes(t))
    block = wire.responses(transcript, source, witness, wire.CERT_COLUMN, source.counts()[0])
    transcript.absorb(wire.CERT_COLUMNS, block)
    return b'\1'+wire.field_bytes(t)+block


def verify_certificate(source, proof):
    count = source.counts()[0]
    t, block = wire.parse(source, proof, count)
    transcript, a = wire.certificate_transcript(source)
    transcript.absorb(wire.CERT_ROW, wire.field_bytes(t))
    verify_responses(transcript, source, a, t, block, wire.CERT_COLUMN, count)
    transcript.absorb(wire.CERT_COLUMNS, block)
    public = source.bytes()
    identity = wire.blake3(b'stele/v0.1/pcs-certificate/id'+struct.pack('<Q', len(public))
                           +public+struct.pack('<Q', len(proof))+proof).digest()
    return wire.Verified(wire._VERIFIED, source, identity)


def open_functional(transcript, identity, verified, witness, a, b, value):
    wire.opening_instance(transcript, identity, verified, a, b, value)
    source = verified.source
    u = wire.row(witness[0], a, source.degree)
    require(wire.dot(u, b, source.degree) == value, 'ValueMismatch')
    transcript.absorb(wire.OPEN_ROW, wire.field_bytes(u))
    block = wire.responses(transcript, source, witness, wire.OPEN_COLUMN, source.counts()[1])
    transcript.absorb(wire.OPEN_COLUMNS, block)
    return b'\1'+wire.field_bytes(u)+block


def verify_opening(transcript, identity, verified, a, b, value, proof):
    require(isinstance(verified, wire.Verified), 'CertificateContext')
    source = verified.source
    count = source.counts()[1]
    u, block = wire.parse(source, proof, count)
    wire.opening_instance(transcript, identity, verified, a, b, value)
    transcript.absorb(wire.OPEN_ROW, wire.field_bytes(u))
    require(wire.dot(u, b, source.degree) == value, 'ValueMismatch')
    verify_responses(transcript, source, a, u, block, wire.OPEN_COLUMN, count)
    transcript.absorb(wire.OPEN_COLUMNS, block)
