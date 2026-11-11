# /// script
# requires-python = ">=3.12"
# dependencies = ["blake3==1.0.11"]
# ///
"""RFC-0010 A14 Policy 2 certificate/opening bytes with RFC-0012 A17 grinding.

Independent byte oracle for the native stele-pcs consumer (task E12-23). It reuses the
A9 oracle in field_wire.py and adds, from the RFC text only: the policy byte 2, the A14
query tables (Circle entries recomputed from the exact inequality), the tensor grinding
bits k_t, and the nonce positions. No native code is imported; no NC credit.
"""
from dataclasses import astuple, dataclass
from hashlib import sha256
import json
from pathlib import Path
import struct

from blake3 import blake3
import field_wire as wire
from field_wire import P, Transcript, eq, row, dot, field_bytes, encode, require, rejects

GRIND = b'stele/v0.1/grind'
COLUMN_BITS = 16
# RFC-0010 A14 item 2, copied from the Accepted text: (q_c, q_o) by Circle m.
HALF = [(92, 1), (222, 92), (222, 136), (308, 136), (308, 152), (339, 152), (339, 156),
        (347, 156), (347, 157), (350, 157)] + [(350, 158)]*20
QUARTER = [(92, 46), (222, 66), (222, 78), (222, 85), (222, 88), (222, 90), (222, 91)] + [(222, 92)]*22
# v2 J = 3..14 (J - 3 index); J = 15 has no entry.
V2 = [(339, 156), (8131, 4050), (9297, 4633), (9467, 4718), (9510, 4739), (9532, 4748),
      (9532, 4751), (9533, 4751), (9534, 4751), (9534, 4751), (9534, 4751), (9534, 4751)]


def least(n, d, e):
    """Least positive q_c, q_o with 2^92·(N−e−1)^q ≤ N^q and 2^92·(N−D+e)^q ≤ N^q."""
    def first(miss):
        q, lhs, rhs = 1, (1 << 92)*miss, n
        while lhs > rhs:
            q, lhs, rhs = q+1, lhs*miss, rhs*n
        return q
    return first(n-e-1), first(n-d+e)


def circle(m, blowup):
    n = 1 << (m+blowup)
    d = n if m == 0 else n-(1 << m)
    return n, d, (d-1)//3


def tensor_bits(ell, e, degree):
    """A14 item 4: least k ≥ 0 with 2·ell·(e+1)·2^108 ≤ |K|·2^k."""
    k = 0
    while 2*ell*(e+1)*(1 << 108) > P**degree*(1 << k):
        k += 1
    return k


@dataclass(frozen=True)
class Source(wire.Source):
    def bytes(self):
        raw = super().bytes()
        require(raw[-33] == 1, 'UnsupportedSource')
        return raw[:-33]+b'\2'+raw[-32:]  # The policy byte precedes the 32-byte root.

    def counts(self):
        return (HALF if self.blowup == 1 else QUARTER)[self.m]

    def kt(self):
        return tensor_bits(self.ell, circle(self.m, self.blowup)[2], self.degree)


def pow_ok(t, bits, nonce):
    require(1 <= bits <= 32, 'InvalidGrindBits')
    digest = blake3(wire.frame(t.state, 3, GRIND, bytes([bits])+struct.pack('<Q', nonce))).digest()
    return struct.unpack('<Q', digest[:8])[0] % (1 << bits) == 0


def verify_grind(t, bits, nonce):
    require(pow_ok(t, bits, nonce), 'GrindMismatch')
    t.state = blake3(wire.frame(t.state, 0, GRIND, bytes([bits])+struct.pack('<Q', nonce))).digest()


def grind(t, bits):
    nonce = 0
    while not pow_ok(t, bits, nonce):
        nonce += 1
    verify_grind(t, bits, nonce)
    return nonce


def commit(matrix, ell, m, blowup, degree, identity):
    source, witness = wire.commit(matrix, ell, m, blowup, degree, identity)
    return Source(*astuple(source)), witness


def certify(source, witness):
    t = Transcript(b'stele/v0.1/pcs-certificate/public'+source.bytes(), source.degree)
    out = b'\1'
    if source.kt():
        out += struct.pack('<Q', grind(t, source.kt()))
    a = eq([t.field(wire.WEIGHT) for _ in range(source.ell)], source.degree)
    u = field_bytes(row(witness[0], a, source.degree))
    t.absorb(wire.CERT_ROW, u)
    out += u+struct.pack('<Q', grind(t, COLUMN_BITS))
    block = wire.responses(t, source, witness, wire.CERT_COLUMN, source.counts()[0])
    t.absorb(wire.CERT_COLUMNS, block)
    return out+block


def split(source, proof, tensor, count):
    tree = source.tree()
    size = 4*source.degree*(1 << source.m)
    start = 1+8*bool(tensor)
    end = start+size
    require(len(proof) == end+8+count*(tree.width+32*tree.height()) and proof[:1] == b'\1', 'ProofShape')
    n_t = struct.unpack('<Q', proof[1:9])[0] if tensor else None
    u = wire.fields(proof[start:end], source.degree)
    return n_t, u, struct.unpack('<Q', proof[end:end+8])[0], proof[end+8:]


def verify_certificate(source, proof):
    count = source.counts()[0]
    n_t, u, n_q, block = split(source, proof, source.kt(), count)
    t = Transcript(b'stele/v0.1/pcs-certificate/public'+source.bytes(), source.degree)
    if source.kt():
        verify_grind(t, source.kt(), n_t)
    a = eq([t.field(wire.WEIGHT) for _ in range(source.ell)], source.degree)
    t.absorb(wire.CERT_ROW, field_bytes(u))
    verify_grind(t, COLUMN_BITS, n_q)
    wire.verify_responses(t, source, a, u, block, wire.CERT_COLUMN, count)
    t.absorb(wire.CERT_COLUMNS, block)
    public = source.bytes()
    identity = blake3(b'stele/v0.1/pcs-certificate/id'+struct.pack('<Q', len(public))
                      + public+struct.pack('<Q', len(proof))+proof).digest()
    return wire.Verified(wire._VERIFIED, source, identity)


def open_functional(t, identity, verified, witness, a, b, value):
    wire.opening_instance(t, identity, verified, a, b, value)
    source = verified.source
    u = row(witness[0], a, source.degree)
    require(dot(u, b, source.degree) == value, 'ValueMismatch')
    t.absorb(wire.OPEN_ROW, field_bytes(u))
    nonce = struct.pack('<Q', grind(t, COLUMN_BITS))
    block = wire.responses(t, source, witness, wire.OPEN_COLUMN, source.counts()[1])
    t.absorb(wire.OPEN_COLUMNS, block)
    return b'\1'+field_bytes(u)+nonce+block


def verify_opening(t, identity, verified, a, b, value, proof):
    source = verified.source
    count = source.counts()[1]
    _, u, n_q, block = split(source, proof, 0, count)
    wire.opening_instance(t, identity, verified, a, b, value)
    t.absorb(wire.OPEN_ROW, field_bytes(u))
    require(dot(u, b, source.degree) == value, 'ValueMismatch')
    verify_grind(t, COLUMN_BITS, n_q)
    wire.verify_responses(t, source, a, u, block, wire.OPEN_COLUMN, count)
    t.absorb(wire.OPEN_COLUMNS, block)


def failing(t, bits, nonce):
    """The next nonce after `nonce` that fails the predicate on state t."""
    while pow_ok(t, bits, nonce):
        nonce += 1
    return nonce


def digest(source, proof):
    public = source.bytes()
    return blake3(b'stele/v0.1/pcs-certificate/id'+struct.pack('<Q', len(public))
                  + public+struct.pack('<Q', len(proof))+proof).digest()


def v2(j):
    c = 4**j
    d = 64 if j == 3 else c//25+1
    return 2*c, d, (d-1)//3


def tables():
    """Recompute every A14 row from the exact inequality; return the native table fixture."""
    lines = []
    for blowup, table in ((1, HALF), (2, QUARTER)):
        assert len(table) == 31-blowup
        for m, counts in enumerate(table):
            assert least(*circle(m, blowup)) == counts, (m, blowup)
            lines.append(f'circle {m} {blowup} {counts[0]} {counts[1]}')
    for j, counts in enumerate(V2, 3):
        assert least(*v2(j)) == counts, j
        lines.append(f'v2 {j} {counts[0]} {counts[1]}')
    return ('\n'.join(lines)+'\n').encode()


def exercise():
    lines = []
    for degree, ell, m, blowup in ((4, 1, 1, 1), (8, 2, 1, 2), (4, 3, 14, 2)):
        matrix = [[(i+2)*(j+3) for j in range(1 << m)] for i in range(1 << ell)]
        source, witness = commit(matrix, ell, m, blowup, degree, 41)
        assert source.bytes()[-33] == 2 and len(source.bytes()) == 105
        certificate = certify(source, witness)
        verified = verify_certificate(source, certificate)
        kt = source.kt()
        n_t, _, n_q, _ = split(source, certificate, kt, source.counts()[0])
        point = [tuple((i+1)*(k+2) for k in range(degree)) for i in range(ell+m)]
        a, b = eq(point[:ell], degree), eq(point[ell:], degree)
        value = dot(row(matrix, a, degree), b, degree)
        prover = Transcript(b'field wire oracle', degree)
        opening = open_functional(prover, 12, verified, witness, a, b, value)
        verifier = Transcript(b'field wire oracle', degree)
        verify_opening(verifier, 12, verified, a, b, value, opening)
        continuation = verifier.challenge()[0]
        assert prover.challenge()[0] == continuation
        n_o = split(source, opening, 0, source.counts()[1])[2]
        # A nonce failing the predicate, a missing nonce and a Policy 1 wire all reject.
        if kt:
            public = Transcript(b'stele/v0.1/pcs-certificate/public'+source.bytes(), degree)
            bad = struct.pack('<Q', failing(public, kt, n_t))
            rejects('GrindMismatch', lambda: verify_certificate(source, certificate[:1]+bad+certificate[9:]))
        at = 1+8*bool(kt)+4*degree*(1 << m)
        bad = struct.pack('<Q', failing(row_state(source, witness), COLUMN_BITS, n_q))
        rejects('GrindMismatch', lambda: verify_certificate(source, certificate[:at]+bad+certificate[at+8:]))
        cut = len(opening)-len(split(source, opening, 0, source.counts()[1])[3])-8
        rejects('ProofShape', lambda: verify_opening(Transcript(b'field wire oracle', degree),
                12, verified, a, b, value, opening[:cut]+opening[cut+8:]))
        policy1 = wire.certify(wire.Source(*astuple(source)), witness)
        rejects('ProofShape', lambda: verify_certificate(source, policy1))
        lines.append(json.dumps({
            'degree': degree, 'ell': ell, 'm': m, 'blowup': blowup,
            'source': source.bytes().hex(), 'tensor_bits': kt, 'tensor_nonce': n_t,
            'certificate_nonce': n_q, 'certificate_bytes': len(certificate),
            'certificate_id': verified.identity.hex(), 'opening_nonce': n_o,
            'opening_bytes': len(opening), 'opening_digest': digest(source, opening).hex(),
            'value': encode(value).hex(), 'continuation': continuation.hex()},
            separators=(',', ':')))
    return ('\n'.join(lines)+'\n').encode()


def row_state(source, witness):
    """Replay a certificate transcript to the state after CertificateRow."""
    t = Transcript(b'stele/v0.1/pcs-certificate/public'+source.bytes(), source.degree)
    if source.kt():
        grind(t, source.kt())
    a = eq([t.field(wire.WEIGHT) for _ in range(source.ell)], source.degree)
    t.absorb(wire.CERT_ROW, field_bytes(row(witness[0], a, source.degree)))
    return t


if __name__ == '__main__':
    import sys
    rows = tables()
    raw = exercise()
    root = Path(__file__).resolve().parents[2]
    fixture = root/'crates/stele-pcs/tests/fixtures/policy2-wire.jsonl'
    table = root/'crates/stele-code/tests/policy2-tables.txt'
    if sys.argv[1:] == ['--write-vectors']:
        fixture.write_bytes(raw)
        table.write_bytes(rows)
    assert fixture.read_bytes() == raw, 'native Policy 2 fixture drift'
    assert table.read_bytes() == rows, 'native A14 table fixture drift'
    print('59 Circle + 12 v2 A14 rows recomputed; 3 Policy 2 certificate/opening cases;',
          sha256(raw).hexdigest())
