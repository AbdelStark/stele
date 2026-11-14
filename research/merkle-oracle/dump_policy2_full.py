# /// script
# requires-python = ">=3.12"
# dependencies = ["blake3==1.0.11"]
# ///
"""Full-byte RFC-0010 A14 Policy 2 certificate/opening vectors for the independent
no_std verifier (task E8-02d, ADR-128).

Uses only this directory's Python oracle (check_policy2_wire.py, field_wire.py), which
is written from the RFC text; no native code is imported. For each of
check_policy2_wire.py's three cases, plus one more, it records:
- the source, certificate and opening bytes;
- the opening's a, b and value;
- the certificate ID;
- the verifier transcript's next challenge after the opening (the continuation).
The first case also carries a ColumnMismatch certificate and a NoncanonicalField source.

It also writes, from the same oracle:
- `pcs-parameters.txt`: (N, D, e, q_c, q_o) for every Circle code (m, b) under Policies 1
  and 2, and k_t for ell = 0..30 under Policy 2 (A9 §1, A14 items 2 and 4);
- `policy1-continuations.txt`: the challenge drawn from each Policy 1 continuation
  state recorded in `stele-pcs`'s `field-wire.jsonl`. That state is taken after the
  first post-opening draw (`opening-continuation.txt`), so this is the second draw;
- `single-mismatch.jsonl`: two Policy 1 certificates whose committed matrix differs from
  the honest encoding in one limb of one column, drawn exactly once: at the first
  query, then at the last (A9 §3; the column and delta were found by search).

    uv run --locked --script research/merkle-oracle/dump_policy2_full.py            # check
    uv run --locked --script research/merkle-oracle/dump_policy2_full.py --write    # regenerate
"""
from dataclasses import replace
import json
from pathlib import Path
import struct
import sys

import check_policy2_wire as p2
from field_wire import P, Transcript, eq, row, dot, field_bytes, encode
import field_wire as wire
from native_policy import counts

CASES = ((4, 1, 1, 1), (8, 2, 1, 2), (4, 3, 14, 2), (4, 6, 3, 2))
# (ell, m, b, degree) and, per position, (column, delta) of the one tampered limb.
SINGLE = (1, 7, 2, 4)
TAMPERS = (('first', 17, 3), ('last', 454, 4))
FIXTURES = Path(__file__).resolve().parents[2]/'crates/stele-verifier/tests/fixtures'


def vectors():
    lines = []
    for degree, ell, m, blowup in CASES:
        matrix = [[(i+2)*(j+3) for j in range(1 << m)] for i in range(1 << ell)]
        source, witness = p2.commit(matrix, ell, m, blowup, degree, 41)
        certificate = p2.certify(source, witness)
        verified = p2.verify_certificate(source, certificate)
        point = [tuple((i+1)*(k+2) for k in range(degree)) for i in range(ell+m)]
        a, b = eq(point[:ell], degree), eq(point[ell:], degree)
        value = dot(row(matrix, a, degree), b, degree)
        opening = p2.open_functional(Transcript(b'field wire oracle', degree), 12, verified, witness, a, b, value)
        verifier = Transcript(b'field wire oracle', degree)
        p2.verify_opening(verifier, 12, verified, a, b, value, opening)
        extra = {}
        if (degree, ell, m, blowup) == CASES[0]:
            # Authentic columns, a row from another matrix: ColumnMismatch.
            changed = ([[x+1 for x in r] for r in matrix], witness[1], witness[2])
            extra['column_mismatch'] = p2.certify(source, changed).hex()
            # A committed column holding the limb p: NoncanonicalField at an authenticated leaf.
            payloads = [struct.pack('<'+'I'*(1 << ell), *[P]*(1 << ell))]*(1 << (m+blowup))
            levels = wire.merkle.build(source.tree(), payloads)
            malformed = replace(source, root=levels[-1][0])
            extra['noncanonical_root'] = malformed.root.hex()
            extra['noncanonical'] = p2.certify(malformed, (matrix, payloads, levels)).hex()
        lines.append(json.dumps({
            **extra, 'degree': degree, 'ell': ell, 'm': m, 'blowup': blowup, 'tensor_bits': source.kt(),
            'source': source.bytes().hex(), 'certificate': certificate.hex(),
            'certificate_id': verified.identity.hex(), 'a': field_bytes(a).hex(),
            'b': field_bytes(b).hex(), 'value': encode(value).hex(), 'opening': opening.hex(),
            'continuation': verifier.challenge()[0].hex()}, separators=(',', ':')))
    return ('\n'.join(lines)+'\n').encode()


def parameters():
    lines = []
    for policy in (1, 2):
        for blowup in (1, 2):
            for m in range(31-blowup):
                n, d, e = p2.circle(m, blowup)
                q_c, q_o = counts(m, blowup) if policy == 1 else p2.Source(4, 41, 0, m, blowup, bytes(32)).counts()
                kt = [p2.tensor_bits(ell, e, degree) if policy == 2 else 0 for degree in (4, 8) for ell in range(31)]
                lines.append(' '.join(map(str, (policy, m, blowup, n, d, e, q_c, q_o, *kt))))
    return ('\n'.join(lines)+'\n').encode()


def continuations():
    lines = []
    wire_cases = FIXTURES.parents[2]/'stele-pcs/tests/fixtures/field-wire.jsonl'
    for line in wire_cases.read_text().splitlines():
        c = json.loads(line)
        t = Transcript(b'field wire oracle', c['degree'])
        t.state = bytes.fromhex(c['continuation'])
        lines.append(t.challenge()[0].hex())
    return ('\n'.join(lines)+'\n').encode()


def single():
    ell, m, blowup, degree = SINGLE
    matrix = [[(i+2)*(j+3) for j in range(1 << m)] for i in range(1 << ell)]
    honest, (_, payloads, _) = wire.commit(matrix, ell, m, blowup, degree, 41)
    lines = []
    for position, column, delta in TAMPERS:
        bad = list(payloads)
        limbs = list(struct.unpack('<'+'I'*(1 << ell), bad[column]))
        limbs[0] = (limbs[0]+delta) % P
        bad[column] = struct.pack('<'+'I'*(1 << ell), *limbs)
        levels = wire.merkle.build(honest.tree(), bad)
        source = replace(honest, root=levels[-1][0])
        t, a = wire.certificate_transcript(source)
        t.absorb(wire.CERT_ROW, field_bytes(row(matrix, a, degree)))
        count = counts(m, blowup)[0]
        draws = [t.column(wire.CERT_COLUMN, 1 << (m+blowup)) for _ in range(count)]
        assert draws.count(column) == 1 and draws[0 if position == 'first' else -1] == column
        certificate = wire.certify(source, (matrix, bad, levels))
        wire.rejects('ColumnMismatch', lambda: wire.verify_certificate(source, certificate))
        lines.append(json.dumps({'position': position, 'degree': degree, 'ell': ell, 'm': m,
            'blowup': blowup, 'source': source.bytes().hex(), 'certificate': certificate.hex()},
            separators=(',', ':')))
    return ('\n'.join(lines)+'\n').encode()


if __name__ == '__main__':
    for name, raw in (('policy2-full.jsonl', vectors()), ('pcs-parameters.txt', parameters()),
                      ('policy1-continuations.txt', continuations()), ('single-mismatch.jsonl', single())):
        if sys.argv[1:] == ['--write']:
            (FIXTURES/name).write_bytes(raw)
        assert (FIXTURES/name).read_bytes() == raw, f'verifier {name} fixture drift'
    print(f'{len(CASES)} full-byte Policy 2 certificate/opening cases; 118 parameter rows; '
          '6 Policy 1 continuations; 2 single-position ColumnMismatch certificates')
