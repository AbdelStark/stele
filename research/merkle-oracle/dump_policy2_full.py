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

CASES = ((4, 1, 1, 1), (8, 2, 1, 2), (4, 3, 14, 2), (4, 6, 3, 2))


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


if __name__ == '__main__':
    target = Path(__file__).resolve().parents[2]/'crates/stele-verifier/tests/fixtures/policy2-full.jsonl'
    raw = vectors()
    if sys.argv[1:] == ['--write']:
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(raw)
    assert target.read_bytes() == raw, 'verifier Policy 2 fixture drift'
    print(f'{len(CASES)} full-byte Policy 2 certificate/opening cases')
