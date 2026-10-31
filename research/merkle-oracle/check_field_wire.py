# /// script
# requires-python = ">=3.12"
# dependencies = ["blake3==1.0.11"]
# ///
"""Q27 exact certificate/opening byte oracle; no native admission or NC credit."""
from dataclasses import replace
from hashlib import sha256
import json
from pathlib import Path
import struct

from field_wire import (P, Transcript, commit, certify, verify_certificate,
                        open_functional, verify_opening, eq, scalar, dot, row,
                        encode, field_bytes, bind_sources, sc, flip, rejects)
import field_wire as wire


def exercise():
    vectors = []
    for degree in (4, 8):
        for ell, m, blowup in ((0, 0, 1), (1, 1, 1), (2, 1, 2)):
            matrix = [[(i+2)*(j+3) for j in range(1 << m)] for i in range(1 << ell)]
            source, witness = commit(matrix, ell, m, blowup, degree, 41)
            certificate = certify(source, witness)
            verified = verify_certificate(source, certificate)
            assert certificate == certify(source, witness)
            point = [tuple((i+1)*(j+2) for j in range(degree)) for i in range(ell+m)]
            a, b = eq(point[:ell], degree), eq(point[ell:], degree)
            value = dot(row(matrix, a, degree), b, degree)
            prover = Transcript(b'field wire oracle', degree)
            proof = open_functional(prover, 12, verified, witness, a, b, value)
            verifier = Transcript(b'field wire oracle', degree)
            verify_opening(verifier, 12, verified, a, b, value, proof)
            assert prover.state == verifier.state
            assert prover.challenge() == verifier.challenge()
            for bad in (certificate[:-1], certificate+b'\0', b'\2'+certificate[1:]):
                rejects('ProofShape', lambda: verify_certificate(source, bad))
            bad = certificate[:1]+struct.pack('<I', P)+certificate[5:]
            rejects('NoncanonicalField', lambda: verify_certificate(source, bad))
            rejects('RootMismatch', lambda: verify_certificate(replace(source, root=flip(source.root)), certificate))
            rejects('RootMismatch', lambda: verify_certificate(replace(source, identity=42), certificate))
            bad = certificate[:-1]+bytes([certificate[-1] ^ 1])
            rejects('RootMismatch', lambda: verify_certificate(source, bad))
            for bad in (proof[:-1], proof+b'\0', b'\2'+proof[1:]):
                rejects('ProofShape', lambda: verify_opening(Transcript(b'field wire oracle', degree),
                        12, verified, a, b, value, bad))
            rejects('ValueMismatch', lambda: verify_opening(Transcript(b'field wire oracle', degree),
                    12, verified, a, b, sc.add(value, scalar(1, degree)), proof))
            vectors.append({'degree': degree, 'ell': ell, 'm': m, 'blowup': blowup,
                'source': source.bytes().hex(), 'certificate': certificate.hex(),
                'certificate_id': verified.identity.hex(), 'a': field_bytes(a).hex(),
                'b': field_bytes(b).hex(), 'value': encode(value).hex(), 'opening': proof.hex(),
                'continuation': verifier.state.hex()})
    return vectors


def rejects_authenticated_bad_fields_and_rows():
    for degree in (4, 8):
        matrix = [[2, 3], [5, 7]]
        source, witness = commit(matrix, 1, 1, 1, degree, 41)
        changed = ([[3, 4], [6, 8]], witness[1], witness[2])
        rejects('ColumnMismatch', lambda: verify_certificate(source, certify(source, changed)))
        payloads = [struct.pack('<II', P, P)]*4
        levels = wire.merkle.build(source.tree(), payloads)
        malformed = replace(source, root=levels[-1][0])
        proof = certify(malformed, (matrix, payloads, levels))
        rejects('NoncanonicalField', lambda: verify_certificate(malformed, proof))
        certificate = certify(source, witness)
        verified = verify_certificate(source, certificate)
        a, b = eq([scalar(3, degree)], degree), [scalar(0, degree)]*2
        zero = scalar(0, degree)
        proof = open_functional(Transcript(b'bad row', degree), 3, verified, changed, a, b, zero)
        rejects('ColumnMismatch', lambda: verify_opening(Transcript(b'bad row', degree),
                3, verified, a, b, zero, proof))
        untouched = Transcript(b'bad shape', degree)
        initial = untouched.state
        rejects('FunctionalShape', lambda: verify_opening(untouched, 3, verified, a[:-1], b, zero, proof))
        assert untouched.state == initial
        # Exchange two distinct responses while retaining the expected query sequence.
        size, start = 8+2*32, 1+2*degree*4
        chunks = [certificate[i:i+size] for i in range(start, len(certificate), size)]
        different = next(i for i in range(1, len(chunks)) if chunks[i] != chunks[0])
        chunks[0], chunks[different] = chunks[different], chunks[0]
        rejects('RootMismatch', lambda: verify_certificate(source, certificate[:start]+b''.join(chunks)))
        assert len(chunks) == 314 and len(set(chunks)) == 4  # Duplicates remain in draw order.


def matches_reference_transcript():
    for degree in (4, 8):
        expected = sc.Transcript(b'byte parity', degree)
        actual = Transcript(b'byte parity', degree)
        for label in (wire.INSTANCE, wire.ROUND, wire.FINAL):
            actual.absorb(label, b'canonical message')
            expected.absorb(label, b'canonical message')
            assert actual.state == expected.state and actual.challenge() == expected.challenge()
        rejects('InvalidChallengeLabel', lambda: actual.challenge(wire.CERT_ROW))
        rejects('InvalidAbsorbLabel', lambda: actual.absorb(wire.WEIGHT, b'bad kind'))
        # Research-only forced candidates test the finite loop, never a native RNG API.
        forced = Transcript(b'exhaustion', degree)
        calls = []
        def candidate(label):
            calls.append(label)
            return scalar(P-1, degree)
        forced.field = candidate
        for size in (0, 1, 3, 2**31, True):
            rejects('InvalidColumnDomain', lambda: forced.column(wire.CERT_COLUMN, size))
        assert not calls
        rejects('ColumnSamplingExhausted', lambda: forced.column(wire.CERT_COLUMN, 4))
        assert calls == [wire.CERT_COLUMN]*64


def rejects_unused_original():
    for degree in (4, 8):
        matrices = [[[2, 3], [5, 7]], [[11, 13], [17, 19]]]
        pairs = [commit(matrix, 1, 1, 1, degree, identity)
                 for matrix, identity in zip(matrices, (41, 42))]
        certs = [verify_certificate(s, certify(s, w)) for s, w in pairs]
        tables = [[scalar(x, degree) for r in matrix for x in r] for matrix in matrices]
        instance = {'id': 71, 'm': 2, 'ids': [41, 42],
                    'terms': [(scalar(1, degree), [0])], 'sum': scalar(17, degree)}
        prover = Transcript(b'A1 closed source oracle', degree)
        bind_sources(prover, instance, certs)
        proof, point = sc.prove(prover, instance, tables)
        a, b = eq(point[:1], degree), eq(point[1:], degree)
        openings = [open_functional(prover, identity, cert, witness, a, b, value)
                    for identity, cert, (_, witness), value
                    in zip(instance['ids'], certs, pairs, proof['final'])]

        def verify(candidate, roster=certs, candidate_openings=openings):
            verifier = Transcript(b'A1 closed source oracle', degree)
            bind_sources(verifier, instance, roster)
            reduction = sc.verify_reduction(verifier, instance, candidate)
            weights = eq(reduction['point'][:1], degree), eq(reduction['point'][1:], degree)
            assert len(candidate_openings) == len(roster)
            for (identity, value), cert, opening in zip(reduction['claims'], roster, candidate_openings):
                verify_opening(verifier, identity, cert, *weights, value, opening)
            return verifier

        assert verify(proof).state == prover.state
        rejects('SourceRoster', lambda: verify(proof, certs[::-1]))
        changed = {**proof, 'final': [proof['final'][0], sc.add(proof['final'][1], scalar(1, degree))]}
        reduction_only = Transcript(b'A1 closed source oracle', degree)
        bind_sources(reduction_only, instance, certs)
        sc.verify_reduction(reduction_only, instance, changed)
        # Rebuild the used source's opening under the changed final-message state.
        # Otherwise its stale query paths reject before reaching the unused original.
        first = open_functional(reduction_only, 41, certs[0], pairs[0][1], a, b, changed['final'][0])
        rejects('ValueMismatch', lambda: verify(changed, candidate_openings=[first, openings[1]]))


if __name__ == '__main__':
    vectors = exercise()
    rejects_authenticated_bad_fields_and_rows()
    matches_reference_transcript()
    rejects_unused_original()
    raw = ''.join(json.dumps(v, separators=(',', ':'))+'\n' for v in vectors).encode()
    target = Path(__file__).with_name('field-wire-vectors.jsonl')
    import sys
    if sys.argv[1:] == ['--write-vectors']:
        with target.open('xb') as output:
            output.write(raw)
    else:
        assert not sys.argv[1:] and target.read_bytes() == raw
    core = Path(__file__).resolve().parents[2] / 'crates/stele-pcs/tests/fixtures/field-wire.jsonl'
    assert core.read_bytes() == raw, 'native field-wire fixture drift'
    print('6 certificate/opening cases; reference A1 unused-original controls;', sha256(raw).hexdigest())
