# Native functional openings

RFC-0010 A9 §§4,9 now has a native producer and verifier for `aᵀ M b = v`.
Both use the caller's transcript, verified certificate and expected coefficients.
The verifier checks shapes before absorption, binds the statement and complete
row, checks the scalar, authenticates each derived column before decoding it,
checks every encoded-row equation, then absorbs the full response block.

OpeningRecord borrows the original CertificateRecord. Two sequential openings
retain the same certificate obligation and separate query terms. Transcript
usage is cumulative; Merkle usage belongs to the individual call. Failed attempts
return only the cause and usage, with no opening record or authorized continuation.

All six independent Python fixtures match native production, verification and
continuation in QM31/OM31. Each receives 128 byte mutations and 128 truncations.
Tests also cover response order, zero coefficients, failure usage and record
lifetimes. NC-0600/0601/0606/0607/0610 and NC-0803 exercise actual opening checks.
NC-0607 obtains a genuine certificate for a tree whose sole malformed leaf is
first queried during the opening; it must reject as NoncanonicalField after
authentication even with zero row weights. NC-0802 changes only a following A1
final derived after omitting OpeningColumns and requires FinalEvaluationMismatch.

E4-03a remains in progress: its closed A1 source adapter, NC-0609 and complete
registration/opening runtime, memory and proof-size ledgers are still required.
This implementation supplies no profile, Q12, privacy, fused-weight-pass claim or
measured cost-model constant. Its work belongs to the existing c_c/T_misc terms.
