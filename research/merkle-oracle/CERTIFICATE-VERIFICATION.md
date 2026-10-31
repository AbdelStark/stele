# Native certificate verification

RFC-0010 A9 §3/§9 verification consumes caller-owned Source and complete proof
bytes. It preflights shape/canonical row fields, derives all row weights and
queries from Transcript, authenticates each ordered response before field
decoding, and checks every encoded-row equation. Only after final response
absorption and exact-frame ID hashing does it construct VerifiedCertificate.
The private record retains the original conditional obligation on every replay.

Both fields match all six independent fixtures, certificate IDs and real
continuation challenges. Each fixture receives 128 deterministic byte mutations
across header, row, payload and path regions plus 128 arbitrary truncations.
Malformed rows/shapes reject before hashing; authenticated invalid limbs reject
as NoncanonicalField, while an unauthenticated invalid limb rejects as RootMismatch.

Actual standalone controls, each executing QM31 and OM31:

| Control | One changed value | Required rejection |
|---|---|---|
| NC-0600 | one committed constant-codeword limb | ColumnMismatch |
| NC-0601 | one derived index and its rebuilt response | RootMismatch |
| NC-0606 | expected root bit | RootMismatch |
| NC-0607 | one authenticated limb becomes p | NoncanonicalField |
| NC-0608 | one imported payload byte after an honest verification | RootMismatch |
| NC-0803 | one differing index from the pre-row transcript | RootMismatch |

Usage reports actual transcript, Merkle and ID hashes, including failures. It is
hash-only; encoder work is not yet returned. Full resource/benchmark evidence,
[functional opening resource reports](FUNCTIONAL-OPENING.md), the A1 adapter, lifetime composition, Q12, privacy and
profiles remain open. No measured cost-model constant or weight-pass claim changes.
