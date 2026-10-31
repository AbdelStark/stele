# Native hash-work observations

RFC-0012 A10 and the [native PCS contract §9](../../formal/native-field-pcs.md#9-conditional-records-and-lifetime-ownership)
require local usage to remain observable after failure. `Transcript::usage()`
returns a copy of its checked counters. Merkle construction and authentication
offer `*_with_usage` entry points taking a caller-owned counter record. Existing
Merkle entry points execute the same implementation and discard that observation.

| Operation | Ordinary hashes | XOF requests / bytes | State updates | Inner words |
|---|---:|---:|---:|---:|
| Transcript construction | 2 | 0 / 0 | 1 | 0 |
| Message absorb | 1 | 0 / 0 | 1 | 0 |
| Successful K challenge | 1 | 1 / 256 | 1 | actual consumed words |
| Inner sampling exhaustion | 0 | 1 / 256 | 0 | 64 |
| Merkle path of height h | h+1 | 0 / 0 | 0 | 0 |
| Merkle construction with P padded leaves | 2P-1 | 0 / 0 | 0 | 0 |

Counts are per invocation, including repeated paths and rejected candidates.
A malformed descriptor, payload length or path length rejects before hashing.
A constructor rejects invalid public input or frame lengths before any hash.
A root mismatch retains all hashes for that path. A batch preflights all shapes,
then counts each path through the first authentication failure; later paths are
not hashed. Canonical absent padding contributes real construction hashes.

Each counter update is checked and atomic. `UsageOverflow` rejects before the
work whose count would overflow. Earlier completed work remains observable,
including an XOF and consumed candidate words before a failed state-update
reservation. Cryptographic state is unchanged on that error. The caller must
abort the whole proof attempt; these observations do not authorize continuation.

The transcript's counters cannot be supplied or reset through its public API.
The public copy and caller-owned Merkle records are ordinary observations,
not verification receipts. They count evaluations rather than distinct oracle
queries and cannot establish adversarial query caps, grinding limits or Q12.
The wrapper permutation is outside these BLAKE3 counters. The native certificate
[producer sampler](CERTIFICATE-PRODUCTION.md) now records every outer attempt.
The native certificate verifier now counts its completed-proof ID hash under A10.

Both-field transcript KATs check every state and challenge byte plus counters.
All ten Merkle fixtures retain their roots and paths. Controls cover counter
overflow, 64-word exhaustion, duplicate work, root mismatch and failed batches.
The transcript/Merkle gates reject omitted usage tests. No protocol binding,
random challenge, NC coverage or evaluated soundness term is added.

Run `cargo test -p stele-hash --all-features --locked --offline` and
`python3 -m unittest discover -s scripts/tests -p test_hash_usage_gate.py -v`.
These are operation counts, not benchmark results. Checked counters add work to
T_misc; no measured constant or weight-pass change is claimed. Full registration
and opening measurements remain part of E4-03a.
