# Soundness accounting (generated per proof config by `stele-verifier::accounting`; this file is the human-readable spec)

Total error ε = Σ SC + Σ RLC + Σ LU + Σ PCS + Σ MASK + FS + H (RFC-0012 §4). Profile bound: standard 2⁻¹⁰⁰, treaty 2⁻¹²⁸.

| Line | Instance count driver | Formula | Proven? |
|---|---|---|---|
| SC | stacked reductions per stage (≈ 10²/proof) | `m·δ/|K|` | yes (Schwartz–Zippel) |
| RLC | RLC batch reductions | `t/|K|` | yes |
| LU | one per (table, challenge pair) | `(N+|T|)/|K|`, squared with double challenge | yes (Haböck 2022) |
| PCS | one per opening (R_stack, 7–9 weight types, multiplicities, aux) | `ε_gap(ρ,δ)+(1−δ)^q+ε_Merkle` | treaty: proven only (BCIKS20, DP23/24, Khatam) |
| MASK | per masked instance | `≤ 1/|K|` | yes |
| FS | adaptive queries `Q` + grinding | ROM bound | assumption A2 |
| H | hash collisions | `Q²/2²⁵⁶` | assumption A1 |

Illustrative treaty budget for W4 appears in RFC-0012 §5; the generator must reproduce it. The gate
`scripts/gates/soundness-accounting.sh` diffs the generator's instance enumeration against the transcript labels actually
used by the prover (every `challenge(label)` call must map to a ledger line).

## Transcript label mapping (RFC-0012 A1)

The initial challenge label `stele/v0.1/sumcheck/challenge` maps to SC, once per
round in each consuming sumcheck; absorption labels introduce no random challenge.
QM31/OM31 denominators are exactly p^4/p^8. A1's conditional uniformity argument
adds no sampling-error line; exhaustion aborts and cannot certify a statement.
FS/H still cover all adversary queries and grinding. The gate compares the validated
`stele-hash` registry producer with [the canonical inventory](transcript-labels.json)
and runs the registry and transcript primitive unit tests. NC-0801 rejects a duplicated label at that same
production validator. Unimplemented protocol crates retain their scaffold guards.
Registry validation alone does not establish per-instance accounting or a profile
budget; the sumcheck consumer is checked separately below.
Q12 (RFC-0019) tracks the missing concrete FS theorem/query convention and the
incompatible illustrative H budget. No profile can be certified from placeholders.

The gate also runs A2's wrapper-feature permutation KATs. This unused permutation
adds no challenge or ledger line. Q14 must resolve the wrapper hash/transcript
mode and its separate budget before E14-01 consumes it. Native A1 is unchanged.

RFC-0006 A1 specifies the SC record: instance id, m, degree bound δ, field degree d,
and exact numerator m*δ over symbolic p^d. Its [interactive obligation](../../formal/sumcheck.md)
bounds passing a false initial sum together with true final evaluations; every
emitted evaluation still needs a consumer. The gate executes the actual Rust
prover/public verifier and independent Python verifier over the shared corpus.
It compares emitted SC records to verifier-owned descriptors and derived-point
lengths. NC-0200/0201/0205/0800/0802 exercise the actual reduction/consumer and
transcript schedule. Full inference enumeration remains E8-05; these finite checks
do not discharge Q12 or certify a profile.

RFC-0012 A3 fixes Merkle authentication bytes without adding a challenge or an
algebraic loss. Its binding argument is conditional on BLAKE3 collision resistance;
PCS ε_Merkle/H still require Q12's concrete global query accounting. Membership
alone does not certify codeword validity, canonical field encodings, unopened
subtrees or a profile budget. NC-0602 now checks both leaf kinds through actual construction/authentication;
this supplies membership-binding evidence, not a PCS or hash-budget certificate.

RFC-0006 A2 / RFC-0012 A4 now have both batching consumers: one BatchCoefficient
challenge maps to RLC t/p^d and shared rounds to SC M D/p^d (D=2 for claim mode).
The eight-entry registry is unchanged. Gates check 42 instance and six claim byte/
record cases, 10^4 coefficient evaluations per field, and actual two-mode controls.
The [interactive obligation](../../formal/batching.md) remains conditional on true
final evaluations. Full E3-02 rejection-corpus/benchmark evidence remains incomplete;
Q12 still blocks certification. Catalog coverage is nine controls, not a full claim graph.
