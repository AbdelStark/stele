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
Those eight label meanings are unchanged; A3 extends the registry below. Gates check 42 instance and six claim byte/
record cases, 10^4 coefficient evaluations per field, and actual two-mode controls.
The [interactive obligation](../../formal/batching.md) remains conditional on true
final evaluations. The 276-case shared Rust/Python corpus checks exact decisions, every returned obligation,
and SC/RLC records against descriptors. E3-02 has [both-field CPU baseline ledgers](../../bench/README.md#batching-e3-02);
Q12 still blocks certification. Catalog coverage is thirteen controls, not a full claim graph.

RFC-0006 A3 / RFC-0012 A5 now have a production zerocheck consumer. With j=m-k
and D=δ*(2^k-1), the three ordered SC phases record j (ZeroWeight), D (optional
skip Sumcheck), and j*δ (tail Sumcheck), over p^d. The twelve-label registry and
canonical inventory include its four labels. The [interactive obligation](../../formal/zerocheck.md)
remains conditional on all original slice claims. Both gates check 130 actual
Rust/Python byte/claim/record cases against descriptors and transcript continuation,
plus NC-0207..0209 and the ZeroFinal extension of NC-0802. Numerator, final-label
and public-consumer bypass mutants fail the gate. The reduction alone does not
accept a statement; the public adapter consumes every original slice claim.
The shared 314-case Rust/Python corpus additionally compares exact public-verifier
decisions, every original claim, phased SC records and the next challenge. Gate
regressions reject changed corpus expectations, omitted claims and wrong records.
Both gates also require 1,000 seeded direct-reference cases per degree and field,
including every eligible (m,k) through m=4, maximum skip with a tail at m=5,
and public claim consumption.
E3-03 has [both-field complete-cost/memory ledgers](../../bench/README.md#zerocheck-e3-03);
performance evidence does not strengthen the conditional algebraic bound. Q12 remains open; these gates do not certify a profile.

RFC-0006 A5's Small strategy retains the A1 transcript, final obligations and
SC m*δ/p^d record without new challenges or registry entries. Both gates require
QM31/OM31 directed proof parity, transcript continuation and the actual NC-0204
original-value rejection. Typed i16/u16 storage is an optimization eligibility
contract, not a range proof. Both gates additionally require 1,000 seeded cases per
degree and field against direct original-MLE evaluation and Dense, with all eligible
(m,k) through m=4 and k=4 with a tail at m=5. These compare the full proof, final
claims, SC record and continuation. A missing field test fails the gate. The shared
Rust reference uses production field/eq/transcript/engine primitives. The shared
302-case small-value corpus additionally compares the actual Rust and independent
Python A1 public decisions, every final claim and SC record. Its 76 honest chains
require actual Small prover bytes followed by an A1 continuation. Corrupted rounds,
proof lengths, unused finals and truncated originals yield 226 exact rejections.
Both gates check regeneration, checked adapter narrowing and actual prover parity;
regressions reject corpus drift, broken adapter selection and missing claims.
E3-04 now has [both-field complete-cost/memory ledgers](../../bench/README.md#small-value-pipeline-e3-04),
including consumer-dominated pipeline peaks and all losses. Performance evidence
does not change the SC bound; these finite checks certify no profile.

RFC-0010 A2's circle map has a deterministic distance lower bound N-k for k>=2,
and N for a constant message. This is not a PCS proximity-gap or profile bound.
Its encoder contract adds no transcript label, challenge or implemented loss line.
The CPU map now has direct-reference and Python-vector checks under E4-02, plus
the full input-size cost/memory ledger at both rates. A1's parameter provenance
and the actual PCS consumer/accounting tasks remain open. The code identity alone
cannot admit a profile or certify codeword validity of a Merkle commitment.

RFC-0006 A6's streaming contract retains A1's m*delta/p^d record, messages and
all original final consumers. No challenge, label or implemented loss changes.
Its source/layout/capacity studies establish neither production NC-0210 nor
profile security. The actual strategy, both-field corpus, control and accounting
gate integration remain E3-05 delivery requirements; Q12 is unchanged.

The A6 caller-buffer engine reuses A1's round/final checks and original public
consumer, without changing any loss line. Both accounting and control gates
require 1,000 Dense/buffered cases per degree and field, full proof/continuation
parity, unchanged caller capacities and typed preflight/false-sum/unused-final
rejections. Independent A1 corpus and digest checks still cover the shared
encoders/interpolator. This engine is not the Streaming strategy: NC-0210, actual
source capacity accounting and complete pipeline memory/cost evidence remain open.

The A6 generic source/arena strategy now preserves A1 proofs and original claims
in both fields. Gates require 1,000 cases per degree/field, canonical tail order,
source visit/error checks, workspace capacity limits and cached-instance rejection
including m=0. Its bound remains the same SC line. A generic source is not an
authenticated consumer or a file adapter; independent streaming corpus decisions,
NC-0210 and complete preparation/consumer memory ledgers are still required.
