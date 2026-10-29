# Private coefficient stage composition (Q20)

Status: research. RFC-0006 A4 stays Draft and E3-06 stays blocked with every
original acceptance criterion. No private PCS or joint ZK construction is admitted.

Question: can the real stacked A1 coefficient final be consumed by the weighted
selection reduction at the restored canonical point, without source values in the
stage descriptor, while retaining every original tensor and source-bit obligation?
Security properties: fixed expected source/view, exact claim/point consumption,
complete original consumption and shared transcript continuation. Cost terms:
c_sc/T_misc, dense reference preparation and actual original consumers. Kill
criterion: source values in the descriptor, a discarded final, wrong-coordinate
acceptance by actual reference consumers, mismatched accounting or continuation.

## Closed statement and framing

The verifier receives the expected stage, not a proof-supplied evaluator. Its
header uses [stacked-statement §2](../../formal/stacked-statement.md) items 1–4:
version/field/stage id, common layout, elimination order, consumed output claim,
coefficient id, original input ids and polynomial terms. Input/term counts are
at most 64, factors per term at most three, and all existing id/layout/field
checks apply. Append the [weighted metadata](WEIGHTED-PRIVATE-SELECTION.md)
prefix: version, field, full layout, ordered source axes, category axis, source id
and selectors. Its full layout must equal the stage layout. There are no source
values or weighted query/value in this prefix. The latter are derived from A1.

This candidate requires a source id distinct from the coefficient, output and
all original input ids. It names a separate typed integer view; no implicit alias
between an index representation and a K-valued tensor is admitted. Authentication
of that view and any future typed alias contract remain production requirements.
Unknown coefficient keys, including values, reject before an absorb. Proof keys
are exactly stage and selection. These Python objects do not define a production
proof byte parser. The complete statement frame is at most 9361 bytes under the
stated caps, including both copies of the common layout and any output point.

PrivateStack uses research label `stele/v0.1/research/gkr/private-selection` and
the concatenated header/metadata bytes above, before the stage A1 Instance. Its
absorb uses the same length-delimited BLAKE3 frame as the other research wrappers.
The existing public Stack format, which contains resolved public source values,
is unchanged. Sharing its header encoder does not use that public resolver for
a private index source.

## Claim consumption and transcript

The exact stage relation remains `v=sum_x A(x)*P(f_0(x),...)`. A is the MLE of
the Boolean onehot table times validity and selected-axis weights, all multiplied
before extension. The dense prover constructs that table from source indices,
reorders it and every original tensor into the chosen layer-first/layer-last
frame, and runs A1. The verifier replays that actual A1 proof, then restores its
draw-order point to canonical coordinates.

The last A1 final is the coefficient claim. Pass its exact value and restored
point into the weighted selection reduction on the same transcript, after the
stage Final. Weighted binds that point/value and the expected source metadata;
its root/tree A1 instances and Originals then follow unchanged. This consumer
runs even for an empty P, a zero coefficient or zero source/broadcast weights.
No provisional stage receipt escapes before the coefficient reduction succeeds.
An error after an absorb invalidates the whole attempt, without rollback/retry.

The resulting receipt exports every original stage input at the canonical point
and every index-bit claim at its own exact source point. It keeps stage and
selection SC records in separate fields. A stage id b must be divisible by 65
and b<=2^64-65. Its main instance is b; selection node j uses b+1+j, j=0..M-1.
The expected plan reserves the entire block [b,b+64], including unused slots.
Distinct private-stage ids therefore give disjoint instance ranges; other plan
instances must also avoid those reserved blocks. The standalone weighted wrapper
retains default base zero, or accepts a verifier-owned base checked for overflow
before any absorb. The root Instance binds that base before its first draw and
fixes every following node id. Logical heap position, not wire id, fixes degree.
Internal virtual-table input ordinals remain scoped to the reduction; actual
global tensor identity/plan validation and registry admission remain A4 obligations.
No intermediate commitment or cut is added.

With m full stage bits, delta=0 for empty P and otherwise 1+max factor count,
a source bits and M the weighted tree's leaf count, there are m+a*M existing-kind
Sumcheck draws. The conditional union-bound numerator is
`m*delta+a*(3M-1)` over |K|. There is no extra RLC draw. Stage A1 transfers a
false relation to an original input or coefficient; weighted reduction transfers
a false coefficient to original source bits, except for these losses. The source
must be fixed before stage challenges. Actual source/bit/range/packing/PCS,
FS/H and joint ZK obligations and losses remain additional.

The independent reference consumer checks every original tensor evaluation and
every scoped original bit claim, including source-domain validity. Actual tensor
and source-index bytes are bound in the test Public context before any challenge;
the context has explicit ids, layouts and lengths. This is a public oracle fixture,
not authentication or privacy for a real private witness. Prover range rejection
is not a verifier range proof. Messages remain unmasked, and one-row originals
still disclose bits. The wrapper does not derive the stage polynomial from an
inference operation or establish the consumed output claim's provenance.

## Costs and evidence

Let f<=64 be the original input count, h<=64 the term count, t<=64 the full axis
count, N=2^m, Ns=2^a, and n,s,k,M the weighted source parameters. Before source
scanning or dense preparation, the prover caps (f+1)*N stage cells and
Ns*(2M+k) selection cells separately at 2^18. Neither is a total-memory cap.
Original inputs, reordered copies, A1 scratch, context bytes and retained proofs
are additional; the reordered stage tables remain live during selection proving.

Including padding validation, coordinate decoding/reordering and polynomial
work, dense preparation/proving costs
`O(N*((f+1)*(m+t+1)+h)+Ns*M+n*s)`, plus bounded descriptor work. Conditional
verifier arithmetic costs O(m+f+h+a*M+k), plus descriptor work and actual original
consumers. Reference consumption costs O(f*N*(m+1)+n*(1+k*(a+s))+s).
The proof contains exactly `m*(delta+1)+f+1+a*(4M-1)+3M-1+k` K elements.
These formulas charge the dense A table: this study does not establish sparse
stage preparation, streaming, a weight-pass guarantee or measured performance.

Run `uv run --locked --script research/stacked-gkr/check_private_stage.py`.
Seed 30625 checks 128 stages per field in QM31/OM31, full extension coordinates,
both elimination orders, arbitrary category placement, multiple source axes,
padding holes, selected broadcasts, degree 0..4 and unused/no original inputs.
All actual coefficient/original consumers, SC records, proof sizes and transcript
continuation agree. The seeded corpus hash is
`88ecc5f3a841544e60426e88e511be899fe2a34fb7383eb2a8f992eb239c9e2b`.

Additional cases cover scalar/no-input stages, zero coefficient terms, independent
frame bytes, malformed identities/views/counts, source range and resource caps.
A 64-node selection range reaches u64::MAX exactly; overflow and misaligned or
overflowing private-stage blocks reject before an absorb.
One changed unused tensor final at a wrong layer or draw-order point passes
conditional replay but fails ClaimMismatch in the actual original consumer.
Empty P still rejects a changed coefficient final. A coherently reproved selection
child at draw-order coordinates rejects with FinalEvaluationMismatch. Omitting
only PrivateStack in a preceding scalar stage changes one successor stage final
and rejects with FinalEvaluationMismatch. These are research controls, not NC-0203.
Public-stage/codec regressions and both previous selection corpora pass unchanged.

Recommendation: continue Q20 with authenticated typed source/bit/range/PCS
consumers, global plan identities, full proof bytes, joint masking and the sparse
cost contract before accepting A4. See the [same-author review](../../agents/reviews/private-stage-study.md).
