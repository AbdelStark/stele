# Candidate stacked statement and bytes (Q20 / RFC-0006 A4)

Status: Draft. This proposes exact statement bytes and the A1 reuse boundary.
It does not authenticate a source, register a production label or authorize core
code. A4 acceptance still requires the source/consumer closure and full reviews.

The revised [conditional runtime contract](stacked-runtime.md) is the current
A4 review proposal. It specifies complete public/certified original consumers
and explicitly separates private coefficient admission. This file preserves the
historical research codec and its evidence; it is not the production contract.

## 1. Statement, coefficient and trust boundary

The verifier derives a statement from its authenticated plan: stage id, common
input layout, layer order, consumed output claim/layout, ordered original input
ids, polynomial P and one public coefficient descriptor A. The plan's producing
reduction must derive A and P from the consumed claim and the specified operation.
The generic kernel cannot infer an operation from tensor ids or prove a caller's
incorrect plan. The proof never supplies this expected statement or an evaluator.

Each layout is an ordered list of (bit width, real length) axes. Width is 0..63,
real length is 1..2^width, total width is at most 63 and axis count at most 64.
The input layout has at least one axis, with the first being the layer axis.
An output scalar may have no axes. Output point length equals its total width.
Materialization separately checks addressability/allocation limits. Source/input
ids refer to their exact declared tensors, not unrecorded partial views.

A is the MLE of the following single Boolean table on the common input layout:
`T(x) = valid(x) * primitive(x) * product_selected_axes eq(z_axis,x_axis)`.
`valid` excludes every axis's padding before extension. Selectors contain full-K
fixed points on selected complete axes; absent selectors contribute one. Primitive
kind eq is constant one; the other primitive Boolean values are the causal/window,
onehot, GQA or exact table values in public-mle.md. This definition allows a layer
selector and a mask to share axes without multiplying their separate MLEs.
The kernel then proves `claim.value = sum_x A(x)*P(f_0(x),...)`, where A and each f
are extended separately. No post-extension selector may be silently inserted.

Weighted evaluation follows the same finite-state proof: multiply each Boolean
bit-choice weight by its fixed selector factor before adding states. Disjoint
axes factor; shared axes use the weighted mask/selection/table sum. This keeps A
multilinear in the queried point. The full A1 degree is zero for an empty P term
list, otherwise one plus the maximum P factor count, including zero coefficients.
P factor lists therefore have length at most three; unsupported degree rejects.

All source values in this descriptor are verifier-owned resolved values. They
are not a proof field or a substitute for authentication. A source id names the
plan's exact source tensor/view. For original public values, resolve against the
actual bound public input. For a committed index vector, the plan must consume
its real prior opening against the expected commitment and shape. For RoPE,
resolve the exact CQIS/passport table identity, shape and values. A source id,
digest, path, self-comparison or caller-set flag is not evidence of that step.

The existing architecture places PCS/CQIS consumers outside stele-gkr. Their fixed
verifier path must resolve these sources before invoking a stage; GKR must not
import an upward PCS dependency or accept a prover callback as an authenticator.
A standalone public reference adapter may close a statement with original public
sources/tables. It cannot claim private-source or inference acceptance. The exact
production source-resolution interface and its actual consumer tests remain an
A4 acceptance gate; this byte codec supplies neither. Source failures abort the
whole attempt, with no fallback to treating supplied values as public.

This public resolver is limited to source values the statement permits to be
public. It cannot satisfy a private selection source by exposing the entire
vector. The [private selection study](../research/stacked-gkr/PRIVATE-SELECTION.md)
proposes a separate conditional index-bit consumer. Actual source/view binding,
range/packing proofs, full selected-axis composition and joint masking remain
prerequisites; the unmasked study is not a private resolver or a ZK construction.

The [weighted continuation](../research/stacked-gkr/WEIGHTED-PRIVATE-SELECTION.md)
checks that composition algebra and a candidate source-scoped frame for multiple
source axes, category placement and selected broadcasts. It still requires the
real stacked-final adapter, authenticated plan/view and private consumers; its
public reference fixture does not close this production interface.

The [private-stage study](../research/stacked-gkr/PRIVATE-STAGE.md) supplies an
actual reference adapter: a separate closed metadata-only frame, canonical point
restoration and consumption of the stage's A final by weighted selection. Its
original data are fixed public fixture bytes; aligned instance-id blocks separate
the stage and child nodes. Production authentication, full plan/tensor identity
validation and joint ZK remain open.

The [typed bit-source baseline](../research/stacked-gkr/SELECTION-SOURCE.md)
connects those bit claims to one original tensor, with actual Boolean/padding/range
reductions. It changes no admitted commitment format: the reference uses fixed
public source bytes, and its material message expansion requires comparison with
compact authenticated representations before adoption.

The [two-bit candidate](../research/stacked-gkr/PAIRED-SOURCE.md) makes that
comparison through derived-bit Booleanity and actual bit-extraction reductions. Its
virtual bit tensor has no commitment; every bit MLE reduces to the same original
symbol tensor. Message savings do not imply smaller working memory or a private
PCS/ZK construction, and do not accept this candidate format.

## 2. Byte grammar

Integers are unsigned little-endian with their stated widths. K elements are d
canonical M31 u32 limbs in the RFC-0003 basis, d in {4,8}; limbs >=p reject.
There is no alignment, padding or terminator. Lists remain in verifier plan order.
No semantic term normalization or duplicate-id aliasing is implicit.

`Layout = u8(axis_count) || each (u8(bits) || u64(real))`.
The Stack payload is the following exact concatenation:

1. u8(1) format version; u8(d); u64(stage_id); input Layout; u8(order), where
   0 is layer-first and 1 layer-last under stacked-ownership.md.
2. u64(output_tensor_id); output Layout; its derived number of K point elements;
   K(output_claim_value).
3. u64(coefficient_tensor_id); u32(input_count); ordered u64 input ids.
   Original input ids are distinct; the coefficient id differs from every original
   input and output id. If the output id aliases an input, its layout must match.
   The coefficient id is a plan-reserved public A1 identity, not a new commitment.
4. u32(term_count); for each P term: K(coefficient), u8(factor_count), then that
   many u32 original-input ordinals. Factor count <=3; ordinals <input_count.
5. u8(kind): 0 eq, 1 causal_mask, 2 window_mask, 3 onehot_sparse,
   4 gqa_broadcast, 5 rope_tables.
6. For each input axis in canonical order: u8(selector_present) in {0,1}; if one,
   exactly axis.bits K elements for its fixed point. A selected zero-bit axis
   has an empty point; this is explicit syntax, not semantic normalization.
7. The kind payload below. End of payload must follow exactly; suffix bytes reject.

| Kind | Kind payload |
|---|---|
| eq | empty |
| causal_mask | u8(row_axis), u8(column_axis) |
| window_mask | same two axes, u64(positive_width) |
| onehot_sparse | two axes, u64(source_tensor_id), u64(value_count), that many u64 indices |
| gqa_broadcast | u8(head_axis), u8(group_axis) |
| rope_tables | u8(source_axis_count), that many u8 axis ordinals, u64(source_tensor_id), u64(value_count), that many canonical M31 u32 values |

Each two-axis kind uses distinct in-range axes; row/column order is significant.
Causal/window axes have equal bit widths. Width may cover the entire padded domain.
GQA real head count is divisible by real group count. Onehot value_count equals
real row count and each index is below real category count. RoPE source axes are
nonempty, distinct and strictly increasing; its unpadded row-major value_count is
the product of their real lengths. All other axes broadcast the primitive value
before validity/selectors are applied. RoPE source values embed from M31 into K;
this does not define CQIS generation or permit replacing its table identifier.
Source ids differ from the coefficient id. If a source id aliases an original
input/output id, its declared source layout must match that tensor layout. The
actual resolver/consumer must also enforce kind and value consistency; matching
ids or layouts alone do not authenticate an alias. Partial views require their
explicit plan identities and real consumers.

Check all sums/products/count widths and available bytes before allocation or
iteration. Unknown versions, fields, orders, kinds/flags, inconsistent dimensions,
noncanonical fields, duplicate identities, out-of-range ordinals/indices, trailing
bytes and truncated payloads reject. Allocation failure is never a verifier bypass.
The research codec uses InvalidStacked for malformed descriptors; production error
mapping and resource admission still require review before A4 acceptance.

## 3. Proposed A1 schedule and obligations

After validating the verifier-owned statement and resolving its actual sources,
absorb Stack using proposed `stele/v0.1/gkr/stacked` (RFC-0012 candidate A6).
Derive A1 Instance with this stage id, m equal to total input bits, ordered ids
`original ids || coefficient id`, and claimed sum equal to the consumed value.
For each P term, append original ordinal input_count to its factor list. A1's
normal Instance absorb follows Stack, then unchanged Round/Sumcheck operations,
all Final values and the ordinary continuation. There is no extra challenge.

A4 applies an explicit coordinate frame around A1: nested input i denotes
`g_i(y)=f_i(restore_pi(y))`, with that frame bound by Stack. The original tensor id
is retained, but the raw nested A1 receipt/claims must remain internal to the
wrapper. They cannot be passed to an original consumer at the draw-order point.
Only the restored A4 claims are exported. This is an explicit variable renaming,
not permission for a standalone A1 strategy to silently reorder its inputs.

The prover materializes/restricts the actual A table and original inputs in the
chosen elimination order; use stacked-ownership.md's exact partials/folds. The
verifier derives the same descriptor, validates A1 shape/replay and restores its
point to canonical coordinates. Independently evaluate A at that point and reject
a wrong coefficient final. Emit every original input claim, including unused
inputs, for its real consumer at that same canonical point. The A coefficient
final is absorbed by A1 even when P is zero; it is checked, not silently omitted.
At m=0 source/shape validation and every final check still apply.

This is a conditional reduction until original obligations are actually consumed.
A public adapter checks exact original table shapes/padding and all evaluations;
private/virtual/committed inputs require their actual reduction/PCS consumers.
No kernel receipt alone proves the complete inference or its source provenance.
Any error after transcript mutation invalidates the attempt; retry starts fresh.

## 4. Loss, costs and remaining controls

The only proposed algebraic line is the reused A1 SC record m*delta/p^d. There is
no new random challenge, RLC, integer identity or bound certificate. FS/H, Q12,
composition and ZK remain separate. Descriptor work includes every source value
and selector byte; source authentication, public A evaluation, materialization,
state movement and original consumers are additional explicit c_sc/T_misc costs.
No benchmark, fitted constant, weight pass or profile admission is asserted.

Before implementation: accept the complete source interface, exact errors,
registry/inventory/accounting mapping, crate dependencies and required reviews.
Before delivery: actual NC-0203 wrong-layer rejection, one-source-value tampering,
wrong canonical final coordinates and chained-final controls, both-field protocol
bytes/decisions and original consumption. Research codec round-trips and truncated
payload rejection earn no production binding or source-authentication credit.


## 5. Closed public execution study

The research wrapper `research/stacked-gkr/stage.py` instantiates this schedule
with the prior A1 oracle. It proves only the stated algebraic relation with all
original tables and coefficient source values fixed as actual public inputs.
It does not derive A/P from an inference operation or authenticate private sources.
The consuming plan and any production private/CQIS paths remain prerequisites.

The fixture's Public payload contains the actual original values: research prefix
`Q20/public-tables/v1`, field-width byte, common Layout, u32 table count and each
original u64 id followed by all its canonical K entries in plan order. Every table
has exactly 2^m entries. This is a test-context envelope, not the production
inference public-input format. Fix and bind these inputs before any challenge;
a literal context string alone is not a binding to mutable original tables.
All coefficient source/selector bytes are then bound by the complete Stack frame.

The prover builds the canonical Boolean A table independently of the weighted
verifier evaluator, reorders every actual input into the selected frame and calls
A1. The verifier replays A1, restores the point, checks its last A final against
the weighted evaluator and exports only the original claims with their common
canonical point. The public adapter checks every one against the actual original
table, including unused inputs. It also validates shape, canonical limbs and
zero padding before replay. Failed post-absorb checks invalidate the whole attempt.

Research errors: descriptor/field mismatch is InvalidStacked; invalid original
shape/limbs/padding is PublicShape; a wrong A final is CoefficientMismatch; an
original evaluation mismatch is ClaimMismatch. A1 retains its own errors. This
mapping is candidate evidence only, not accepted production resource/error policy.

The seeded study checks 600 stages per field across all kinds, both layer orders,
full extension limbs, degrees 0..4 and m=0/3, plus 12 no-original-input boundary
cases. A wrong-layer unused final and a draw-order unused final each pass the
conditional reduction but fail actual public consumption with ClaimMismatch.
Changing one exact table source at m=0 with empty P changes one proof final and
fails CoefficientMismatch. Omitting a prior Final only in the adversarial prover
changes one final of the next one-round proof and fails FinalEvaluationMismatch.
These are research rejection examples, not NC-0203 or source-authentication credit.

The dense research preparation and direct original consumers explicitly charge
O((a+1)*m*2^m) work (plus scalar cases), with a original inputs, multiple live table
copies and O((a+1)*2^m) field storage beyond the public context bytes. A1 proving,
weighted A evaluation and descriptor work are additional. No streaming, measured
cost constant, weight-pass guarantee, distributed partial execution or production
parity is claimed. The SC record remains m*delta/p^d; Q12/FS/H and profile bounds
are not resolved by honest transcript agreement or these rejection examples.
