# Conditional matmul with original field sources

Status: Draft for RFC-0007 A2, RFC-0010 A10 and RFC-0012 A12.
This is one complete stacked field statement, using the actual A4/A1
reduction and A9 source consumers. It is a prerequisite of E7-01/E7-02, not
integer matmul, a model plan, a complete weight phase, private inference or admission
to either profile. No new inference cut or commitment to a partial row is
authorized. E7-01/E7-02, A6 packing, virtual-source and W8 criteria remain.

## 1. Expected statement and source geometry

The caller supplies the expected stage, output tensor and public coefficient
ids, dimensions `L=2^h, n=2^a, d=2^b, m=2^c`, point
`(r_l in K^h, r_i in K^a, r_j in K^c)`, value `v in K`,
and two actual verified A9 certificates in order X,W. All are fixed before
this stage's transcript segment, independently of proof metadata. K is the
existing QM31 or OM31 transcript field. The output claim means
`C_tilde(r_l,r_i,r_j)=v` for `C[l]=X[l]*W[l]` over M31, embedded in K.

The exact physical A9 matrices are:

* `M_X[i*(L*d)+l*d+k]=X[l,i,k]`, rows n and message columns L*d;
* `M_W[j*(L*d)+l*d+k]=W[l,k,j]`, rows m and message columns L*d.

Each source uses its own expected A9 Circle identity, policy, root and
verified certificate id. The code message length must equal L*d; the two
rates may differ. All extents are full powers of two without implicit
padding, packing or range interpretation. Source identities X,W and the
output and coefficient identities are pairwise distinct u64 values. The stage id is
unique within the enclosing expected statement. Reject shape/field/context
disagreement before any absorb. Zero-bit axes are valid, including L=d=1.

This explicitly fixes logical X coordinates `(l,i,k)` to physical `(i,l,k)`
and logical W coordinates `(l,k,j)` to physical `(j,l,k)`. It does not infer a
transpose from a root or relabel an existing commitment, including R_stack's
different layout. Registration
must prepare exactly this physical representation under the expected root;
its transpose/encoding/certification costs are registration costs. A source
owner must already authorize the original tensors. This contract cannot turn
a virtual activation into a committed cut or establish passport ownership.
It supplies a conditional two-source statement until the full plan connects
the selected original sources to CQIS/model authority.

Derive two uncommitted partial rows, with canonical MSB-first eq weights:
`A[l,k]=sum_i eq(i,r_i)*M_X[i,l*d+k]` and
`B[l,k]=sum_j eq(j,r_j)*M_W[j,l*d+k]`.
Then `v=sum_{l,k} eq(l,r_l)*A[l,k]*B[l,k]`. Their A4 original input ids are
the ordered X,W ids within this stage; this amendment assigns those local
evaluations to partial-row functions, not to an original tensor point missing i/j.
Neither A nor B gets a commitment, certificate, source id or authority handle.

## 2. Retained functional row and prover schedule

Add a producer-only retained-row type in stele-pcs. Its checked constructor
borrows one immutable PreparedSource and takes exact row weights of the
source's row count. It validates all dimensions and capacities, then reads
each original message element exactly once in row-major order, accumulating
the K-valued row `u[column]=sum_row a[row]*M[row,column]`. It retains the
source borrow, exact row weights and immutable u. No public constructor from
an arbitrary u, mutable row access, deserialization or digest constructor is
allowed. The type supplies no verification or profile credit.

The matmul producer constructs A with eq(r_i) and B with eq(r_j). The actual
A4 dense strategy uses a checked folding copy of these same retained rows;
it may not obtain a second caller-supplied A/B or recompute them from sources.
Retain the original rows while folding scratch. Capture (s_l,r_k) from the
actual A4 execution; replaying a verifier to recover challenges is not the
producer schedule. Derive the exact A4 statement with input axes [(h,L),(b,d)],
fixed layer-first order, output axes [(h,L),(a,n),(c,m)] and point r_l||r_i||r_j.
Use inputs [X,W], P with one coefficient-one term [0,1], the expected public
coefficient id, and Eq with selectors [Some(r_l),None]. Its nested actual A1
instance has h+b variables and inputs [X,W,coefficient_id], with one term
[0,1,2], claimed sum v and degree three. This conservative degree also holds
when L=1; there is no separate single-instance encoding. The A4 coefficient
final is independently consumed by its existing A7 evaluator.

After A1, open X followed by W. The retained-row opening method takes the
matching verified certificate, expected row weights, column weights eq(s_l||r_k),
opening id and expected final value. Before transcript mutation it checks
exact source bytes, row weights, dimensions and field against its retained
owner. Different source or row weights return RowContext. It serializes the
retained immutable u itself as the existing A9 OpeningRow, checks its dot
product with eq(s_l||r_k), and uses the existing ordered response producer. It
does not scan the original message again or accept a replacement row.

The general A9 opening remains available with its existing behavior. Sharing
its response/framing implementation is required; the retained method does
not define a second PCS protocol. Sampling authenticated encoded columns
reads the prepared commitment, not the source message; charge those reads
and all proof buffers separately. Registration is outside the online pass
counter and must remain separately measured. Do not hide source reads in a
preparation phase charged to another stage.

## 3. Exact proof bytes and transcript order

All integer fields below are unsigned little-endian, and all K values use
canonical RFC-0003 bytes of width w=4*[K:M31]. There is no padding, metadata
override, implicit length prefix or trailing data.

The new absorb-only label MatmulStatement is
`stele/v0.1/matmul/statement`. Its exact payload is
`u8(1) || u8([K:M31]) || u64(stage_id) || u64(output_id) || u64(coefficient_id) ||
u8(h) || u8(a) || u8(b) || u8(c) || r_l_bytes || r_i_bytes || r_j_bytes || v_bytes ||
X_source_bytes || X_certificate_id || W_source_bytes || W_certificate_id`.
Source bytes are the exact 105-byte A9 contexts; certificate ids are 32 bytes.
Payload length is `304+w*(h+a+c+1)`. Bind it once before A4 Stack and A1 Instance.

The complete proof wire is `u8(1) || A1_rounds || A1_finals ||
X_opening_wire || W_opening_wire`. A1_rounds contains h+b ordered quadruples
`g_r(0),g_r(1),g_r(2),g_r(3)`, followed by exactly three ordered final values
for X,W and the public coefficient.
Both complete A9 wires retain their version bytes and expected-context sizes.
Total size is `1+w*(4*(h+b)+3)+size(X_opening)+size(W_opening)`.
No original point or final value is duplicated in the outer wire.

After complete preflight, the schedule is MatmulStatement; actual A4 Stack;
actual A1 Instance/Round/Sumcheck/Final; actual X Opening/OpeningRow/OpeningColumn
draws/OpeningColumns; then actual W in the same order. Use the original
tensor id as each opening id inside the bound stage. Both source contexts
and certificate ids bind before any A1 draw. Use the unclosed A4 kernel only;
do not call its public/certified closed adapters or emit StackSources. This
operation's explicit original-source mapping supplies the kernel's fixation
precondition. It changes neither existing A4 adapter nor A9 FieldSources.
Opening queries follow the
complete corresponding retained row; repeated indices and both response
absorptions retain A9 rules. No new random challenge is introduced.

Preflight every proof length, canonical A1/OpeningRow encoding, certificate roster,
source/point shape, A1 descriptor and capacity before the first absorb.
The verifier derives all lengths from its expected statement. Reject wrong
version, short/trailing bytes or extra records with ProofShape; preserve
NoncanonicalField for invalid limbs. A9 response paths authenticate before
canonical column decoding, preserving its existing error order. Invalid expected
ids/point/exponents return InvalidMatmul; mismatched source roster/layout returns
SourceRoster. Any subsequent error aborts the whole
attempt without a usable record or continuation. No rollback or hidden retry.

## 4. Closed verifier and records

The verifier receives only the expected statement, two verified certificates
and complete proof bytes. It receives no original matrices, prover-chosen
source descriptors, consumer callbacks or replacement points. It runs the
actual A4 verify_reduction, including A1 and its independent A7 final check,
obtaining the restored (s_l,r_k) and two ordered partial-row claims. Restore X
as r_i||s_l||r_k and physical W as r_j||s_l||r_k; independently derive
the corresponding eq weights. Run the actual A9 point/functional verifier
for X then W with those final values and complete opening bytes.

Both openings execute even if one final is zero, the incoming claim is zero,
or L=d=1. A1 product consistency cannot exempt an original. The successful
opaque record retains the actual SC record and both OpeningRecords, borrowing
their real verified certificates and original lifetime losses. It cannot be
constructed from a digest, boolean or unverified wire. It gives conditional
field-relation credit only after both consumers finish. No unused proof data
or unconsumed final survives. All errors preserve the actual failing consumer
and observed usage, without a partial acceptance record.

## 5. Soundness and accounting

For fixed original messages, A and B are multilinear in (l,k). A4's actual
degree-three A1 argument from RFC-0006 A1/A4 contributes exactly
`3*(h+b)/|K|`, recorded once even when its numerator is zero. The separately
multilinear eq coefficient has its independent A7 consumer. Physical coordinate
restoration is deterministic and adds no random loss. Each actual A9 opening
contributes its own `((N-D+e)/N)^q_o`, with its expected source parameters.
Retain both certificate tensor/query terms, every reuse/lifetime obligation,
and the global RFC-0010 A8 collision/late-preimage conditions. The derivation
is conditional on those same A8/A9 hypotheses; retained-row ownership changes
neither the PCS theorem nor its finite policy.

Before replay, check the u64 sum of both maximum local Merkle hash counts
`q_o*(1+path_height)` so every successful or failing prefix is representable.
Count h+b A1 field draws and the two actual opening samplers, including rejected
attempts, responses and failure prefixes. One cumulative outer transcript
snapshot is separate from disjoint ordinary Merkle hash work and standalone
registration transcripts. Do not add cumulative snapshots to one another or
interpret local observations as adversarial FS/H query caps. The new absorb
adds framing/hash work only. Q12, complete profile budgets and joint-view ZK
remain open; neither standard nor treaty is admitted. No integer identity is
claimed, so there is no inferred CQIS bound certificate or range proof.

## 6. Costs, capacities and required delivery

Online partial preparation reads L*n*d X elements and L*d*m W elements once
and performs L*n*d+L*d*m base-to-K MACs. This contributes to c_a/c_w; the
degree-three folds contribute O(L*d) K work to c_sc. The current A4 reference
also builds its coefficient in O(L*d*(h+1)) work and initializes/reduces L
partial slots per round, O(L*(h+b)); retain these costs. Two A9 consumers add row encoding,
scalar checks, ordered paths and column equations to c_c/T_misc under their
existing formulas. The verifier reads no original matrix. No L*n*d*m witness,
extra original-weight traversal, packed row or short-column claim is allowed.
The m-element W columns and retained dense state are explicit limitations;
this does not satisfy the complete configured weight-phase, bucketed, memory
or succinctness criteria. Charge the public coefficient, per-layer partials
and all A4 dense strategy capacity in addition to retained A/B.

Preflight checked integer shifts/products/sums and fallible allocation before
every buffer. Caller budgets bound complete descriptor/proof bytes and peak
working elements, including retained A/B, folding copies, eq weights, encoded
rows, response material, codec buffers and overlap. Preserve A9's own limits.
Keep the existing unclosed Prepared::for_certified_sources conservative
descriptor reservation, including its unused closed-roster allowance, and
add the MatmulStatement frame and opening costs. This accounting does not
mean StackSources was emitted. No new GKR constructor is required to save it.
Include preparation, registration matrices/encodings/Merkle nodes, generated
proof and verification allocations in complete process-memory measurements.
Budget exhaustion returns Capacity, never truncated work or partial success.

The native delivery must include both fields; L=d=1 and zero-bit outer axes;
asymmetric dimensions and code rates; all-zero factors; malformed/noncanonical
wires; checked maximum-shape and budget rejection; deterministic repeat bytes;
the actual controls below; and independent Python verification of identical
wire, decisions, restored claims, conditional terms, usage and continuation.
Use at least 1000 seeded bounded cases per field with varying dimensions and
zero factors. The Python oracle must derive the restored source geometry and
run actual A9 verification, not trust native receipts or partial-row tables.

Measure the complete registration/prove/verify flow with all bindings enabled,
actual proof bytes, memory, one source visit per element and retained-row
identity observations. Report preparation and source/encoded-column reads
separately. The ledger must record both verifier timings and every terminal
consumer. No partial-row microbenchmark substitutes for complete delivery.
No measured constant, throughput or full inference result is asserted here.

## 7. Controls and remaining integration

Keep NC-0300..0305 and NC-0605's original obligations. Reserve these precise
conditional controls; specification acceptance earns no executed coverage:

* NC-0306: compute one partial row using a changed outer-point coordinate,
  while keeping the verifier's statement fixed and the opposite source zero.
  Generate A1 and all dependent opening bytes at the expected transcript
  history using this false row. A1's product check still passes; the actual
  A9 column equation must reject ColumnMismatch. Use L=d=1 with a nonconstant
  affected source, so every sampled column detects the changed functional.
  Exercise both X and W, with asymmetric geometry to detect axis swaps.
* NC-0307: change one A1 final under a zero other factor, keeping all rounds
  and honest retained opening rows unchanged. A1 still passes; the actual
  X or W opening must reject ValueMismatch before queries. Exercise both.
* NC-0611: change one OpeningRow value under a zero opposite factor and
  reconstruct its A1 final and all dependent proof arithmetic/responses at
  the expected history, with L=d=1 for deterministic column rejection.
  The closed verifier must reject ColumnMismatch at the affected source.
  Separately test opaque-row owner/weight substitution rejects RowContext
  before any transcript change; that API test alone earns no control credit.

Also extend real NC-0606 source/certificate substitution and NC-0802 missing
MatmulStatement/terminal-response absorption through this complete consumer
and a genuine following A1 instance. Preserve existing control coverage;
no research-only sensitivity test or producer rejection replaces a verifier
control. Each honest artifact must first pass the same production verifier.

E7-01b implements this contract after E7-01a review. Full E7-01 still needs
its original CQIS requant/range and configured-plan/source criteria; E7-02
still needs stacking, bucketed B, one per-type pass and its original controls.
RFC-0010 A6/RFC-0007 A1 remain Draft for signed/packed original functionals.
Virtual activation consumers, GPT-2-small semantics, canonical plan/passport
artifacts, independent full inference verification, privacy and profile
admission remain required by the first-inference DAG. No additional research
question is opened; this closes only a conditional implementation boundary.
