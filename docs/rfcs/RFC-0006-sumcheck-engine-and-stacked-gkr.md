# RFC-0006 — Sumcheck engine and layer-stacked GKR core

Status: Accepted · Version: 0.1.0 · Depends: RFC-0003, RFC-0005

## 1. Sumcheck instance
`Σ_{x∈{0,1}^m} g(x) = v` where `g = P(f_1(x), …, f_t(x))` for multilinears `f_i` and a polynomial `P` of total degree
`δ ≤ 4` (higher degrees are split with the product-of-many algorithm of Dao–DeStefano–Bagad–Domb–Thaler 2026/587).
Round `r`: prover sends `g_r(X) = Σ_{x'} g(r_1..r_{r−1}, X, x')` as `δ+1` evaluations; verifier checks
`g_r(0)+g_r(1) = g_{r−1}(r_{r−1})`, samples `r_r ∈ K` from the transcript. Final: claims `f̃_i(r)`.
Soundness per instance: `m·δ/|K|` (RFC-0012 ledger line `SC`).

## 2. Engine API (`stele-sumcheck`)
```
trait Summand { fn degree(&self) -> u8; fn eval_round(&self, state) -> [K; δ+1]; fn fold(&mut self, r: K); fn final_claims(&self) -> Vec<Claim>; }
fn prove(t: &mut Transcript, s: &mut dyn Summand) -> SumcheckProof
fn verify(t: &mut Transcript, proof, claimed_sum, degree, m) -> (Vec<K>, K)   // point, final value
```
Batched instances share challenges via `Σ_b γ_b·g_b` (γ from transcript) when they have equal `m`; unequal `m` are padded
with the standard "zero-extension" (sum over the extra variables of `eq(0, ·)`).

## 3. Layer-stacked GKR (ST-1)
A stacked reduction over `(ℓ, x)` is a plain sumcheck whose first `log L` variables are the layer bits. Block `ℓ`'s
data lives on the device owning layer `ℓ`; each round's message is the sum of per-block round polynomials (an
all-reduce of `δ+1` elements of `K`, RFC-0015). Claims emerge on the stacked tensor at `(r_ℓ, r_x)`.
Variable order is fixed per reduction and recorded in the plan: `ℓ` bits last when the rest can use base-field
first rounds (§5), first when block-sparsity of the coefficient is being exploited.

## 4. Batching claims on one tensor (RLC batch reduction)
Claims `{ỹ(z_t) = v_t}` → `Σ_t γ_t v_t = Σ_x y(x)·Σ_t γ_t eq(z_t, x)`; the coefficient is built block-sparsely
(`z_t` with boolean layer part touches one block), cost `O(|y|)`; emits one claim `ỹ(r)`. Used only for virtual
tensors; committed tensors take arbitrary functionals straight to the PCS (RFC-0010 §4).

## 5. Prover optimisations (mandatory in `stele-sumcheck`)
- **eq-trick / univariate skip** (Gruen): for zerochecks `Σ eq(ρ,x)·C(x)`, factor `eq` and skip its degree; first
  round over a univariate of degree `2^k·δ` where it pays.
- **Small-value first rounds** (BDT 2025/1117 Alg. 3/4): when all `f_i` are integers below 2¹⁶ (requant, lookups, cuts),
  the first `k ∈ [2,4]` rounds use base-field/integer arithmetic; the state stays base-field sized.
- **Bucketed partial evaluation** (ST-9): for `f̃(r, ·)` with `f ∈ int4/int8`: per row accumulate `eq` into `2^b` buckets
  (adds in `K`), then `Σ_v v·bucket_v` — turns base×K MACs into K adds; weight pass becomes bandwidth-bound.
- **Delayed reduction**: accumulate products in 64/128-bit integers and reduce once per 8–16 terms.
- **Streaming / two-pass** (Rothblum–Zitek-Estrada; BDT streaming prover) for stacked tensors exceeding device memory (RFC-0014 §4).
Each optimisation is a `Strategy` with a reference-parity test against the naive prover (INV-3 applies on CPU too).

## 6. GKR layer reduction (generic)
For a virtual tensor `y = Op(x_1..x_t)` with `Op` expressible as `ỹ(z) = Σ_x A(z,x)·P(f̃_1(x)..)`, the reduction is
the sumcheck of §1 with `A` a public, verifier-computable MLE (eq, mask, selection, rotation tables). The library
provides `A ∈ {eq, causal_mask, window_mask, rope_tables, onehot_sparse, gqa_broadcast}` with `O(log)` or
`O(n)` verifier evaluation documented per kind.

## 7. Cost
Per element of the summand per instance ≈ `δ` K-mults in the first K-round, halving thereafter ⇒ `≈ 2δ` K-mults per
element amortised, minus small-value savings. Recorded as `c_sc(δ, small)` in the bench ledger.

## 8. Negative controls
NC-0200 wrong round polynomial; NC-0201 challenge reuse across instances; NC-0202 batching with one instance omitted;
NC-0203 block-sparse coefficient hitting wrong layer; NC-0204 small-value strategy on out-of-range inputs.

## 9. Amendment log

### A1 — Canonical instance, final obligations and sumcheck schedule

Status: Accepted. Question Q15. Review: [skill passes](../../agents/reviews/sumcheck-a1.md). Evidence: [sumcheck study](../../research/sumcheck/REPORT.md).
Motivation: §§1–2 leave P's verifier representation, message bytes, degree-zero
behavior and consumption of final claims implicit. This amendment makes those
boundaries explicit before E3-01 implementation; it does not instantiate PCS,
batching, zero-knowledge or a complete inference verifier.

Addition to §§1–2 (statement and API contract):

> An instance is supplied by the verifier's Accepted reduction/plan, never copied
> from proof metadata. It contains a u64 instance id, u32 variable count m, an
> ordered list of distinct u64 input tensor ids, an ordered polynomial description
> P, and the claimed sum v in K. Ids identify plan instances/tensors under the
> already-absorbed public input; independent plan instances have distinct ids.
> The field K is fixed by the verified profile and the RFC-0012 A1 Transcript.
>
> P is a sum of ordered terms. Each term consists of a coefficient in K and a
> list of zero to four u32 input ordinals; repeated factors represent powers.
> Ordinals must be in range. Empty factors mean a constant; an empty term list
> means zero. The degree bound δ is the maximum factor count (zero for no terms),
> computed from this description, not declared by the prover. Zero coefficients
> do not lower this conservative bound. The verifier evaluates this same P; an
> unaccounted callback or prover-supplied degree/evaluation function is forbidden.
> Term/factor order is the plan's order; no sorting or semantic normalization is
> implicit. The input list may include unused tensors, whose emitted evaluations
> remain obligations. Counts and ids must fit their specified widths without
> truncation. Inputs are multilinear tables on the same m-dimensional hypercube.
>
> `Summand` is a prover-side strategy interface for round evaluations, folding and
> final values. The engine supplies the independently derived instance, enforces
> message dimensions and transcript order, and draws every challenge itself.
> The first implementation is the dense CPU reference for arbitrary P of degree
> at most four. It folds the leading remaining coordinate: first point coordinate
> is the most significant table-index bit. It never silently pads or reorders.
> Future strategies retain this relation and the reference-parity requirement.
>
> A subproof contains exactly m round messages of δ+1 field elements each and
> exactly one final value per ordered input id. Before replay, the verifier checks
> all these lengths against its instance. Canonical field parsing rejects limbs
> outside [0,p). This is the logical subproof, not a replacement for RFC-0016's
> eventual inference-proof container. No prover-supplied point is accepted.

Addition to §2 (exact schedule and byte encoding):

> Use RFC-0012 A1's existing Instance, Round, Final and Sumcheck labels. Integers
> below are unsigned little-endian with the stated widths; K elements are their
> canonical RFC-0003 basis encodings (4d bytes, d=4 or 8). Concatenations have no
> padding, alignment or terminators. All lengths are checked before conversion.
>
> Instance payload, before any round: u8(1) format version, u8(d), u64(instance id),
> u32(m), u8(δ), u32(input count), u32(term count), then all input ids as u64; then
> each term as coefficient K, u8(factor count), factor ordinals as u32; finally v.
> Absorb this under Instance exactly once for this invocation.
>
> In round r=0..m-1, interpret the δ+1 message elements as g_r(0)..g_r(δ).
> Check g_r(0)+g_r(1) equals the running claim (initially v). For δ=0, g_r(1)
> equals the sole transmitted value, so the check is 2*g_r(0)=running claim.
> A mismatch is `RoundSumMismatch`. Absorb u64(instance id), u32(r), followed
> by exactly δ+1 K elements under Round. Only then draw `challenge(Sumcheck)`.
> Evaluate the unique degree-at-most-δ interpolant at that challenge to obtain
> the next running claim; the prover folds at the identical challenge. Nodes
> 0..δ are distinct because p>4. No cached challenge or externally supplied RNG.
>
> After all rounds, check P(final values) equals the running claim, otherwise
> `FinalEvaluationMismatch`. Absorb u64(instance id), u32(input count), then all
> ordered final K values under Final before returning or beginning any dependent
> operation. For m=0 there are no rounds/challenges; this final check is P(final)=v
> and the same Instance/Final absorbs still occur, even with an empty final list.
> Any error aborts the proof attempt; no rollback/retry contract is provided for
> a partially advanced transcript. Return no usable reduction result on error.
>
> Successful reduction verification returns the derived point, ordered input
> evaluation obligations (tensor id, that same point, final value), and an SC
> accounting record. It is not acceptance of a complete statement. Every final
> obligation must be discharged by the consuming reduction or PCS opening.
> The production public-table adapter discharges them by evaluating the supplied,
> verifier-owned tables at the returned point; mismatch is `ClaimMismatch`.
> It validates table counts/shapes and never substitutes prover-supplied tables.
> This adapter is the real closed-statement verifier for initial protocol controls.

Soundness and accounting (§§1,7): δ is a static bound on every individual variable
of P(f_1,..,f_t). For a false initial sum, the probability that interactive sumcheck
passes and all emitted evaluations are true is at most m*δ/p^d by the standard
round-by-round Schwartz–Zippel argument ([Thaler §4.1](https://people.cs.georgetown.edu/jthaler/ProofsArgsAndZK.pdf)).
The precise obligation is recorded in [the formal statement](../../formal/sumcheck.md).
No integer field-faithfulness certificate is needed for these field-only identities.
The SC record contains instance id, m, δ, d and exact u64 numerator m*δ; denominator
is symbolically p^d, never a rounded bit length or floating approximation. Emit
one record per verified instance, including zero-numerator instances, mapped to
the existing SC label. The gate must compare records with actual descriptors and
challenge counts; it must not certify a full profile from this partial enumeration.
The public adapter closes the evaluation obligations exactly, but neither adapter
nor research tests prove the Fiat–Shamir transformation. Q12 remains unresolved;
FS/H include all adversary queries. PCS, composition, ZK and profile errors remain
separate obligations. No new random challenge or soundness-loss family is added.

Prover/verifier costs (§7): for N=2^m, t inputs and e field operations per P
application, the dense reference uses O(N*(δ+1)*(e+t)) field operations and O(t*N)
working field elements, plus proof storage. Verifier work is O(m*δ^2+e+t), excluding
consumption of final obligations; the public adapter additionally reads all tables.
These contribute to c_sc and T_misc. E3-01 must record the naive c_sc measurement
and working-memory evidence in a real benchmark ledger; no measured constant is
changed by this amendment. Weight-pass phases are unaffected. E3-03..E3-05 retain
all their optimization and reference-parity obligations.

Controls (§8): NC-0200 changes one round evaluation; NC-0201 replaces one final
evaluation by the value folded with a challenge from another instance; NC-0800
uses a challenge drawn before its required round absorb. In the latter two,
choose a one-round nonconstant summand so precisely one final value changes and
`FinalEvaluationMismatch` is required. NC-0802 uses two real consecutive instances:
replay the first history omitting its Final message, then run the production prover
for a one-round single-input second instance. Its round message is unchanged and
exactly its one final value changes; the honest chained verifier must reject it
with `FinalEvaluationMismatch`. Both honest instances must first be accepted.
NC-0205 changes one unused input's final value in a constant-P instance: reduction
verification leaves that value as an obligation, and the real public adapter must
reject it with `ClaimMismatch`. These are finite controls, not soundness proofs.

Workflow 08 additionally permits a post-proof control path: produce and verify
an honest proof with the real implementations, clone that artifact, mutate exactly
one declared value, then require the same real verifier's exact rejection. The
hook must assert the one-value difference and hold the verifier's statement fixed.
A malicious transcript-history calculation may compute the replacement value,
using only the production Transcript operations and prover; it cannot inject
state/RNG, disable verifier checks or replace a verifier with a toy relation.
No-op mutation, honest rejection, prover failure, acceptance or wrong error fails.
This remains proof coverage, not a new configuration exception. Witness-first
controls remain available. Research-only prototypes receive no catalog credit.

E3-01 delivery also requires Rust/Python acceptance and rejection agreement on the
actual protocol corpus (RFC-0002 S10), both-field byte vectors, malformed-shape and
degree tests, and real accounting/control gates before removing the sumcheck
scaffold guards. E2-01 retains its full NC-0800..0802 integration acceptance.
Affected tasks: E3-01, E2-01, E8-04, E8-05, E12-09; no dependency is removed.

### A2 — Ordered batching, zero-extension and virtual-tensor claims

Status: Accepted. Question Q18. Review: [skill passes](../../agents/reviews/batching-a2.md).
Evidence: [batching study](../../research/batching/REPORT.md).
Motivation: §§2,4 omit the coefficient schedule, encoding, padding degree and
final obligations; §4's unconditional linear coefficient cost needs qualification.
The following replaces their batching rules; A1's unbatched bytes stay unchanged.

**Statement and verifier inputs.** K and d follow A1. An ordered nonempty batch
has a verifier-owned u64 batch id and one of two modes. All counts fit u32;
canonical K encodings, checked lengths, allocation arithmetic and error-abort
rules follow A1. Plan instance/batch ids are distinct across invocations; tensor
ids are a separate namespace. The plan fixes ordering before any batch challenge.
Mode 0 contains t A1 instances with distinct member ids, none equal to the batch
id. Each keeps its own m_b, polynomial P_b, degree δ_b and claimed sum v_b.
An input tensor id repeated across members must have the same dimension and
refer to the same tensor. Define M=max m_b, p_b=M-m_b, and
D=max(max δ_b, 1 if any p_b>0 else 0). On x in K^M define

```
S_b(x) = product_{j=0}^{p_b-1}(1-x_j)
G(x) = sum_{b=0}^{t-1} gamma^b S_b(x) P_b(f_b,1(x[p_b:]), ...)
V = sum_b gamma^b v_b
```

This is zero-extension of the whole summand, not of each input before applying
P_b. Its Boolean sum preserves each original sum, including constant P_b.
Padding and real coordinates are disjoint, so individual degree is at most D<=4,
not δ_b+1. Equal-size batches have empty selectors. Empty input/term lists,
m_b=0 and t=1 remain valid. No member or input obligation may be dropped because
its coefficient, selector or polynomial happens to vanish.

Mode 1 contains one virtual tensor id y, its u32 dimension m, and t ordered
claims (z_b,v_b), with exactly m coordinates in each z_b. D=2, M=m, and

```
A(x) = sum_b gamma^b eq(z_b,x)
G(x) = y(x) A(x); V = sum_b gamma^b v_b
```

Arbitrary K points, overlapping blocks and duplicate claims are allowed. The
verifier derives the virtual role from its authenticated plan; no proof flag
can select this route. Committed tensors retain the PCS functional-opening
route of RFC-0010. A is public and verifier-computable, never committed and
never accepted as a prover-supplied final evaluation.

**Exact bytes and schedule.** Integers are unsigned little-endian. K uses A1's
canonical 4d bytes. There is no alignment or implicit normalization. Before any
challenge, absorb Batch (RFC-0012 A4) with this complete descriptor:

```
u8(1) || u8(d) || u8(mode) || u64(batch id) || body
mode 0 body: u32(t) || u32(M) || u8(D) || members
  each member: u64(byte length of its full A1 Instance payload) || that payload
mode 1 body: u64(y id) || u32(m) || u32(t) || claims
  each claim: m ordered K coordinates || K value
```

M,D are recomputed from the verifier's inputs, never trusted from the proof.
Draw exactly one challenge(BatchCoefficient) after this absorb; use powers
1,gamma,...,gamma^(t-1), including for singleton batches. Zero and roots of unity
are valid challenges, not retry conditions. Do not separately absorb the member
Instance payloads or draw member challenges. Run M rounds exactly as A1 at
individual degree D, starting from V, with the batch id in each Round payload.
This includes A1's doubled sole evaluation when D=0. Draw Sumcheck only after
each Round absorb. Final proof values are ordered by member/input for mode 0,
or exactly one y value for mode 1. Preflight all proof lengths before replay.
The verifier checks G(r) using these values and its own selectors/A(r), then
absorbs BatchFinal before returning any result:

```
u64(batch id) || u8(mode) || body
mode 0 body: u32(t) || [u64(member id) || u32(input count) || ordered K values]_b
mode 1 body: u64(y id) || K value
```

Use ProofShape, RoundSumMismatch and FinalEvaluationMismatch as in A1;
invalid descriptors are InvalidBatch. For M=0 there are no rounds, but both
batch absorbs and gamma still occur and G()=V is checked directly. Mode 0 emits
all (tensor id, r[p_b:], value) obligations in order; selectors do not scale their
values. Mode 1 emits (y id,r,value), even if A(r)=0. A successful reduction is not
statement acceptance. Real consumers must discharge every emitted obligation.
The public-table adapter checks counts, exact 2^m_b lengths and consistent alias
tables before replay, then evaluates every obligation independently; shape/alias
errors are PublicShape and wrong evaluations are ClaimMismatch.

**Algorithms and costs.** Mode 0 folds original tables only on their active
suffix coordinates, using virtual selectors rather than 2^M copies of smaller
tables. With a_b inputs and e_b operations per P_b, a direct reference costs
O(sum_b (D+1)(a_b+e_b)2^m_b + t M (D+1)) field operations, plus descriptor
processing; keep original tables and per-member partial sums until activation.
For padded-prefix rounds, the residual contribution is the member's computed
true sum times its prefix selector, never a trusted claimed v_b. Memory is
O(sum_b a_b 2^m_b + t + M(D+1)) field elements excluding descriptors/obligations.
Verifier arithmetic is O(M D^2 + t (M+1) + sum_b(a_b+e_b)), excluding consumers.

Mode 1 finds each z_b's maximal leading Boolean prefix of length k_b and adds
its weighted suffix eq table into that contiguous block. Accumulate overlaps;
never overwrite. Building eq tables by successive splits costs
O(2^m + t m + sum_b 2^(m-k_b)), with O(2^m+t) working field elements plus inputs.
Disjoint blocks give O(2^m+t m+t); arbitrary points can require O(t 2^m+t m).
The y*A sumcheck then costs O(2^m); the verifier computes A(r) directly in O(t (m+1))
and checks m degree-2 rounds. The exhaustive research oracle is not this efficient
implementation. These terms contribute to c_sc and T_misc (and consuming-stage
c_a/c_x); no measured constant, weight-pass count or committed tensor changes.
E3-02 must record actual c_sc and peak memory in a bench ledger before completion.

**Soundness and accounting.** For fixed inputs with at least one false sum/claim,
the aggregate error is a nonzero polynomial in gamma of degree at most t-1.
The root bound gives (t-1)/p^d; conditioned on avoiding those roots, sumcheck
adds M D/p^d when all emitted evaluations are true. See the explicit
[interactive obligation](../../formal/batching.md); these are proven algebraic
bounds, conditional on independent uniform challenges, not a Fiat–Shamir theorem.
Emit one RLC record (batch id,t,d,numerator=t) and one SC record
(batch id,M,D,d,numerator=M D), denominators exactly p^d. Keep singleton and
zero-round records. Do not count member SC records or add a second RLC for mode 1.
The conservative RLC t/p^d follows the existing ledger, even for t=1.
Standard uses d=4 and treaty d=8; neither has a certified total until Q12 and the
remaining PCS/composition/ZK obligations are resolved. No integer identity or
bound certificate is added. FS/H still include every adversary query.

**Controls and delivery.** NC-0202 omits one member's actual weighted contribution
from one first-round evaluation under the unchanged full descriptor. In mode 1
it omits one claim's contribution. Require a nonzero difference and
RoundSumMismatch using the real prover/public verifier in both modes/fields.
NC-0206 changes one first-round evaluation to that computed using gamma drawn
before Batch, requiring the same error. Both use A1's one-value post-proof hook;
no injected state, cached challenge API or verifier bypass is permitted.
Extend NC-0205 to an unused input of a batched constant polynomial (ClaimMismatch),
and NC-0802 to omission of BatchFinal before a real subsequent A1 instance
(one changed subsequent final value, FinalEvaluationMismatch). Existing controls
remain required. NC-0203's wrong-layer GKR requirement remains with E3-06.
E3-02 also requires both-field bytes, Rust/Python acceptance/rejection agreement,
10^4 seeded prover/verifier coefficient evaluations (including arbitrary points,
Boolean-prefix blocks, overlaps and duplicates), unequal-size/constant/empty/zero
cases, and actual SC/RLC descriptor/challenge accounting gates. The production
registry and canonical label inventory must change together. Research earns no
NC credit. Affected tasks: E3-02, E3-06, E8-04/E8-05, E12-09; no dependency removed.
