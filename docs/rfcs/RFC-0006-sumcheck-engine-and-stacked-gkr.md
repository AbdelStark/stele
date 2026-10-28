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

### A3 — Eq-factored zerocheck and bounded univariate skip

Status: Accepted. Question Q19. Review: [skill passes](../../agents/reviews/zerocheck-a3.md).
Evidence: [zerocheck study](../../research/zerocheck/REPORT.md).
Motivation: §5's skip changes both the round schedule and the final functional;
A1's ordinary MLE result cannot represent it. The following replaces that bullet's
protocol contract. A1/A2 bytes and APIs remain unchanged. This is a separate,
plan-selected zerocheck relation, not an interchangeable A1 proof encoding.

**Statement.** The verifier supplies a distinct u64 invocation id, u32 dimension
m, u8 skip count k, ordered distinct input tensor ids and polynomial C in A1's
ordered term representation. Its computed total degree is δ<=4; unused inputs,
zero coefficients and empty lists retain A1's meaning. The assertion is
C(f_1(x),...,f_a(x))=0 for every Boolean x. Tensors and C must be fixed before the
first challenge, through the authenticated claim graph; no commitment is added.
The plan determines padding/masks and the consumer of each original tensor claim.
This primitive does not assert range, field faithfulness, privacy or inference.

Require 0<=k<=min(m,4); when δ=0 require k=0. Define s=2^k, j=m-k and D=δ(s-1).
For k>0 use base-field nodes B={0,...,s-1}, mapped to the k leading table-index
bits in most-significant-first order. These are interpolation nodes, not a
multiplicative subgroup (M31 has no such subgroup of order four). Let L_b(U)
be the Lagrange basis on B, and define

```
F_i(U,z) = sum_{b=0}^{s-1} L_b(U) f_i(bits_k(b),z)
Q_0(U) = sum_{z in {0,1}^j} eq(alpha,z) C(F_1(U,z),...,F_a(U,z)).
```

For k=0 there is no U: F_i(z)=f_i(z), and the initial running claim is zero.
For k>0, Q_0 has degree at most D and vanishes on B for a true assertion.
After its challenge u, fix U=u. In tail round h=0..j-1 send the degree-at-most-δ
polynomial

```
Q_{h+1}(T) = sum_{z in {0,1}^{j-h-1}} eq(alpha[h+1:],z)
            C(F_1(u,r[:h],T,z),...,F_a(u,r[:h],T,z)).
```

Omit u when k=0. Factoring eq removes its extra degree. The verifier checks
(1-alpha_h)*Q_{h+1}(0)+alpha_h*Q_{h+1}(1)=running. No inverse of alpha_h,
1-alpha_h, an eq factor or a random evaluation is permitted. Zero/one challenges
remain valid, including u in B. For δ=0 both evaluations are the sole value.

**Bytes and schedule.** K, canonical field parsing, checked widths/allocations,
error-abort behavior and public-input binding follow A1. Before replay, validate
the descriptor and every proof length. Invalid descriptors are InvalidZerocheck;
malformed proof dimensions are ProofShape. Absorb Zero (RFC-0012 A5) with:

```
u8(1) || u8(field degree) || u64(id) || u32(m) || u8(k) || u8(δ)
|| u32(input count) || u32(term count) || ordered u64 input ids || ordered terms
```

Terms use A1's coefficient, u8 factor count and u32 ordinals, with no claimed-sum
suffix. Integers are little-endian; no implicit padding, sorting or normalization.
Draw exactly j consecutive ZeroWeight challenges, in tail-coordinate order, to
obtain alpha. Do this even for a zero/constant polynomial; j=0 draws none.
For k>0 the proof sends exactly L=D+1-s=(δ-1)(s-1) values Q_0(s)..Q_0(D).
The verifier prepends s implicit zeros and interpolates at nodes 0..D. Absorb
ZeroSkip with u64(id), u32(L), then the L ordered K values; only then draw one
Sumcheck challenge u and set running=Q_0(u). Even L=0 has this absorb/challenge.
For k=0 there is no skip message or skip challenge and running=0.

There are exactly j tail rows of δ+1 K values at 0..δ. Check the weighted identity
above (RoundSumMismatch on failure), absorb A1's Round payload with this id and
zero-based tail index h, then draw Sumcheck r_h and interpolate the row at r_h.
There is no forced-zero first tail row and no compressed missing endpoint.
After the tail rounds, read exactly a*s final values v_{i,b}, input-major then
ascending b. For k>0 compute w_i=sum_b L_b(u)*v_{i,b}; for k=0 set w_i=v_{i,0}.
Require C(w)=running (FinalEvaluationMismatch otherwise). Absorb ZeroFinal:

```
u64(id) || u32(a) || u32(s) || all a*s ordered K final values
```

Return every (tensor_i, bits_k(b) concatenated with r, v_{i,b}) claim in that
same order. These are original tensor MLEs, not a hybrid value mislabeled as an
MLE. All claims survive unused inputs, zero Lagrange weights and cancellations.
The public adapter validates a tables of exactly 2^m entries before replay
(PublicShape on mismatch), then independently discharges every returned claim
(ClaimMismatch). Other consumers must discharge all claims through reductions
or PCS; successful reduction verification alone never accepts a statement.
No s new commitments or intermediate tensor commitments are introduced.
The k=0,m=0 case has only Zero, the C(final)=0 check and ZeroFinal.

**Soundness and accounting.** Let q=p^d. Conditional on fixed tensors and fresh
independent uniform interactive challenges, a false row survives and all emitted
claims are true with probability at most (j+D+j*δ)/q. A fixed bad prefix row has
a nonzero multilinear residual in alpha, giving j/q; a false skip interpolant
collides with the true degree-D polynomial with probability at most D/q; each
false tail polynomial contributes at most δ/q. See [the obligation](../../formal/zerocheck.md)
and [Gruen, Appendix A.4](https://eprint.iacr.org/2024/108). Full endpoint messages
make the same argument valid without excluding zero challenges. For k=0 the
skip term is absent; j=0 and zero-degree cases keep their zero terms.

Emit three SC records identified by (invocation id, phase): phase 0 (weights)
with m=j, degree=1, numerator=j; phase 1 (skip) with m=1 if k>0 else 0,
degree=D, numerator=D; phase 2 (tail) with m=j, degree=δ, numerator=j*δ.
All carry field degree d and symbolic denominator p^d, including zero records.
Phase distinguishes records, not additional transcript absorbs. Check u64
arithmetic; D<=60. Gates must compare records to the descriptor and actual
challenge schedule. This is an algebraic SC bound for both profiles, not a full
Fiat-Shamir/profile theorem; Q12, PCS, composition and ZK remain separate.

**Algorithms and costs.** A dense strategy constructs hybrid tables at u, folds
only the j tail coordinates, and keeps the original tables for final slice
claims. With N=2^m and e operations per C evaluation, direct interpolation at
the L outside nodes costs O(L*(a*s+e)*N/s+L*s^2); at u costs O(a*N+s^2). Weighted tail
rounds cost O((δ+1)*(a+e+1)*N/s), and computing all slice finals costs O(a*N).
Precompute the base-node Lagrange weights; direct verifier interpolation costs
O(D^2+j*(δ^2+1)+s^2+a*s+e), excluding downstream claim consumption. Working memory
is O(a*N+a*N/s+N/s+D+j*(δ+1)+a*s) field elements with retained originals and proof;
report caller-owned inputs and scratch separately. Final payload grows to a*s
values. Descriptor processing and round transcript/interpolation work are additional
on the prover too. The k=0 strategy has no initial interpolation or slice expansion.
These costs move c_sc and T_misc; no weight pass or fitted constant changes here.
E3-03 must measure the complete prover and claim-consumption costs, including
when skip loses, before selecting a plan's k. Do not claim subgroup/FFT costs.

**Controls and delivery.** NC-0207 changes one skip evaluation, requiring
RoundSumMismatch with j>0 and FinalEvaluationMismatch with j=0. NC-0208 changes
one tail endpoint, requiring RoundSumMismatch. NC-0209 changes one unused slice
final, requiring ClaimMismatch even though the reduction check passes. Extend
NC-0802 with an omitted ZeroFinal before a real A1 continuation, changing exactly
one continuation final value and requiring FinalEvaluationMismatch. Also test
fresh false-row proofs, early weight/skip/round challenges, descriptor changes,
all malformed shapes, δ=0..4, k=0..4, m=k, zero/one algebraic edge cases, and both
fields. Research checks earn no NC credit. E3-03 remains incomplete until actual
consumers, controls, registry/inventory/accounting, Rust/Python byte/decision
parity, 10^3 seeded reference cases per degree and a measured c_sc improvement
ledger pass. Reference and optimized provers must agree byte-for-byte within
each (descriptor,k); different k is a different protocol, not a parity failure.
Affected tasks: E3-03..E3-06, E8-04/E8-05, E12-09. No acceptance criterion removed.

### A4 — Stacked public coefficients and canonical claim coordinates

Status: Draft. Question Q20. Evidence: [stacking study](../../research/stacked-gkr/REPORT.md).
Motivation: §§3,6 do not fix public-MLE descriptor bytes, their padding and
axis semantics, the consumed/output claim encoding, or the ownership changes
required when a layer coordinate is folded. Implementing these choices implicitly
would create protocol behavior outside an Accepted contract. This draft is not
permission to replace a scaffold or claim E3-06 complete.

Proposed replacement contract for §3 (pending the complete wire contract below):

> Tensor coordinates remain in RFC-0005's canonical order with layer bits most
> significant. A verifier-owned elimination permutation may place layer bits
> first or last; bind it before any reduction challenge. Restore every emitted
> point to the original tensor coordinate order before its consumer receives it.
>
> A single stacked invocation proves its stated polynomial over global stacked
> input MLEs. Do not substitute an A2 batch of per-layer polynomials: applying
> nonlinear P after folding a layer axis differs from folding the old P values.
> Per-block round sums partition evaluations of the actual current round
> polynomial exactly once. Their deterministic ownership must be specified for
> every round; they cannot be independent original-layer proofs. When an axis
> fold mixes input blocks, redistribute the required input state before computing
> the following nonlinear round. An all-reduce of round messages alone does not
> perform that redistribution. CPU tests must expose and sum the same partials.

Proposed addition to §6 (pending exact kinds and encoding):

> The verifier derives the consumed claim, public coefficient and ordered input
> obligations from its authenticated plan. The reduction must bind their complete
> canonical descriptor before its first challenge. A prover cannot supply a
> coefficient evaluator, degree, coordinate permutation or substitute table id.
> Every public final evaluation is recomputed by the verifier; all original
> private/virtual/committed input evaluations remain real consumer obligations.
>
> State explicitly whether A is the MLE of a Boolean coefficient table or a
> product of separately extended factors. These agree on Boolean points but need
> not agree off the cube. The sumcheck degree and final equation must use the
> chosen polynomial, including every selector. No public factor is free merely
> because its table is Boolean, sparse or known to the verifier. A1's degree-at-most
> four bound applies to the complete summand; unsupported degrees must reject or
> use a separately Accepted reduction. No intermediate commitment is introduced.

Open requirements before acceptance (all part of Q20):

1. Specify complete bytes and validation for the consumed claim, tensor ids,
   dimensions, real/padded blocks, coordinate permutation, polynomial and public
   coefficient. Decide the transcript labels and how the A1 schedule is reused;
   update RFC-0012 registry/inventory and exact SC accounting together. No new
   random challenge is presumed by this draft.
2. Define the six required public kinds exactly: eq, causal_mask, window_mask,
   rope_tables, onehot_sparse and gqa_broadcast. Fix bit/axis order, real dimensions,
   padding, window endpoints, head-to-group mapping, table identity and source
   authentication. Selection indices must be authenticated by their actual prior
   commitment/opening; calling them public does not waive that obligation.
3. Give independent prover/verifier evaluations and explicit costs per kind.
   Preserve RFC-0009's mask complexity requirement or amend it explicitly with
   evidence. Distinguish MLE-of-product from product-of-MLE selectors. No guessed
   RoPE table or unauthenticated index vector is acceptable.
4. Specify per-round partial ownership and the data movement required for both
   elimination orders. Prove that summing partials gives the global round and
   that final claims refer to the original stacked tensors, including unused
   inputs and padded blocks under the chosen padding rule.
5. Define actual NC-0203 wrong-layer mutation and any new binding controls, using
   real closed-statement consumers and exact errors. Require both-field canonical
   bytes/decisions, 10^4 seeded points per public kind, round-partial agreement,
   malformed descriptors and a chained-final transcript control before delivery.

Soundness: this draft adds no implemented challenge or certified error term.
Acceptance must name the complete summand degree, SC numerator and every final
consumer; Q12 and PCS/composition remain separate. Integer inference identities
retain RFC-0004 static certificate obligations; a field-only kernel study does not
satisfy them. Cost impact: c_sc, public evaluation in T_misc, memory and block-state
redistribution. No measured constant, weight-pass count or performance result
changes here. Affected tasks: E3-06 and downstream GKR/lookup/reduction/distribution
work; all original acceptance criteria remain required.

### A5 — Typed small-value inputs and deferred prefix folding

Status: Accepted. Question Q21. Review: [skill passes](../../agents/reviews/small-value-a5.md). Evidence: [small-value study](../../research/small-value/REPORT.md).
Motivation: §5's small-value bullet does not distinguish retained input storage
from the challenge-dependent grid, specify static eligibility or define NC-0204's
actual verifier rejection. This amendment completes that prover optimization
without changing A1's statement, proof bytes, transcript or verifier.

Exact replacement for §5's small-value bullet and its strategy contract:

> Use the A1 Summand interface for a deferred-prefix small-value strategy.
> Every input table is owned signed i16 or unsigned u16 storage: its representation
> statically implies [-32768,32767] or [0,65535], respectively. Different tables
> may use different representations. Canonical signed/unsigned embedding gives
> the original M31/K values. Validate the instance and all counts/shapes at
> construction. Do not accept arbitrary K/i64 tables plus an asserted smallness
> flag or infer eligibility from a scanned runtime maximum. External narrowing
> must be checked; never wrap, truncate, saturate or project a K challenge to M31.
> Other input formats use a suitable separately validated strategy such as Dense.
>
> Choose k in {2,3,4} with k<=m before proving. This is a prover configuration,
> not new proof metadata: all valid choices must produce exactly the A1 proof.
> Reject invalid k as InvalidSmallValue, malformed tables as PublicShape and
> address/allocation overflow as Capacity; invalid A1 instances retain their
> existing errors. A cached polynomial/descriptor must match the Instance passed
> by the engine before any round result is used. Small dimensions may use Dense.
>
> Define N=2^m, s=2^k, W=N/s, a=input count, delta=A1 degree and b=max(2,delta+1).
> On the prefix grid {0,..,b-1}^k compute, for every ordered monomial t,
> q_t(X)=sum_{z Boolean^(m-k)} product_{i in t} f_i(X,z) in M31. Apply its
> original coefficient c_t in K after this suffix sum and accumulate q=sum_t c_t q_t.
> A simple builder extends each factor's Boolean prefix table one axis at a time
> with f(u)=f(0)+u*(f(1)-f(0)), preserving MSB coordinate order. Accumulate one
> monomial grid at a time; constants include the exact suffix multiplicity.
> Repeated factors and zero coefficients retain A1's degree/ordering semantics.
> M31 arithmetic is modular field arithmetic; do not treat it as an unproved
> no-wrap integer identity or add delayed machine-integer accumulation implicitly.
>
> At prefix round h, send exactly the A1 nodes 0..delta of
> sum_{y Boolean^(k-h-1)} q(r[:h],T,y). Absorb the ordinary Round message and
> obtain its challenge only through the A1 engine, then fold the small grid in K.
> The large original input storage stays 16-bit; the grid, messages and challenges
> are K-valued. Thus "base-field sized state" does not mean all state stays in M31.
> Degree-zero uses a constant grid and A1's single transmitted endpoint; zero/one
> challenges remain valid without retries or random inversions.
>
> After k rounds compute f_i(r[:k],z) by a direct prefix eq dot product from each
> original table, allocating only a*W K values rather than a full a*N K copy.
> Include every input, even one unused by P. Release original storage when its
> ownership permits, and use ordinary dense A1 folds for the tail. Preserve all
> original final obligations, the complete Final absorb and the continuation.
> Construction/transition overlap and retained allocation capacities count in
> peak memory; claimed memory savings cannot omit them or downstream consumption.

Verifier and soundness: A1 is unchanged. No new public item in the proof, transcript
label, challenge, commitment or SC record is introduced; the same m challenges and
exact m*delta/p^d bound apply for d=4 and d=8. The [parity argument](../../formal/small-value.md)
uses only multilinearity, field embedding and interpolation on fixed distinct
nodes. It proves deterministic equivalence, conditional on correct implementation,
not Q12 or profile certification. Typed magnitude eligibility is not a private
range proof or a CQIS integer bound certificate. Original authenticated inputs
still require every range/consumer obligation in their Accepted reduction; K-valued
masked tables are not eligible merely because their unmasked source was small.

Cost impact: with F=sum of term factor counts and T=term count, the simple builder
uses O(F*k*b^k*N/2^k) M31 operations plus O(T*b^k) K scale/add work. Early grid
folds/sums cost O(k*b^k) K work; prefix materialization costs O(a*N) base-by-K
operations, followed by the reduced-size A1 dense tail. Non-input working storage
is O(b^k+s+a*N/2^k+m*(delta+1)+a) field elements, with a fixed number of per-term
base grids. Retained typed inputs cost 2*a*N bytes; descriptors and allocation
headers/capacities are additional. These move c_sc/T_misc, not a weight-pass count
or fitted constant. Benchmark complete preparation/proving/claim consumption and
peak memory, keep all tested k/degree losses, and do not auto-select k without
measured evidence. The simple builder claims no optimal product-engine constant.

NC-0204: verify an honest constant-zero A1 statement with an unused original table
containing 65536 using Dense. A control-side truncating adapter feeds zero to the
real Small strategy, under the unchanged instance. Require exactly one changed
unused final value (all round values unchanged), then require the original real
public consumer to reject with ClaimMismatch. Assert a nonzero difference and
both-field honest acceptance; no verifier bypass, substituted public table or
constructor failure earns control credit. This tests actual small-strategy misuse
and original-value binding, not a new proof of range. Separate construction tests
cover k/shape/cached-instance errors and checked conversion boundaries.

E3-04 delivery retains measured memory reduction and NC-0204, and requires both-field
byte/receipt/continuation parity with 1,000 seeded cases per degree, all supported
k, boundary types, constants, empty/unused inputs and zero coefficients; independent
Python/Rust decisions; actual control and accounting gates; and clean-source c_sc
and complete-cost/memory ledgers including losses. A5 does not complete E3-04.
Affected tasks: E3-04, later streaming/GPU strategies and their consumers. Existing
A1/A2/A3 bytes and all unrelated acceptance criteria remain unchanged.

### A6 — Streaming source visits, round windows and peak memory

Status: Draft. Question Q22. Evidence: [streaming study](../../research/streaming/REPORT.md).
The sequential-file experiment in that study supplies a tested bit-reversed
candidate layout and exact file-position/read-byte evidence. It does not close
the source preparation, immutable identity or allocation-capacity requirements.
Motivation: §5 does not specify what a two-pass source can enumerate, whether its
order matches storage layout, or a bound including the prefix-grid/dense-tail
transition. RFC-0014 §4 inherits the ambiguity. This draft authorizes no production
behavior; E3-05 remains blocked until both amendments are complete and Accepted.

Proposed replacement for §5's streaming bullet, pending the requirements below:

> Streaming is an A1 prover strategy with unchanged proof bytes, transcript and
> verifier. Use a sequence of positive integer round-window widths with total at
> most m. With S challenges already fixed, width w, N=2^m, a original inputs and
> b=max(2,delta+1), construct on {0,..,b-1}^w the polynomial
> q(X)=sum_z P(f_0(r[:S],X,z),...,f_(a-1)(r[:S],X,z)), z Boolean^(m-S-w).
> Original input MLEs are used, not MLEs of Boolean products. Interpolate q to
> emit the ordinary A1 nodes 0..delta, sum only the remaining Boolean coordinates,
> and fold only after the engine absorbs that round and draws its full K challenge.
> Constants, repeated factors, zero coefficients and zero/one challenges retain
> their A1 semantics. No special transcript labels or extra challenges are added.
>
> After the last window, materialize every original input at the accumulated
> challenge prefix and use ordinary dense A1 folds. Preserve unused inputs, all
> original final claims, their order and complete Final absorption. A source or
> cached state must not silently change the instance or tensor coordinates.
>
> A logical source visit enumerates every original input index once. In the
> direct indexed construction, each window and final materialization requires one
> such visit. This is not automatically a physical sequential read: the needed
> prefix/suffix order changes with S and w. Report source bytes, seeks/gathers,
> preparation/transposition and recomputation separately. A source resident in
> host RAM still counts toward complete process memory even if it saves device RAM.
> A one-window specialization uses two logical visits only if both its complete
> grid and tail budgets fit. Do not promise two visits for all shapes/budgets.
>
> A source for virtual tensors may recompute only under an explicit cost and
> memory contract. No window replay authorizes another weight pass. Applying this
> strategy to a weight-bearing source requires preserving RFC-0007/INV-7, or a
> separately Accepted RFC-0007 amendment. Distributed partial sums must partition
> the actual global window polynomial, not independently fold nonlinear blocks.

Open requirements before acceptance (Q22):

1. Define the source API, stable identity/shape validation, canonical field input,
   layout, read/rewind failures and immutable replay semantics. Give an implementable
   bounded-memory adapter with actual storage order. Account for preparation and
   any additional storage; an arbitrary indexed oracle is insufficient evidence.
2. Fix a deterministic integer window schedule or checked explicit schedule and
   its eligibility/budget rules. Cite the exact algorithm and source assumptions.
   Handle degree zero, no inputs, m=0, impossible budgets and overflow. Do not
   claim the paper's asymptotics for a direct-interpolation implementation.
3. Derive the actual allocation-capacity peak including all live grid/scratch,
   prefix weights, source buffers, proof/descriptor state, dense-tail transition
   and retained capacities. Specify what is caller-owned, host, device or external
   storage and report total pipeline memory separately. Validate against actual
   storage lifetimes in tests; a formula returned by its own estimator is not a
   measurement of the implementation. Grid b^w and tail a*2^(m-S) are lower bounds,
   not the complete allocation contract.
4. Specify errors and failure state, cached-instance checks, resource rejection
   before large allocations, source count/index checks and all original final
   obligations. Mutable/malformed sources must never yield a false accepted
   statement under the real original consumer. Define actual misuse controls;
   research ClaimMismatch checks earn no catalog credit.
5. Require both-field bytes/receipts/continuations against Dense and direct
   reference with 1,000 seeded cases per degree, every supported schedule boundary,
   independent Python/Rust decisions, actual read-count and memory-bound tests,
   per-block partial agreement, and full cost/memory ledgers including losses.

Soundness: the candidate's algebraic argument is deterministic equivalence through
multilinearity and fixed-node interpolation. Conditional on correct implementation,
A1's m*delta/p^d loss, for d=4,8, and all original consumer obligations are unchanged.
No implemented challenge, ledger line, commitment, profile or CQIS bound certificate
changes. Q12/PCS/composition remain open separately. No conjectural lower bound is
used to justify soundness or claimed as an unconditional impossibility theorem.

Cost impact: c_sc/T_misc, working/source memory and read bytes; T_witness if virtual
tensors are recomputed. For W windows the direct indexed candidate visits a*N*(W+1)
original field elements, excluding source preparation and consumer reads. A replay
is not free because its output is small. No fitted constant, benchmark result or
weight-pass count changes here. Affected tasks: E3-05, E3-06, GPU/distribution and
their downstream consumers. The original peak-memory acceptance criterion remains.
