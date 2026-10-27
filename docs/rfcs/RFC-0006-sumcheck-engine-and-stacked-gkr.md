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
