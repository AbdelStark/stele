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
