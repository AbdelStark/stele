# RFC-0010 — Interleaved-code PCS, fused opening, certified commitments

Status: Accepted · Version: 0.1.0 · Depends: RFC-0003, RFC-0012

## 1. Object
A multilinear `f` over `N = R·C` evaluations arranged as an `R × C` matrix `M` (rows = the variables folded by the
row functional, columns = the rest). Commitment: encode every row with a linear code `Enc: F^C → F^{C'}` (rate `ρ`),
Merkle-commit the `C'` columns (leaf = one column of `R` elements, domain-separated), publish the root.

## 2. Supported functionals (what an "opening" proves)
`⟨a ⊗ b, f⟩ = aᵀ M b` for verifier-computable `a ∈ K^R`, `b ∈ K^C`. Point evaluation is `a = eq(·, r_row)`, `b = eq(·, r_col)`;
batched claims on committed tensors (RFC-0007 §4) use `a = Σ_t γ_t eq(ℓ_t,·)⊗eq(…)`. Prover sends `u = aᵀ M ∈ K^C`
(or commits to it in Ligerito mode §7); verifier checks `u·b = v` and, for `q` fresh random columns `c`,
`Enc(u)[c] = Σ_r a_r·Enc(M)[r,c]` using the opened columns and Merkle paths.

## 3. Codes
| Use | Code | Why |
|---|---|---|
| Weights (one-time, RFC-0011) | Reed–Solomon over the circle group of M31 (circle FFT), rate 1/4 (treaty) or 1/2 | smallest proof, proven proximity gaps up to Johnson bound; encoding cost is paid once per model |
| Residual cuts, multiplicities, aux (per proof) | linear-time RAA/expander code (Brakedown/Blaze/Bolt family) over M31, rate 1/2–1/4 | no FFT; encoding ≈ 10–20 adds per element on GPU; proximity via Khatam/Brakedown bounds |
| Wrapper (RFC-0016) | whatever the wrapper's prover prefers | out of the hot path |
A code is a `trait Code { fn encode(row) ; fn eval_row(u, cols) ; fn params() -> ProximityParams }`; parameters
(distance, proven gap, query count for each profile) live in `codes.toml` and in the soundness ledger.

## 4. Layouts
- `R_stack(ℓ, i, k)`: rows = `(ℓ, i)` (so per-layer and per-position functionals are row combinations), columns = `k` (d).
  Column length `n·(L+1)` can be large (≈ 6·10⁵ for 405B/4608) ⇒ use Ligerito mode or a row split `(i_hi)` into columns.
- `W_τ(ℓ, k, j)`: rows = `j` (the dimension folded by `eq(·, r_j)` in the phase sumcheck), columns = `(ℓ, k)`; column
  length `d_out` (16 384 for Q). Short-column variant: rows = `j_hi`, columns = `(j_lo, ℓ, k)`; `B[ℓ,k] = Σ_{j_lo} eq(j_lo, r_j,lo)·u'[j_lo, ℓ, k]`.
- Multiplicities/aux: square.

## 5. Fused opening (ST-2)
In the phase sumcheck (RFC-0007 §5) the prover's `B[ℓ,k] = Σ_j eq(j, r_j)·W_τ(ℓ,k,j)` is **exactly** `u = aᵀM` for
`a = eq(·, r_j)`. The opening therefore costs no additional pass: the prover sends/commits `u = B`, the verifier evaluates
`u·b` with `b = eq((ℓ,k), (r_ℓ', r_k))` and spot-checks columns. Soundness: `r_j` is sampled after the commitment (the
passport predates the transcript), so the tensor-structured combination is a valid proximity test by the
logarithmic-randomness theorem (Diamond–Posen for RS; Khatam for general linear codes) with the error terms in §6.
No separate random-combination pass is needed; a one-time proximity certificate (RFC-0011 §3) is still published
for defence in depth and for the `treaty` profile's audit trail.

## 6. Parameters and soundness (per opening)
Error ≤ `ε_gap(ρ, δ, |K|)` (proximity gap at relative distance `δ` below the chosen bound) + `(1 − δ)^q` (queries) +
`ε_Merkle`. Treaty: proven gaps only (RS: `δ` up to Johnson `1 − √ρ − η`, BCIKS20 + DP23/24; RAA/expander: Khatam /
Brakedown-style bounds with the code's certified distance), `q` chosen for `(1−δ)^q ≤ 2⁻¹³⁰`. Standard: may use
`δ` up to `1 − ρ − η` with the usual capacity conjecture, labelled. **Query count affects proof size and verifier only.**

## 7. Ligerito mode (succinct columns and row vectors)
Instead of sending `u` (length `C`, possibly 10⁶–10⁸), the prover commits `u` as a smaller interleaved-code matrix and
proves the two linear checks (`u·b = v`, `Enc(u)[c] = Σ a_r Enc(M)[r,c]` over sampled `c`) by a sumcheck that reduces
them to an opening of the smaller matrix; recurse `O(log log)` times (Novakovic–Angeris 2025). This allows short
columns (≈ 256 elements) with proof size ≈ 1 MB per weight type and verifier cost `O(q·R + polylog)`. Mandatory for
the wrapper path; optional for native verification.

## 8. Packing, blinding, DPA
- Packing: `k` int8 (4) or int16 (2) values per M31 message element; the consumer side (RFC-0008 §5) pins the decomposition.
- ZK blinding (RFC-0013): one extra random row per matrix; functionals are extended with a random coefficient on it.
- DPA (RFC-0019): leaves hold the packed systematic bytes once plus one parity block per field.

## 9. Distributed openings
`LigeSIS`-style sharding (RFC-0015 §4): each device commits its row shard; a root of roots; the row functional's
contributions are summed across devices; column openings touch only the device owning the column shard.

## 10. Negative controls
NC-0600 `u` inconsistent with opened columns; NC-0601 column index not from transcript; NC-0602 Merkle path for wrong
leaf; NC-0603 packed decomposition altered (x0 = 256, x1 − 1); NC-0604 blinding row omitted in treaty profile;
NC-0605 fused `u ≠ B` (cross-check with NC-0305).
