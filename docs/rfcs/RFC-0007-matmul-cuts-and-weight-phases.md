# RFC-0007 — Matmul reduction, residual cuts, four-phase weight passes

Status: Accepted · Version: 0.1.0 · Depends: RFC-0006, RFC-0010

## 1. Matmul reduction (Thaler 2013)
Claim `C̃(r_i, r_j) = v` with `C = X·W`, `X ∈ F^{n×d}`, `W ∈ F^{d×m}`.
`v = Σ_{k∈{0,1}^{log d}} X̃(r_i, k)·W̃(k, r_j)`.
Prover: `A[k] = X̃(r_i, k)` (`n·d` base×K MACs), `B[k] = W̃(k, r_j)` (`d·m` MACs, bucketed), then a degree-2 sumcheck over `k`.
Emits `X̃(r_i, r_k)` and `W̃(r_k, r_j)`. Soundness `2·log d/|K|`. Never materialises `n·d·m`.

## 2. Stacked weights
For weight type `τ ∈ {Q, K, V, O, up, gate, down, lm, emb}` the passport commits one polynomial
`W_τ(ℓ, k, j)` over `(log L + log d_in + log d_out)` variables (per-type `d_in, d_out`; `lm`/`emb` have no `ℓ`).
Int8 values embed signed; scales are separate public tensors applied in the requant reduction, not inside the matmul.

## 3. Residual cuts (ST-1)
Committed tensors per proof: `R_stack = (R_0, …, R_L)` (int16, `n·d·(L+1)` elements, packed 2 per M31 for commitment,
RFC-0010 §8), multiplicities, aux. **Nothing else.** Rationale: the residual stream is the only tensor whose
production (layer `ℓ−1`) and consumption (layer `ℓ`) would otherwise force the backward claim flow to visit weight
polynomials once per layer.

## 4. Claim flow for one layer (reductions in execution order; all stacked over ℓ)
| # | Reduction | Consumes | Emits |
|---|---|---|---|
| 0 | start | verifier `ρ` | `R̃_stack(ℓ+1, ρ) ∀ℓ` (functional on committed R) |
| 1 | split | `R_{ℓ+1}(ρ)` | `R_mid(ρ)`, `ffn_out(ρ)` (prover sends both; linear) |
| 2 | requant16 ⟵ ffn_out | `ffn_out` | `C_down`, remainder lookups |
| 3 | **DOWN matmul** (stacked, one pass over `W_down`, fused opening) | `C_down(r)` | `H̃(r_ℓ, r_i, r_k)` |
| 4 | silu·gate zerocheck + `silu_q` lookups + requant8 | `H` | `U`, `G` |
| 5 | requant16 ×2 | `U`, `G` | `C_up`, `C_gate` |
| 6 | **UP, GATE matmuls** | `C_up`, `C_gate` | two claims on `X2` → RLC batch → `X2(r)` |
| 7 | RMSNorm2 (§RFC-0004 5.3) | `X2` | `R_mid(r')` |
| 8 | RLC batch on `R_mid` | `R_mid(ρ)`, `R_mid(r')` | `R_mid(r'')` |
| 9 | split | `R_mid(r'')` | `R_ℓ(r'')` → PCS batch; `attn_proj_out(r'')` |
| 10 | requant16 | `attn_proj_out` | `C_O` |
| 11 | **O matmul** | `C_O` | `A_out` |
| 12 | attention (RFC-0009) | `A_out` | `Q`, `K`, `V` (post-RoPE, post-requant) |
| 13 | RoPE zerocheck + requant16/8 | `Q`, `K`, `V` | `C_Q`, `C_K`, `C_V` |
| 14 | **QKV matmuls** | `C_Q`, `C_K`, `C_V` | three claims on `X1` → RLC → `X1(r)` |
| 15 | RMSNorm1 | `X1` | `R_ℓ(r)` → PCS batch |
| 16 | embedding (layer 0 only) / LM head (final norm + argmax/sampling) | `R_0`, `R_L` | one pass over `E`, `W_lm` |
| 17 | PCS openings: `R_stack` (one batched functional), weights (fused in 3/6/11/14/16), multiplicities, aux | | |

Fifteen sequential sumcheck stages; stages 3, 6, 11, 14, 16 contain the only weight passes: **exactly one pass over
every weight element per proof** (INV-7).

## 5. The batched weight phase in detail (type τ)
Inputs: one claim per layer block on the stacked output `C_τ`, all at the same point `(r_i, r_j)` because the preceding
requant zerocheck is itself stacked (its final point is shared). Hence a single claim `C̃_τ(r_ℓ, r_i, r_j) = v`.
Identity: `v = Σ_{ℓ,k} eq(ℓ, r_ℓ)·X̃_τ(ℓ, r_i, k)·W̃_τ(ℓ, k, r_j)` — degree-3 sumcheck over `(ℓ, k)`.
Prover:
1. `A[ℓ,k] = X̃_τ(ℓ, r_i, k)`: per layer `n·d_in` MACs over the recomputed activations (RFC-0014 §4).
2. `B[ℓ,k] = W̃_τ(ℓ, k, r_j)`: **one streaming pass** over `W_τ` with the bucketed kernel; `B` has `L·d_in` K-elements (e.g. 2M, 32 MB).
3. Sumcheck over `(ℓ,k)` with `eq(ℓ, r_ℓ)` as the (cheap) third factor; `log(L·d_in)` rounds, `O(L·d_in)` K-ops.
4. Emit `X̃_τ(r_ℓ', r_i, r_k)` (virtual → next reduction) and `W̃_τ(r_ℓ', r_k, r_j)`; the latter is proven by the fused
   opening whose row vector is `B` itself (RFC-0010 §5): `W̃_τ(r_ℓ', r_k, r_j) = Σ_{(ℓ,k)} eq((ℓ,k),(r_ℓ',r_k))·B[ℓ,k]`.
Cost: `T_weights(τ) = |W_τ|·c_w / R` with `c_w → ≈1` bucketed; bandwidth floor `|W_τ|·bytes/BW`.
Multiple sequences in a batch extend `i`; generated positions extend `i`; neither touches `W`.

## 6. Alternatives (recorded; rejected for the default)
- B: per-layer `r_j^ℓ` with `rows = (ℓ,j)` layout — one pass but 2M-element columns (≈ 800 MB openings).
- C: unfused, two passes over `W` (partial evaluation + separate opening). Fallback if ST-2 fails review.

## 7. Verifier
Per phase: `log(L·d_in)` round checks (degree 3), computing `eq(ℓ, r_ℓ)` at the final point, plus the PCS opening
check (RFC-0010 §6). Total ≪ 1 ms per phase natively.

## 8. Negative controls
NC-0300 `B` computed with a wrong `r_j`; NC-0301 swapped layer blocks in `W_τ`; NC-0302 X-claim value forged;
NC-0303 requant zerocheck omitted for one layer; NC-0304 extra position appended to `X` without `R` cut;
NC-0305 fused opening with a row vector that is not the sumcheck's `B`.

## 9. Amendment log

### A1 — Packed sources and the fused row identity

Status: Draft. Question Q28. Companion RFC-0010 A6; evidence:
[packing and fused-row study](../../formal/packed-commitments.md).
Motivation: §3's two unrestricted int16 values do not fit in M31, and §5's
original-value B is not the PCS row of an unspecified packed message matrix.

Proposed replacement of §3's packing parenthesis and addition to §5:

> Derive the committed message count/layout from an Accepted injective source
> map, including canonical signed representation and tail/code padding. Do not
> assume two int16 values per M31 element. Physical int8/int16 source storage
> remains distinct from the field-message representation used by the code.
> B is still the partial evaluation of the original signed weight tensor at the
> exact stage point. The opening must consume that same object or an explicitly
> specified authenticated reduction from it to the committed representation.
> A packed row functional is not a substitute. The complete reduction schedule
> must retain exactly one source weight visit per proof, with all required
> functionals accumulated in that visit and every source claim consumed.

The packing/decomposition consumer and full fused schedule remain open in Q28;
this Draft authorizes no alternate weight pass or commitment. E4-04 and E7
criteria, NC-0300..0305/0605 and static certificates remain unchanged. Any future
challenges/losses require explicit accounting. Message counts, c_w/c_c/T_misc,
decomposition and memory need actual ledgers; no measured constant changes here.
