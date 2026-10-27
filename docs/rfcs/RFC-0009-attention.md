# RFC-0009 — Attention protocol

Status: Accepted · Version: 0.1.0 · Depends: RFC-0007, RFC-0008

## 1. Objects (per layer ℓ, head s; stacked over (ℓ, s))
`Q (n×d_h, int8·2^{eq})`, `K (n×d_h, int8)`, `V (n×d_h, int8)` (GQA: `K,V` indexed by group `g(s)`, a public
broadcast MLE), `S = Q·Kᵀ` (virtual int), `m` (per row, committed aux), `j*` (committed aux), `P̂ = exp_q(S − m)` (virtual),
`Z = row sums` (virtual), `O = P̂·V` (virtual int32 or blockwise), `A = requant8(O / Z)` (virtual → feeds O-proj).
Masks `M(i,j) ∈ {0,1}` public: causal, sliding-window, sequence-block-diagonal (batching), all with `O(log n)` MLE evaluation.

## 2. Reduction chain (consumes a claim on `A`, emits claims on `Q, K, V`)
1. **Output normalisation** (RFC-0004 §5.6): zerocheck `A·Z − O − ρ = 0` with `ρ` range-checked vs `Z`; emits claims on `O`, `Z`, `A`‑requant remainders.
2. **O = P̂·V**: matmul reduction over `j` (activation×activation): `Õ(r_i, r_c) = Σ_j P̂̃(r_i, j)·Ṽ(j, r_c)`; prover computes
   `P̂̃(r_i, ·)` — `O(n²)` per head on the *recomputed* `P̂` tile by tile — and `Ṽ(·, r_c)`. Emits `P̂̃(r_i, r_j)`, `Ṽ(r_j, r_c)`.
   Blockwise variant (RFC-0004 §5.7): sum over blocks of requant'd block products; each block product is its own matmul reduction, stacked over blocks.
3. **Z = Σ_j P̂(i,j)**: sumcheck over `j` of `P̂̃(r_i', j)`; emits `P̂̃(r_i', r_j')`; batch with the claim from step 2 (RLC).
4. **exp lookups**: `(S(i,j) − m_i, P̂(i,j))` into `exp_q` with selector `M(i,j)` — the table domain `[−2^B, 0]` proves `S(i,j) ≤ m_i`
   for all unmasked `j`; masked entries must satisfy `P̂(i,j) = 0`: zerocheck `(1 − M)·P̂ = 0`. Emits claims on `S̃` and `m̃` (broadcast MLE over `j`).
5. **Attained max** (ST-10): selection sumcheck `Σ_{i,j} S(i,j)·onehot(j = j*_i)·eq(i, r) = m̃(r)` — the one-hot is virtual:
   `onehot(i,j) = eq(j, bits(j*_i))` computed from the committed index vector `j*`; verifier evaluates its MLE at `(r_i, r_j)` as
   `Σ_i eq(i, r_i)·eq(bits(j*_i), r_j)` in `O(n)` from the opened `j*` (or via a committed one-hot in the wrapper). Emits a claim on `S̃`; batch with step 4's.
6. **S = Q·Kᵀ**: matmul reduction over `d_h`: `S̃(r_i, r_j) = Σ_c Q̃(r_i, c)·K̃(r_j, c)`; prover cost `O(n·d_h)` per head —
   **the n² score matrix is never touched by this step**. Emits `Q̃`, `K̃` claims (K through the GQA broadcast MLE).
7. RoPE and requant reductions then reach `C_Q, C_K, C_V` (RFC-0007 stage 13).

## 3. Cost
Steps 2–4 are `O(n²·h)` per layer: one exp lookup (`c_lu`), one partial-evaluation MAC for `P̂̃(r_i,·)`, one for `Z`, and
the mask zerocheck ⇒ `c_x ≈ c_lu + ~10`. Steps 1, 5, 6: `O(n·d)`. The `n²` tile is produced by recomputation from `Q, K`
(flash-style tiling) and consumed in a single streaming sweep per reduction (RFC-0014 §4).

## 4. Soundness
Standard sumcheck/LogUp terms (RFC-0012). Attained max: if `m_i < max_j S(i,j)` some lookup index exceeds the domain
(caught by LogUp); if `m_i > max` the selection check fails unless `S(i, j*_i) = m_i`, impossible. Masked leakage:
`(1−M)·P̂ = 0` plus selector exclusion ⇒ masked entries contribute nothing to `O` and `Z`.

## 5. Variants (RFC-0017)
Sliding window (mask), logit softcap (`softcap_q` table before exp), QK-norm (RMSNorm reductions on `Q,K`), MLA
(low-rank `K,V` from a compressed latent: two extra `MatmulA` reductions), sink tokens (mask), ALiBi (public bias MLE).

## 6. Long context
Block size `2^{10}` keys per block for `P̂·V` (CQIS §5.7) keeps every integer sum `< 2³⁰` for `E = 12`; `n` up to `2^{20}`
needs no DPA. Memory for the exp phase is one tile `(T_i × T_j)` at a time.

## 7. Negative controls
NC-0500 masked entry with nonzero `P̂`; NC-0501 `m_i` below max (index out of domain); NC-0502 `m_i` above max; NC-0503 `Z`
mismatch by one; NC-0504 GQA broadcast to wrong group; NC-0505 block sum carries dropped; NC-0506 `j*` pointing at a masked entry.
