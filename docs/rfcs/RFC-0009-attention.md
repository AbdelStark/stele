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

## 8. Amendment log

### A1 — Explicit exponential function, scale and representation

Status: Accepted. Companion RFC-0021/RFC-0004 A4. Review: [coordinated skill sign-off](../../agents/reviews/cqis-functions-contract-accepted.md).
Motivation: the old exp lookup sketch does not distinguish the inclusive domain,
split-dependent product, correctly rounded alternative or multiple small tables.

Replacement for §2 step 4: for each configured attention instance, authenticate
the exact exponential FunctionId/RepresentationId and B,F,E (and k where selected).
The integer argument is t=S(i,j)-m_i; the real reference exponent is t/2^F.
No implicit score scaling, clamping or tail replacement is permitted. Enforce
the complete -2^B<=t<=0 domain and the selected RFC-0021 decomposition, every
component membership, product/remainder relation and integer range. At u=2^B,
the final high index requires low index zero. Large signed/index relations need
their actual limb consumers and static bounds, not modular aliases.

Keep selector M and (1-M)*P_hat=0 for masked/padded entries. Every real query row
must have an allowed key; m_i is attained at an unmasked real j*. P_hat(0)=2^E
for both exponential functions, hence that row's Z is positive. Padded query
rows are excluded and retain the plan's canonical zeros. This does not alter
the output division, score matmul, source claims or original NC-0500..0506.

Step 4 costs one membership for direct exp, two for product, three for corrected
exp, plus all index/recombination/range work. Charge these in c_lu/c_a/T_misc;
the old single-membership estimate is not the cost of a decomposed function.
Attained-max and all lookup/source/PCS/FS errors require their actual schedules
and ledger entries. No full attention protocol or profile is admitted by a
function descriptor. E5/E7/E10 delivery retains all original gates; no measured
constant, new committed tensor or weight-pass change is asserted.

### A2 — Restore value and block units before normalization

Status: Draft. Companion RFC-0004 A6; [evidence](../../research/cqis-checkpoint/ATTENTION.md)
and [same-author review](../../agents/reviews/attention-units-draft.md).
Motivation: raw int8 V codes with differing scales do not share physical units;
block rounding changes those units and the existing division is ceiling.

Proposed replacement for §1's value/output definitions, §2 steps 1–2 and §6:
use RFC-0004 A6's D=s*V, fixed exact/block1024 mode, shifted signed division
and final configured conversion. Consume each scale from the same prepared
value source, including head/group views and cached prefixes. Keep each block
product virtual; introduce no new cut. The row sum, exponential function,
mask and attained maximum requirements of A1 remain in force. The old <2^30
block claim applies only to unscaled codes, not restored values. Use the A6
static bound and actual limb consumers for every enlarged arithmetic relation.

No new challenge is specified or error term waived. A complete reduction still
requires exact claim/consumer schedules, degree/query accounting and controls
for source/scale association, signed division and restored block units. Charge
these to c_a/c_x/T_misc; no measured constant or weight-pass count changes.
E7-06/07 are blocked on A2/A6. Original NC-0500..0506, memory and cost criteria
remain; this amendment is not a complete attention proof or profile admission.

Q26 composition proposal for A2: §2 step 6 must first consume A6's score conversion
and sq/sk source scales, then reduce the underlying int8 QK dot product. The
original raw-score matmul is insufficient for these restored units. GQA uses
floor(t/(h/g)); cached positions select the same public rotation and absolute
accumulation block as full evaluation. All new source/scale/rotation/comparison
consumers, static schemas and accounting remain mandatory before admission.
