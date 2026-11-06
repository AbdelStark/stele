# R-BF16 — cost of proving exact bf16 serving arithmetic

Task E15-04, RFC-0019 R-BF16. Research only: nothing here is protocol behaviour, a profile
decision or a measured benchmark. All times are projections from the planning constants of
[docs/cost-model.md](../../docs/cost-model.md) §1. No ledger entry exists for them.

**Question.** What does it cost to prove the arithmetic a server actually runs? That means bf16
products with fp32 accumulation in a fixed order. How does that compare with proving the CQIS
model (RFC-0004)?

**Property at stake.** The whole per-proof budget `T_proof`. Today it is `Θ(P + n·L·N_act + N_attn)`.
Exact float semantics would add a term in the number of multiply-accumulates (MACs), `Θ(n·P)`.

**Kill criterion, stated in advance.** If a sound per-MAC reduction costs less than 10× the CQIS
budget on the cost-model requests, exact serving arithmetic becomes a candidate profile.
Otherwise the recommendation is that treaties mandate CQIS.

## Result

At the idealised floor, exact bf16 costs **5.7·10² to 1.9·10³ times** CQIS. This floor allows
one lookup per MAC and nothing else. With the validated reference reduction the factor is
**2.7·10⁴ to 1.7·10⁵**. In both cases it grows with model size. For Llama-3.1-8B with a 4,608-position
request on one H100, the projection is:
- CQIS: **1.3 s**.
- Exact arithmetic, idealised floor: **≥ 12 min**.
- Exact arithmetic, reference reduction: **10–18 h**.

The reference reduction's witness for that one request is **6.3 PB**. The kill criterion holds by more
than two orders of magnitude.

**Recommendation: drop.** Treaties should mandate CQIS. Exact serving arithmetic is also not a single
well-defined target (§1), so a serving fleet that wants proofs should serve the CQIS model itself
(RFC-0019 R-SERVE, task E5-06). It should not try to prove its floating-point kernels.

## 1. Which semantics?

"Exact serving arithmetic" has to be pinned to one rounding sequence before it can be proved.
This study uses the cheapest well-defined choice, a sequential FMA chain:

    s_0 = +0,   s_i = RN_binary32(s_{i-1} + a_i · b_i),   a_i, b_i ∈ bfloat16

The product is exact, and rounding is round-half-to-even after every step. Real serving is at least
this hard to prove, and is not even this well-defined:

- **Tensor cores do not compute this chain.** Fasi, Higham, Mikaitis and Pranesh ("Numerical
  behavior of NVIDIA tensor cores", PeerJ Comput. Sci. 7:e330, 2021) measured tensor-core inner
  products on the GPUs they tested. These were not a sequence of IEEE binary32 round-to-nearest
  additions: the alignment of summands truncates bits. The vendor does not document the internal
  rounding. DeepSeek-V3 (arXiv:2412.19437, §3.3) reports that FP8 GEMM accumulation on H800
  keeps only about 14 bits. The arithmetic differs by datatype and by hardware generation.
- **The summation order belongs to the kernel, not the model.** Tiling, split-K and the choice of
  reduction tree vary with the kernel, the shape and even the batch size. He and Thinking Machines
  Lab ("Defeating Nondeterminism in LLM Inference", 2025) show the batch-size dependence for served
  models. A proof of "the served arithmetic" would therefore have to fix a kernel, a GPU model and a
  batch shape as part of the statement.
- **Only MACs are counted.** Exact fp32 softmax, `exp`, `rsqrt`, SiLU and the bf16 rounding of
  stored activations are left out. Every omission makes the exact-arithmetic numbers lower, so all
  conclusions are conservative.

## 2. The per-MAC reduction

The reduction lives in `reduction.py`. It checks one step `s ← RN32(s + a·b)` over M31 using three kinds
of constraint:
- field identities,
- range checks, built from 16-bit limb lookups,
- four tables: `T_norm`, a 65,026-row table that normalises the product significand, and three
  shift tables of 28, 6 and 25 rows.

The accumulator state is `(sign, m, e)`. Either `m ∈ [2^23, 2^24)`, or `e = −149` (zero or
subnormal). Overflow to infinity lies outside the statement and is rejected. The reduction works in
the following steps:

1. **Normalise the product.** `T_norm` maps the product significand `m_a·m_b` to `m_q ∈ [2^23, 2^24)`.
   A zero product is placed at the subnormal floor.
2. **Order and align.** Let `hi` be the operand with the larger exponent, and `d` the exponent gap,
   capped at 27. The low operand is truncated to three guard bits, plus a sticky bit for any bits
   lost: `8·m_lo = q·2^d + rem`. The sticky bit is the indicator `[rem ≠ 0]`, proved with an inverse.
3. **Sum at scale `2^(e_hi − 4)`.** `T = 16·m_hi ± (2q + sticky)`. A sign bit, a zero flag and an
   inverse make `|T|` and the IEEE sign of an exact zero explicit.
4. **Round.** The rounding position `r` comes from a shift `k = k⁺ − k⁻`. Then
   `|T|·2^(k⁻) = m0·2^(k⁺) + rem2`. The constraints `m0 ≥ 2^23` (normal) or `r = −149`
   (subnormal) determine `r` uniquely. Round-half-to-even is the single range check
   `up ⇔ 2·rem2 − 2^(k⁺) + (m0 mod 2) ≥ 1`. If rounding carries to `2^24`, the result renormalises.

**Why truncating to guard and sticky bits is exact.** If `d ≥ 4`, then `hi` is normalised and
`lo < 2^(e_hi−3)`. Cancellation can therefore remove at most one bit, so `r ≥ e_hi − 1`. Rounding
boundaries fall on multiples of `2^(r−1)`, which is at least 2 units of `q`. Replacing the true
value, which lies in `(q, q+1)`, with `q + ½` never crosses a boundary. When `d ≤ 3` the sum is
exact. When `hi` sits at the subnormal floor, `r = e_hi`. (Goldberg, "What every computer scientist
should know about floating-point arithmetic", 1991, gives the guard/round/sticky argument.)

**Soundness: the constraints determine the output uniquely.** Each committed value is pinned by one
of four mechanisms:
- a Euclidean division whose quotient and remainder are both range-checked, with static bounds
  that keep both sides of the identity below `p/2`. `BOUNDS` in `reduction.py` asserts this, in
  INV-5 style;
- a bit constraint, together with an order range check;
- an indicator proved by an inverse;
- a table row.

In particular, the quotient bound `q < 2^(27−d)` and the left-shift bound `|T| < 2^(24−k⁻)` stop
an identity from wrapping mod `p`. Without them, the necessity controls below show that an
attacker forges outputs.

**Cost per MAC** (`Meter`, conservative): **26 lookups, 42 committed elements, 19 identities.**
The committed elements are the witness values that are not low-degree functions of earlier values,
plus the limbs of range checks wider than 16 bits.

The sign, mantissa and exponent of each bf16 input are decoded once per tensor element, not per
MAC, so they are excluded. Three constraints were removed after the necessity sweep showed them
redundant:
- an exponent-order range check: a wrong order makes the shift negative, which the shift table or
  the cap rejects;
- the significand upper bound: the parity range already forces `m0 < 2^24`;
- `k⁺·k⁻ = 0`: shifting both ways gives the same `r`, `m0` and rounding decision.

## 3. Validation (`check_reduction.py`, standard library only)

There are two oracles, and neither shares the reduction's guard/sticky construction:
- **Exact oracle:** rational `s + a·b` rounded to binary32 by its definition.
- **Hardware oracle:** the host's binary64 add, then the C double-to-float conversion. Both
  operands are binary32 numbers, so this double rounding equals direct binary32 rounding
  (Figueroa, "When is double rounding innocuous?", SIGNUM Newsletter 30(3), 1995; 53 ≥ 2·24 + 2).

| Check | quick (CI) | `--full` |
|---|---|---|
| accepted steps equal to both oracles, bit-identical | 15,699 | 577,450 (568,306 also hardware-checked) |
| overflow statements rejected exactly when the oracle overflows | 93 | 3,600 |
| exact ties (half-ulp and 1.5-ulp, both parities) | 1,100 | 7,334 |
| every finite bf16 `a` × `b = 1` × 8 accumulator states | every 97th pattern | all 65,280 |
| single-value tampering: rejected / leaves the output unchanged | 5,135 / 65 | 38,230 / 510 |
| constraints shown necessary | 27 of 28 | 27 of 28 |

The test categories are:
- K = 4096 serving-like chains,
- full-exponent-range chains,
- subnormal accumulators,
- engineered cancellations,
- signed zeros.

The 65 tamper cases that leave the output unchanged move an inverse whose operand is zero, so they
do not affect soundness.

**Necessity controls.** For every constraint, the script searches for a forgery that the full reduction
rejects for exactly that reason, but that the reduction accepts with a *different* output once that one
constraint is disabled. A forgery here means a consistent witness with one value moved and
everything downstream recomputed. The search includes coordinated wrap attacks: it picks `t`, `k⁻`
and `k⁺` so that `A·2^(k⁻)` wraps mod `p` into a normalised `m0`. It found such a forgery for 27 of
the 28 constraint reasons. The 28th, `finite result`, is shown necessary by the overflow cases.

Two further checks guard the validation itself:
- **Mutants.** A reduction mutated to use 1 guard bit, to break ties upward, to use a 20-bit shift
  cap, or to drop the zero-sign rule is caught: by an oracle mismatch, by the static bound audit
  (shift cap), or, for a prover that breaks ties upward, by the checker rejecting its step.
- **Every forgery was rejected.** No forgery was ever accepted by the complete reduction.

## 4. Cost projection (`cost.py`)

Per MAC, the reduction costs `26·c_lu + 42·c_c` = **2,820 to 5,160 Mops**. Here `c_lu` is 60–150, the
cost model's per-lookup range, and `c_c = 30`. The idealised floor is one lookup per MAC with
nothing committed: **60 Mops**.

The MAC count is `n × (every linear layer, LM head included)` plus the causal `QKᵀ` and `PV` products.
The request is 4,096 prompt positions plus 512 generated, at batch 1, on one H100, with
`R = 3·10¹² Mops/s`. CQIS is `T_proof` from cost-model §2, computed from that section's formulas.

| Model | MACs | T_CQIS | T_bf16 floor | T_bf16 reduction | ratio floor | ratio reduction | reduction witness |
|---|---|---|---|---|---|---|---|
| Llama‑3.1‑8B | 3.7·10¹³ | 1.3 s | 747 s | 9.8–17.9 h | 574× | 2.7–4.9·10⁴× | 6.3 PB |
| Llama‑3.1‑70B | 3.3·10¹⁴ | 6.5 s | 1.9 h | 3.6–6.7 d | 1,036× | 4.9–8.9·10⁴× | 56 PB |
| Llama‑3.1‑405B | 1.9·10¹⁵ | 19.8 s | 10.6 h | 21–38 d | 1,925× | 0.9–1.7·10⁵× | 320 PB |

**Why the cost is `Θ(MACs)`.** CQIS proves a matmul as one integer identity per output tensor,
`Y = W·X`, exact in F_p under a bound certificate. A sumcheck reduces that identity to a single
weight evaluation, so no per-MAC work remains beyond the weight pass. Floating-point accumulation
cannot be reduced the same way, because every step `RN(s + p)` is a non-polynomial function of
the previous state. The rounding error depends on the order of summation, so the `K` steps of a dot
product do not combine into a single linear identity. Every proof system we know of then pays at
least a lookup, or an equivalent nonlinear check, per step.

That "every known system" claim is not a lower-bound theorem. The floor column is an optimistic
model of it, and even the floor is ~600–1,900× above CQIS.

The ratio also grows with `n`. The exact-arithmetic work scales as `n·P`, while CQIS pays for the
weights once per proof (INV-7). Longer requests and larger batches make exact arithmetic relatively
worse still.

**Cost-model finding.** Recomputed from §2's formulas, the Llama-3.1-70B row of
`docs/cost-model.md` §3 was inconsistent with them:
- `N_attn = n²/2·h·L` = 5.4·10¹⁰ with `h = 64`, but the row said 3.4·10¹⁰;
- `n·L·N_act` = 6.5·10¹⁰, but the row said 6.2·10¹⁰.

The 8B and 405B rows reproduce. This change corrects that row (`T_attn` 2.0 s, `T_proof` ≈ 6.5 s).

## 5. Limits

- All times are projections from planning constants. `c_lu`, `c_c` and `R` have not yet been
  measured on GPUs (cost-model §5). The ratios depend mainly on the MAC count, which is exact, and
  on `c_lu`, which is given as a band.
- The reduction is a reference design. It is not claimed to be minimal; the floor column bounds what
  any further optimisation could reach. The 19 identities, fp32 nonlinear functions and the bf16
  rounding of outputs are not costed, all of which favours exact arithmetic.
- The reduction fixes the FMA-chain semantics of §1. Tensor-core semantics would need a different and
  vendor-specific reduction. Nothing here suggests it would be cheaper.
- No transcript, challenge, profile or RFC behaviour changes, so there is no soundness-accounting
  line. Graduating "treaties mandate CQIS" into a binding statement would take an RFC amendment
  (Workflow 02). This report is evidence for that amendment, not the amendment itself.

Reproduce from the repository root:

    python3 research/r-bf16/check_reduction.py          # CI scope, < 1 s
    python3 research/r-bf16/check_reduction.py --full   # ≈ 25 s
    python3 research/r-bf16/cost.py
