# RFC-0013 — Zero-knowledge

Status: Accepted · Version: 0.1.0

## 1. Goal
Treaty profile: the proof reveals nothing about `W`, activations, or private tokens beyond the public input. Standard
profile: optional.

## 2. Leakage without ZK
Every emitted claim `f̃(r)` is a random linear functional of a secret tensor; every PCS opening reveals `u = aᵀM` and
`q` raw columns. Over many proofs these accumulate. Not acceptable for weights.

## 3. Mechanisms
1. **Masked sumchecks**: BlindFold-style (Thaler 2025; as used in Jolt Atlas) — the prover commits to a low-degree random
   masking polynomial per sumcheck instance (stacked ⇒ ≈ 10² per proof), adds it to the summand with a transcript
   challenge, and opens it at the end; round polynomials become uniformly random. Overhead ≈ `O(rounds)` per instance.
2. **Blinded commitments**: each committed matrix gains one uniformly random row (RFC-0010 §8); every functional `a` gains
   a random coefficient on it; opened columns are then uniformly random; `u` is blinded by the random row's contribution.
3. **Hidden final claims**: claims on committed tensors are never revealed in the clear; they are proven via blinded `u`.
4. **Multiplicities** are committed with blinding and are never opened in the clear (functional openings only).
5. **Public tables and masks** are public by construction; shapes are public (RFC-0017 §8 for hidden shapes).

## 4. Simulator sketch
Standard: given the public input and the verifier's challenges (programmable ROM), sample random round polynomials
consistent with the chain, random `u`, random columns; the blinding rows and masks make the real distribution identical.
A full proof is a track R-FORMAL deliverable (L-5).

## 5. Cost
≤ 5% (PRD G6): one extra row per commitment, `O(rounds)` masking per instance, no extra passes.

## 6. Negative controls
NC-0900 proof produced without the mask (treaty verifier must reject by ledger line MASK missing); NC-0901 blinding row
reused across proofs (detectable by digest equality test in the harness).

## 7. Amendment log

### A1 — Complete commitment privacy and joint mask lifecycle

Status: Draft. Question Q29. Evidence: [privacy derivation](../../formal/commitment-privacy.md)
and [executable study](../../research/commitment-privacy/REPORT.md).
Motivation: §3.2's extra row does not hide the original entries of an opened
column. A base-field mask also need not hide an extension-field row functional;
reused masks can leak even when whole-proof digests differ. The simulator sketch
and MASK presence do not establish the claimed joint distribution.

Proposed replacement for §3.2 and clarification of §§4–6, pending a complete
construction and review:

> Commitment randomization must hide both queried encoded coordinates and all
> row/claim messages jointly, including every mask-related disclosure. Specify
> the mask field, exact distribution, source/code map, canonical leaves, secret
> seed lifecycle, zero-coefficient behavior and all repeated-opening state.
> Appending a random row alone is not a ZK construction. Analyze the entire view
> conditioned on allowed public outputs and previous disclosures; marginal
> uniformity of one message is insufficient. Provide the actual simulator and
> separately state soundness, statistical privacy and computational assumptions.
> Bind the masked row's shifted functional to the original sumcheck claim;
> neither retaining the unshifted check nor accepting an unrelated shifted value
> implements the original statement. Include every correction in the joint view.
> A bounded-query randomized code must account for all queries to its fixed
> oracle over the passport's lifetime, including registration certificates.
> New challenges or proof digests do not refresh that oracle's hidden entropy.
> Changes to the root/masks require an authenticated lifecycle and cost contract.
> Actual protocol tests must reject omitted masking/binding and exercise reuse;
> whole-proof digest inequality alone is not evidence of mask independence.

Before acceptance, supply the complete sumcheck/PCS/private-final-claim protocol,
transcript order, simulator, source bindings and privacy construction for
Circle and expander paths, with native CPU/Python/GPU evidence as applicable.
The full <=5% overhead and one-weight-pass requirements remain; no unmeasured
claim, relaxed profile or substitute smaller workload satisfies them. NC-0604
and NC-0900/0901 remain actual consumer controls, not research credit.

Soundness impact: no production challenge, label, loss or admission change.
Future losses need explicit derivation and accounting; the existing MASK row is
not a completed privacy proof. Cost impact: randomization/encoding, full joint
opening work, repeated-use state and c_c/T_misc/registration costs; no constant
or benchmark changes. Affected tasks: E4-05 and E12-01 are blocked on this
contract, with E4-03/E4-06/E10/E12 passport and inference consumers also affected.

### A2 — Bounded-query encodings and committed masks on commitment scheme v3

Status: Draft. Questions Q29, Q40. Depends on RFC-0029. Tasks: E23-01..E23-04.
Motivation: A1 states what a construction must provide and names none. Two
published constructions fit a hash-only, sumcheck-based prover, and one of them has a
machine-checked precedent for single proofs (FlashProve; ePrint 2026/391).

Proposed construction (candidate A), replacing §3 on acceptance:

> 1. **Encoding.** Every committed row carries `t` uniformly random coefficients
>    beside its message (RFC-0029 §7 reserves the slots). The construction must make
>    every set of positions the verifier can open jointly uniform. That needs the
>    randomiser block of the generator to have full rank on each such set. It is not
>    automatic for the circle code, whose span is not MDS (RFC-0010 A2). Example: two
>    randomisers in coefficient slots `C` and `C+1` use the functions `v_m` and
>    `y·v_m`, both even in `x` for `m ≥ 2`, so the mirror positions `(x, y)` and
>    `(−x, y)` share a randomiser row and their difference reveals the message part.
>    The placement of the randomiser coefficients, the admissible query sets and the
>    rank proof are part of the construction (task E23-01). The plan fixes `t` at
>    least the number of positions of that row opened over the source's lifetime.
> 2. **Row combinations.** Every committed source has mask rows. Each fold `u = aᵀM`
>    includes a fresh mask row with a transcript coefficient, at every level.
> 3. **Sumcheck messages.** Each sumcheck instance adds a committed low-degree mask
>    polynomial to its summand with a transcript coefficient; the mask is opened with
>    the instance's final claims.
> 4. **Evaluation claims** on committed sources are never sent in the clear; they are
>    carried as claims on masked folds.
> 5. **Lifetime.** A model source has an opening budget fixed at registration and a
>    persistent counter. When the budget is spent the provider links a fresh encoding
>    of the same weights to the registered one with a proof of equality.
> 6. **Leak list.** `docs/security/leak-list.md` states everything a proof reveals
>    (shapes, lengths, timing, public outputs, any value outside the masks). A value
>    not on the list and not covered by the simulator is a defect.

Candidate B, kept as the alternative until E23-01 decides: pad every algebraic prover
message with a one-time pad and prove the verifier's algebraic checks on the padded
values in a small zero-knowledge argument (ePrint 2026/683).

Decision criteria for E23-01: prover overhead on L3b, proof bytes, coverage of
batches and segments, interaction with base-field first rounds (Q5), and how directly
the simulator can be stated in Lean.

A1's requirements stand in full: the joint-view simulator, the fixed-oracle query
accounting over the passport's lifetime, NC-0604 and NC-0900/0901 as actual controls.
Soundness impact: MASK records per masked instance (RFC-0012 §4); exact terms with
the construction. Cost impact: `c_c` for the randomisers and mask rows, `c_sc` for
masks; the PRD G6 bound is re-stated as at most 15% at M5 and 5% at M7.
Affected tasks: E23-01..E23-04; E4-05, E12-01 and E12-01a are superseded (RFC-0027 §6).
