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
