# E12-13 masked A1 sumcheck review (RFC-0013 A2 item 2, RFC-0012 A18)

Reviewer: claude-code, also the author. This file records same-author
sumcheck-prover-engineer and soundness-auditor passes. It is not an independent
review, and one is still needed.

## What changed

- `stele-hash`:
  - Registers `stele/v0.1/zk/mask-sum` (absorb) and `stele/v0.1/zk/mask-weight`
    (challenge) as registry entries 46 and 47, with the new loss line
    `LossLine::Mask`.
  - `docs/security/transcript-labels.json` lists both, the second as `MASK`.
  - `MaskStream::element` samples a `K` value as `D` M31 limbs.
- `stele-sumcheck::masked`:
  - `Mask::derive` uses the `zk/sumcheck-mask` stream; `sum` and `evaluate`
    are defined there too.
  - `prove` and `verify` follow A2 steps 1–6.
  - `Reduction` keeps A1's claims and SC record. It adds `mask_final` as an
    undischarged obligation.
- A1, A3, the existing labels and every existing proof byte are unchanged.

## Pass 1 — soundness-auditor

- **Order.** The instance is absorbed under `Instance`, then `G` under
  `zk/mask-sum`, then `α` is drawn under `zk/mask-weight`. The rounds follow,
  with A1's `Round` and `Sumcheck` labels. Last, `finals ‖ μ` is absorbed under
  `Final` at index `k + 1`. `α` follows `G`, as the MASK line requires.
- **Changed `G`.** NC-0904 changes `G` in an honest proof and keeps the rounds.
  The first round check fails (`RoundSumMismatch`), because the running claim
  moved by `α·ΔG`.
- **Changed `μ`.** NC-0905 changes `μ` and gets `FinalEvaluationMismatch`.
- **False claim.** A false `H` (claimed sum + 1) makes the honest prover's
  own round check fail. A zerocheck in A1 form with one wrong product entry
  fails the same way.
- **Open gap (R2).** Nothing binds `g` before `G`, so a prover could pick `μ`
  after `ρ`. `accepts_forged_mask_final_for_a_false_sum` shows it: a proof of a
  false claimed sum with arbitrary rounds and `μ` solved last is accepted.
  Independent review asked for "no consumer" to be enforced, not only stated:
  the module is `#[doc(hidden)]`, and the `masked quarantine` check in
  `scripts/gates/check.py` (run by the negative-controls and accounting gates)
  rejects any use of `masked::` outside its own tests and the NC-0904/0905
  controls.
- **Ledger.** `masked::Reduction` carries a `MaskRecord` (instance id, field
  degree) for the one `zk/mask-weight` draw, charged `1/|K|` on MASK and valid
  only once `g` is bound.
- **Label indices.** This branch registers the two labels at indices 46 and 47.
  The coordinator assigned this stack index 47 after the Q12 stack's entry at
  46, so the rebase onto the merged Q12 stack moves them to 47 and 48, with the
  registry tests and `transcript-labels.json`.
- **Degenerate instances.** `n = 0` and `δ = 0` are rejected with
  `InvalidInstance`.
- **SC record.** It is unchanged (`n·δ`). The record shows `numerator = 8`
  for `n = 4`, `δ = 2`.

I tried to break it by shifting `G`, by shifting `μ` and by proving a false sum,
and the controls NC-0904 and NC-0905 and the prover's own round check rejected
each. Choosing `μ` late is not blocked. That is R2, and it is why A2 admits no
consumer.

## Pass 2 — privacy evidence

- `accepts_masked_rounds_and_rejects_unmasked` looks at `p_1(2)`, a round value
  that consistency does not fix.
  - Over 256 seeds, its top-three-bit histogram passes a χ² test (7 degrees of
    freedom, bound 30) for two different witnesses.
  - Unmasked, `p_1(2)` is identical across runs and differs between the two
    witnesses, so the test detects the leak.
- This is evidence for Lemma 4, not a proof of it.
- The final values are not hidden (R1).

## Checklist

- RFC: RFC-0013 A2 item 2 and RFC-0012 A18.
- Challenges: `zk/mask-weight` follows the `Instance` and `zk/mask-sum`
  absorbs.
- Claims: the A1 finals and `μ` have no consumer.
- Controls: NC-0904 and NC-0905 are done. The catalog shows 28/75 bindings and
  75/177 controls.
- Ledger: MASK `1/|K|` per masked instance, conditional on binding `g`. SC is
  unchanged.
- Determinism: `g` is a fixed function of the seed and the instance id.
- Parity: no GPU path.
- Cost: no constant moves.
- Verifier: `no_std` with no new dependency.
