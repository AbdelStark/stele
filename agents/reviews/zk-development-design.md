# Zero-knowledge development design review (Q29, task E12-10)

Reviewer: claude-code, also the author. Two same-author passes, the
soundness-auditor and the rfc-author skills. This is not an independent review
and approves no protocol. The note is research: it changes no RFC, label,
ledger line, wire format or control. RFC-0013 A1 and RFC-0010 A7 stay Draft.

## Pass 1 — soundness-auditor

I read [the note](../../formal/zk-development.md) as an adversary looking for a
claimed privacy property that does not hold, and for a soundness term that the
masking quietly removes.

- Lemma 1. I checked the degree count of the A2 basis against RFC-0010 A2's
  definition (`b_j = y^{j_0}·Π v_h^{j_h}`, `deg v_h = 2^{h−1}`): every index
  below `k − 1` has degree at most `C − 1`, so the first `k − 1` basis
  elements span `L_{C−1}`. I tried to break the budget by querying `C`
  positions. `rejects_query_budget_at_mask_width` finds such a set where the mask
  half does not reach every value, so the note states the budget as `C − 1`,
  not `C`. The rank test confirms `C − 1` on the actual encoder for `m = 1..6`
  at both rates.
- Expander sources. I tried to hide a v2 message by placing a mask in its upper
  half. `rejects_systematic_expander_mask` shows the codeword prefix equals the
  data for two different masks. The note excludes expander sources (R11).
- Lemma 2. I tried to drop the mask rows (the note's first leak, commitment
  privacy §1) and to use one mask row for both the certificate and an opening
  with `D = 4`. Both make `rank Λ < D(1 + J)`, and the proof's solvability step
  fails exactly there. The abort on a short rank depends only on public
  challenges. Its probability is not bounded (R9), and the note says it affects
  completeness only.
- Lemma 3 is the ordinary random-oracle salt argument. It needs the simulator to
  program the oracle under Fiat–Shamir; the note leaves that to R7.
- Lemma 4. I checked `Γ_i` against a direct sum over the remaining Boolean
  variables, and the dimension count `nδ + 1`. `α = 0` exposes `f`'s round
  polynomials; the note charges it as a statistical privacy term, separate from
  the MASK soundness line. A mask of degree below `δ` would leave `f`'s top
  coefficients visible; the protocol fixes `deg g_i ≤ δ` from the instance.
- Soundness of Z4. A prover that chooses `μ` after `ρ` passes any final check.
  The note makes the binding of `g` before `G` a precondition of the MASK line
  and lists how to open `g` as open item R2, since a sum of univariates is not a
  tensor functional. Any implementation must return `μ` as an undischarged
  obligation.
- Composition. I tried the obvious `V̇` with one mask block and found two leaks:
  M31 entropy against `K` claims after the first fold, and the certificate
  mixing `X` and `S0` differently from `V̇`. Both are written in §5 with R1. The
  note claims nothing for the composed proof.

I tried to break it by querying `C` positions, by masking a systematic
expander message, and by sharing one mask block between the certificate and the
claim, and the tests `rejects_query_budget_at_mask_width` and
`rejects_systematic_expander_mask` and the written §5 analysis rejected each.

## Pass 2 — rfc-author

- Every lemma names its hypotheses, and the recommendation keeps INV-1: no
  profile flag and no consumer before an Accepted amendment.
- Words: source, column, functional opening, claim, mask, certificate,
  commitment group and passport are used as the glossary defines them. "Hiding
  source", "mask half", "mask rows" and "masked sumcheck" are new and are
  defined in the note; the amendment that adopts them must add them to the
  glossary. No forbidden synonym (glossary lint passes).
- The note gives no cost figure without a ledger. The `4×` factor is a layout
  count, not a measurement.
- FlashProve is cited from its documents for what it claims; nothing is copied
  from its code (AGENTS.md §4).

## Checklist (Workflow 03)

- Public items: one research note and three tests in `stele-code/tests`; no
  library item.
- Challenges: none added. Z4's `α` is a proposal for an amendment.
- Claims and consumers: none emitted. The note lists the consumers that a
  composed design needs (R1–R6).
- Bindings and controls: none added; R12 lists the controls needed.
- Ledger: unchanged.
- Bound certificate: none.
- Padding and masks: the hiding layout puts the data on the `W = 0, Y = 0`
  face; padding rules for consumers are open under R1.
- Determinism: the tests use a fixed LCG and exhaustive search.
- Parity: no GPU path.
- Cost model: no term moves.
- Verifier: unchanged.
- Glossary: no forbidden synonym; new terms listed above.
