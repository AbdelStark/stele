# Q12 Fiat–Shamir composition note: review record (task E12-20)

Reviewed: `formal/fs-composition.md` on branch `task/E12-20-fs-composition`. These are
internal agent passes, not an external cryptographic audit.

Reviewers:

- **Pass 1, soundness-auditor (same author).** Checked every round family against its
  Accepted interactive lemma, the label registry and the RFC-0026 schedule in
  `stele-reductions::relation`.
- **Pass 2, independent soundness-auditor.** A reviewer outside the drafting session,
  given the file and the repository and asked for a hostile review. It found no
  argument from the author.

## Verdict

**Accept after fixes.** Pass 2 found the Theorem 1 argument correct in shape: RBR,
then state-restoration counting, then grinding, with the multi-chain union over
shared queries. It also confirmed that the Lemma 4 fix is real. The required
changes below are applied on this branch.

## Findings and resolutions

| Id | Finding | Resolution |
|---|---|---|
| H1 | Step 1 omitted *forward guessing*: a query whose input contains a chaining value that later appears as an output. | Bad_H now includes it, at Q_t² extra. |
| H2 | A15's per-registration H sum grows like Q³ when roots are registered adaptively, so it fails (C3) at 2^80. "H(2^80) ≈ 2^-97" understated it. | H* = [C(Q_t,2) + 3Q_t²]/2^256, a single convex function of Q_t: 2^-94.2 at 2^80 and 2^-54.2 at 2^100. Proposed to replace the A15 H line for profile ledgers (A17). |
| H3 | "No 256-bit hash can meet it" and "required" over-claimed. The collision term is a proof artifact, not an attack. | Reworded as "no bound of Theorem 1's form with 256-bit digests can certify it", and the change is called a deliberate change of convention. |
| M1 | 192-bit Merkle truncation was not addressed. | (C3) requires 256-bit digests in any profile. |
| M2 | Falsity is relative to the frozen oracles. | F1/F2 are now in Theorem 1's statement, and property (iii) holds outside Bad_H. |
| M3 | §6 cited a file absent from the PR. | It now points to the stacked E12-21 study and `PARAMETERS.md`. |
| M4 | The Holmgren equivalence, the FlashProve figure and BCHKS/CFW were cited unverified. | Holmgren is cited only for RBR ⇒ SR. FlashProve is cited by file and section. BCHKS and CFW are marked abstract-only and unused. |
| L1 | §2 defined S inconsistently. | S is the state after the last prover message, before the nonce absorb. |
| L2 | ε_floor depended on the adversary's statement, and the multi-proof form was missing. | ε_floor is now a maximum over admitted shapes; the m-proof bound is stated. |
| L3 | Lemma 4 left its state conjunction implicit and did not fix a canonical bad tuple. | The conjunction is explicit and x is canonical. The gap is labelled a proof-technique gap, vacuous at h = 0, and the per-round sum is called out. |
| L4 | Lemma 3 gave the wrong degree for independent coefficients. | Split into the linear case and the power case. |
| L5 | The g = 8 rationale was loose. | g is described as a tuning choice; (C2) is checked independently. |

## Checked and unchanged

- Round-start counting, including multi-request rounds.
- Exactness of the samplers under abort.
- Grinding independence (tag 3 against tag 0).
- Lemmas 2, 5 and 6.
- The §5 arithmetic.
- The RFC-0026 arity bound (`relation.rs`).
- The §6 figures, reproduced by re-running the study.

## Not checked

- The Diamond–Posen and BCHKS papers themselves (Diamond–Posen Theorem 2 was already
  adopted by RFC-0010 A3).
- C3 against an exact native Q_V. This is an E8-05 item.
