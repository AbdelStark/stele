# RFC-0013 A3 acceptance review (bound mask, task E12-15)

Decision: accept A3 at its conditional scope, under the owner's authorisation for
autonomous amendment acceptance after Workflow 02 review. Reviewer: claude-code,
also the author. Two same-author passes follow; an independent review is
requested before merge.

## Pass 1 — soundness-auditor

Order on the caller's transcript:
1. `Instance`.
2. `FieldSources` with the mask source bytes, root included.
3. `zk/mask-sum` (`G`).
4. `zk/mask-weight` (`α`).
5. The A1 rounds.
6. `Final` (`finals ‖ μ`).
7. The A9 opening: `Opening` frame (it contains the certificate id), `OpeningRow`,
   then the column draws.

The certificate runs on its own transcript, from the source bytes. The verifier
rebuilds the expected version-3 bytes from the instance alone and requires
equality, so the proof cannot choose the layout.

Attempts:

1. *The A2 forgery.* A false sum, free rounds and `μ` solved last, sent with a
   genuine mask source, certificate and opening. The opening verifier checks
   `u·b = μ` and rejects (`ValueMismatch`; NC-0908, and
   `rejects_forged_mask_final`). Changing `u` to match `μ` instead breaks the
   column equation at the queried positions (A9's `ColumnMismatch`), which is
   A9's opening term.
2. *Choose the mask after `α`.* The mask source bytes are absorbed before `G`.
   Substituting another seed's source moves `α`, and the first round check
   fails (NC-0907, `RoundSumMismatch`).
3. *Commit a mask of the wrong shape.* Whatever message the certificate fixes,
   the functional reads exactly `n(δ + 1) − 1` columns as a two-block mask of
   degree `≤ δ` per variable. Other columns get weight zero. So the committed
   `G` always has the degree the SC line assumes.
4. *Open the mask rows.* The functional is fixed by the verifier, with zero
   mask-row weight. The producer refuses any other functional on a mask source
   (`MaskRank`), and a second opening (`MaskBudget`).

I tried to break it with the A2 forgery, with a substituted mask source and
with a re-shaped mask, and the controls NC-0908 and NC-0907 and the fixed
functional rejected each.

Ledger: SC and MASK as in A2, plus one certificate term and one opening term of
the mask source (PCS line, conditional as in A9). No new label.

## Pass 2 — privacy (rfc-author as the hostile reader)

- Lemma 5's translation was checked step by step:
  - rounds: Lemma 4 with the factor `1 − τ ≠ 0`, and the last round as the
    polynomials vanishing at `ρ_n`, dimension count `nδ − 1`;
  - the opening row's mask half: the `V ⊗ K` coset contains 0 because `ΔB = 0`;
  - the certificate: Lemma 2's mask-row translation.
- The two excluded points `ρ_n ∈ {0, 1/2}` are public aborts.
- `accepts_masked_rounds_and_opening_row` shows uniform `p_1(2)` and a uniform
  first opening-row limb over 128 seeds, for two different witnesses.
- Not covered: the final values (R1), A3 zerocheck form (R3), composition and
  Fiat–Shamir ZK.
- The statement is honest-verifier and conditional on uniform masks, as A2's.

## Checklist (Workflow 03)

- RFC: RFC-0013 A3 items 1–6.
- Challenges: as listed above, all after their absorbs.
- Claims: `μ` is consumed by the mask opening, at the same point `ρ`. The finals
  remain obligations for the caller.
- Controls: NC-0907 and NC-0908 are done. NC-0902..0906 still cover the source.
- Ledger: MASK and SC unchanged, plus the mask source's PCS terms.
- Determinism: masks, salts and the source are fixed functions of the seed and
  the instance id.
- Parity: no GPU.
- Cost: no constant moves.
- Verifier: `no_std`, no new dependency. The `stele-reductions` and `stele-pcs`
  API gates admit `zk`, `hiding_mask` and the quarantine exception.
- Glossary: "mask source" added.
