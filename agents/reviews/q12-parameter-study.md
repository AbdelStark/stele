# Q12 PCS parameter study: review record (task E12-21)

Reviewed: `research/fs-pcs/` and its research-CI registration, on branch
`task/E12-21-pcs-parameter-study`. These are internal agent passes, not an external
audit.

- **Pass 1, pcs-engineer / soundness-auditor (same author).**
- **Pass 2, independent reviewer.** Outside the drafting session. It re-ran the study,
  recomputed counts independently, compared `proof_bytes` with
  `stele_pcs::Source::sizes` and traced the lookup schedule in `relation_lookup.rs`.

## Verdict

**Accept after fixes.** Pass 2 confirmed:

- the query counts for all 59 Circle and 12 v2 identities, and Policy 1's
  reproduction at 130 bits;
- the comparison figures that the script does not print;
- the size model against `stele-pcs`, and the count of 48 column rounds with no
  double counting;
- the proof and public hashes against the E16-18 ledger.

## Findings and resolutions

| Id | Finding | Resolution |
|---|---|---|
| H1 | β and α are drawn with no absorb between them, so they form **one** FS round, but the study charged them as two separately ground rounds. For four table lookups the one-round error after grinding exceeded 2^-108. | `rounds()` now charges one (β, α) round per check: the numerator for ranges (c=1), and 2·numerator+1 for tables (c≤2, conservative). The grinding bits are re-derived, now 2–12. Lemma 4 of fs-composition.md is restated with one round. C1 and C2 still pass: worst round 2^-108.0, floor 2^-102.2. |
| M1 | The match with the total proof size is circular. | PARAMETERS §1 now says the non-PCS bytes are a remainder and are not independently checked. |
| M2 | The capture could not be reproduced. | `capture.patch` and the exact command are committed, and the provenance of the ledger TSV is stated. |
| M3 | §5 over-claimed adoption, and C3/C4 were not computed. | §5 now says "proposed", and an explicit "not an admission" note is added. |
| L1 | The SC part of C1 was a hard-coded 30/\|K\|. | It now uses the largest SC record, a sum that bounds every one of its rounds. |
| L2 | LU and tensor nonces were not priced. | They are priced at 8 bytes per grinding round. |
| L3 | "Up to 6 bits" did not apply to v2 at full size. | Scoped to stories42M, with about 11 bits at the largest v2 size. |
| L4 | The Johnson-radius comparison was mis-stated. | Restated as n² ≈ 2^60 against \|QM31\|·2^-108 ≈ 2^16. |
| L5 | Grinding hashes mixed in the one-time model certificate. | Hashes are now reported per proof, with the public certificate's rounds listed separately. |
| L6 | Dead code, and a tensor-round claim that held only for Circle. | Removed and corrected. |

## Not checked

Whether the recorded ledger lists every round, for example an opening-batch RLC
outside the printed lines. The native generator must enumerate rounds exactly
(E8-05).
