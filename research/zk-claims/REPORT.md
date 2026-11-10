# R1: exact linear view of masked claims and batching

Question: does the dev-zk view of `formal/zk-claims.md` §§2–3 hide the
witness? The view covers masked claims, a hiding source, the A2 certificate,
the zero-weight batch with a masked sumcheck, the opening row and the queried
columns. Kill criterion: a draw without a public abort where
`rank([B A]) ≠ rank(B)`. Run
`python3 research/zk-claims/check_view.py` (standard library).

Model:
- Field and code: `F_31 ⊂ F_{31²}` (`D = 2`) and a Reed–Solomon toy code
  (8-symbol messages, 16-symbol codewords).
- Witness: one 8-entry column with a 4-entry claim mask and two masked claims.
- Source: one hiding source with `R = 2D` data rows.
- Batch: the zero-weight batch of §2.3 with Lemma 4 masking.
- Challenges: drawn uniformly, as for an honest verifier.

Result over 60 draws per case:

| Case | Private in |
|---|---|
| honest, 3 queried positions | every draw without an abort (55 of 55) |
| claim masks removed | 0 draws |
| mask rows removed | 0 draws |
| batch sumcheck mask removed | 0 draws |
| opening at `w* = 0` | 0 draws |
| 5 queried positions, above the budget | 0 draws |

The abort column counts draws where a public challenge breaks a condition:
`κ = 0`, `w* = 0`, `α = 0`, or a short rank in Lemma 6 or Lemma 2. Every
honest draw with a short rank leaks, so these rank conditions must be producer
aborts. In this tiny field they fail in about 1 draw in 12; at M31 the bound is
`D·t·ℓ/p`.

Scope: one column, one source, one batch. The note's item 2 extends this to two
relations sharing a column and to correlated claim points. This is not a proof
of the composed protocol, and it earns no NC credit.
