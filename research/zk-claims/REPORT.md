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

## Two relations sharing a column

Run `python3 research/zk-claims/check_two.py` (about one minute).

Model:
- Field: `F_97 ⊂ F_97[i]/(i² − 5)` (`D = 2`).
- Source: one hiding source with five columns (x, y, z, w, o) and their
  per-claim mask blocks (formal/zk-claims.md §2.1a).
- Identity `x·y − z = 0` on a 3-variable domain, with masked claims on x, y
  and z at one point.
- Matmul zero-sum `o(i) = Σ_k x(i,k)·w(k)`, with masked claims on x (a second,
  correlated claim on the same column, in its own block), on w, and on o
  through `Ȯ` on a summed bit.
- The A2 certificate, the zero-weight batch with a Lemma 4 mask, the opening
  row and the queried columns.

Result over 12 draws without a public abort per case:

| Case | Private in |
|---|---|
| honest, 6 queried positions | 12 of 12 |
| honest, 15 queried positions (`C − 1`, the budget) | 12 of 12 |
| claim masks removed | 0 |
| mask rows removed | 0 |
| batch sumcheck mask removed | 0 |
| the second x claim reusing the first one's mask block | 0 |
| 17 queried positions, above the budget | 0 |

The shared-block case is why each claim occurrence needs its own block
(Lemma 6′).

## ZK-GKR over the A5 trees

Run `python3 research/zk-claims/check_gkr.py` (about 40 seconds).

The model is two masked layers of a fraction tree (formal/zk-gkr.md):
- `p` and `q` each have a `4D`-entry block on coordinates `(T, u1, u2)`;
- each layer reveals its values at `t = 0, 1` and one selector-final claim;
- the claims are batched over the shared mask source, with its certificate,
  the opening and the queried columns.

The true layer values are treated as free secrets. Over 10 draws without a
public abort per case:

| Case | Private in |
|---|---|
| honest | 10 of 10 |
| masks removed | 0 |
| mask rows removed | 0 |
| one block shared by `t = 0` and `t = 1` | 0 |
| a `2D` block | 0 |

## Scope

These are small fixed shapes. They are not a proof of the composed protocol, and
they earn no NC credit.
