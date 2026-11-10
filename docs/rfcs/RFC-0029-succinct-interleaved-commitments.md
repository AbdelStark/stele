# RFC-0029 — Commitment scheme v3: interleaved circle Reed–Solomon with a recursive opening

Status: Draft · Version: 0.1.0 · Depends: RFC-0003 §3, RFC-0006, RFC-0010 (A2, A3, A8, A9), RFC-0012, RFC-0027

Scope: the development tier first. Admission to `standard` needs RFC-0030 and
Workflow 10. Questions: Q27, Q39. Tasks: E19-01..E19-06. This RFC adds a mode to
RFC-0010; it withdraws nothing that is Accepted there.

## 1. Statement

### 1.1 Motivation

- The per-proof sources of RFC-0026 use the v2 expander code, whose proven distance
  forces 13,472 certificate and 6,714 opening queries. They are 91% of a development
  proof ([assessment §3](../assessment.md#3-the-end-to-end-prover-measured)).
- An RFC-0010 opening sends the row combination `u` in full. For a model source that
  is megabytes per opening, and RFC-0010 §7 (Ligerito mode) was never admitted (Q27).
- Published systems with this shape reach sub-megabyte openings with proven
  unique-decoding parameters (Ligerito, ePrint 2025/1187: 255 KiB at 2^24 and 420 KiB
  at 2^30 coefficients, rate 1/4, 148 queries per level, 100 bits).

### 1.2 Object

A **source** is an `R × C` matrix over M31 (level 0) or over `K` (levels 1 and up),
`R = 2^ℓ`, `C = 2^m`. Each row is encoded with the RFC-0010 A2 circle code of blow-up
`2^b`; the `N = 2^(m+b)` columns are leaves of an RFC-0012 A3 Merkle tree. This is
source version 1 of RFC-0010 A9 at level 0. A `K`-valued row is encoded limb by limb,
which is the `K`-linear extension of the code.

An **opening** proves `⟨a ⊗ b, M⟩ = v` for verifier-computable `a ∈ K^R`, `b ∈ K^C`.
Version 3 adds: the prover commits `u = aᵀM` as the next level's source in place of
sending it, and the checks on `u` become claims on that source.

### 1.3 Two modes

- **Fresh mode**, for per-proof sources (witness segments, multiplicity sources) and
  for every recursion level. All claims on the source are first reduced to one point
  by RFC-0006 A2 mode 1. That point is made of sumcheck challenges drawn after the
  source's root was absorbed, so `a = eq(·, r_row)` is a fresh random tensor and the
  row combination is also the proximity test. No separate certificate is produced.
- **Certified mode**, for model sources. The registration certificate of RFC-0010 A9
  is kept. An opening may then use any verifier-computable `(a, b)`, in particular
  the weight-side partial evaluation of a matmul sumcheck (the fused opening), with no batching pass over
  the weights.

## 2. Protocol (transcript order)

For one source at level `i` with claim `⟨w_i, M_i⟩ = v_i`. At level 0 in fresh mode
`w_0 = eq(·, r*)`; in certified mode `w_0 = a ⊗ b`.

1. **Row rounds.** In fresh mode at level 0 the row point is already fixed. At levels
   `i ≥ 1` run RFC-0006 A1 sumcheck rounds over the `ℓ_i` row variables of
   `Σ_x w̃_i(x)·M̃_i(x)`; the challenges are the row point `r_i`.
2. **Commit the row combination.** The prover computes `u_{i+1} = eq(·, r_i)ᵀ M_i` (certified
   level 0: `aᵀM_0`), arranges it as `R_{i+1} × C_{i+1}`, encodes, hashes and sends
   the root, which is absorbed. If `C_i` is at most the plan's final length the
   prover sends `u_{i+1}` itself and the recursion ends.
3. **Query.** The verifier draws `q_i` distinct column indices from the transcript
   (RFC-0012 A10 sampler). The prover sends each column of `M̂_i` with its Merkle path.
4. **Derive the next claim.** For each queried column `j` let
   `y_j = Σ_r eq(r_i)_r · M̂_i[r, j]`. Because the code is linear,
   `Enc(u_{i+1})[j] = ⟨g_j, u_{i+1}⟩`, where `g_j` is the vector of circle-basis
   functions at domain point `j`. The verifier draws one batching coefficient `β`
   (its label is registered at acceptance) and sets
   `w_{i+1} = w_i(r_i, ·) + Σ_j β^j·g_j` and `v_{i+1} = v_i' + Σ_j β^j·y_j`,
   where `v_i'` is the sumcheck's running claim and `j` counts queries from 1.
5. Recurse on `⟨w_{i+1}, u_{i+1}⟩ = v_{i+1}`.
6. **Final check.** With `u_L` in the clear the verifier evaluates `⟨w_L, u_L⟩`,
   re-encodes `u_L` and checks the last level's queried columns directly.

The verifier never materialises `w_i`. It evaluates the multilinear extension of each
part at the point the sumchecks produce: `eq` terms in `O(log)` field operations, and
each `g_j` in `O(m)` because the circle FFT basis is a tensor basis
(`g_j = ⊗_k (1, t_k(P_j))`).

**Several sources in one recursion.** Row combinations produced at the same point of
the transcript are stacked into one next-level source (RFC-0026 A4 layout). There is one
recursion per proof.

**Segments.** A segment's row combination `u_1` is committed when the segment closes, and its
level-0 queries are drawn immediately after that root is absorbed, so the segment's matrix
leaves memory (RFC-0028 §2.4). The pending row combinations of all segments and of the model
sources join the one recursion at the end of the proof.

## 3. Prover algorithm and cost

- Commit: `R` circle FFTs of length `N` and one Merkle tree over `N` leaves of `R`
  elements. Rows are independent; the encoder batches them.
- Row combination: `R·C` small-by-extension products at level 0 (the weight pass when fused);
  extension arithmetic on `C_i` elements at higher levels, a geometric tail.
- Memory: the level-0 matrix of one segment and its codeword, or the codeword
  recomputed for the queried columns when the plan says so (model sources).
- Proof bytes: `Σ_i q_i·(elem_i·R_i + 32·log2 N_i) + elem·C_L`, with 4-byte elements
  at level 0 and 16-byte elements above. The plan fixes `(ℓ_i, m_i, b_i)` per level by
  minimising this expression; no proof byte selects a parameter.

Cost-model terms: `c_c` (encode and hash, now with an FFT), `T_cuts` opening term, and
`T_weights` (one read when fused). The size model and its minimiser are checked by an
exact-integer script, as RFC-0010 A3 item 4 does for Policy 1 (task E19-01).

## 4. Verifier algorithm and cost

Per level: `ℓ_i` sumcheck rounds, `q_i` Merkle paths, `q_i·R_i` field products for the
`y_j`, and `O(q_i·m_i)` for the `g_j` evaluations. Final level: one encoding of length
`C_L`. Every length, level count and query count comes from the plan.

## 5. Soundness

Per level, with distance `D_i = N_i − C_i + 1`, proximity radius `e_i` and
`e_i < D_i/3`:

| Source | Line | Formula | Status |
|---|---|---|---|
| tensor row combination is a proximity test | PCS | `2·ℓ_i·(e_i+1)/|K|` | proven for linear codes (Diamond–Posen, as RFC-0010 A3 item 6) |
| queries, far case | PCS | `((N_i − e_i − 1)/N_i)^q_i` | proven |
| queries, near case (wrong `u`) | PCS | `((N_i − D_i + e_i)/N_i)^q_i` | proven |
| consistency batch | RLC | `q_i/|K|` | proven |
| row-round sumcheck | SC | `ℓ_i·2/|K|` | proven |
| Merkle | H | RFC-0012 A15 | proven under its caps |

- **Radius.** Policy 3 uses `e = ⌊(D−1)/3⌋`, the regime every line above is proven in
  for any linear code. A larger radius (unique decoding to `D/2` for Reed–Solomon, or
  the Johnson regime with out-of-domain samples) needs a written transfer of the
  cited theorem to the circle code and its own evidence id (Q39).
- **Certified mode.** The certificate fixes a radius once. A smaller certified radius
  costs more certificate queries, paid at registration, and fewer opening queries per
  proof. The plan states the radius; the verifier derives both counts.
- **No conjecture** on proximity gaps is used. The disproved capacity conjectures are
  not a fallback.
- Rounds are stated per round for RFC-0030. On QM31 at rate 1/4 the first line limits
  row codewords to about `2^21` positions at 100 bits; the parameter script enforces
  the exact cap.

## 6. Negative controls

Proposed ids, entered in the catalogue at acceptance.

| NC | Tamper | Expected |
|---|---|---|
| 0630 | commit a row combination `u_1` that differs from `aᵀM_0` in one entry | `ColumnMismatch` at the next level or the final check |
| 0631 | answer a level-`i` query with the column of another index | Merkle `RootMismatch` |
| 0632 | send a final vector `u_L` with one entry changed | `ValueMismatch` or `ColumnMismatch` |
| 0633 | present a level count or `(ℓ, m, b)` other than the plan's | `ProofShape` |
| 0634 | fresh mode: open at a point that is not the batching sumcheck's | `RoundSumMismatch` |
| 0635 | certified mode: a certificate for another radius offered for the expected source | `CertificateContext` |

## 7. Zero-knowledge reservation

The source context reserves, per level, a count of randomiser coefficients per row
and a count of mask rows. Both are zero until RFC-0013 A2 is Accepted. Reserving them
now keeps the byte layout stable.

## 8. Open questions

- **Q27** (restated): this RFC is the proposed answer for succinct openings.
- **Q39**: the largest proven radius for the interleaved circle code under tensor
  combination, and whether the Reed–Solomon results up to `D/2` and to the Johnson
  bound transfer to it.
- **Q44**: column height against segment count. Merkle paths dominate when many small
  segments are opened; the plan-level choice of segment size and rate is a measured
  trade-off.
- **Q45**: whether a linear-time first layer (sketched or repeat-accumulate codes) is
  worth its larger query count when encoding dominates. Fallback only.

## 9. Amendment log

None.
