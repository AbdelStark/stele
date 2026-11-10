# RFC-0029 — Commitment scheme v3: interleaved circle Reed–Solomon with a recursive opening

Status: Draft · Version: 0.1.0 · Depends: RFC-0003 §3, RFC-0006, RFC-0010 (A2, A3, A8, A9), RFC-0012, RFC-0027

Scope: the development tier first. Admission to `standard` needs RFC-0030 and
Workflow 10. Questions: Q27, Q39, Q44, Q45, Q48, Q50, Q51. Tasks: E19-01..E19-06.
RFC-0010 A3 item 1 reserves the fresh-tensor mode and the succinct ("Ligerito") mode
for a new amendment. This RFC is the proposal for that amendment; §1.4 lists the
companion texts it needs at acceptance.

## 1. Statement

### 1.1 Motivation

- The per-proof sources of RFC-0026 use the v2 expander code, whose proven distance
  forces up to 13,472 certificate and 6,714 opening queries. They are 91% of a development
  proof ([assessment §3](../assessment.md#3-the-end-to-end-prover-measured)).
- An RFC-0010 opening sends the row combination `u` in full. For a model source that
  is megabytes per opening, and RFC-0010 §7 (Ligerito mode) was never admitted (Q27).
- Published systems with this shape reach sub-megabyte openings (Ligerito, ePrint
  2025/1187: 255 KiB at 2^24 and 420 KiB at 2^30 coefficients, rate 1/4, 100 bits).
  Its 148 queries per level are the unique-decoding radius `D/2`. Under the radius
  this draft admits (`D/3`, §5) the count at rate 1/4 is 241 for 100 bits and 314 for
  130 bits, so sizes here are larger by that factor until Q39 is answered.

### 1.2 Object

A **source** is an `R × C` matrix over M31 (level 0) or over `K` (levels 1 and up),
`R = 2^ℓ`, `C = 2^m`. Each row is encoded with the **coefficient-form circle code** of
blow-up `2^b`: the row's `C` entries are the coefficients in the basis `b_0..b_(C−1)`
of RFC-0010 A2, zero-padded to `N = 2^(m+b)` and evaluated on `D_(m+b)`. The `N`
columns are leaves of an RFC-0012 A3 Merkle tree. A `K`-valued row is encoded limb by
limb, which is the `K`-linear extension of the code.

This is not the map of RFC-0010 A2, which takes message rows as evaluations on `D_m`
and interpolates first. The two maps have the same set of codewords, so the distance
bound of A2 (`D = N − C` for `C ≥ 2`) holds unchanged. They differ in which message a
codeword encodes, so the coefficient form has its own code identity and its own
source version (3). Version 1 sources (RFC-0010 A9) keep A2's map and are not opened
recursively. The coefficient form costs one transform per row where A2 costs two.

An **opening** proves `⟨a ⊗ b, M⟩ = v` for verifier-computable `a ∈ K^R`, `b ∈ K^C`.
Version 3 adds: the prover commits `u = aᵀM` as the next level's source in place of
sending it, and the checks on `u` become claims on that source.

### 1.3 Modes

- **Fresh mode**, for the stacked witness source of each segment and for every
  recursion level. All claims on the source are point claims and are first reduced to
  one point by RFC-0006 A2 mode 1. That point is made of sumcheck challenges drawn
  after the source's root was absorbed, so `a = eq(·, r_row)` is a fresh random tensor
  and the row combination is also the proximity test. No separate certificate is
  produced.
- **Certified mode**, for model sources. The registration certificate of RFC-0010 A9
  is kept, computed on the coefficient-form map under a version-3 source context. An
  opening may then use any verifier-computable `(a, b)`. With exactly one claim on
  the source per proof, `a` is the weight-side partial evaluation of the matmul
  sumcheck (the fused opening) and no batching pass reads the weights. That needs one
  model source per weight role, stacked over layers (task E18-07). A source with
  several claims first reduces them to one point, which is an extension-field pass
  over the source and gives up the fused opening.
- **Multiplicity sources are in neither mode.** RFC-0008 A5 opens them with rank-one
  prefix-mask functionals on limb-encoded values. Those are not point claims and their
  row functional is not a random tensor, so fresh mode does not apply
  (`formal/tensor-opening.md` has the counterexample for a fixed coordinate). They
  stay version-1 sources with their A9 certificate and openings, as RFC-0026 uses
  them, until an amendment reduces such a functional to a point claim (Q51).

### 1.4 Companion amendments required at acceptance

- **RFC-0010 A14** (new): admits fresh mode for sources whose claims are reduced to one
  transcript-random point, and the recursive opening of §2, replacing for those two
  cases the last sentence of A3 item 1 and the cost sentence of A3 item 10; registers
  the coefficient-form code identity and source version 3 (Q48).
- **RFC-0012 A17** (new): the batching-coefficient label, the level roots' absorb
  label, and one PCS record per level.
- RFC-0008 A5 and RFC-0006 A8 are unchanged.

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
3. **Query.** The verifier draws `q_i` column indices from the transcript with the
   RFC-0012 A10 sampler (independent draws; duplicates are kept). The prover sends
   each column of `M̂_i` with its Merkle path.
4. **Derive the next claim.** For each queried column `j` let
   `y_j = Σ_r eq(r_i)_r · M̂_i[r, j]`. Because the code is linear,
   `Enc(u_{i+1})[j] = ⟨g_j, u_{i+1}⟩`, where `g_j` is the vector of circle-basis
   functions at domain point `j`. The verifier draws one batching coefficient `β`
   (its label is registered at acceptance) and sets
   `w_{i+1} = w_i(r_i, ·) + Σ_j β^j·g_j` and `v_{i+1} = v_i' + Σ_j β^j·y_j`,
   where `v_i'` is the sumcheck's running claim and `j` counts queries from 1. At
   level 0 no row round is run and `v_0' = v_0`. In fresh mode the row weights are
   `eq(·, r*_row)` and the first term is `eq(·, r*_col)`. In certified mode the row
   weights in `y_j` are `a` and the first term is `b`.
5. Recurse on `⟨w_{i+1}, u_{i+1}⟩ = v_{i+1}`.
6. **Final check.** With `u_L` in the clear the verifier evaluates `⟨w_L, u_L⟩`,
   re-encodes `u_L` and checks the last level's queried columns directly.

The verifier never materialises `w_i`. It evaluates the multilinear extension of each
part at the point the sumchecks produce: `eq` terms in `O(log)` field operations, and
each `g_j` in `O(m)`. The second holds because rows are in coefficient form and A2's
basis is a tensor basis in the bits of the coefficient index: with `P_j = (x, y)`,
`g_j = (1, y) ⊗ (1, v_1(x)) ⊗ (1, v_2(x)) ⊗ …`, so its extension at a point `r` is
`(1 − r_0 + r_0·y)·Π_h (1 − r_h + r_h·v_h(x))`. It would not hold for A2's
evaluation-form rows.

**Several sources at one level.** Sources of one level with the same row length are
treated as row blocks of one logical source (RFC-0026 A4 placement; the block index
joins the row variables). They may have been committed at different points of the
transcript, each under its own root, all absorbed before the step below.

- Their `k` linear claims are combined with powers of one coefficient `γ`:
  `W = Σ_s γ^s·(block s ↦ w^(s))`, claim `Σ_s γ^s·v^(s)`. This is one RLC record,
  `(k − 1)/|K|`.
- The row rounds of step 1 run over the block and row variables together and give one
  row point; step 2 commits one row combination for all blocks.
- A query index is drawn once and opened in every block's tree: `k` paths per query.
  `y_j` sums the blocks' contributions with the block weights `eq(r_block, s)`.

There is one recursion per proof from level 1 on.

**Segments.** A segment's level-0 step runs when the segment closes: its row
combination `u_1` is committed, its queries are drawn immediately after that root is
absorbed and answered, and its matrix leaves memory (RFC-0028 §2.4). Its `q_0 + 1`
claims on `u_1` are combined with powers of its own `β`. The plan gives every `u_1`
the same row length, and all pending `u_1` sources (segments and model sources) join
as blocks of the logical level-1 source at the end of the proof.

## 3. Prover algorithm and cost

- Commit: `R` forward circle transforms of length `N` (no interpolation) and one
  Merkle tree over `N` leaves of `R` elements. Rows are independent; the encoder
  batches them.
- Row combination: `R·C` small-by-extension products at level 0 (the weight pass when fused);
  extension arithmetic on `C_i` elements at higher levels, a geometric tail.
- Memory: the level-0 matrix of one segment and its codeword, or the codeword
  recomputed for the queried columns when the plan says so (model sources).
- Proof bytes: `Σ_i q_i·(elem_i·R_i + 32·k_i·log2 N_i) + elem·C_L`, with 4-byte
  elements at level 0 and 16-byte elements above, and `k_i` blocks at level `i`. The
  plan fixes `(ℓ_i, m_i, b_i)` per level by minimising this expression under the caps
  of RFC-0030 §3; no proof byte selects a parameter. Under those caps a row codeword
  is short, so a large witness has many rows and its level-0 columns dominate the
  proof (Q50).

Cost-model terms: `c_c` (encode and hash, now with an FFT), `T_cuts` opening term, and
`T_weights` (one read when fused). The size model and its minimiser are checked by an
exact-integer script, as RFC-0010 A3 item 4 does for Policy 1 (task E19-01).

## 4. Verifier algorithm and cost

Per level: `ℓ_i` sumcheck rounds, `q_i·k_i` Merkle paths, `q_i·R_i` field products for
the `y_j`, and `O(q_i·m_i)` for the `g_j` evaluations. Final level: one encoding of
length `C_L` and `(Σ_i q_i + 1)·C_L` products for `⟨w_L, u_L⟩`. Every length, level
count and query count comes from the plan.

## 5. Soundness

Per level, with distance `D_i = N_i − C_i` (RFC-0010 A3 item 3; `D_i = N_i` when
`C_i = 1`), proximity radius `e_i` and `e_i < D_i/3`:

| Source | Line | Formula | Status |
|---|---|---|---|
| tensor row combination is a proximity test | PCS | `2·ℓ_i·(e_i+1)/|K|` | proven for linear codes (Diamond–Posen, as RFC-0010 A3 item 6) |
| queries, far case | PCS | `((N_i − e_i − 1)/N_i)^q_i` | proven |
| queries, near case (wrong `u`) | PCS | `((N_i − D_i + e_i)/N_i)^q_i` | proven |
| consistency batch within a source (`β`) | RLC | `q_i/|K|` | proven |
| claims of `k` sources at one level (`γ`) | RLC | `(k − 1)/|K|` | proven |
| row-round sumcheck | SC | `ℓ_i·2/|K|` | proven |
| Merkle | H | RFC-0012 A15 | proven under its caps |

- **Policy 3** (policy byte 3; target `T` bits, 100 unless the profile says more).
  `e_i = ⌊(D_i − 1)/3⌋`. In fresh mode and at every recursion level `q_i` is the
  least positive integer with `2^T·(N_i − e_i − 1)^q_i ≤ N_i^q_i`; that count also
  covers the near case, whose base `(N_i − D_i + e_i)/N_i` is smaller. In certified
  mode the level-0 opening count is the least positive integer with
  `2^T·(N − D + e_c)^q ≤ N^q` for the certified radius `e_c`. The verifier derives
  every count; an exact-integer script checks each inequality and its failure at one
  fewer (task E19-01).
- **Radius.** `D/3` is the regime every line above is proven in for any linear code.
  A larger radius (unique decoding to `D/2` for Reed–Solomon, or the Johnson regime
  with out-of-domain samples) needs a written transfer of the cited theorem to the
  circle code and its own evidence id (Q39).
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
- **Q48**: the byte identity and version of the coefficient-form code, and whether
  model sources registered in evaluation form (version 1) need a one-time
  re-registration or a proved change of basis. The development tier has no long-lived
  registration, so RFC-0026 A6 may use version 1 and task E19-03 may change the row
  map once more.
- **Q50**: the challenge field of the commitment rounds. On QM31 the proximity round
  caps a row codeword (RFC-0030 §3), so a `2^32`-cell witness needs thousands of rows
  and megabytes of level-0 columns. Drawing only the commitment's challenges from a
  wider field removes the cap at the price of wider row combinations. The parameter
  script prices both, and the per-round form of the proximity bound (one coordinate
  per sumcheck round, not the `ℓ`-fold union) is part of the question.
- **Q51**: a reduction of RFC-0008 A5's prefix-mask functional to a point claim, so
  that multiplicity sources can join fresh mode.
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
