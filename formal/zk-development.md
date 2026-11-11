# Zero-knowledge for the development path (Q29)

Status: Draft research note, task E12-10. Question Q29. Companions: RFC-0013 A1
(Draft), RFC-0010 A7 (Draft), RFC-0026 §1.2. Prior study:
[commitment privacy](commitment-privacy.md). Evidence:
`crates/stele-code/tests/hiding.rs`. Components adopted by RFC-0013 A2. Review:
[same-author passes](../agents/reviews/zk-development-design.md).

This note answers one question: what is the smallest construction that makes a
Stele proof hide the weights and the activations, given the engine that exists
today? It gives a gap analysis against the RFC-0026 development profile and
against FlashProve, chooses a construction, proves the lemmas for its
components, and lists exactly what is still open. It changes no protocol.

## 1. Gap analysis

### 1.1 What a development proof reveals

RFC-0026 §1.2 says the development profile is not zero-knowledge. Walking §4 in
order, a proof reveals the following values that depend on secrets. "Secret"
means the weights `W` and every witness column; the tokens, `y`, `T`, `[r,e)`,
the model bytes and all shapes are public by §1.1.

| # | RFC-0026 step | Revealed value | Why it leaks |
|---|---|---|---|
| D1 | 2, 3 | group, multiplicity and weight roots | deterministic hash of the encoded columns: anyone can test a guess of a whole source |
| D2 | 2, 3 | certificate row `t = γᵀM` per source | a K-linear combination of the source rows |
| D3 | 2, 3, 7 | certificate and opening columns (`q_c`, `q_o` per source) | raw encoded symbols; v2 expander columns in the systematic half are message entries |
| D4 | 5, 7 | opening row `u = aᵀM` per source | a K-linear combination of the source rows, of length `C` |
| D5 | 4, 6, 7 | zerocheck, matmul and claim-batch round polynomials | partial sums of products of secret columns |
| D6 | 4, 5, 6 | final values (column evaluations at the reduction point) and matmul `out~(ρ)` | random linear functionals of each secret column |
| D7 | 5 | LogUp fraction-tree round polynomials and layer claims | functions of the multiplicities and the looked-up columns |
| D8 | all | the weight sources' D1–D4 values in every proof | the model commitment is fixed, so the disclosures accumulate across proofs |

### 1.2 What FlashProve does for each

FlashProve (docs/protocol.md §5, §7; docs/what-is-not-hidden.md;
guide/weight-hiding.md) hides every published value that depends on the
weights, except a declared list, as follows:

- **D3**: a zero-knowledge Reed–Solomon encoding (§5.1). Each row's message
  includes random elements, so any `t` values of an encoded row are uniform;
  `t`, the query bound, is about the number of random elements.
- **D1**: a random salt in each Merkle leaf (§5.2), so an unopened column cannot be
  guessed and checked.
- **D2, D4–D7**: masks on every value sent during the reductions and proximity tests
  (§5.3, §5.4); the out-of-domain answers carry one pad each (§5.5, §7).
- **D8**: the weight table is encoded once with masks (the anchor), then
  re-encoded with fresh randomness into leaf tables, each linked to the anchor by
  a link proof (§6.2). Batches open columns of a leaf table, and a counter stops
  before the leaf table's query bound. Masks derive from a secret seed with
  ChaCha20, so hiding is computational.
- **Not hidden** (what-is-not-hidden.md): replies, served/failed, time, the
  architecture and sizes, settings fitted to the weights, batch membership,
  lengths and nonces, masked sums of the weights.

Its theorem (Lean) is honest-verifier ZK of the IOP and ZK of the compiled
prover in the random-oracle model, for one commitment, one leaf table and one
request per proof, with fresh random masks; batches and the programs are not
covered.

### 1.3 Engine constraints

- **Fields.** Sources are M31 matrices; row combinations, challenges and claims
  are in `K` (QM31, degree `D = 4`, or OM31, `D = 8`). A uniform M31 mask
  covers one M31 coordinate of a `K` value, not the value
  ([commitment privacy §3](commitment-privacy.md#3-base-field-masks-do-not-generally-hide-extension-field-rows)).
  Every `K` value we hide needs `D` independent M31 mask coordinates.
- **The v2 expander code is systematic.** Its codeword starts with a copy of the
  message (RFC-0010 A4; `encoder/expander.rs` copies `source` into `prefix`).
  A queried position in that half is a message entry, whatever else the message
  holds. No message-side mask can hide it
  (`rejects_systematic_expander_mask`). RFC-0026 sources are v2 sources today.
- **The Circle code is not systematic.** RFC-0010 A2 interpolates a message of
  length `k = 2^h` as evaluations on `D_h` in the span of `b_0..b_{k-1}`, then
  evaluates on `D_{h+b}`. The two domains are disjoint (their points have 2-adic
  orders `2^{h+1}` and `2^{h+b+1}`). §3 uses `h = m + 1`, where `C = 2^m` is
  the data width. This is the setting of FlashProve's §5.1 and of
  [commitment privacy §5](commitment-privacy.md#5-what-a-randomized-row-encoder-can-and-cannot-establish).
- **Openings are general functionals.** RFC-0010 A9 §4 verifies `⟨a ⊗ b, M⟩`
  for any verifier-computed `a, b`, so a change of message layout needs no new
  verifier arithmetic.

## 2. The construction

The zero-knowledge development variant (working name **dev-zk**) changes three
things:

1. **Hiding sources (Z1–Z3).** Every committed source becomes a hiding Circle
   source: a mask half in each message row, mask rows, and salted leaves (§3).
   Expander sources are not used.
2. **Masked sumchecks (Z4).** Every RFC-0006 A1 sumcheck adds a random
   sum-of-univariates mask polynomial scaled by a challenge (§4), as in Libra
   (Xie et al., CRYPTO 2019, §4.1) after Chiesa–Forbes–Spooner (2017).
3. **Masked claims (Z5).** Every claim on a committed column is a claim on a
   randomized extension that agrees with the column on the Boolean cube, so the
   final values a verifier sees are masked. This is the Libra `V̇` idea, placed in
   the source's mask rows (§5).

Z1–Z4 are proved below, each on its own. Z5 and the composition are not: §5
shows why the obvious instantiations leak and lists what remains.

## 3. Hiding sources

### 3.1 Layout

A hiding source holds a secret M31 matrix `X` with `R = 2^ell` rows and
`C = 2^m` columns. Its message matrix `M'` has `2R` rows and `2C` columns:

```
M' = [ X   | Rm ]    rows 0..R    (data rows)
     [ S0  | S1 ]    rows R..2R   (mask rows)
```

`Rm`, `S0` and `S1` are uniform over M31 and independent of `X`. Row index bits
are `(W, row)` and column bits `(Y, col)`, most significant first, so `X` is
the face `W = 0, Y = 0`. Each row of `M'` is encoded with the Circle code at
`log k = m + 1` and blowup `b`. The `Y = 1` half of a row is its **mask half**:
evaluations at `C` points of `D_{m+1}` that hold uniform values.

Each Merkle leaf is `salt_c ‖ column_c`, with a uniform 32-byte salt per
codeword position `c`. The salt is part of the payload, so RFC-0012 A3 leaf
hashing is unchanged, and the payload width is `32 + 4·2R` bytes.

### 3.2 Lemma 1: column privacy

**Lemma 1.** Let `Q` be a set of at most `C − 1` distinct positions of
`D_{m+b+1}`. For every data half `x ∈ M31^C`, if `r` is uniform over `M31^C`
then the symbols `Enc(x ‖ r)[Q]` are uniform over `M31^{|Q|}`.

*Proof.* `Enc(x ‖ r) = Enc(x ‖ 0) + Enc(0 ‖ r)`, so it suffices that
`r ↦ Enc(0 ‖ r)[Q]` is onto. Write `k = 2C`, `Z = D_{m+1}` with data points
`Z_x` (the first `C` indices) and mask points `Z_r`. Let `L_d` be the circle
polynomials of degree at most `d` (dimension `2d + 1`). The basis
`b_0..b_{k−2}` has degrees at most `C − 1`, is linearly independent (the
transform is invertible), and has `k − 1 = dim L_{C−1}` elements, so it spans
`L_{C−1}`. A nonzero element of `L_d` has at most `2d` zeros on the circle
(Bézout with the conic `x² + y² = 1`), so evaluation on any `2d + 1` distinct
points is a bijection, and on fewer points it is onto. Fix a target
`t ∈ M31^Q`. The `C + |Q| ≤ 2C − 1` points of `Z_x ∪ Q` are distinct
(`Z ∩ D_{m+b+1} = ∅`), so some `p ∈ L_{C−1}` is 0 on `Z_x` and `t` on `Q`. Put
`r = p|Z_r`. The Circle interpolant of `0 ‖ r` lies in the span of
`b_0..b_{k−1}`, which contains `p`, and interpolation on `Z` is unique there, so
it is `p` and `Enc(0 ‖ r)[Q] = t`. A uniform `r` therefore gives a uniform image. ∎

The bound is sharp: RFC-0010 A2 notes the FFT span is not MDS, and some sets of
`C` positions are not reached (`rejects_query_budget_at_mask_width`). The rank
check `matches_reference_mask_half_rank_below_budget` confirms Lemma 1 on the
actual encoder for `m = 1..6`, `b = 1, 2`.

**Query budget.** `Q` is the union of every position ever opened in the source,
over its whole lifetime: its certificate, all its openings, in all proofs. A
fresh challenge does not refresh the masks (commitment privacy §4). For a
per-proof source, `q_c + J·q_o ≤ C − 1` with `J` openings bounds it (repeated
draws only help). With the RFC-0010 A9 Circle tables at `b = 1`, one
certificate and one opening need `C ≥ 2^10` (`495 + 223 = 718`); at `b = 2`,
`C ≥ 2^9` (`314 + 130 = 444`).

### 3.3 Lemma 2: the joint linear view of one source

A source's algebraic view is: the certificate row `t = γᵀM'`, the opening rows
`u_j = a_jᵀM'` for `j = 1..J`, and the columns of `Enc(M')` at the query set
`Q`. The opened values `v_j = u_j·b_j` are functions of `u_j`. Split each
coefficient vector into its data and mask parts, `γ = (γ_x, γ_s)`.
Let `Λ` be the `D(1+J) × R` M31 matrix whose rows are the M31 coordinates of
`γ_s, a_{1,s}, …, a_{J,s}`.

**Lemma 2.** Fix public coefficients `γ, a_1..a_J`, any `b_j`, and `Q` with
`|Q| ≤ C − 1` distinct positions. If `rank Λ = D(1+J)`, the view has the same
distribution for every `X`.

*Proof.* We show a translation of the masks that removes `X` from the view. Let
`V_Q = {w ∈ M31^{2C} : Enc(w)[Q] = 0}`, of dimension `2C − |Q|` (by Lemma 1
the map `w ↦ Enc(w)[Q]` is onto). For each data row choose `Δ_row` with
`Enc(X_row ‖ Δ_row)[Q] = 0` (Lemma 1), and put `m_row = X_row ‖ Δ_row ∈ V_Q`.
We need mask-row shifts `ΔS` with rows in `V_Q` such that
`γ_sᵀΔS = −γ_xᵀm` and `a_{j,s}ᵀΔS = −a_{j,x}ᵀm` for every `j`. The right sides
lie in `V_Q ⊗ K`. With an M31 basis `v_1..v_s` of `V_Q`, write
`ΔS = Σ_k σ_k ⊗ v_k` with `σ_k ∈ M31^R`. On the coordinate of `v_k` the
conditions read `Λ σ_k = τ_k` for a target `τ_k ∈ M31^{D(1+J)}`, which is
solvable because `Λ` has full row rank. Now the matrices
`[X | Rm ; S]` and `[0 | Rm − Δ ; S − ΔS]` differ by `[m ; ΔS]`, whose rows encode
to 0 on `Q` and whose combinations under `γ` and every `a_j` vanish. So they
give the same view. The map `(Rm, S) ↦ (Rm − Δ, S − ΔS)` is a translation, a
bijection of the uniform masks, so the view for `X` and for `0` have the same
distribution. ∎

`Λ` depends only on public challenges. The prover checks `rank Λ` and aborts if
it is short; the abort is a function of public values, so it does not affect
privacy. Its probability affects completeness only and is not bounded here.
`rank Λ = D(1+J)` needs `R ≥ D(1+J)` (for QM31 with one certificate and one
opening, `ell ≥ 3`).

This lemma covers the source in isolation. It says nothing about what a
consumer does with the opened values `v_j`, which are functionals of the whole
`M'`, including the mask rows. See §5.

### 3.4 Lemma 3: salted leaves

**Lemma 3.** Model the leaf and node hash as a random oracle. Let a source have
`N` codeword positions, and let an adversary make `q_H` oracle queries. Every
root, path and opened leaf the verifier sees can be produced from the opened
payloads alone, with uniform digests in place of the unopened leaves, except
with probability at most `N·q_H/2^256`.

*Proof.* An unopened leaf's digest is the oracle at an input containing a
uniform 256-bit salt that is never revealed. Unless the adversary queried that
exact input (probability at most `q_H/2^256` per leaf), the digest is uniform
and independent of the column. Internal nodes above uniform, unqueried digests
are uniform too. Union bound over the `N` leaves. ∎

The simulator must program the oracle so the root is consistent with paths
that it fixes later. In the interactive model it knows `Q` in advance; under
Fiat–Shamir this is the usual programmable random-oracle step (§6).

### 3.5 Lifecycle and cost

- **Per-proof sources** (commitment groups, multiplicity sources): fresh masks
  and salts for each proof, from a 32-byte secret seed. The budget is checked
  per proof.
- **Weight sources**: masked once, when the model commitment is made. Each
  proof opens `q_o` more positions. The lifetime budget is
  `q_c + P·q_o ≤ C − 1`, so at most `P = ⌊(C − 1 − q_c)/q_o⌋` proofs per model
  commitment. For a weight source with `C = 2^20` at `b = 1` this is 4699 proofs.
  The prover keeps a persistent counter and refuses beyond `P`. More proofs need
  a new commitment, or FlashProve-style re-encodings with link proofs, which are
  not designed here.
- **Derivation.** Masks and salts come from a BLAKE3 keyed stream on the seed,
  with a context naming the source. Lemmas 1–3 assume uniform masks; with
  derived masks hiding is computational, under the assumption that the keyed
  stream is a pseudorandom function. A reused seed voids every lemma, and
  equal proof bytes for an equal seed are the expected deterministic behaviour
  (INV-8), not evidence of fresh masks.
- **Cost.** A hiding source encodes and hashes `4×` the data (`2R × 2C`), adds 32
  bytes per leaf, and doubles the opening and certificate rows (`2C` symbols).
  This does not meet RFC-0013 §5's 5% overhead target, which this variant does
  not claim.

## 4. Masked sumcheck (Z4)

### 4.1 Protocol

An RFC-0006 A1 instance has claim `H = Σ_{x ∈ {0,1}^n} f(x)` and individual
degree `δ`. The masked variant:

1. The prover samples `g(X) = Σ_{i=1}^n g_i(X_i)` with each `g_i` a uniform
   polynomial of degree at most `δ` over `K`, and binds it (§5 item R2).
2. It sends `G = Σ_{x} g(x) = 2^{n−1} Σ_i (g_i(0) + g_i(1))`, which is absorbed.
3. The verifier draws `α` (a new challenge label, charged on the MASK line,
   `1/|K|`).
4. The A1 rounds run on `f + α·g` with claim `H + α·G`, with the existing labels.
5. The prover sends the final values of `f`'s inputs and `μ = g(ρ)`. The verifier
   checks `P(finals) + α·μ` against the last running value, and returns the
   finals and `μ` as obligations.

Soundness: `g` has degree at most `δ` in each variable, so the SC term
`n·δ/|K|` is unchanged. If `H` is false, then for the bound `g`,
`H + α·G = H_true + α·G_true` holds for at most one `α` unless `G = G_true`
and `H = H_true`; this is the MASK line. Both rest on `μ` being bound to the
committed `g`.

### 4.2 Lemma 4: the rounds reveal only the final values and `μ`

For an honest verifier, `ρ` is uniform and fixed in advance.

**Lemma 4.** Fix `f`, `ρ`, and `α ≠ 0`. The tuple `(G, p_1, …, p_n, μ)` is
distributed as follows: `(G, μ)` as for a fresh `g`, and the round polynomials
uniform among those that satisfy `p_1(0) + p_1(1) = H + αG`,
`p_i(0) + p_i(1) = p_{i−1}(ρ_{i−1})` and `p_n(ρ_n) = F(ρ) + αμ`, where
`F(ρ) = P(finals)`. A simulator that knows `F(ρ)` produces it exactly.

*Proof.* `p_i = F_i + αΓ_i`, where `F_i` is `f`'s round polynomial and
`Γ_i(t) = 2^{n−i}(g_i(t) + Σ_{j<i} g_j(ρ_j)) + 2^{n−i−1} Σ_{j>i}(g_j(0) + g_j(1))`.
These satisfy `Γ_1(0) + Γ_1(1) = G`, `Γ_i(0) + Γ_i(1) = Γ_{i−1}(ρ_{i−1})` and
`Γ_n(ρ_n) = μ`. The set of `Γ` with the chain conditions has dimension `nδ + 1`:
each `Γ_i` minus its constant is free, and so is `Γ_1`'s constant. The map
`g ↦ Γ` reaches all of it, because `Γ_i − Γ_i(0)` is `2^{n−i}(g_i − g_i(0))`
and `Γ_1(0)` moves with `g_1(0)`, and `2^{n−i}` is invertible. A linear map
sends the uniform `g` to the uniform distribution on its image, also after
conditioning on the linear values `(G, μ)`. Since `F` satisfies the chain
conditions with `F_1(0) + F_1(1) = H` and `F_n(ρ_n) = F(ρ)`, and `α ≠ 0`,
`p = F + αΓ` is uniform on the stated set. ∎

`α = 0` happens with probability `1/|K|`, a statistical privacy term. The
lemma needs `F(ρ)`, the final values of `f`; hiding them is Z5.

**Zerocheck.** RFC-0006 A3's eq-factored rounds and skip have a different round
structure, and Lemma 4 is not proved for them. Under dev-zk a zerocheck runs in
A1 form, `Σ eq(τ, x)·P(x) = 0`, one degree higher, until A3 is analysed (R3).

### 4.3 Lemma 5: binding the mask with one opening (RFC-0013 A4)

Lemma 4 needs `μ = g(ρ)` from a `g` fixed before `G`. A sum of univariates is not
a tensor functional, and opening a row that holds all of `g`'s coefficients
would reveal `g` and hence `f`'s rounds. A4 uses the two-block mask
`G(X) = (1 − X_n)·g⁰(X) + X_n·g¹(X)`, `g^b = Σ g^b_i(X_i)`,
`deg g^b_i ≤ δ` (`i < n`), `deg g^b_n ≤ δ − 1`. Its coefficient rows (each block
stored as `D` M31 limb rows) form the data of a hiding source, and one opening
with `a = (ℓ_0(ρ_n)·e_d, ℓ_1(ρ_n)·e_d; 0 on mask rows)` and the Lagrange weights
as `b` gives `u·b = G(ρ)`. The opening row's coefficient half is
`B = (1 − ρ_n)·g⁰ + ρ_n·g¹` (as coefficient vectors).

**Lemma 5.** Fix the honest verifier's public challenges with `α ≠ 0`,
`ρ_n ∉ {0, 1/2}`, a query set with at most `C − 1` distinct positions, and a
certificate whose mask-row coefficients have M31 rank `D`. For any two `f, f'`
with the same claimed sum and the same final values `F(ρ)`, the joint view
(certificate row, opening row `u`, every queried column, `G`, the rounds, `μ`)
has the same distribution.

*Proof.* We give a translation of the uniform randomness that turns the view for
`f` into the view for `f'`. The randomness is the two blocks, the mask halves of
all rows and the mask rows.

1. *Rounds.* `p_i = F_i + α·Γ_i`, where `Γ_i` is `G`'s round polynomial. We
   need a shift `(Δg⁰, Δg¹)` with `ΔΓ_i = (F_i − F'_i)/α` for all `i`,
   `ΔG = 0`, `ΔG(ρ) = 0` and `ΔB = 0`. Put `Δg¹ = −τ·Δg⁰` with
   `τ = (1 − ρ_n)/ρ_n`, which gives `ΔB = 0`. For `i < n`, summing `X_n` over
   `{0,1}` leaves the sum of univariates with parts `Δg⁰_i + Δg¹_i =
   (1 − τ)·Δg⁰_i`, and `1 − τ = (2ρ_n − 1)/ρ_n ≠ 0`, so these rounds follow
   Lemma 4's argument: every non-constant part, and the first constant, is
   reachable. In the last round,
   `ΔΓ_n(t) = (ρ_n − t)/ρ_n · (ΔP_0 + Δg⁰_n(t))`, where
   `ΔP_0 = Σ_{j<n} Δg⁰_j(ρ_j)`. As `Δg⁰_n` ranges over degree `≤ δ − 1`, this
   covers every polynomial of degree `≤ δ` that vanishes at `ρ_n`. That is
   exactly the freedom the target set leaves: the chain fixes `Γ_n(0) + Γ_n(1)`,
   and `ΔΓ_n(ρ_n) = ΔG(ρ) = 0`. Counting gives `nδ − 1` on both sides. The
   targets satisfy these conditions because `f, f'` share the claimed sum and
   `F(ρ)`.
2. *Columns.* The shift changes each block's limb rows `Δc_{b,d}`. For each
   such row, choose a mask-half shift `Δr_{b,d}` with
   `Enc(Δc_{b,d} ‖ Δr_{b,d})[Q] = 0` (Lemma 1). The opening row's mask half
   then moves by `Σ ℓ_b e_d Δr_{b,d}`. Each `Δr_{b,d}` is free within a coset of
   `V = {v : Enc(0 ‖ v)[Q] = 0}`, and `ℓ_0, ℓ_1` are not both zero, so the
   movement ranges over a coset of `V ⊗ K`. That coset contains 0 exactly when
   `Enc(0 ‖ Σ ℓ e Δr)[Q] = −Enc(ΔB ‖ 0)[Q] = 0`, which holds since `ΔB = 0`.
   So the opening row is unchanged, and so is every queried column of the
   block rows.
3. *Certificate.* All changed rows encode to 0 on `Q`, so the certificate row's
   change lies in `V_Q ⊗ K`. Lemma 2's translation of the mask rows cancels it,
   using rank `D` of the certificate's mask-row coefficients. The mask rows have
   zero opening weight, so this changes neither `u` nor the rounds.
4. *Revealed scalars.* `G` and `μ` are unchanged by construction; `μ = u·b`.

The translation is a bijection of the uniform randomness, so the two views have
the same distribution. ∎

Soundness is unchanged in form. `G` is the polynomial of the certificate's
unique near message, fixed before `G` is absorbed, so Lemma 4's MASK line holds.
The single opening term binds `μ = G(ρ)`. The tests are
`crates/stele-reductions/tests/zk.rs`: round trip, the A2 forgery rejected, a
substituted mask source rejected, and a statistical check of `p_1(2)` and of
the opening row. The controls are NC-0907 and NC-0908.

## 5. Masked claims and composition: what is still open

Lemmas 1–4 do not yet make a development proof zero-knowledge, because every
reduction ends in final values D6 that the verifier must see in the clear to
evaluate `P`. The plan is Libra's: run every relation on a randomized extension
`V̇` of each committed column that equals the column on the Boolean cube. In a
hiding source this is a point of the multilinear `M̃'`:
`V̇(ρ) = M̃'(κ(ρ), ρ_row, 0, ρ_col) = (1 − κ)·X̃(ρ) + κ·S̃0(ρ)` with a public `κ`
that vanishes on the cube, such as `ρ_1(1 − ρ_1)`. It is opened by an ordinary
point opening, and claim batching still sees a multilinear polynomial. Two
leaks show it is not yet a proof:

- **M31 entropy against `K` claims.** After the first round binds `ρ_1`, each
  entry of the folded table is `(1−κ)·x̄ + κ·((1−ρ_1)S0(0,·) + ρ_1 S0(1,·))`. The
  mask spans only the 2-dimensional M31 space `κ·span{1 − ρ_1, ρ_1}` inside `K`,
  so each entry reveals its data part `x̄` modulo that space. For generic `ρ_1`
  that fixes both data values the entry folds. One mask block per data row is not
  enough; `D/2` blocks are needed, and the `rank Λ` condition grows with them.
- **Certificate against `V̇`.** The certificate row contains
  `eq(r_row)ᵀ((1 − r_W)X + r_W S0)` in its `Y = 0` half, and the folded table
  contains `(1 − κ)X + κS0`. Two different mixes of the same `X` and `S0` reveal
  a combination of `X` alone. The certificate needs mask rows that `V̇` does not
  use.

Exact remaining list, in dependency order:

- **R1 Claim masking.** Fix `κ`, the number and role of mask-row blocks (`D/2`
  for `V̇`, separate blocks for the certificate), the resulting `rank Λ`
  condition and the degree increase in every consumer sumcheck. Prove the joint
  view of the folded tables, the openings and the certificate.
- **R2 Binding `g`.** Closed by RFC-0013 A4 (§4.3, Lemma 5): a two-block mask in a
  hiding source, opened once at `G(ρ)`.
- **R3 Zerocheck.** Analyse A3 (eq-factored rounds, skip) or fix the A1 form and
  its cost.
- **R4 LogUp.** RFC-0008 A5 grouped LogUp: the fraction-tree layers are not
  committed, so each layer claim needs its own randomization (Libra's per-layer
  `V̇`), plus the A5 root equation and grouped units. Multiplicity sources become
  hiding sources.
- **R5 Matmul.** `out~(ρ)` becomes a `V̇` claim; the matmul sumcheck is masked.
- **R6 Claim batching.** RFC-0006 A2 mode 1 is masked (Z4) and runs on `M̃'`.
- **R7 Fiat–Shamir.** The compiled proof must be ZK in the programmable random
  oracle model: the statement absorbs only public bytes, roots are salted, and
  every message is masked. The FS line is still Q12's placeholder.
- **R8 Weight lifetime.** The counter, its persistence and the operator's
  duties; refresh by a new commitment or by linked re-encodings; RFC-0011 A1
  passports.
- **R9 Completeness.** A bound on the `rank Λ` abort probability.
- **R10 Cost.** A native ledger for the `4×` sources and the masked rounds, and a
  decision on RFC-0013 §5's 5% target.
- **R11 Expander sources.** Excluded; a hiding variant would need a
  non-systematic randomized code or a punctured query set, with its own
  proximity argument.
- **R12 Controls.** NC-0900, NC-0901 and NC-0604 consumers, new controls for the
  salt, the mask-sum binding and the budget, and GPU parity.
- **R13 Simulator.** A composed simulator for the whole proof and its
  machine-checked statement (track R-FORMAL L-5).

## 6. Privacy claim

**Target for dev-zk.** For an honest prover with fresh uniform masks and salts:
the view of an honest verifier is identically distributed to a simulator's
output, given only the public input of RFC-0026 §1.1, except with statistical
error `ε_zk` (the salt term of Lemma 3, the `α = 0` events, and the terms R1
adds). After Fiat–Shamir, in the programmable random-oracle model, the proof is
statistically zero-knowledge against verifiers making at most `q_H` queries,
with error `ε_zk` plus the salt-guess terms. With seed-derived masks this
becomes computational, under the PRF assumption on the keyed stream. Privacy
errors are not soundness errors; they are reported separately from the ledger.

**Proved here.** Lemmas 1–4, each for its component alone, with an honest
verifier and fixed public challenges. Nothing is proved for the composed proof.

## 7. What dev-zk would not hide

Following FlashProve's declared list, by design:

1. The public input: the model bytes (`Model`, `Scales`, `Preparation`,
   including mantissas and exponents chosen from the weights), every 1-D record
   (norm gains and other vectors, RFC-0026 A2), `T`, the tokens, `[r, e)` and
   `y`.
2. Every shape, the plan, the source layouts and the query budgets.
3. Whether a proof was produced: an unsupported model, an out-of-range value or
   a wrong token fails, and that depends on the weights.
4. Time, proof size and the number of proofs made under one model commitment.
5. The model commitment's root (salted, fixed). Under RFC-0013 A6 (Proposed,
   E12-25), one published commitment serves up to `P` proofs. Two proofs under it
   show they share a model, as they must, since they pin it. They also reveal
   their proof indices and the budget `P`. Each proof's claims use fresh mask
   blocks, and the source's view stays within A6's query and rank budgets.
6. Anything the operator leaks by breaking the lifecycle: a reused seed, a lost
   counter, or a run past the budget.

No one has shown this list is complete.

## 8. Recommendation

- Make RFC-0013 A1 the vehicle only for the complete construction (it requires
  Circle and expander paths, the 5% target and native evidence). Accept the
  proved components now as a separate, conditional amendment, in the way
  RFC-0010 A9 accepted a conditional field source: hiding Circle sources
  (Lemmas 1–3) and the masked A1 sumcheck (Lemma 4), with exact bytes, labels
  and budgets, admitted for no profile and wired into no consumer. A1 stays
  Draft with R1–R13 as its exact remaining list.
- Implement those two components as engine primitives, with tests that proofs
  verify, that opened values are masked, and that removing a mask is detected.
- Do not add a dev-zk profile flag until R1–R7 are accepted (INV-1).
