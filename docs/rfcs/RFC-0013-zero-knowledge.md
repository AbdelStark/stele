# RFC-0013 — Zero-knowledge

Status: Accepted · Version: 0.1.0

## 1. Goal
Treaty profile: the proof reveals nothing about `W`, activations, or private tokens beyond the public input. Standard
profile: optional.

## 2. Leakage without ZK
Every emitted claim `f̃(r)` is a random linear functional of a secret tensor; every PCS opening reveals `u = aᵀM` and
`q` raw columns. Over many proofs these accumulate. Not acceptable for weights.

## 3. Mechanisms
1. **Masked sumchecks**: BlindFold-style (Thaler 2025; as used in Jolt Atlas) — the prover commits to a low-degree random
   masking polynomial per sumcheck instance (stacked ⇒ ≈ 10² per proof), adds it to the summand with a transcript
   challenge, and opens it at the end; round polynomials become uniformly random. Overhead ≈ `O(rounds)` per instance.
2. **Blinded commitments**: each committed matrix gains one uniformly random row (RFC-0010 §8); every functional `a` gains
   a random coefficient on it; opened columns are then uniformly random; `u` is blinded by the random row's contribution.
3. **Hidden final claims**: claims on committed tensors are never revealed in the clear; they are proven via blinded `u`.
4. **Multiplicities** are committed with blinding and are never opened in the clear (functional openings only).
5. **Public tables and masks** are public by construction; shapes are public (RFC-0017 §8 for hidden shapes).

## 4. Simulator sketch
Standard: given the public input and the verifier's challenges (programmable ROM), sample random round polynomials
consistent with the chain, random `u`, random columns; the blinding rows and masks make the real distribution identical.
A full proof is a track R-FORMAL deliverable (L-5).

## 5. Cost
≤ 5% (PRD G6): one extra row per commitment, `O(rounds)` masking per instance, no extra passes.

## 6. Negative controls
NC-0900 proof produced without the mask (treaty verifier must reject by ledger line MASK missing); NC-0901 blinding row
reused across proofs (detectable by digest equality test in the harness).

## 7. Amendment log

### A1 — Complete commitment privacy and joint mask lifecycle

Status: Draft. Question Q29. Evidence: [privacy derivation](../../formal/commitment-privacy.md)
and [executable study](../../research/commitment-privacy/REPORT.md).
Motivation: §3.2's extra row does not hide the original entries of an opened
column. A base-field mask also need not hide an extension-field row functional;
reused masks can leak even when whole-proof digests differ. The simulator sketch
and MASK presence do not establish the claimed joint distribution.

Proposed replacement for §3.2 and clarification of §§4–6, pending a complete
construction and review:

> Commitment randomization must hide both queried encoded coordinates and all
> row/claim messages jointly, including every mask-related disclosure. Specify
> the mask field, exact distribution, source/code map, canonical leaves, secret
> seed lifecycle, zero-coefficient behavior and all repeated-opening state.
> Appending a random row alone is not a ZK construction. Analyze the entire view
> conditioned on allowed public outputs and previous disclosures; marginal
> uniformity of one message is insufficient. Provide the actual simulator and
> separately state soundness, statistical privacy and computational assumptions.
> Bind the masked row's shifted functional to the original sumcheck claim;
> neither retaining the unshifted check nor accepting an unrelated shifted value
> implements the original statement. Include every correction in the joint view.
> A bounded-query randomized code must account for all queries to its fixed
> oracle over the passport's lifetime, including registration certificates.
> New challenges or proof digests do not refresh that oracle's hidden entropy.
> Changes to the root/masks require an authenticated lifecycle and cost contract.
> Actual protocol tests must reject omitted masking/binding and exercise reuse;
> whole-proof digest inequality alone is not evidence of mask independence.

Before acceptance, supply the complete sumcheck/PCS/private-final-claim protocol,
transcript order, simulator, source bindings and privacy construction for
Circle and expander paths, with native CPU/Python/GPU evidence as applicable.
The full <=5% overhead and one-weight-pass requirements remain; no unmeasured
claim, relaxed profile or substitute smaller workload satisfies them. NC-0604
and NC-0900/0901 remain actual consumer controls, not research credit.

Soundness impact: no production challenge, label, loss or admission change.
Future losses need explicit derivation and accounting; the existing MASK row is
not a completed privacy proof. Cost impact: randomization/encoding, full joint
opening work, repeated-use state and c_c/T_misc/registration costs; no constant
or benchmark changes. Affected tasks: E4-05 and E12-01 are blocked on this
contract, with E4-03/E4-06/E10/E12 passport and inference consumers also affected.

### A2 — Conditional hiding sources and masked A1 sumcheck (development components)

Status: Accepted, conditional scope only. Question Q29. Task E12-11.
Evidence: [design note](../../formal/zk-development.md) §§3–4 and
`crates/stele-code/tests/hiding.rs`. Companions: RFC-0010 A15 (source bytes and
leaves) and RFC-0012 A18 (labels). Review:
[same-author passes](../../agents/reviews/rfc0013-a2-acceptance.md). Decision: ADR-094.

Motivation: A1 asks for the complete construction (Circle and expander paths,
the 5% overhead target, native evidence). Two of its components are fully
specified and proved on their own, and can be built and tested now. A2 admits
those two components, in the way RFC-0010 A9 admitted a conditional field
source. A2 does not make any proof zero-knowledge, admits no profile, adds no
consumer, and changes no Accepted text of §§1–6. A1 stays Draft.

**1. Hiding source.** A hiding source commits a secret M31 matrix `X`
(`R = 2^ell` rows, `C = 2^m` columns) as the message
`M' = [X | Rm ; S0 | S1]` of `2R` rows and `2C` columns, with the bytes,
code, leaves and admission of RFC-0010 A15. `Rm`, `S0`, `S1` and the leaf salts
are the **masks** of the source. The certificate and the opening are RFC-0010
A9 §§3–4 on `M'`, unchanged; an opened value is a functional of `M'`, not of
`X`.

- **Masks.** The prover derives them from a 32-byte secret seed `σ`, drawn
  fresh for each source and never reused, with the stream
  `XOF(σ, ctx) = BLAKE3-keyed(key = σ).update(ctx).finalize_xof()`. Mask
  elements read the stream for
  `ctx = ASCII(stele/v0.1/zk/source-mask) || u64le(id)` as consecutive u32le
  words `w`, keeping `w & 0x7fffffff` unless it equals `p`. They are taken in
  this order: `Rm` row-major (`R × C`), then the mask rows row-major
  (`R × 2C`, `S0 | S1` per row). Salts are consecutive 32-byte blocks of the
  stream for `ctx = ASCII(stele/v0.1/zk/source-salt) || u64le(id)`, one per
  codeword position, in position order.
- **Rank check.** Let `Λ` be the M31 matrix whose rows are the M31 coordinates
  of the mask-row parts (rows `R..2R`) of every row-coefficient vector the
  source has revealed: the certificate's `a`, then each opening's `a`. Before
  sending a row message, the prover requires `rank Λ = D·(messages so far)`,
  with `D` the degree of `K`. Otherwise it aborts with `MaskRank` and sends
  nothing more. The abort depends on public challenges only.
- **Lifetime.** One certificate and at most one opening per seed. The producer
  counts openings of a prepared hiding source, through any opening path, and
  refuses a second one with `MaskBudget` (a third revealed row combination would
  leave `rank Λ` short and exceed the query budget). Weight sources, repeated
  openings and any reuse of `σ` are not admitted.
- **Privacy (conditional).** Lemmas 1–3 of the design note: for uniform masks,
  an honest verifier, `q_c + q_o ≤ C − 1` and no abort, the source's algebraic
  view (certificate row, opening row, every queried column) has the same
  distribution for every `X`. Roots and paths are simulatable from the opened
  payloads except with probability `N·q_H/2^256` in the random-oracle model.
  With derived masks the statement is computational, under the assumption
  that the keyed BLAKE3 stream is a pseudorandom function.

**2. Masked A1 sumcheck.** For an RFC-0006 A1 instance with claim `H`,
`n ≥ 1` variables, degree `δ ≥ 1` and input count `k`:

1. Absorb the instance exactly as A1 does (`Instance`).
2. The prover holds the mask polynomial `g = Σ_{i=1}^n g_i(X_i)`, each `g_i`
   given by its `δ + 1` values at `0..δ`, uniform over `K`, derived from a
   fresh seed with `ctx = ASCII(stele/v0.1/zk/sumcheck-mask) || u64le(id)`
   (each `K` value is `D` M31 elements in limb order, sampled as in item 1,
   with `g_1` first and nodes in ascending order).
   It sends `G = 2^{n−1}·Σ_i (g_i(0) + g_i(1))`. Absorb
   `message_bytes(id, 0, [G])` under `zk/mask-sum`.
3. Draw `α` under `zk/mask-weight`.
4. Run the A1 rounds with running claim `H + α·G`. Round `i` (1-indexed) sends
   `p_i(t) = f_i(t) + α·Γ_i(t)` at `t = 0..δ`, where `f_i` is the A1 round
   polynomial of the instance and
   `Γ_i(t) = 2^{n−i}(g_i(t) + Σ_{j<i} g_j(ρ_j)) + 2^{n−i−1}·Σ_{j>i}(g_j(0) + g_j(1))`.
   Round checks, labels and challenges are A1's.
5. The prover sends the `k` final values and `μ = g(ρ) = Σ_i g_i(ρ_i)`. The
   verifier requires `P(finals) + α·μ` to equal the running claim
   (`FinalEvaluationMismatch`), then absorbs
   `message_bytes(id, k + 1, finals ‖ μ)` under A1's `Final` label.
6. The result is A1's reduction plus the **mask obligation** `(ρ, μ)`.

Soundness: the SC line is A1's `n·δ/|K|`, unchanged. `α` adds the MASK line
`1/|K|` per masked instance. Both hold only if `μ = g(ρ)` for a `g` bound
before `G` is absorbed. A2 supplies no such binding (design note R2), so no
consumer may accept a masked reduction yet: the mask obligation is an
undischarged claim, like every A1 final value.

Privacy (conditional): Lemma 4 of the design note. For `α ≠ 0` and an honest
verifier, `(G, p_1..p_n, μ)` is simulatable from the final values alone. The
event `α = 0` (probability `1/|K|`) is a privacy error, not a soundness term.
The final values themselves are not hidden.

**Relation to A3 (Draft, commitment scheme v3).** A3's candidate A states that it
starts from A2 if A2 is accepted first. A2 is the development-tier instance of
candidate A's items 1–3, on RFC-0010 version-1 Circle sources (rows in evaluation
form).

- **Item 1, the encoding.** A2 places the randomisers on evaluation points of
  the message domain (the mask half). It does not place them in coefficient
  slots. Lemma 1 proves full rank for every set of at most `C − 1` positions.
  This avoids A3's mirror-position counterexample, which arises for adjacent
  coefficient slots.
- **Item 2, the mask rows.** A2's mask rows with the producer rank check are
  item 2 for one fold level.
- **Item 3, the sumcheck masks.** A2's masked sumcheck is item 3 before its
  binding.
- **What changes under scheme v3.** Coefficient-form rows and recursive levels
  (RFC-0029) need Lemma 1 restated for the coefficient basis. That is task
  E23-01. A2 claims nothing for scheme v3.

**3. Not covered.** Composition into any proof, masked claims, zerocheck
(RFC-0006 A3), LogUp, matmul, claim batching, Fiat–Shamir zero-knowledge,
weight lifetimes, expander sources, cost and profile admission. These are
items R1–R13 of the design note and remain A1's open contract; NC-0604 and
NC-0900/0901 stay `todo`.

Controls reserved: NC-0902..0906 (catalog). Cost-model terms: none move; a
hiding source encodes and hashes four times its data, and a masked instance
adds two `K` values. Affected tasks: E12-12 (hiding source), E12-13 (masked
sumcheck), E12-14 (composition, blocked on A1).
### A3 — Bounded-query encodings and committed masks on commitment scheme v3

Status: Draft. Questions Q29, Q40. Depends on RFC-0029. Tasks: E23-01..E23-04.
A2 is not used here: it is reserved by task E12-11 (hiding Circle sources and a masked
sumcheck for the development path), which is under review. If that work is Accepted
first, candidate A below starts from it and this amendment keeps only what commitment
scheme v3 adds.
Motivation: A1 states what a construction must provide and names none. Two
published constructions fit a hash-only, sumcheck-based prover, and one of them has a
machine-checked precedent for single proofs (FlashProve; ePrint 2026/391).

Proposed construction (candidate A), replacing §3 on acceptance:

> 1. **Encoding.** Every committed row carries `t` uniformly random coefficients
>    beside its message (RFC-0029 §7 reserves the slots). The construction must make
>    every set of positions the verifier can open jointly uniform. That needs the
>    randomiser block of the generator to have full rank on each such set. It is not
>    automatic for the circle code, whose span is not MDS (RFC-0010 A2). Example: two
>    randomisers in coefficient slots `C` and `C+1` use the functions `v_m` and
>    `y·v_m`, both even in `x` for `m ≥ 2`, so the mirror positions `(x, y)` and
>    `(−x, y)` share a randomiser row and their difference reveals the message part.
>    The placement of the randomiser coefficients, the admissible query sets and the
>    rank proof are part of the construction (task E23-01). The plan fixes `t` at
>    least the number of positions of that row opened over the source's lifetime.
> 2. **Row combinations.** Every committed source has mask rows. Each fold `u = aᵀM`
>    includes a fresh mask row with a transcript coefficient, at every level.
> 3. **Sumcheck messages.** Each sumcheck instance adds a committed low-degree mask
>    polynomial to its summand with a transcript coefficient; the mask is opened with
>    the instance's final claims.
> 4. **Evaluation claims** on committed sources are never sent in the clear; they are
>    carried as claims on masked folds.
> 5. **Lifetime.** A model source has an opening budget fixed at registration and a
>    persistent counter. When the budget is spent the provider links a fresh encoding
>    of the same weights to the registered one with a proof of equality.
> 6. **Leak list.** `docs/security/leak-list.md` states everything a proof reveals
>    (shapes, lengths, timing, public outputs, any value outside the masks). A value
>    not on the list and not covered by the simulator is a defect.

Candidate B, kept as the alternative until E23-01 decides: pad every algebraic prover
message with a one-time pad and prove the verifier's algebraic checks on the padded
values in a small zero-knowledge argument (ePrint 2026/683).

Decision criteria for E23-01: prover overhead on L3b, proof bytes, coverage of
batches and segments, interaction with base-field first rounds (Q5), and how directly
the simulator can be stated in Lean.

A1's requirements stand in full: the joint-view simulator, the fixed-oracle query
accounting over the passport's lifetime, NC-0604 and NC-0900/0901 as actual controls.
Soundness impact: MASK records per masked instance (RFC-0012 §4); exact terms with
the construction. Cost impact: `c_c` for the randomisers and mask rows, `c_sc` for
masks; the PRD G6 bound is re-stated as at most 15% at M5 and 5% at M7.
Affected tasks: E23-01..E23-04; E4-05, E12-01 and E12-01a are superseded (RFC-0027 §6).

### A4 — Bound mask polynomial for the masked A1 sumcheck (closes design note R2)

Status: Accepted, conditional scope only. Question Q29. Task E12-15. Numbered A4
because A3 is the Draft scheme-v3 direction (ADR-096); A4 is A3's candidate A
item 3 (committed sumcheck masks, opened with the final claims) made concrete for
the development tier, and does not decide anything for scheme v3.
Evidence: [design note](../../formal/zk-development.md) §4.3 (Lemma 5) and
`crates/stele-reductions/tests/zk.rs`. Companions: RFC-0010 A15 (sources),
RFC-0012 A18 (labels). Review:
[same-author passes](../../agents/reviews/rfc0013-a4-acceptance.md).
Decision: ADR-097.

Motivation: A2's masked sumcheck returns `μ = g(ρ)` with nothing binding `g`
before its sum, so a prover can solve `μ` last and prove a false sum. A2 item 2
admits no consumer for that reason. A sum of univariates is not a tensor
functional, and an opening that sends `g`'s whole coefficient row would expose
the rounds. A4 changes the mask's shape so that one ordinary A9 opening of a
hiding source reveals exactly what the rounds can afford.

Replacement for A2 item 2's mask and order (A2's labels, MASK line and privacy
error are kept):

1. **Mask.** `G(X) = (1 − X_n)·g⁰(X) + X_n·g¹(X)`, with
   `g^b = Σ_{i=1}^n g^b_i(X_i)`, `deg g^b_i ≤ δ` for `i < n` and
   `deg g^b_n ≤ δ − 1`. `G` has degree at most `δ` in every variable. Each
   `g^b_i` is stored by its values at nodes `0..=δ` (`0..δ` for `i = n`), drawn
   from the `zk/sumcheck-mask` stream: block 0 then block 1, variables
   ascending, nodes ascending, each value `D` M31 elements in limb order. The
   canonical column order of a block is the same (variables, then nodes), with
   `n(δ + 1) − 1` columns.
2. **Mask source.** A version-3 hiding source (RFC-0010 A15) with id equal to
   the instance id, `R = 2D` data rows (`ell = log2(2D)`), blowup 2 and the least
   `m ≥ 9` with `2^m ≥ n(δ + 1)`. Data row `b·D + d` holds limb `d` of block `b`
   in canonical column order; every other data entry is zero. Masks and salts
   use A2 item 1's streams on the same seed. The producer marks it a
   **mask source**: its one opening has zero weight on the mask rows; the
   certificate keeps A2's rank check, and the one-opening budget applies.
3. **Order.** On the caller's transcript: absorb the instance (`Instance`);
   absorb the mask source's exact bytes (`FieldSources`, root included);
   absorb `G = Σ_{x ∈ {0,1}^n} G(x)` (`zk/mask-sum`); draw `α`
   (`zk/mask-weight`); run the A1 rounds of `f + α·G` with claim `H + α·G`;
   send the finals and `μ`, check `P(finals) + α·μ`, absorb `finals ‖ μ` at
   index `k + 1` (`Final`). The mask source's A9 certificate is verified on its
   own transcript before its handle is used; the verifier first rebuilds the
   expected version-3 bytes from the instance and requires equality.
4. **Opening.** One A9 functional opening of the mask source on the caller's
   transcript, at value `μ`, with `a_(b·D+d) = ℓ_b(ρ_n)·e_d` (`ℓ_0 = 1 − X`,
   `ℓ_1 = X`, `e_d` the M31 basis of `K`), zero on the mask rows, and
   `b` = the Lagrange weight of each mask column's node at its variable's
   coordinate of `ρ`, zero on every other column. Then `u·b = G(ρ)` exactly.
5. **Producer abort.** The producer aborts with `MaskPoint` when `ρ_n = 0` or
   `2ρ_n = 1`. The event depends on public challenges only.
   A mask source has exactly `2D` data rows. Its producer refuses any opening
   that is not of item 4's shape (`MaskRank`): weights `w_b·e_d` on block `b`,
   zero on the mask rows, `w_0 + w_1 = 1` and `w_1 ∉ {0, 1/2}`.
   **Seed lifetime.** A seed is used once per `(seed, instance id)` across all
   transcripts. Two proofs that share one reveal the opening row at two points,
   which recovers both blocks and the witness rounds. The producer API takes a
   move-only seed that is consumed by one proof. After an abort, retry with a
   fresh seed only if nothing from the attempt was published.
6. **Result.** The verifier returns A1's reduction (finals still obligations)
   and the MASK record; the mask obligation is discharged by the opening.

Soundness: `G` is fixed by the certificate's unique near message before `G` is
absorbed, so A2's MASK line `1/|K|` and A1's SC line hold as stated, plus the
mask source's A9 certificate and one opening term (conditional, as A9). The
quarantine of A2's raw module now admits exactly this consumer.

Privacy (conditional): Lemma 5 of the design note. For an honest verifier, fixed
public challenges with `α ≠ 0`, `ρ_n ∉ {0, 1/2}`, `q_c + q_o ≤ C − 1` and the
certificate's rank check, the joint view (mask source certificate, columns,
salts, opening row, `G`, rounds, `μ`) is the same for any two `f` with the same
claimed sum and the same final values. The final values themselves are not
hidden (R1).

Controls: NC-0907 (another seed's mask source substituted: `α` moves,
`RoundSumMismatch`) and NC-0908 (A2's forgery with a genuine mask opening:
`ValueMismatch`). Cost: one mask source of `4D` rows and `2^(m+1)` columns, its
certificate and one opening per masked instance; no constant moves.
Affected task: E12-15. A1 stays Draft; R1 and R3–R13 remain.

### A5 — Masked claims and the dev-zk composition (closes design-note R1 for the development path)

Status: Accepted, conditional scope only. The dev-zk profile is defined here and
is admitted only once implemented (item 8). E12-14 admits it at the development
tier (ADR-109; see **Admission** at the end of A5). Relation to the Draft A3 (scheme v3,
ADR-096): A5 is A3's candidate A item 4 (evaluation claims never sent in the
clear) and item 6 (a leak list) made concrete for the development tier on
version-1 Circle sources, as A3 anticipates. Under RFC-0028's commit rule (Draft),
claims on virtual columns are intermediate sumcheck claims. They take RFC-0008
A7's per-layer mask blocks (ZK-GKR), not claim masks. A5 decides nothing for scheme
v3 or for the `standard` profile of RFC-0030. Question Q29. Task E12-17.
Evidence: [masked claims note](../../formal/zk-claims.md) (Lemmas 6′ and 7,
abort bounds, census) and the exact small-field checks
`research/zk-claims/check_view.py` and `check_two.py`. Companions: RFC-0026 A9
(relation forms, padding, profile tag) and RFC-0008 A7 (committed-fraction
lookups). Review: [same-author passes](../../agents/reviews/rfc0013-a5-acceptance.md).
Decision: ADR-098.

Motivation: A2/A4 make every masked sumcheck simulatable from its final values,
and every hiding source simulatable from its opened values. The final values
themselves (column evaluations, matmul `out~(ρ)`, lookup layer claims) still
reveal the witness. A4 masks every revealed claim and fixes the composition.

1. **Claim masks.** Every committed column `x` (witness and weight) has a
   **claim mask** `r_x`: `t_x` blocks of `2^{c_D} = D` uniform M31 entries
   (`c_D = log2 D`). It is committed in the same source as `x`, at a plan-fixed
   position, and drawn from A2's `zk/source-mask` stream after that source's
   data masks. `t_x` is the number of masked occurrences of `x` in the proof, in
   plan order. Block `a` serves occurrence `a` only.
2. **Masked occurrence.** Occurrence `a` of `x` in a relation instance chooses:
   - a summed domain variable `v_a`, the vanishing variable;
   - `c_D` other domain variables `u_a`, the mask coordinates.

   Both are plan-fixed; the default is the lowest-index summed variables not
   used by an earlier factor of the same term. The instance runs on
   `V̇_{x,a}(X) = x̃(X|vars_a) + κ(X_{v_a})·r̃_x(a, X_{u_a})`, with
   `κ(t) = t(1 − t)`. The revealed final value is
   `c_a = x̃(ρ|vars_a) + κ(ρ_{v_a})·r̃_x(a, ρ_{u_a})`. Public columns and tables
   are not masked. A domain must have at least `c_D + 1` variables (RFC-0026 A9
   padding).
3. **Degrees.** Each masked factor adds one to the degree of its own vanishing
   variable. The A1 instance's degree bound is the per-variable maximum:
   identities 5, matmul 4, A7 identities 4, A7 sum 2. The SC line uses it.
4. **Producer aborts (all on public challenges).** Before sending any message
   that depends on them, the producer aborts the whole proof:
   - `κ(ρ_{v_a}) = 0`, for any occurrence;
   - **claim-block rank:** the `D` M31 coordinates of `eq(ρ_{u_a}, ·)` have rank
     `< D`;
   - A2's mask-row rank failure;
   - `w* = 0` in a batch;
   - `α = 0` in a masked sumcheck;
   - A4's `ρ_n ∈ {0, 1/2}`.

   A retry redraws every seed, and is allowed only if nothing was published.
   The total abort probability is `≤ Σ_claims (2/|K| + D·c_D/p) +
   Σ_sources 2D·(ell + 1)/p + Σ_instances 3/|K|` (about `2^{−17}` on the census
   windows for QM31).
5. **Batching per source.** After all relation instances, each source with
   claims runs:
   - batch coefficients `γ_a` (`BatchCoefficient`);
   - one A4 bound masked sumcheck of
     `Σ_{w,x} (1 − w)·W(x)·M̃'(w, x) = Σ_a γ_a·c_a`, over the source's row bit
     `w` and its data bits (`Y = 0` face), with `W = Σ γ_a w_a` the claims' data
     weights;
   - one A2 point opening at its final point, whose value times
     `(1 − w*)·W̃(x*)` must equal the instance's final.

   No other batching is used for dev-zk sources.

   5a. **Shared mask source.** One hiding source per proof holds every masked
   sumcheck's mask polynomial `g_j` (a sum of univariates, as `D` limb rows) and
   every RFC-0008 A7 layer block. It is committed and absorbed before the first
   masked instance. Each `μ_j = g_j(ρ_j)` and each block claim is a linear claim
   on it, batched by item 5 and opened once. Only that batch uses an RFC-0013 A4
   two-block mask source, one per proof. This replaces one A4 source per
   instance. Soundness: each `g_j` is bound before its `G_j` is absorbed, and the
   `μ_j` are bound by the batch's RLC. Privacy: Lemma 4 per instance, and
   Lemma 7 for the batch.
6. **Order (dev-zk).** RFC-0026 §4 with A6, as follows:
   1. Statement, including the profile byte.
   2. Every witness and weight source as a hiding source with its claim masks.
      Roots are absorbed and certificates verified.
   3. Multiplicities (A5).
   4. `θ, β, α` (A5), then the A7 fraction sources.
   5. Identities, A7 zerochecks and sums, and matmul zero-sums: each a bound
      masked sumcheck (A4) on the `V̇` of item 2.
   6. Item 5 per source.
7. **Privacy (conditional).** For an honest verifier, uniform masks and no
   abort, the view of a dev-zk proof is simulatable from the public input
   (RFC-0026 §1.1 with the profile byte). The proof is the hybrid argument of
   the note §3 with Lemmas 1–5, 6′ and 7. The statistical error is
   `Σ_sources N·q_H/2^256` (salts, random-oracle model) plus FS programming.
   With seed-derived masks hiding is computational (A2). Weight sources carry a
   lifetime budget, `q_c + P·q_o ≤ C − 1`. A weight's claim mask holds `P·t_W`
   blocks, a fresh set for each proof, in proof order. The prover refuses beyond
   either budget. Declared not hidden: the design note §7
   list, which includes the plan and every shape.
8. **Profile flag.** `dev-zk` is profile byte 1 (RFC-0026 A9). It is
   **defined**, not admitted. No verifier accepts it, and the CLI does not
   offer it, until E12-18, E12-19 and E12-14 deliver the following. They are
   delivered, and E12-14 admits it (ADR-109, **Admission** below):
   - the implementation;
   - NC-0909..0915 executed;
   - the privacy tests on the one- and eight-layer synthetic windows;
   - an independent review.

   The seed for a dev-zk proof is drawn by its CLI or orchestrator entry point
   from the OS RNG (an ADR at that point). The library takes a move-only seed
   (A4).
9. **Cost (projection, not a measurement).** On the eight-layer synthetic
   window (`T = 64`, census): 4868 committed columns with 1.6·10^7 entries,
   11 547 claims, 21 lookup checks and 570 tree layers. The projected dev-zk
   commitment is about
   - `4 × 1.6·10^7` for the hiding witness and weight sources;
   - `4 × (4.6·10^4 + 1.05·10^5 + ...)` for the claim masks, the ZK-GKR layer
     masks and blocks, and the shared mask source's sumcheck masks.

   That is about `6.5·10^7` M31 message entries against `1.6·10^7` today,
   roughly 4 times (formal/zk-gkr.md §3; the committed-fraction route would be
   about 20 times). For stories42M
   (`d = 512`, 8 layers, 8 heads, `T = 64`), claims depend on layers and heads
   only, so the projection is about `1.2–2.3·10^4`. The entry counts scale with
   the widths and need the converted checkpoint for a census. No ledger
   constant moves.
10. **Controls.** Reserved as `todo`, each through the actual dev-zk verifier:

| NC | Tamper | Expected rejection |
|---|---|---|
| NC-0909 | one masked claim value changed in an honest proof | `RoundSumMismatch` (the batch) |
| NC-0910 | a matmul claimed through a sent `out~(ρ)` instead of the zero-sum | `ProofShape` |
| NC-0911 | one claim-mask block of a source changed after its commitment | `RootMismatch` |
| NC-0912 | profile byte flipped between development and dev-zk | `StatementMismatch` |
| NC-0913 | RFC-0008 A7 masked layer value changed | `RoundSumMismatch` |
| NC-0914 | RFC-0008 A7 layer mask-block entry changed after commitment | `RootMismatch` |
| NC-0915 | batch weight on the `w = 1` half made nonzero | `FinalEvaluationMismatch` |

Soundness impact: the SC degrees of item 3; RFC-0008 A7's lines; A4's MASK and
PCS terms per instance and per source. No new label. A1 stays Draft for the
standard and treaty profiles: expander sources, the 5% target and GPU parity.
Affected tasks: E12-18, E12-19, E12-14.

**Implementation notes (E12-18, ADR-099).** They make three points exact that the
items above leave open. None changes a label, a loss or an order.
- **Declared degree.** Item 3's degree is the masked instance's degree
  everywhere: the round length, the SC record, and the degree byte of the
  absorbed A1 `Instance` encoding. The verifier derives it from the plan and
  rejects a degree below the factor count.
- **Shared mask source contents.** Item 5a's `g_j` is A2 item 2's plain sum of
  univariates. Each `g_i` is stored by its `δ + 1` values at `0..δ`, drawn from
  the `zk/sumcheck-mask` stream under the instance id. `μ_j = g_j(ρ_j)` is the
  linear claim with weight `e_d·L_c(ρ_i)` on limb `d` of column `c`. The batches of
  item 5 are masked instances too, so their `g_j` are in the shared source. The
  shared source's own batch takes the A4 two-block source. Its id is distinct from
  every source and instance id of the proof, so each mask stream is used once.
- **Item 4's `α = 0`** is a producer abort of every masked sumcheck, including
  A4's (`MaskWeight`).
- **Item 2's default** must find a fresh vanishing variable for every
  occurrence. A statement that leaves none is refused (`Statement`); the
  variable is never silently shared.
- **Item 3's matmul degree** is 4 with the `eq(ρ_shared, ·)` factor of RFC-0026
  A9, and 3 for a matmul without shared bits, which is the form E12-18 builds.
- **NC-0916** (added): A4's NC-0908 attack on a composed relation over honest
  sources. The rounds are free, `μ` is solved last and the finals are true. Only
  binding each relation's `μ_j` in the shared batch rejects it
  (`RoundSumMismatch`).

**Implementation notes (E12-14a, ADR-101; development tier, pending independent
review).** These state how `stele_reductions::zk::relation` derives one claims
statement from a validated RFC-0026 relation. No label, loss form or order item
changes. Item 8 still holds: dev-zk is not admitted.
- **Sources.** Source 0 holds every witness column in `ColumnId` order, then each
  check's multiplicities. Source 1 holds every weight column. Its root is the
  dev-zk model commitment (item 7 with `P = 1`): the weights and their claim masks
  are committed from the proof's seed, for one proof. Public columns are never
  committed. The verifier evaluates each public operand's final at its column
  point (`ClaimMismatch`).
- **Identities.** There is one instance per domain size, increasing. It covers
  that size's identities in relation order, then its `Compose` identities.
  `relation/identity` coefficients are drawn before `τ`. Each distinct
  `(column, vars)` read is one masked occurrence (item 2).
- **Matmuls.** The A9 zero-sum runs over the shared free variables (under
  `eq(ρ_shared, ·)`), the summed variables and padding. Free variables not shared
  are fixed at `ρ`. A6 fixed bits are Boolean coordinates of the occurrence.
- **Checks.** RFC-0008 A7's implementation notes (E12-14a).
- **Controls.**
  - NC-0920..0926 are false witnesses. The adversary (`zk::relation::forge`, under
    the `controls` feature) sends the false relation's honest rounds and the true
    `μ`, without the producer's own round-sum check. That relation's first round
    rejects it.
  - NC-0928 and NC-0929 substitute one public column (`zk::relation::forge_substituted`).
    The verifier's own evaluation of that final rejects it.
  - Each control accepts the same adversary on the honest witness (mutation M0).
    Each one goes red, with the false proof accepted, when its own check is removed.
  - NC-0930..0932 are `todo` until a substitution adversary keeps the A5 statement
    message.

**Implementation notes (E12-14b, ADR-102; development tier, pending independent
review).** These wire dev-zk through the development orchestrator and the CLI.
- **Profile byte.** A dev-zk public input is the development public input followed by
  the byte `1` (RFC-0026 A9). A development public input keeps its pre-A9 bytes, with
  the byte implied `0`, so development proofs are unchanged. The verifier reads the
  profile from the public file (`stele-dev-zk-public-v1`). The transcript binds the
  public input. The container header (`stele-dev-zk-v1`, with the `cqis_id` and the
  statement digest) fails fast (NC-0912).
- **Seed.** `stele prove-dev --zk` draws the 32-byte seed from the OS RNG
  (`/dev/urandom`). The library takes it move-only, for one proof.
- **Model commitment and claim.** It is one root, the proof's hiding weight source
  (item 7 with `P = 1`). Its certificate travels in the proof. The verifier checks
  the proof's weight source against the public root (NC-0927). The root comes from
  the proof's own seed, so no published commitment pins the weights.
  - A dev-zk proof states only that *some int8 weights of the declared shape*,
    with the public 1-D records, produce the statement. It does not state that a
    named model ran.
  - `verify-dev` prints `weights: unbound (per-proof commitment)` in place of the
    model digest. `--expect-model` is a usage error.
  - E12-25 (a persistent hiding commitment with item 7's `P·t_W` budget and a
    lifetime counter) gates admission.
- **Not hidden.** Besides the design note's §7 list, every 1-D record (norm gains
  and other vectors) is public input. E12-25 commits them.
- **Verifier output.** dev-zk verify reports counts of instances, steps and
  batches. It does not report an RFC-0026 §6 soundness ledger; E12-26 adds one.
- **Item 8 deliverables.** These are present:
  - the implementation (E12-18, E12-19, E12-14a, E12-14b);
  - NC-0909..0915, executed;
  - on the one-layer window (`T = 4`): an exact test that no revealed occurrence
    final equals its bare `x̃(ρ)`, and two witnesses of one statement (a moved Q
    weight code, the same tokens and `y`) with equal byte lengths and
    χ²-homogeneous revealed values; the exact test on the eight-layer window runs
    ignored, locally;
  - the privacy tests on small relations:
    - χ² uniformity of revealed values across seeds;
    - the leak control: without masks, a claim equals `ã(ρ)` and tells two witnesses
      apart;
    - two witnesses of one statement, with equal byte lengths and χ²-homogeneous
      revealed values.
  - The one- and eight-layer synthetic windows prove and verify under dev-zk.

  The independent review (fix-then-merge) did not admit dev-zk (profile byte 1).
  Item 8's "defined, not admitted" stands until E12-25 binds the model and a
  further review admits it (superseded by the Admission paragraph in this section). The CLI prints the profile; it makes no privacy claim.

**Admission (E12-14, ADR-109; development tier).** dev-zk, profile byte 1, is
admitted at the development tier. The independent review of the admission change
decides it; ADR-109 records the outcome.
- **What it rests on.**
  - Item 8's deliverables (above).
  - A6 (Accepted): one published model commitment for `P` proofs, with the lifetime
    counter and `--expect-model`.
  - A7 (Accepted): the 1-D records are committed weights with their encoding proof.
  - Controls NC-0909..0915 and NC-0933..0938, executed. NC-0930..0932 are `todo`
    (they await a substitution adversary) and are listed below as open.
  - The ignored eight-layer tests, run at the admission head with A7 in place:
    the dev-zk window, the claim census, and the exact bare-evaluation privacy
    test.
  - The eight-layer window proved under dev-zk against a published commitment, both
    proofs verified, and a pinned other model refused
    (`bench/ledger/e12-14-synthetic-8layer-zk-admission-mac.json`).
- **What it claims.** For a statement `(Model bytes, plan, T, tokens, [r, e), y)`,
  the proof shows that some weights and gains under the published commitment yield
  `y`, and it reveals nothing more about them than the design note's §7 list
  (as amended by A6 and A7). The claim holds under the masked-claims note's lemmas, with
  seed-derived masks (computational, A2) and the `P`-proof lifetime (A6).
- **What it does not claim.**
  - A security level. The development tier has none: FS is unproven, the PCS is
    conjectural (RFC-0026 §6).
  - Hiding beyond `P` proofs, or after a reused proof index (A6 item 5).
  - A soundness ledger for dev-zk; `verify-dev` reports counts (E12-26).
  - Anything for the `standard` profile or scheme v3 (A3, Draft).
  - A real checkpoint. The evidence covers the synthetic one- and eight-layer
    windows only; no real model has been proved under dev-zk.
  - Executed controls for the member weight, `eq·Z` and shared-bit finals
    (NC-0930..0932, `todo`). Their checks exist in the verifier, but no control
    yet shows that removing one is caught.
- **CLI.** `prove-dev --zk`, `commit-model --zk` and `verify-dev` keep their
  behaviour. `verify-dev` prints `profile dev-zk`.

### A6 — Lifetime hiding weight source for dev-zk (P proofs against one published commitment)

Status: **Accepted** (development tier, Workflow 02 development-tier path).
Independent review, two rounds: fix-then-merge on the first, then MERGE with
"accept A6: yes" on the second. The reviewer confirmed the `P + 1` extension by an
exact `F_61²` check and spot-checked the mutations. Task: E12-25. Decision: ADR-104.
dev-zk stays not admitted until E12-27 commits the 1-D records (A5 item 8). E12-14
admits it after E12-27 (ADR-109).
It amends A2 item 1's lifetime ("at most one opening per seed … weight sources,
repeated openings and any reuse of `σ` are not admitted") and A5 item 7's
`P`-proof budget. It applies only to dev-zk weight sources.

Motivation: with E12-14's `P = 1`, every dev-zk proof made its own weight
commitment, so a proof bound no published model (review F1). A model owner must be
able to publish one commitment and prove up to `P` windows against it, each proof
hiding the weights.

1. **Commitment.** The weight source is committed once from a secret model seed
   `σ_M` (RFC-0010 A15 bytes, A2's masks and salts from `σ_M`). Its weight columns
   reserve `P·t_x` claim-mask blocks each, where `t_x` is the column's masked
   occurrences per proof, counted on a reference window. The published commitment
   is the root, `P`, every `t_x` and the reference length. A proof whose window
   needs more than `t_x` blocks for a column is refused (`Statement`).
2. **Admission.** The source needs `R ≥ max(2D, (P + 1)·D)` data rows and
   `q_c + P·q_o ≤ C − 1` (`Source::admits_lifetime`). The verifier rejects a
   source that does not admit `P` (`MaskSource`).
3. **Proof `j`.** Proof `j < P` opens the source once, in its own A5 batch, and
   uses blocks `j·t_x .. (j + 1)·t_x` of every weight column. Every other source
   and mask comes from the proof's own fresh seed, as in A5. The public input
   carries `j`, after the profile byte, and then the commitment bytes.
4. **Rank across the lifetime.** Before each opening, the producer checks A2's
   rank condition. It covers the certificate's row vector and every earlier
   opening's row vector of this source, in index order, and fails with
   `MaskRank`. The owner keeps those vectors with the counter.
   - The certificate bytes are identical in every proof, so they add no row.
   - The index reveals proof order.
   - Owners should commit at the largest `T` they will prove, since `t_x` is
     counted on that reference window.
5. **Counter.** The owner's state is `σ_M`, the next index and the revealed row
   vectors. It is persisted before each proof starts. The producer refuses
   `j ≥ P`, and any index whose earlier openings are missing from the state
   (`MaskBudget`). It also refuses, before any transcript work, a rebuilt source
   whose root differs from the published one (`RootMismatch`): other weights `X′`
   under the same masks would leak `(X − X′)·G` on the shared queried columns.
   Inputs are read and validated before the index is taken. A failed proof
   restores the prior state, which is safe because no proof bytes left the
   producer.

   **Index reuse.** A restored or forked state that reuses an index is the
   owner's duty, as in A5 item 7. It leaks the following:
   - **Claim blocks.** Two proofs share each claim-mask block of that index. Each
     shared block whose finals both proofs reveal gives `D` M31 linear equations
     on the weights, so up to `D·Σ_x t_x` equations per reused index.
   - **Rank.** The forked state misses the other opening's row from its rank
     check. `r` reuses break PCS hiding once `(P + 1 + r)·D > R`. Below that
     bound, hiding holds only with high probability, through the rank check.
   - **Queries.** The extra queries can break PCS hiding once the union of queried
     columns reaches `C`, and always break it at `C + 1`.
   - **Detection.** Reuse is publicly detectable afterwards: two proofs carry the
     same root and the same index.
6. **Privacy (conditional, to be reviewed).** The source's view across its
   lifetime is one certificate row, `P` opening rows and at most `q_c + P·q_o`
   queried columns. Every claim on a weight column uses its own block, never
   reused across proofs. Under item 4's rank condition and item 2's query bound,
   A2 Lemmas 1–3 apply to that whole view, as they do to one opening when
   `R ≥ 2D`. With the A5 claim-mask argument per block, the `P` proofs together
   are simulatable from their public inputs.

   The design note's §7 gains the item that proofs under one commitment are
   linkable: they share its root. The argument extends A2's lemmas from two
   revealed rows to `P + 1`. That extension is the text this amendment asks the
   independent review to check.
7. **Not changed.** No label, loss or order of A5 changes. The certificate is
   the same bytes in every proof. Each proof carries it again.

Controls:
- NC-0933: a proof against another commitment of the same weights.
  - The header half expects `StatementMismatch`; the pinned digests differ.
  - The transcript half expects `RootMismatch`: an adversary with A's secret,
    under B's public input and header.
- NC-0934: the lifetime counter, expecting `MaskBudget`.

Evidence: `research/zk-claims/check_lifetime.py` (the independent review's exact
`F_61²` check). Within budget the weights stay hidden. Index reuse, an opening
past the rank budget, and `C + 1` queries expose them. The 1-D records stay public input until E12-27 commits them
(A7).

### A7 — Committed 1-D records for dev-zk (the gains as weights with a CQIS encoding proof)

Status: **Accepted** (development tier, Workflow 02 development-tier path).
Independent review of #346: fix-then-merge, with the encoding relations complete
and unique, the binding correct and the full width necessary (int16 is fixed); F1
to F3 applied. Task: E12-27. Decision: ADR-107.

Motivation: under A5/A6 the 1-D records (the RMSNorm gains, RFC-0026 A2) are public
input, so a dev-zk proof hides the matrices but not the norm gains (review F2 of
E12-14b).

1. **Columns.** Under dev-zk, each RMSNorm's gain-derived columns are weight
   columns of the lifetime source (A6):
   - `H0`, the low byte of the int16 gain `h`, unsigned 8;
   - `H1`, its high byte, signed 8;
   - `σH = [h < 0]`, unsigned 1;
   - `flipH = 1 − 2σH`, signed 2.

   The plan declares them at these fixed widths (`RmsNormPlan::fixed_widths`), so
   the relation and its static bounds (RFC-0026 §3.6) depend on no gain value. The
   development profile keeps its value-derived widths, and its proof bytes are
   unchanged.
2. **Encoding relations.** Per group, `commit_records` adds:
   - ranges `H0 ∈ [0, 256)`, `H1 ∈ [−128, 128)`, `σH ∈ {0, 1}`, `flipH ∈ [−2, 2)`;
   - a weight column `H1low ∈ [0, 128)` with the identity
     `H1low − H1 − 128·σH = 0`, so `σH` is `H1`'s two's-complement sign;
   - the identity `flipH − 1 + 2σH = 0`;
   - `x·(1 − gainvalid) = 0` for `H0`, `H1` and `σH`, where `gainvalid` is the
     public mask `[k < d]` of the model width `d`, so padding gains are zero.

   Together these make each group the encoding `h = H0 + 256·H1` of one int16 gain
   with its sign and flip.
3. **Public input.** The 1-D records in a dev-zk public input are replaced by the
   fixed pattern `min, max, −1, 0, …` of each record's format; lengths are kept.
   The verifier derives the relation from it. The prover derives the same relation
   from the real gains, and it refuses a window whose committed relation differs
   from the verifier's. The `--expect-model` digest hashes this pattern, not the
   gains; the gains are bound only through the commitment root. A model commitment
   made before E12-27 does not fit the new relation (its weight columns lack the
   gain groups), so such a model must be committed again.
4. **Not hidden.** The record lengths and formats, and that the norms have
   gains. The values are hidden as weights under A6.
5. **Cost.** The full-width gain columns enlarge some carries' static bounds (wider
   range checks), measured on the eight-layer window by the admission ledger.

Controls:
- NC-0935: a flipH inconsistent with σH.
- NC-0936: σH set on a non-negative H1. The sign identity is kept, so the 7-bit
  range of `H1low` rejects it.
- NC-0937: a nonzero gain past `d`.
- NC-0938: σH = 1 and flipH = −1 on a non-negative gain with `H1low = H1`, so the
  ranges and the flip identity hold and only the sign identity rejects it (review F1).

Each control uses the unchecked adversary, expects `RoundSumMismatch`, and passes
on the honest encoding (M0). Removing the flip identity, widening `H1low` to 8 bits,
removing the padding identity, or removing the sign identity turns exactly NC-0935,
NC-0936, NC-0937 or NC-0938 red, with the false encoding accepted.

### A8 — dev-zk on balanced Policy 2 hiding sources (profile byte 4)

Status: Accepted (development tier, Workflow 02 development-tier path) with ADR-114 after
independent review: final review with the implementation FIX-THEN-MERGE, all fixes applied
at 02008a0. Task: E12-28. Decision:
ADR-114. Design note: [dev-zk sources](../../formal/zk-sources.md). Independent review
of the first draft (2e56537): accept with fixes, applied here; final review with the
implementation. Companion: an RFC-0026 A9 tag value, written into RFC-0026 with the
implementation, after RFC-0026 A12 (byte 3).

Motivation: the eight-layer dev-zk proof is 141.7 MB (E16-24 ledger
`e16-24-dev-zk-synthetic-8layer-mac-after`). 95% of it is two combined rows of the
witness source. That source has A5's least row count (`R = 2D`, `ell = 3`) and `2^21`
data columns. Every dev-zk source is already an RFC-0010 A15 Circle source at rate 1/4;
the sources use RFC-0010 A3 Policy 1.

1. **Profile byte 4.** RFC-0026 A9's profile tag gains the value 4: "dev-zk proof on A8
   sources".
   - Byte 1 (A5, A6, A7) is unchanged and its proofs still verify.
   - The byte-4 public file is `stele-dev-zk-public-v2`.
   - The model commitment file is `stele-dev-zk-model-v2` and the secret state file
     `stele-dev-zk-model-secret-v2`; both record the profile byte. `verify-dev`
     rejects a commitment of the other byte (`StatementMismatch`).
   - A byte-4 model commitment draws a fresh `σ_M`. A byte-1 secret state is never
     used to build a byte-4 source: the producer refuses a secret file whose byte is
     not the proof's. The mask stream contexts carry no byte and no geometry, so
     reusing `σ_M` across bytes would reuse masks under a different geometry.
2. **Balanced geometry.** Under byte 4 each claim source of `2^S` data entries takes
   the `ell` that minimises `(1 + J)·16·2C + (q_c + J·q_o)·(8R + 32·log2 N + 32)`
   (`R = 2^ell`, `C = 2^(S−ell)`, `N = 8C`, `J = 1`), ties to the smallest `ell`.
   - The rule applies subject to A2's `R ≥ 2D` and `q_c + q_o ≤ C − 1`, and for the
     lifetime source A6's `R ≥ (P + 1)·D` and `q_c + P·q_o ≤ C − 1`.
   - If no `ell` is admissible, commit and plan refuse with `Statement`.
   - The verifier derives every `ell` from the statement.
   - **Claim sources** pack their columns and blocks as under byte 1, as one linear
     sequence of data positions. A claim is a dense linear functional over those
     positions (A5 item 5's weight table and batch), so no alignment to a row is
     needed at any `ell`.
   - **The shared source** is a claim source under this item. Its data face is one
     linear sequence of `R·C` positions. Limb `d` of the plain masks occupies
     `[d·L, (d + 1)·L)`, where `L` is the total plain-mask width (relations, GKR
     steps, batches, in order). The `4D`-entry layer blocks follow from position
     `D·L`. Byte 1 keeps `L = C` (limb `d` in data row `d`, blocks from row `D`).
   - The A4 mask source keeps `R = 2D`.
3. **Policy 2.** Every byte-4 source carries RFC-0010 A14 policy byte 2: item 2's
   counts, item 3's 16-bit column grinding and item 4's tensor grinding, with item 8's
   errors.
   - They are resolved as the development profile (`proven: false`), as RFC-0026
     A11 item 3 does.
   - `k_t` uses the source's row exponent `ell + 1` (RFC-0010 A15 item 1) in A14
     item 4. For example, `k_t = 5` at `ell = 9`.
4. **Least nonce.** The producer's grinding nonces are the least passing nonce on the
   transcript state (`Transcript::grind`). No nonce depends on a mask, a seed or `X`.
   Every producer grinder, including any parallel or GPU one, returns the least
   passing nonce. A grinder that returns another valid nonce is non-conformant even
   though it verifies.
5. **Hiding.** A2's Lemmas 1–3 apply with the item 2 constraints
   ([design note §3](../../formal/zk-sources.md)).
   - Grinding nonces are functions of the public prefix (item 4).
   - The column draws that follow them are too, and Lemmas 1–2 hold for every fixed
     query set within the budget.
   - So the statement stays A2's: conditional and computational.
6. **No level is claimed.** As RFC-0026 A11 item 4: each grinded PCS round is
   `≤ 2^-108` instead of `≤ 2^-130`, and the development tier claims no λ.
7. **Superseded Accepted text (development tier only).**
   - RFC-0010 A15 item 2, "with `q_c`, `q_o` from A9's tables at `(m + 1, b)`",
     reads "with `q_c`, `q_o` from the source's policy tables at `(m + 1, b)`: A9's
     for policy 1, A14 item 2's for policy 2 (RFC-0013 A8)".
   - RFC-0010 A14 item 1, as amended by RFC-0026 A11 item 5, reads "may use policy 1
     or, under RFC-0026 A11 or RFC-0013 A8, policy 2 without any profile claim".
   - RFC-0026 A11 item 4's sentence "The development path reaches Policy 2 only
     through `Source::from_code_id_development` and
     `PreparedSource::from_code_id_development`, which resolve `Development`" gains
     "and the RFC-0013 A8 hiding-source constructors, which resolve `Development`".

Soundness: the new rounds are A14's grinding rounds on each byte-4 source: one PoW frame
per certificate and opening column round, and one per certificate tensor round with
`k_t ≥ 1`, counted by RFC-0012 A17 Theorem 1. Each such PCS round is `≤ 2^-108` (A14
item 5) instead of Policy 1's `≤ 2^-130`. No challenge or label is added; nothing is
summed into a level. Byte 1 is unchanged.

Cells, lookups, bytes: cells and lookups unchanged. Bytes were projected at about 6.6 MB
for the eight-layer window, against 141.7 MB (design note §2). E12-28 measures 6,421,222
bytes (ledger `e12-28-dev-zk-synthetic-8layer-mac`).

Controls (done, E12-28):
- NC-0939: one byte of a hiding source's column nonce changed (`GrindMismatch`).
- NC-0940: a byte-1 model commitment under a byte-4 proof (`StatementMismatch`).
- NC-0941: a byte-4 proof verified as byte 1 (`StatementMismatch`).

Producer-side tests, not controls:
- a byte-1 secret file refused for byte 4;
- each grinder's nonce equal to the recomputed least nonce;
- the claim and shared layouts at `ell ∈ {3, 7, 9}`.

Affected tasks: E12-28. Promotion to `standard`: not granted (Workflow 10).
