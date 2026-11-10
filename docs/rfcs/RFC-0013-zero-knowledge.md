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
