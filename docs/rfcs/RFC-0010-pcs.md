# RFC-0010 — Interleaved-code PCS, fused opening, certified commitments

Status: Accepted · Version: 0.1.0 · Depends: RFC-0003, RFC-0012

## 1. Object
A multilinear `f` over `N = R·C` evaluations arranged as an `R × C` matrix `M` (rows = the variables folded by the
row functional, columns = the rest). Commitment: encode every row with a linear code `Enc: F^C → F^{C'}` (rate `ρ`),
Merkle-commit the `C'` columns (leaf = one column of `R` elements, domain-separated), publish the root.

## 2. Supported functionals (what an "opening" proves)
`⟨a ⊗ b, f⟩ = aᵀ M b` for verifier-computable `a ∈ K^R`, `b ∈ K^C`. Point evaluation is `a = eq(·, r_row)`, `b = eq(·, r_col)`;
batched claims on committed tensors (RFC-0007 §4) use `a = Σ_t γ_t eq(ℓ_t,·)⊗eq(…)`. Prover sends `u = aᵀ M ∈ K^C`
(or commits to it in Ligerito mode §7); verifier checks `u·b = v` and, for `q` fresh random columns `c`,
`Enc(u)[c] = Σ_r a_r·Enc(M)[r,c]` using the opened columns and Merkle paths.

## 3. Codes
| Use | Code | Why |
|---|---|---|
| Weights (one-time, RFC-0011) | Reed–Solomon over the circle group of M31 (circle FFT), rate 1/4 (treaty) or 1/2 | smallest proof, proven proximity gaps up to Johnson bound; encoding cost is paid once per model |
| Residual cuts, multiplicities, aux (per proof) | linear-time RAA/expander code (Brakedown/Blaze/Bolt family) over M31, rate 1/2–1/4 | no FFT; encoding ≈ 10–20 adds per element on GPU; proximity via Khatam/Brakedown bounds |
| Wrapper (RFC-0016) | whatever the wrapper's prover prefers | out of the hot path |
A code is a `trait Code { fn encode(row) ; fn eval_row(u, cols) ; fn params() -> ProximityParams }`; parameters
(distance, proven gap, query count for each profile) live in `codes.toml` and in the soundness ledger.

## 4. Layouts
- `R_stack(ℓ, i, k)`: rows = `(ℓ, i)` (so per-layer and per-position functionals are row combinations), columns = `k` (d).
  Column length `n·(L+1)` can be large (≈ 6·10⁵ for 405B/4608) ⇒ use Ligerito mode or a row split `(i_hi)` into columns.
- `W_τ(ℓ, k, j)`: rows = `j` (the dimension folded by `eq(·, r_j)` in the phase sumcheck), columns = `(ℓ, k)`; column
  length `d_out` (16 384 for Q). Short-column variant: rows = `j_hi`, columns = `(j_lo, ℓ, k)`; `B[ℓ,k] = Σ_{j_lo} eq(j_lo, r_j,lo)·u'[j_lo, ℓ, k]`.
- Multiplicities/aux: square.

## 5. Fused opening (ST-2)
In the phase sumcheck (RFC-0007 §5) the prover's `B[ℓ,k] = Σ_j eq(j, r_j)·W_τ(ℓ,k,j)` is **exactly** `u = aᵀM` for
`a = eq(·, r_j)`. The opening therefore costs no additional pass: the prover sends/commits `u = B`, the verifier evaluates
`u·b` with `b = eq((ℓ,k), (r_ℓ', r_k))` and spot-checks columns. Soundness: `r_j` is sampled after the commitment (the
passport predates the transcript), so the tensor-structured combination is a valid proximity test by the
logarithmic-randomness theorem (Diamond–Posen for RS; Khatam for general linear codes) with the error terms in §6.
No separate random-combination pass is needed; a one-time proximity certificate (RFC-0011 §3) is still published
for defence in depth and for the `treaty` profile's audit trail.

## 6. Parameters and soundness (per opening)
Error ≤ `ε_gap(ρ, δ, |K|)` (proximity gap at relative distance `δ` below the chosen bound) + `(1 − δ)^q` (queries) +
`ε_Merkle`. Treaty: proven gaps only (RS: `δ` up to Johnson `1 − √ρ − η`, BCIKS20 + DP23/24; RAA/expander: Khatam /
Brakedown-style bounds with the code's certified distance), `q` chosen for `(1−δ)^q ≤ 2⁻¹³⁰`. Standard: may use
`δ` up to `1 − ρ − η` with the usual capacity conjecture, labelled. **Query count affects proof size and verifier only.**

## 7. Ligerito mode (succinct columns and row vectors)
Instead of sending `u` (length `C`, possibly 10⁶–10⁸), the prover commits `u` as a smaller interleaved-code matrix and
proves the two linear checks (`u·b = v`, `Enc(u)[c] = Σ a_r Enc(M)[r,c]` over sampled `c`) by a sumcheck that reduces
them to an opening of the smaller matrix; recurse `O(log log)` times (Novakovic–Angeris 2025). This allows short
columns (≈ 256 elements) with proof size ≈ 1 MB per weight type and verifier cost `O(q·R + polylog)`. Mandatory for
the wrapper path; optional for native verification.

## 8. Packing, blinding, DPA
- Packing: `k` int8 (4) or int16 (2) values per M31 message element; the consumer side (RFC-0008 §5) pins the decomposition.
- ZK blinding (RFC-0013): one extra random row per matrix; functionals are extended with a random coefficient on it.
- DPA (RFC-0019): leaves hold the packed systematic bytes once plus one parity block per field.

## 9. Distributed openings
`LigeSIS`-style sharding (RFC-0015 §4): each device commits its row shard; a root of roots; the row functional's
contributions are summed across devices; column openings touch only the device owning the column shard.

## 10. Negative controls
NC-0600 `u` inconsistent with opened columns; NC-0601 column index not from transcript; NC-0602 Merkle path for wrong
leaf; NC-0603 packed decomposition altered (x0 = 256, x1 − 1); NC-0604 blinding row omitted in treaty profile;
NC-0605 fused `u ≠ B` (cross-check with NC-0305).

## 11. Amendment log

### A1 — Concrete encoder identity and parameter provenance

Status: Draft. Question Q23. Evidence: [code provenance study](../../research/code-provenance/REPORT.md).
Motivation: §3 names code families but does not fix a concrete M31 encoder, setup
or supported lengths. The distance-estimate task and a `proven` boolean cannot
replace evidence for the distance and proximity hypotheses of §6. This draft
authorizes no production code or parameter set; E4-01 is blocked until completion
and acceptance. Original §3/§6 text remains in force outside this amendment.

Proposed addition to §3, pending the exact construction and encoding below:

> A code instance is a fully specified injective M31-linear map, including its
> message/codeword lengths, canonical coordinate order, coefficients, graph or
> permutations, recursion/base case and padding rule. The same map extends to
> QM31/OM31 by embedding M31 coefficients. Do not reuse binary-field distance
> parameters for M31 by replacing XOR with modular addition. A family name or seed
> alone is not a complete algorithm or a distance certificate.
>
> `encode` maps a validated row to its complete codeword. `eval_row(u, cols)` must
> return exactly those coordinates of `encode(u)`, in the supplied order, with a
> specified duplicate-index policy. It is an encoder query, not a PCS acceptance
> decision. Code parameters and requested column bounds are checked before use;
> input length mismatch, malformed setup, noncanonical coefficients, unknown code
> identity and arithmetic/allocation overflow must fail with specified errors.
> No malformed setup may silently fall back to another code or profile.
>
> `codes.toml` records exact rational/integer lengths, rate and bounds; no floating
> point enters protocol code. Separate (1) certified minimum-distance lower bound,
> (2) sampled-distance observations, (3) proximity radius and exceptional-combination
> bound, (4) setup failure probability and its sampling assumptions, and (5) query
> count. A sampled nonzero codeword gives only an upper bound on minimum distance.
> An upper estimate must never populate a certified-lower-bound field.
>
> Every proven parameter requires an immutable theorem identifier/version and
> checked hypotheses for this field, code instance/ensemble, supported lengths,
> setup distribution and consumer. A `proven` flag is a summary of that evidence,
> not authority supplied by the prover. Unknown or mismatched evidence rejects.
> The verifier derives approved code parameters from its authenticated public
> configuration; changing a TOML flag or prover-supplied theorem name cannot enable
> acceptance. Missing evidence is unsupported, not a zero error term. Treaty
> rejects every unproven required component; standard still requires its explicit
> labelled assumptions and complete bound. Neither profile accepts arbitrary
> estimates merely because an encoder passes linearity tests.
>
> For M31-linear maps the base/extension minimum symbol distances agree, by the
> basis-component support argument in the study. This does not prove the base
> distance, a proximity gap, or a codeword-validity claim for a Merkle commitment.
> Query count alone cannot cure an unaccounted gap or setup failure probability.

Open requirements before acceptance (Q23):

1. Select and reproduce an applicable concrete M31 construction with exact
   finite-length conditions. Extract the Brakedown field-agnostic construction
   and its proof; do not substitute the weak identity-permutation RAA example.
   Fix all integer rounding, graph/weight generation, duplicate edges, recursion,
   base encoder, systematic/packing layout, domain restrictions and unsupported-length behavior. If RAA is
   selected instead, supply an applicable M31 distance theorem or certificate.
2. Specify canonical setup and code-id bytes, registry schema, authoritative
   parameter selection and binding to future commitment/plan/passport descriptors.
   Determine setup generation/security assumptions, who may choose or grind setup,
   and how failure/reuse is accounted. A uniformly random ensemble theorem does
   not automatically certify an arbitrary fixed seed or adversarial graph.
3. Give the complete `Code`/parameter API, errors, extension-field behavior,
   coordinate ordering and allocation limits. Specify which fields are verified
   against fixed supported entries rather than trusted at parse time. Unknown,
   missing, duplicated or inconsistent registry data must fail closed.
4. Record minimum-distance and proximity hypotheses separately with exact sources,
   rational bounds and applicability. Derive query counts with exact arithmetic
   and instantiate exceptional-combination/setup errors before profile admission.
   If this adds an error term to §6, amend §6/RFC-0012 and the ledger explicitly.
   Do not hide it inside the query term or assume the code has distance by name.
5. Require independent encoding vectors and linearity over M31/QM31/OM31, direct
   generator-matrix parity at small lengths, `eval_row` coordinate parity and
   malformed setup/row/column/parameter rejection. Keep distance estimates clearly
   one-sided; use exact small cases and adversarial low-weight witnesses. Real
   controls must reject parameter/provenance substitution under the actual
   consumer; no research counterexample earns NC-0600..0605 credit.
6. Supply clean-source adds/multiplications per element, preparation cost and full
   memory ledgers for the selected production code. Include graph/permutation
   storage and extension-field encoding. The requested linear-time encoder must
   remain linear-time; exhaustive small-code checks are validation, not its setup
   algorithm or a substitute for scalable distance evidence.

Soundness impact: none implemented. The research makes no PCS, profile or new
challenge claim. A code's distance, codeword validity, proximity gap, column
authentication and Fiat–Shamir bounds are separate obligations. All existing
consumer bindings, CQIS certificates and Q12 remain. No integer inference identity
is introduced, and no conjectural bound is promoted to treaty evidence.

Cost impact: c_c encoding work, setup/memory, PCS query work and proof size. The
research counts additions for a deliberately unspecified-for-production RAA map;
it changes no measured constant, benchmark or weight-pass count. Affected tasks:
E4-01, E4-03/E4-05, E10-06 and E12-04, with original criteria retained. The circle
RS encoder E4-02 still requires its own construction/parameter evidence.
