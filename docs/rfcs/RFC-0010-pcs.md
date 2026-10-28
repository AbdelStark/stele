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
Follow-up: [finite expander bounds](../../research/code-provenance/EXPANDER.md).
Candidate map/bytes: [recursive encoder](../../formal/recursive-code.md), using the
Accepted A2 circle base and all twelve finite-bound degree pairs. Independent dense
encoding and the legal zero-edge distance-one counterexample separate map correctness
from setup admission. The candidate does not resolve registry/proximity or authorize
a production encoder/profile; all remaining requirements below stay in force.
Seeded v2 candidate: [manifest, bounded sampler and all-seed setup loss](../../formal/seeded-setup.md).
RFC-0012 A7 records the proposed separate setup error. Stronger finite parameters
bound the complete 256-bit seed universe in the ideal oracle, independent of quantum
selection. V1 descriptors reject. Actual admission/consumer binding and Q12 remain
open; regeneration consistency alone supplies no concrete distance/profile certificate.
Candidate common API and registry: [code identity](../../formal/code-identity.md).
The factory derives map/length/distance/setup metadata from exact Circle or v2
manifest bytes; arbitrary raw graphs and caller-modified metadata are not inputs.
A sealed native Code interface and separate fail-closed PCS parameter resolution
are proposed. The research codes.toml is a checked export; both proven flags stay
false. No proximity parameter, native capacity contract or profile is admitted.
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

### A2 — Canonical M31 circle encoder

Status: Accepted. Question Q24. Review: [skill passes](../../agents/reviews/circle-a2.md). Evidence: [circle study](../../research/circle-code/REPORT.md)
and [deterministic derivation](../../formal/circle-code.md).
Motivation: §3 leaves the circle basis, ordered domains, normalization and maximum
size unspecified. The full circle polynomial space is one dimension larger than
the FFT span; its name alone cannot determine interoperable codewords. This
amendment fixes an encoder independently of A1's unresolved PCS parameter registry.

Exact addition to §3's weight-code row and encoder contract:

> Use p=2^31-1, g=(-3/5,4/5)=(1717986917,1288490189), with circle multiplication
> (x,y)*(u,v)=(xu-yv,xv+yu). For 0<=h<=30 define ordered
> D_h[j]=g^((2j+1)*2^(30-h)), 0<=j<2^h. This order is part of the code definition;
> it is not a freely permutable implementation convention. D_0={(-1,0)} is the
> constant-only base case. Never use the full group as though it were this domain.
>
> Define v_1=x and v_(h+1)=2*v_h^2-1. For coefficient index j with bits j_0,j_1,...
> from least to most significant, b_j=y^j_0*product_(h>=1) v_h^j_h. Message rows of
> length k=2^m are evaluations on D_m, not coefficients. Interpolate in exactly the
> span of b_0..b_(k-1), zero-pad the coefficient vector to N=2^(m+b), then evaluate
> on D_(m+b). Supported log blowups are b=1 and b=2, with m>=0 and m+b<=30.
> Input and output domains differ; this encoder is not systematic. No raw input
> prefix or packed-byte layout may be assumed by its consumers.
>
> Interpolation splits inverse-point indices j,k-1-j using
> even=(f_j+f_(k-1-j))/2 and odd=(f_j-f_(k-1-j))/(2*y_j).
> On the first-half x quotient, split x,-x by the same formulas with x_j replacing
> y_j and recurse on 2*x_j^2-1. Interleave the resulting even/odd coefficients at
> indices 2i,2i+1. Evaluation reverses these splits using even +/- twiddle*odd.
> Every factor 1/2 is included; a scaled transform must normalize before it returns.
> All required divisors are nonzero on supported domains. Length-one transforms
> return the constant. Implementations may reorder internal work only if returned
> coefficients/codewords retain these exact conventions.
>
> The concrete Circle encoder accepts checked log dimensions and exposes message
> and codeword lengths, encode(row), and eval_row(row,cols). Both row methods use
> the identical map and preserve selected-column order and duplicates; an empty
> column list returns empty only after row/field validation. Support the validated
> M31 field and its extensions by embedding twiddles; reject a different base
> characteristic. Typed field values are already canonical; byte decoding remains
> the caller's checked field decoder. The code identity is the fixed ASCII bytes
> `stele/circle-m31/v1` followed by m and b as one byte each. It identifies the base
> linear map; surrounding protocols must also bind the element field/encoding.
>
> Reject unsupported dimensions/rates as InvalidSize, wrong row length as RowShape,
> any column >=N as Column, wrong characteristic as FieldMismatch, and checked
> size/allocation failure as Capacity. Validate dimensions before shifting,
> allocating or generating domains. Validate the whole row/column request before
> returning output; no unchecked truncation, padding, partial-success result or
> fallback code is allowed. Capacity is a resource error, not a false-statement
> acceptance. Allocation capacities and construction overlap count in measurements.
> eval_row may use complete encoding then selection; no sublinear-query cost is
> promised. This concrete API may precede the general Code trait, whose integration
> still requires A1's contract. It exposes no admissible PCS/profile parameters.

Distance and soundness: the map is injective and linear by invertible butterflies.
For k>=2 its minimum symbol distance is at least N-k, by the rational
parametrization/root bound in the derivation; for k=1 it is N. The same bound
holds in M31 extensions. Do not silently replace this bound with N-k+1: the study
gives a counterexample. The omitted v_m vanishes on D_m, so interpolating the
entire degree-k/2 circle space instead of the specified span is incorrect.
This is a distance lower bound only, not an exact-distance, proximity-gap,
codeword-validity, PCS, zero-knowledge or profile certificate. No challenge,
commitment, transcript label or certified ledger line is introduced. A1/E4-03,
E4-05/E12-04 and Q12 retain their full obligations; §6 is not discharged here.

E4-02 acceptance retains direct-naive parity and the actual large benchmark:
the `2^30 encode benchmark` must process 2^30 input symbols at each rate. Use two
rows of k=2^29 at rate 1/2 and four rows of k=2^28 at rate 1/4; every row produces
N=2^30 codeword symbols. Report both per-row and total input/output lengths.
This is the existing row-wise matrix encoding, not a single unsupported 2^30-symbol
row. Reusing or rescaling one measured row does not meet the gate: execute every
required row. The ledger must include preparation, inverse transform, expansion,
domain/twiddle work, output validation and peak memory; separately
report reusable setup if amortized. A formula, sampled output without performing
the full encoding, extrapolated runtime or metadata-only case is not this gate.
Require independent vectors/direct evaluation at small sizes, generator order,
both-field extension parity, linearity, selected-column parity, constant case,
malformed dimensions/rows/columns and normalized inverse round trips. Test the
maximum dimension's arithmetic without allocating it in ordinary unit tests.

Binding/control impact: no PCS binding is implemented. Encoder/order/normalization
mutations must be detected by independent expected codewords. NC-0600..0605 remain
actual consumer controls, not credited by constructor errors or research checks.
The full degree-space and MDS counterexamples are algebraic diagnostics only.

Cost impact: O(k log k+N log N) arithmetic for complete encoding, with base-field
twiddles, and O(N) storage achievable by butterfly reuse. Include inversions,
twiddle/domain generation and allocation; no fitted constant or speed claim is
made. This is one-time weight registration work, not another per-proof weight
pass. Existing c_c/fused-opening/per-proof terms do not change. Affected tasks:
E4-02 and its registration/PCS consumers. A2 does not complete E4-02.
