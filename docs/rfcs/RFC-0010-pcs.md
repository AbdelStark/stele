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

Status: Accepted. Question Q23. Review: [acceptance](../../agents/reviews/code-a1-accepted.md).
Evidence: [code provenance study](../../research/code-provenance/REPORT.md).
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
Candidate native execution/resource contract: [bounded encoder](../../formal/bounded-encoder.md).
It regenerates each exact v2 row into fixed recursion scratch; graph serialization
is not required on the encoding path. Requested buffer bounds are separated from
u64 operation counters and native allocator/stack/process evidence. This remains
Draft, with no native implementation or PCS admission.
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

Acceptance resolution (companion RFC-0012 A7). The quoted §3 addition is in force.
The six open requirements are discharged as follows; nothing else is admitted.

> Supported codes are exactly the A2 Circle identities and the A4 v2 expander
> manifests of [code identity](../../formal/code-identity.md) §1. Their derived
> lengths, distance lower bounds and setup errors are §2 of that note, with
> immutable evidence IDs `rfc-0010-a2/root-bound-v1`, `rfc-0010-a1/finite-v2` and
> `rfc-0012-a7/2^256-all-seeds-v2`. Changing any premise needs a new evidence ID.
> The expander distance bound holds for the ideal-oracle ensemble and applies to a
> regenerated seed only together with the A7 setup event.
>
> The native registry is the fixed two-entry catalog of code-identity.md §3,
> compiled into `stele-code`. `research/code-provenance/codes.toml` is a checked
> export of it, never an input. `proven` means a complete admitted PCS parameter
> set; it is false for both entries. A parameter resolver takes code identity,
> field degree and profile, rejects malformed or edited registry data as
> `InvalidRegistry`, and returns `UnsupportedParameters` for every request until
> an Accepted amendment admits a proximity radius, exceptional-combination bound
> and query count for that identity (A3) together with Q12's composition.
> Distance tuples, flags or theorem names supplied by a caller never satisfy it.
>
> Proximity, codeword validity and query selection stay with A3; packing with A6;
> blinding with A7 of this RFC. The verifier binds the complete code identity and
> field in each commitment, plan or passport descriptor that consumes a code.
> NC-0612 reserves code-identity/evidence substitution under the first actual
> expander PCS consumer. E4-01 delivers the catalog, resolver, linearity tests, a
> one-sided distance-estimate script and the adds/element ledger.

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


### A3 — Functional-opening proximity hypotheses and finite query parameters

Status: Accepted. Question Q27. Review: [A3/A6 acceptance](../../agents/reviews/pcs-a3-a6-acceptance.md).
Companion RFC-0012 A15. The acceptance resolution at the end of this entry replaces
the proposed text; only the resolution is in force.
Evidence: [conditional tensor opening](../../formal/tensor-opening.md)
and research/code-provenance/check_proximity.py. Motivation: §2's arbitrary public
functional is not automatically a valid random proximity test, and §6 does not
instantiate a finite exceptional-combination bound or integer query count.

Candidate continuation: [certified arbitrary/batched openings](../../formal/certified-functional-opening.md)
derives a near-matrix bound after a separate certificate and a lifetime union
bound for adaptive reuse. Its general batch retains all row equations; aggregating
them with coefficients already known to the prover is explicitly rejected by the
study. This is ideal-oracle research only. Native certificate/root/cache binding,
extraction, packed values, ZK, transcript bytes and Q12 remain acceptance gates;
neither this argument nor its smaller conditional query count enables a profile.

Proposed addition to §§2,5,6, pending the complete native/mode contracts:

> For the fresh random tensor mode, bind the exact code ID, field, dimensions and
> encoded-column oracle before all independent uniform row challenges. Use the
> ordered tensor of (1-r,r) factors and bind u, b and v before any independent
> uniform column draws. Check dot(u,b)=v and every authenticated column equation.
> Native challenges come only from Transcript; a caller-provided point or mode
> flag does not certify freshness or its distribution.
>
> The conditional lemma in formal/tensor-opening.md uses the proved distance lower
> bound D, e=floor((D-1)/3), exceptional term 2*ell*(e+1)/|K|, and query miss term
> ((N-e-1)/N)^q. It covers rejection of far matrices and consistency with the unique
> near matrix. Keep setup, Merkle, FS/H and other losses separate. Derive the least
> q satisfying the exact 130-bit miss inequality; unsupported arithmetic/budgets
> reject. A distance theorem alone cannot authorize arbitrary query counts.
>
> Preserve support for arbitrary and batched functionals, but provide their actual
> admissible-query or prior-proximity relation and consumers before enabling them.
> Do not apply the fresh-tensor theorem to a fixed point, an arbitrary coefficient
> vector, or a batched sum merely by naming it a tensor. Do not silently introduce
> another weight pass or replace the actual fused u=B object with an unbound copy.

Acceptance still requires exact native statement/proof bytes, label/order and
unbiased index sampling, canonical leaf interpretation, source/extraction and
multi-opening semantics, complete arbitrary/batched modes, parameter policy,
prover/verifier APIs and actual NC-0600/0601/0603/0605 consumers (NC-0602 remains
Merkle authentication only). No production protocol or parameter set is enabled
by this draft. E4-03 is blocked on A3; E4-01 A1 retains its full obligations.

Soundness impact: proposes finite tensor/query terms in the PCS record; no new
production challenge, label, registry flag or ledger line. The complete bound and
Q12 remain open. The conservative generic-code theorem is not a conjectural
larger-radius gap or the paper's full extraction theorem.

Cost impact: verifier work and proof bytes depend on actual q (up to 13472 draws
in the checked examples). Counts are exact arithmetic, not a benchmark. Additional
proximity work, if selected for other modes, must be measured/accounted while
preserving the one-weight-pass invariant. Affected tasks: E4-01/E4-03/E4-04/E4-05,
E8-05 and E12-04; no production c_c/T_misc constant changes.

Acceptance resolution. The following is in force; the proposed text above is not.

1. **One mode.** Every functional opening is an A9 §4 general opening on a
   source context with a verified registration certificate (A9 §3). The verifier
   owns a in K^R, b in K^C and v; the prover sends the full u; the verifier checks
   dot(u,b)=v and then q_o fresh column equations. Fixed, sparse, tensor and
   sum-of-tensor a are all allowed: the certificate supplies proximity, not the
   distribution of a ([certified-functional-opening.md §2](../../formal/certified-functional-opening.md#2-arbitrary-functionals-after-certification)).
   Withdrawn from the Accepted text: §5's claim that a fresh tensor makes a
   separate certificate unnecessary (the weight certificate is required, not
   defence in depth; RFC-0007 A2/A10 already open certified sources); §2's batched
   `a = Σ_t γ_t eq(ℓ_t,·)⊗eq(…)` as one opening (each claim is a separate opening
   with its own q_o term, unless an Accepted consumer RFC first reduces the claims
   to one (a,b,v) and charges that reduction). The same holds for every other
   Accepted "one batched opening" sentence: RFC-0007 §4 row 17 and RFC-0001 §4.1
   (replaced by RFC-0007 A7 and RFC-0001 A4); RFC-0008 §6's was already withdrawn
   by RFC-0008 A2 item 8. Not admitted, and usable only after
   a new amendment: the certificate-free fresh-tensor mode, the batch and grouping
   protocols of certified-functional-opening.md §3, and §7 Ligerito mode (Q27).
2. **Code identities and source bytes.** Source version 1 is A9's Circle source,
   unchanged. Source version 2 admits the v2 expander identities of A1/A4 with
   J in 3..14. Its bytes are A9 §1's table with exactly two changes: version is
   u8(2), and the code identity is the exact 55-byte v2 manifest, which must pass
   `Encoder::from_code_id`. Then C=k=4^J (message exponent m=2J) and N=2k=2^(2J+1).
   The Merkle descriptor, response format, wires, labels, order, column sampler,
   certificate ID, opening, records and the RFC-0006 A1 adapter are A9 §§1-9
   verbatim with these N, C, D. The version byte fixes each source's byte length,
   so a FieldSources bundle may mix versions. J=15 (N=2^31 exceeds RFC-0012 A10's
   sampler domain) and every other manifest reject as UnsupportedSource before any
   transcript work. J=3 is the same map as Circle(6,1) but a different identity and
   a different source; identities are never normalized.
3. **Distance and setup.** Circle: D=N-C for C>=2 and D=N for C=1, deterministic
   (`rfc-0010-a2/root-bound-v1`). v2: D=64 at J=3 and floor(k/25)+1 at J>=4
   (`rfc-0010-a1/finite-v2`), valid outside the RFC-0012 A7 setup event
   (`rfc-0012-a7/2^256-all-seeds-v2`). In both, e=floor((D-1)/3). Policy byte 1
   pins these evidence IDs; a changed premise needs a new evidence ID and a new
   policy byte. The setup term 200431782/2^160 is charged once in every ledger
   that contains a v2 source with J>=4; J=3 and Circle sources add zero.
4. **Query policy 1.** q_c and q_o are the least positive integers with
   `2^130*(N-e-1)^q_c <= N^q_c` and `2^130*(N-D+e)^q_o <= N^q_o`. Circle uses
   A9 §1's tables. v2 uses this immutable u16 table, indexed by J:

   | J | 3 | 4 | 5 | 6 | 7 | 8 | 9 | 10 | 11 | 12 | 13 | 14 |
   |---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
   | q_c | 478 | 11489 | 13137 | 13377 | 13438 | 13469 | 13469 | 13471 | 13472 | 13472 | 13472 | 13472 |
   | q_o | 221 | 5722 | 6546 | 6666 | 6697 | 6708 | 6713 | 6713 | 6713 | 6714 | 6714 | 6714 |

   `research/merkle-oracle/check_expander_policy.py` checks every inequality and
   its failure at q-1 with exact integers. The verifier derives q; no proof byte,
   TOML flag or caller selects it. Policy 1 is a conditional interactive policy,
   not a profile parameter set: A1's resolver still returns UnsupportedParameters
   for every profile request, and both registry `proven` flags stay false.
5. **Where each statement field comes from.** Purpose, version, layout and policy
   are constants of this amendment. Field degree, tensor ID, ell, R, C and code
   identity come from the consuming Accepted RFC's expected statement (plan or
   passport). The root comes from the passport for registered weights (RFC-0011)
   or from the consuming RFC's pre-challenge commitment for per-proof sources
   (for example RFC-0023's advice cut). No proof byte supplies any of them. When
   E4-05/E12-04 admit a profile, K and the policy derive from that profile.
6. **Soundness terms and labels.** Per certificate attempt:
   `2*ell*(e+1)/|K|` (Diamond–Posen Theorem 2, proven, unique-decoding regime
   e<=(D-1)/3) plus `((N-e-1)/N)^q_c` (tensor-opening.md §3, proven). Per opening:
   `((N-D+e)/N)^q_o` (certified-functional-opening.md §2, proven). Adaptive reuse
   is the union bound adopted by A9. The Merkle lift is A8's hash event, charged
   under H. The setup term is item 3's. No Johnson-radius, list-decoding or
   capacity conjecture is used anywhere. §6's RS Johnson-radius option and its
   standard-profile capacity option are withdrawn; a larger radius needs its own
   amendment with a proven theorem. These are interactive bounds. They establish
   soundness relative to the unique near message of A8's frozen oracle, not a
   knowledge extractor; a consumer that needs knowledge soundness (RFC-0016
   recursion) must supply it.
7. **Fiat–Shamir, hand derivation for Q12 (not a theorem).** The rounds are
   CertificateWeight (re-rolled by changing the root), with error
   `2*ell*(e+1)/|K|`; CertificateColumn (re-rolled by changing t), at most 2^-130;
   and OpeningColumn (re-rolled by changing u), at most 2^-130. Under RFC-0012 §4's
   charge of Q times the largest round error:
   - Policy 1's query rounds give 2^-30 at treaty Q=2^100 and 2^-50 at standard
     Q=2^80, so they fail both profiles.
   - The tensor round fails both profiles in QM31 for every ell>=1. In OM31 it
     passes standard but fails treaty unless `2^229*ell*(e+1) <= p^8`: ell*(e+1)=2^18
     passes and 2^19 fails, so it fails at almost every real weight source.
   A profile parameter set (E4-05, E12-04) must bring every query round to at most
   2^-(target+log2 Q), or use RFC-0012 §2's counted grinding nonce, and must change
   the certificate's tensor round (for example independent repetitions) or rest on
   a Q12 theorem. At treaty's 2^-228 the least counts are q_c=550, q_o=228 (Circle
   rate 1/4, m>=20), q_c=867, q_o=390 (rate 1/2) and q_c=23627, q_o=11774 (v2, J=14).
   Policy 1 cannot be admitted to either profile.
8. **Errors.** A9 §8's errors apply unchanged. A v2 manifest or J outside item 2,
   or a policy byte other than 1, is UnsupportedSource. A verified handle whose
   context names a different code identity is CertificateContext. An edited
   registry evidence ID is A1's InvalidRegistry.
9. **Controls.** NC-0612 (todo, E4-03) runs under the actual v2 consumer and has
   three variants: a verified certificate for another seed's v2 source, or for
   Circle(6,1), offered for the expected v2 source (CertificateContext); a
   certificate for the expected context whose rows were encoded under another seed
   (ColumnMismatch); and an edited registry evidence ID (InvalidRegistry).
   NC-0613 (todo, E4-03): a v2 source context with J=15, or with policy byte 2,
   rejects as UnsupportedSource before any transcript work.
10. **Cost.** Circle is unchanged from A9. A v2 certificate sends q_c responses of
    4R+32*log2(N) bytes and an opening sends q_o of them; at J=14 that is 13472 and
    6714 responses, against 314 and 130 for Circle rate 1/4. Verifying encodes t
    and u with full v2 regeneration (A4), O(N) work. This is the price of
    linear-time encoding in c_c; no measured constant moves. E4-03's proof-size
    regression test must pin these counts. Because the certificate is required,
    every per-proof source (cuts, multiplicities, advice) is certified within its
    proof: one more R·C row combination, one encoding of t and q_c responses each,
    charged in c_c/T_misc, as RFC-0023/0024 sources already are.
11. **Tasks.** E4-03 becomes ready with its original criteria plus NC-0613.
    E4-05 inherits item 7. E8-05's ledger generator uses RFC-0012 A15's PCS line.
    E4-04 stays blocked on RFC-0007 A1. A6, A7 and Q12 keep their own obligations.


### A4 — Native deterministic v2 encoder and closed identity factory

Status: Accepted. Question Q23. Review: [skill passes](../../agents/reviews/native-code-a4.md).
This separates the deterministic encoder implementation
from A1's unresolved parameter/consumer admission, following A2's circle precedent.
The original E4-01 criteria remain; E4-08 becomes its native encoder prerequisite.
Exact contract and delivery gates: [native code](../../formal/native-code.md).
No profile, PCS parameter or soundness-ledger admission follows from an encoding.

Exact addition to §3's deterministic encoder interface, independently of the
unaccepted A1 parameter/consumer contract:

> Implement the exact native API, identity and validation rules in native-code.md.
> Code and CodeField are sealed; Encoder::from_code_id is the only new factory.
> Accept exact A2 Circle IDs and exact v2 expander manifests, retaining all bytes.
> No raw graph, arbitrary Field/Code implementation, metadata snapshot or registry
> override is an input to this factory. Existing Circle APIs remain compatible.
>
> EncoderInfo returns only mathematical message/codeword lengths and sparse row/
> edge counts in u64. It is not ProximityParams or authority for a profile. A1's
> registry/provenance requirements and §6's full soundness budget remain required.
>
> Use recursive-code.md §§1–2 for the fixed v2 map/base/degrees/coordinates,
> seeded-setup.md §1 for exact deterministic manifest and capped block generation,
> and bounded-encoder.md §§1–2 for execution and checked resource handling.
> Preserve all zero edges and generate every row. SamplingExhausted rejects the
> whole operation; no partial output, fallback seed or code is returned.
>
> Use the same pinned no_std BLAKE3 dependency as stele-hash directly in stele-code.
> These bytes are setup expansion, never Fiat-Shamir challenges. No internal
> dependency edge, transcript label or production soundness line changes.

The accepted scope is algorithm/API implementation. Native parity,
malformed-input/fault tests, sealed API checks, actual capacities/process peaks,
complete preparation/arithmetic ledgers and repository gates remain E4-08 delivery
requirements. E4-01 retains every original criterion and depends on E4-08; it stays
blocked on A1. A1/A3/A7 and Q12 are not accepted, weakened or marked complete here.
No new proof binding or NC id is created by returning encoded values.

Soundness impact: none added to a verifier. Deterministic map equality is checked;
codeword validity, minimum-distance admission, setup/proximity composition and all
actual source/PCS consumers remain separate. No proven flag becomes true.
Cost impact: d*E(J) sparse adds/multiplies plus fixed base and capped regeneration,
with explicit input/output/scratch/base/query overlap. Native benchmarks must charge
all work and process memory; no measured constant, c_c claim or weight-pass change.
Affected tasks: E4-08, E4-01 and their E4/E10/E12 consumers.

### A5 — Observed native encoder work and allocation reports

Status: Accepted. Task E4-08. Review: [measurement review](../../agents/reviews/encoder-measurement.md).
Motivation: A4 delivery needs actual allocation and complete work evidence from
its production path. Requested workspace formulas alone cannot supply that data.
This amendment adds observations to A4, without changing its identity, map,
validation, caps, sealed fields, errors or authority boundary.

Exact addition to the A4 native interface:

- `Encoder::encode_measured` and `Encoder::eval_row_measured` return
  `MeasuredEncoding<K> { values: Vec<K>, work: EncoderWork }` on success.
- EncoderWork contains observed peak owned vector capacity in bytes, hash blocks,
  completed sparse rows, sparse base-limb additions/products, initialized/copied
  K slots, Circle calls, Circle transform K additions/products, constructed base
  twiddle elements, inverse-prefix elements and maximum recursive frame count.
  Field names and units are documented on the public Rust members.
- Ordinary and measured calls execute one implementation. Ordinary calls discard
  observations. No caller supplies a sampler, counter, field implementation,
  resource width, admission flag or observation callback through this interface.
- Actual vector capacities are charged when allocated and released in execution
  order, including the outer output, scratch, temporary Circle output, all
  twiddle/header/prefix allocations and selected-column/full-encoding overlap.
  Borrowed input, stack, allocator metadata and process/runtime memory are outside
  the owned-vector measure and must be recorded separately by the benchmark.
- Counters count completed logical operations, not machine instructions or DRAM
  traffic. Each sparse edge executes d base-limb products/additions, including
  zero edges. Circle transform counters use K operations; twiddle construction,
  inversions, sampling comparisons/sorting and hashing remain additional work.
  Full operation timing must include every category and observation overhead.
- Whole-request validation and A4 capacity checks still precede generation. An
  error returns no measured encoding. Empty queries perform no allocation or
  generation. No partially accumulated report is a successful encoding.

Reports are descriptive outputs. No production function may accept them as code,
source, distance, setup, PCS or profile authority. No verifier reads a report.
No proof bytes, challenge, claim, binding, soundness loss or negative-control id
changes. E4-01/A1, A3/A7 and Q12 retain all original obligations. All A4 delivery
gates remain, including actual capacity/stack/process and complete per-call work
ledgers through 2^20 input symbols in every supported field. Changes in c_c/T_misc
from observation overhead require measured ledgers; no constant or speed result
is supplied here. No committed tensor or matmul weight pass changes.

### A6 — Injective packing and authenticated original-value functionals

Status: Accepted. Question Q28. Review: [A3/A6 acceptance](../../agents/reviews/pcs-a3-a6-acceptance.md).
Companion RFC-0007 A7. The acceptance resolution at the end of this entry replaces
the proposed text; only the resolution is in force.
Evidence: [packing and fused-row study](../../formal/packed-commitments.md)
and [executable report](../../research/packing/REPORT.md).
Review: [same-author skill passes](../../agents/reviews/packing-contract-study.md).
Continuation: [fused layout derivation](../../formal/fused-layout.md) proves a
rank lower bound for direct linear consumption, derives the minimal signed
u=B layout, and separates the larger short-column row from its low-coordinate
fold B. It compares exact message/payload/state counts and instruments one source
visit in both extension fields. This recommends a contract direction only;
neither layout nor private packing/PCS/ZK consumer is admitted by the study.
Motivation: §8's four int8/two int16 values contain 32 unrestricted bits and cannot
fit injectively in one M31 element. A legal integer packing map also changes the
linear functional and cannot automatically preserve §5's original B identity.

Proposed replacement for §8's packing bullet, pending the consumer below:

> Physical source bytes and committed field-message packing are distinct formats.
> Use a registered injective source map with explicit signed representation,
> word count, logical axes, row boundaries, code padding and canonical decoding.
> The candidate packed30 map in formal/packed-commitments.md uses fixed 30-bit
> words and rejects nonzero tail/message padding; its word count is derived from
> the authenticated shape. Never reduce an unrestricted 32-bit source word into
> one M31 element or treat source-range rejection as support for that source.
> Every original-value claim must be connected to this same committed packed
> source by an Accepted decomposition/range/sign/position reduction. A codec,
> source flag, digest or equality on unbounded digits does not supply that proof.

Open requirements before acceptance:
1. Select the complete versioned packing/layout bytes and canonical source/field
   decoding. Compare valid alternatives with full message/padding and consumer
   costs; packed30 is a candidate, not an unmeasured optimum or admitted format.
2. Specify the actual decomposition/range/sign/fragment/padding reduction and
   static certificates, range-table registry and every final claim consumer.
   Preserve privacy and the dominating-check rule of RFC-0008 §5.
3. Reconcile the original B and the packed opening row, including arbitrary lane
   functionals and the full one-weight-pass schedule. Amend RFC-0007 explicitly;
   a packed row must not silently replace the B consumed by the sumcheck.
4. Exercise NC-0603 with the real private range/claim consumer and fused NC-0605
   with the actual B object. Require both-field decisions, exact proof bytes,
   canonical padding and complete native cost/memory/read-count evidence.

Soundness: the counterexamples are exact finite arithmetic, not a cryptographic
attack on implemented PCS code. No production challenge, binding, loss or NC
credit changes. Future reduction challenges and controls must be accounted before
acceptance. A3, setup/registry admission, ZK and Q12 retain their obligations.
Cost: message/encoded counts, c_c, decomposition in c_a/T_misc, state and query
work. No measured constant, benchmark or extra weight pass is introduced.
Affected tasks: E4-03 (blocked on A3/A6), E4-04, E5-03/E6 range lowering, E7 weight/
cut consumers and E10/E12 passport/inference work. Original criteria remain.

Acceptance resolution. Exact replacement for §8's packing bullet:

> Committed field messages hold exactly one canonical M31 element per original
> source value. No packing of several int8, int16, int24 or other values into one
> M31 element is admitted: four int8 or two int16 values carry 32 bits, and no map
> from them into M31 is injective (formal/packed-commitments.md §1). Raw source
> storage, such as int8 or int16 bytes, is a separate physical format whose byte
> layout belongs to RFC-0011. The message expansion takes typed signed values, not
> bytes, and emits one canonical element per value.
>
> A signed w-bit value x, w in {8,16,24}, has one of two message embeddings:
> signed, the field image of x (x for x>=0, p+x for x<0; RFC-0007 §2), or offset,
> x+2^(w-1) in [0,2^w) (RFC-0024 §1 at w=8). The consuming Accepted RFC names the
> embedding in its expected statement. Every consumer of one source context uses
> the same embedding; the plan fixes it once per source. A plan whose consumers
> name two embeddings for one source, or none, is rejected. Both embeddings are
> injective on [-2^(w-1), 2^(w-1)) because 2^24 < p. The layout is A9's row-major layout 0, with
> logical and padded extents equal. The original-value MLE is the message MLE for
> signed, and the message MLE minus 2^(w-1) for offset, at every point.
>
> A commitment proves no width. A consumer that relies on a width runs an actual
> whole-source range lookup on the same certificate, with an all-one selector over
> every message entry: for offset int8 this is RFC-0024 §1.1's byte-range handle.
> No Accepted whole-source range consumer exists yet for w=16, w=24 or the signed
> embedding; a consumer that needs one must specify it first. A width tag, codec,
> honest decoder or digest proves nothing.
>
> For residual cuts, RFC-0008 §5's "RMSNorm's limb split enforces int16" satisfies
> this rule only if every limb column it looks up is an A9-bound source (RFC-0008
> A2), its recombination to the cut value is an Accepted identity checked against
> openings of the same cut certificate, and its selectors cover every cut message
> entry. No Accepted RFC yet specifies such a split for R_stack, so a cut's width
> is currently unproven; E6-02's checker must reject any plan whose committed cut or
> signed-embedding weight source lacks one of these two width proofs.

How each requirement above is closed:

1. Layout: one element per value, selected over packed30. Direct linear
   consumption of every original coordinate needs at least one message element
   per value ([fused-layout.md §1](../../formal/fused-layout.md#1-a-lower-bound-for-direct-linear-consumption)).
   packed30 commits w/30 elements per value, but its lanes need a range proof.
   Accepted RFC-0008 A2 looks up only A9-bound columns (virtual columns are open
   in Q31), so the lanes would have to be committed too: at least 1+w/30 elements
   per value, more than this layout. Packing cannot save message symbols until a
   virtual-column amendment and a decomposition reduction exist (RFC-0008 A1 stays
   Draft for such a future format; Q28).
2. Reduction: none needed. There is no decomposition, fragment, sign or padding
   relation; the range lookup's all-one selector is the dominating check. Messages
   stay below 2^24 < p, so no new integer identity or bound certificate arises.
   Privacy stays with A7 and RFC-0013 A1.
3. Fused row: at a=eq(·,r_j), A9's row aᵀM is the original row functional B
   (signed) or B plus 2^(w-1)·Σa (offset), with no decomposition; RFC-0007 A2/A4/A10
   already consume it in one weight pass. RFC-0007 A7 removes §3's two-per-element
   cut packing. Short-column splits (u_s ≠ B) and the complete fused schedule stay
   with RFC-0007 A1 and E4-04.
4. Controls: NC-0603 is redefined (todo, E4-03). In an offset int8 source, replace
   one adjacent pair (x0,x1) with x1>=1 by (x0+256, x1-1), which keeps the withdrawn
   packed word x0+256·x1. Commit and certify the tampered source honestly; the
   actual RFC-0024 §1.1 byte-range verifier must reject it (RootMismatch, as for
   NC-0401). NC-0614 (todo, E4-03) exercises the new expansion itself: one value
   expanded into two message elements under the expected one-element context
   (ColumnMismatch at the actual certificate), and an expanded row containing the
   limb p (NoncanonicalField). NC-1207 and NC-1208 (todo, E8-02): a plan whose
   consumers name two embeddings for one source context, and one whose consumers
   name none, are rejected by the plan verifier (EmbeddingMismatch,
   MissingEmbedding). NC-0605 stays with E4-04.

Soundness: no new challenge, label or loss. The range lookup's LU and A9 terms are
the consuming RFC's. Cost: the committed message count equals the number of values
(the withdrawn text claimed 1/4 for int8 and 1/2 for int16). Non-wide int16 cut
messages double, as wide int24 cuts already did (A11); raw storage is unchanged.
No measured constant moves. Affected tasks: E4-03 (ready), E4-04 (still blocked on
RFC-0007 A1), E6-02 (cut and signed-weight width in the range-discipline checker),
E7 weight/cut consumers and E8-02 (the plan verifier enforces one embedding per
source, NC-1207/1208), each with original criteria plus the lines named here.

### A7 — Separate column privacy from row-combination masking

Status: Draft. Question Q29. Companion RFC-0013 A1 and RFC-0011 A1.
Evidence: [complete-view privacy study](../../formal/commitment-privacy.md).
Motivation: §8's extra row leaves the original encoded column entries exposed;
extension-field rows and repeated openings add separate masking obligations.

Proposed replacement for §8's blinding bullet, pending RFC-0013 A1:

> Use the complete Accepted joint-view ZK construction for the committed oracle,
> row messages and hidden final claims. Its source/mask code and field, leaf
> bytes, point/query restrictions, mask coefficients and lifetime policy must
> all be explicit. A random appended row alone neither hides opened columns
> nor proves privacy of general extension-field messages. Code distance or a
> proximity certificate does not establish mask rank or hiding. Include all
> certificate, inference and recursive disclosures in the same privacy analysis.

No production format, randomized encoder, coefficient rule or extra commitment
is admitted by this Draft. A1/A3/A6, Q12 and the complete simulator remain open.
E4-05 is blocked on A7/RFC-0013 A1; its NC-0604 and proven-parameter criteria
remain. E4-03/E4-04/E4-06 retain their source, packing and fused requirements.
No ledger line or measured constant changes; any eventual randomization must
account for source reads, code dimensions/rates, entropy, state and native costs.

### A8: Fixed field oracle from a partially defined Merkle tree

Status: Accepted. Review: [conditional field PCS skill passes](../../agents/reviews/field-pcs-acceptance.md). Question Q27. Evidence: [frozen-oracle argument](../../formal/merkle-field-oracle.md)
and [executable controls](../../research/merkle-oracle/REPORT.md).
Motivation: A3's complete field oracle does not follow from byte authentication
alone. A malicious root may contain unresolved digests or malformed field leaves.

Conditional authentication premise adopted for A9's field-source contract:

> In the classical ideal-hash model, freeze the query log when the complete
> expected root/context is first fixed. Exact RFC-0012 A3 frames and canonical
> M31 decoding define known columns. Complete unknown or malformed subtrees
> with zero columns only in the proof argument. The actual verifier rejects
> every missing, malformed or unauthenticated column. Real accepted equations
> refer to that fixed oracle unless a collision occurs or a later new hash
> query hits a frozen unresolved digest. Charge both events explicitly.

For lambda-bit hash output, a conservative lifetime bound is
`[choose(Q_total,2)+sum_(r=1..R_max)(1+2*Q_pre,r)*Q_after,r]/2^lambda`, capped
at one, with deterministic registration/query caps fixed before execution.
The sum covers every permitted slot. The query caps cover all adversary
and verifier calls to the modeled hash. Each distinct registration r fixes a completion
once. Replaying its certificate cannot erase its loss or re-freeze its tree.
Fresh certificate attempts retain separate proximity/query terms.

This conditional lemma neither assumes a source extractor nor supplies one.
It does not establish quantum/Fiat-Shamir security, model ownership, canonical
unqueried absent padding, private openings or profile admission. A3's native
wire, sampling, parameter, cache and actual claim-consumer requirements remain.
No native API, challenge label, parameter flag or production ledger changes.
E4-01/E4-03 retain their original blocked criteria; A1/A3/A6/A7 and Q12 stay open.
Cost terms are authentication, decoding, encoding and cache work in T_misc/c_c;
the mathematical query-log completion is not charged as native verifier work.

### A9: Conditional native Circle field-source consumer

Status: Accepted. Review: [conditional field PCS skill passes](../../agents/reviews/field-pcs-acceptance.md). Question Q27. Exact conditional contract:
[native field PCS](../../formal/native-field-pcs.md). Companion RFC-0012 A10
and RFC-0020 A5. Motivation: A3/A8 need actual source/context, certificate,
opening and original-claim consumers before native arithmetic can terminate
at expected roots without receiving original tables.

Conditional implementation scope:

> Implement the version-1 field-source bytes, fixed Circle query policy,
> standalone registration certificate and general functional opening exactly
> as specified in formal/native-field-pcs.md. The verifier derives all shapes,
> column indices and counts from expected context. Canonical M31 columns are
> authenticated at their actual queried indices. Complete row messages bind
> before column sampling; complete response blocks bind before continuation.
> An opaque verified certificate is constructed only by full verification.
> Its identity includes expected context, policy, K and the framed canonical
> certificate digest, with collision accounting. This refines A8's exact-byte
> cache identity; it grants no unchecked deserialization or receipt path.
>
> The stele-reductions adapter binds the complete ordered expected source bundle
> before invoking the actual RFC-0006 A1 verifier and consumes every returned original
> point/value through its matching PCS opening. Original tables and arbitrary
> authentication callbacks are absent from its verifier interface. Every error
> aborts the enclosing attempt with no usable accounting or certificate handle.

A9 adopts only the following conditional mathematics from the Draft studies:
for the fixed oracle justified by A8, tensor-opening.md §§1-3 and
certified-functional-opening.md §§1-2 establish the certificate's far-oracle
bound `2*ell*(e+1)/|K| + ((N-e-1)/N)^q_c`, uniqueness of a near message, and
the individual-opening bound `((N-D+e)/N)^q_o`. Their adaptive individual-opening
argument (certified-functional-opening.md §3, final paragraph only) charges
the certificate once plus every opening term over the bounded
lifetime; fresh certificate attempts retain separate obligations. The precise
hypotheses and proofs in those sections are normative for this scope only.
The general batching/grouping optimization and every broader A3 acceptance
criterion remain Draft. A9 authorizes this conditional field primitive without
claiming completion of E4-03 or accepting A3 wholesale.

The independent policy checker verifies all 59 least-count pairs by exact
integer powers, 12 small uniform index distributions and every M31 threshold
exponent. This evidence does not implement the native consumer or its controls.
The conditional losses retain the certificate tensor/query terms, each opening
query term, A8's complete lifetime hash events and all A1 SC terms. No profile,
proven flag, packed/CQIS ownership, fused B, privacy or extraction is admitted.
General multi-functional batching and the original A1/A3/A6/A7 obligations stay.

Implementation must supply native/Python byte parity, actual source controls
NC-0600/0601/0606..0609 and query-schedule control NC-0803, malformed-proof
testing, exact records and repository gates. NC-0606..0609 are reserved as todo; implement their binaries with the
corresponding bindings. This amendment adds no coverage. The original task
criteria remain intact. Cost terms include complete registration, source rows,
encoding, queries, paths, coefficient storage and proof buffers in c_c/T_misc.
No measured constant, native benchmark or extra model weight pass is supplied.

### A10 — Retained field row for the conditional matmul consumer

Status: Accepted. Companions RFC-0007 A2 and RFC-0012 A12.
Review: [coordinated skill sign-off](../../agents/reviews/matmul-contract-accepted.md).
Motivation: A9 §4 deliberately supplies no fused B ownership; its ordinary
producer recomputes the row. Addition to §5 and A9's producer boundary:
[native-matmul.md §2](../../formal/native-matmul.md#2-retained-functional-row-and-prover-schedule)
defines a producer-only immutable row owner borrowing its actual PreparedSource
and exact row weights. Its checked construction visits each message element
once. The matmul fold scratch derives from those retained rows; the opening
serializes the same retained row with no original-message reread or replacement
vector. Expected source/row-weight disagreement rejects before mutation.

This changes no A9 verifier, source bytes, finite policy, wire, challenge or
theorem. The operation's explicit expected original layout is fixed before A4;
it cannot relabel an existing commitment or authorize a new activation cut.
The owner is not a verified certificate or acceptance receipt. Charge retained
rows, folding copies, queries, source/encoded-column reads and full registration
separately. Actual one-pass and row-identity evidence is required in E7-01b;
NC-0611 requires a real column-equation attack, not only an API rejection.
A6/A7, E4-03/E4-04/E4-05, signed packing, short columns and joint privacy retain
all obligations. No fitted cost, complete weight-phase or profile claim follows.

### A11 — Wide int24 residual cuts (companion of RFC-0004 A14)

Status: Accepted. Task E5-05a. Review: [E5-05a sign-offs](../../agents/reviews/wide-residual-a14.md).
Exact addition to §8's packing bullet (int8 ×4 / int16 ×2 per M31): in a wide Model (RFC-0004 A14: every
rmsnorm_q at version 2), wide cut values are int24 and use one value per M31 element; no multi-value packing of int24 is admitted. Non-wide Models are unchanged.
RFC-0004 A14 records the motivation, the ledger impact (no challenge, loss or profile
change) and the cost impact (the cut commit/opening message count doubles; cut storage is
1.5x the int16 bytes). Affected tasks: E5-05c, E6-02/E6-03, E7-10.

### A12 — Full-row fused weight layout (companion of RFC-0007 A1)

Status: Accepted. Review: [RFC-0007 A1 acceptance](../../agents/reviews/rfc0007-a1-acceptance.md).
Withdrawn from §4: "Short-column variant: rows = `j_hi`, columns = `(j_lo, ℓ, k)`;
`B[ℓ,k] = Σ_{j_lo} eq(j_lo, r_j,lo)·u'[j_lo, ℓ, k]`." A fused weight source uses
RFC-0007 A1 item 2's full-row layout (rows j, s=0), and §5's u is RFC-0007 A1 item 3's
retained row: u = B (signed) or B + 2^(w−1) (offset). A split layout needs a new
amendment. No challenge, label or loss changes. Cost and tasks are RFC-0007 A1's.

### A13 — Plan-fixed row shards under a root of roots (Q17)

Status: Accepted. Question Q17. Task E4-07. Companions RFC-0015 A1 and the Q17
resolution in RFC-0019. Review: [sharding Q17 acceptance](../../agents/reviews/sharding-q17-acceptance.md).
Motivation: §9 names a root of roots but no bytes, partition or opening. It also
contradicts itself: it shards rows, yet says a column opening touches one device.
E4-07 asks for the same digest on 1 and N shards, which RFC-0012 A3 cannot give
if the logical partition follows the device count. This amendment fixes the
partition in the statement, so the device count never enters any byte.

Exact replacement for §9 (the Accepted §9 text is withdrawn):

1. **Shard exponent.** A source context carries a shard exponent s, written in
   the layout byte of A9 §1 (and of A3 item 2's version 2): layout `u8(s)`.
   s=0 is the existing single-tree source, unchanged byte for byte. For s>=1 the
   source has S=2^s row shards. Admitted range: `1 <= s <= min(ell, 8)`; any
   other layout byte is UnsupportedSource before any transcript work. Like ell, R
   and C, s comes from the consuming Accepted RFC's expected statement (plan or
   passport), never from a proof byte, a device count, a rank or a topology.
   Every Accepted consumer today fixes s=0. A consumer that wants s>=1 states s
   as a function of public plan data in its own Accepted text (RFC-0015 A1).
   This shard exponent is unrelated to the split index s of
   formal/fused-layout.md §3, which RFC-0007 A1 item 2 fixes at 0.
2. **Shard index.** Shard σ, 0 <= σ < S, holds the R_s=R/S consecutive message
   rows `σ·R_s .. (σ+1)·R_s − 1`, that is, the rows whose top s row-index bits
   equal σ (A9 §1: point coordinate zero is the highest bit). The message M,
   the code, N, D, e, q_c and q_o are those of the same context with s=0.
   Sharding changes only how encoded columns are authenticated.
3. **Child trees.** Each shard encodes its own rows with the source's code and
   commits its N encoded column segments as an RFC-0012 A3 byte-column tree with
   descriptor `{kind: Columns, id, count: N, width: 4·R_s}`. id is the source's
   tensor/tree id. A payload is R_s canonical u32le M31 elements in row order.
   Its root is child root σ.
4. **Root of roots.** The source's expected root (the 32-byte root field of the
   source bytes) is the root of the RFC-0012 A3 kind-2 tree with descriptor
   `{kind: Roots, id, count: S, width: 32}` whose payload σ is child root σ.
   Children are ordered by σ only; arrival order or device rank cannot reorder
   them. Different s give different commitments (RFC-0012 A3); the same s gives
   the same bytes for any device count.
5. **Transcript.** The root of roots takes the flat root's place in every
   existing absorption, with no new label: the consumer's pre-challenge
   commitment, the certificate public input, absorb(Opening) and
   absorb(FieldSources), all through the source bytes. There is no new round
   and no new challenge.
6. **Certificate (A9 §3 for s>=1).** The certificate wire is
   `u8(1) || child_roots || t_bytes || response_block`, where child_roots is the
   S child roots in σ order (32·S bytes). Before creating the transcript the
   verifier parses the complete wire, then rebuilds the kind-2 root from
   child_roots and requires equality with the expected root (RootMismatch).
   The certificate public input is
   `ASCII(stele/v0.1/pcs-certificate/public) || source_bytes || child_roots`.
   So the child roots are bound before CertificateWeight. The certificate ID of
   A9 §3 hashes the full certificate bytes, child roots included.
7. **Responses (A9 §§3-4 for s>=1).** A response to draw c is S segments in σ
   order. Segment σ is `4·R_s` payload bytes followed by `log2(N)` siblings,
   authenticated at index c against child root σ under item 3's descriptor.
   The column is the concatenation of the S decoded segments, which is R
   elements in row order. The column equation, query counts, duplicate rule,
   response-block absorption and error order of A9 are unchanged. Every segment
   is required, including segments whose row coefficients are zero.
8. **Opening.** The opening wire is A9 §4's with item 7's responses. It sends no
   child roots: the verifier takes them from the verified certificate, whose ID
   absorb(Opening) already binds. The certificate record retains them.
9. **Row functional.** Device d computes `Σ_{r in its shards} a_r·M[r,·]` for
   its shards. The prover adds these partial rows in K and sends one t or u.
   Partial rows are not prover messages and are never absorbed or verified.
   Addition in K is exact, so the sum, and every proof byte, is independent of
   device count and reduction order.
10. **What a column opening touches.** With row shards every queried column
    touches every shard: each shard owner returns its segment and path. The
    §9 sentence "column openings touch only the device owning the column shard"
    is withdrawn. Column sharding of one code is not admitted, because an
    encoded column depends on the whole message row.
11. **Frozen oracle (extends A8).** A8's traversal starts at the root of roots.
    A matching kind-2 internal frame fixes two child digests. A matching kind-2
    leaf frame at position σ fixes child root σ, and traversal continues in child
    tree σ under item 3's descriptor. A matching column frame fixes the segment
    of rows of shard σ at its index. Unresolved or malformed subtrees complete with
    zero segments, as in A8. Each recorded input still fixes at most two child
    digests, so `|F| <= 1+2·Q_pre` and the A8 lifetime bound hold unchanged. An
    accepted column equals the frozen W's column outside BadCollision and
    BadLate, by A8 §3's argument applied along the two-level path.
12. **Accepted text that pinned layout 0.** Exact replacements, each in force
    from this amendment:
    - A3 item 2, "Its bytes are A9 §1's table with exactly two changes: version
      is u8(2), and the code identity is the exact 55-byte v2 manifest" becomes
      "Its bytes are A9 §1's table with exactly two changes: version is u8(2),
      and the code identity is the exact 55-byte v2 manifest; the layout byte is
      the same row-major; layout byte u8(s) with s=0 unless the consumer's
      Accepted text fixes s per RFC-0010 A13".
    - A3 item 5, "Purpose, version, layout and policy are constants of this
      amendment." becomes "Purpose, version and policy are constants of this
      amendment. Layout is row-major; layout byte u8(s) with s=0 unless the
      consumer's Accepted text fixes s per RFC-0010 A13."
    - A6, "The layout is A9's row-major layout 0, with logical and padded extents
      equal." becomes "The layout is row-major; layout byte u8(s) with s=0 unless
      the consumer's Accepted text fixes s per RFC-0010 A13, with logical and
      padded extents equal." A6 cut sources may use s>=1 only where their
      consuming Accepted text fixes s; today none does (RFC-0015 A1). The message
      embedding and expansion are per value and do not depend on s.
    - [native-field-pcs.md §1](../../formal/native-field-pcs.md#1-expected-source-and-exact-parameters),
      layout row "u8(0), canonical row-major field elements" becomes "row-major;
      layout byte u8(s) with s=0 unless the consumer's Accepted text fixes s per
      RFC-0010 A13", and "Other layouts or logical extents reject as
      UnsupportedSource" becomes "Layout bytes outside RFC-0010 A13 item 1, or
      other logical extents, reject as UnsupportedSource". For s>=1 the Merkle
      descriptor sentence of that section is replaced by items 3-4.
    - [native-lookup.md §1](../../formal/native-lookup.md#1-statement-and-expected-data), "field, policy=1,
      layout=0 and canonical code identity are not proof choices" stays in force:
      multiplicity sources are always s=0.

Soundness impact. Same N, D, e, q_c, q_o and the same proven PCS terms as the s=0
context (RFC-0012 A15 PCS line, unchanged). No challenge, round, label or registry
entry is added, so no FS term is added. The certificate transcript is still
re-rolled only by changing the root of roots; given that root, child roots are
fixed up to an H event. The H line keeps its formula; its deterministic caps
Q_total, Q_pre,r and Q_after,r must cover the extra child-tree hashes. Item 11 is
the A8 classical ideal-hash argument, conditional in the same way; no conjectured
bound is used. Q12 is unchanged.

Cost impact. Payload bytes hashed are unchanged (N·4R per source). Commitment
hashes S·N leaf frames and S·(N−1) internal frames instead of N and N−1, plus
2S−1 for the root of roots (c_c). A response grows from `4R + 32·log2 N` to
`4R + 32·S·log2 N` bytes; a certificate also carries 32·S bytes of child roots.
Verifier work per response is S leaf and S·log2 N internal hashes, plus 2S−1
hashes once per certificate (T_misc). At Circle rate 1/4 with N=2^22, S=8 and
q_o=130, an opening grows by 130·7·22·32 bytes, about 0.64 MB. No weight pass,
measured constant or fit moves.

Errors and controls. Wire lengths follow from the context, so a wrong number of
child roots or segments is ProofShape before any transcript work; a layout byte
outside item 1 is UnsupportedSource. Reserved todo, owned by E4-07, each through
the actual certificate or opening verifier: NC-0615 one child root replaced by the
root of a different shard (RootMismatch); NC-0616 two distinct child roots swapped,
with their segments swapped in every response (RootMismatch); NC-0617 one child
root and its segments omitted, or one extra appended (ProofShape); NC-0618 a
commitment and proof built honestly at s+1, offered under the expected context
with s (ProofShape), and a context with s > min(ell, 8) (UnsupportedSource);
NC-0619 a valid segment of shard σ placed in shard σ' 's slot (RootMismatch);
NC-0620 one shard committed off-code, or t/u inconsistent with one shard's
segment, with all paths valid (ColumnMismatch); NC-0621 one payload byte changed
in a segment of a shard whose row coefficients are all zero (RootMismatch).
All run at s>=1.

Affected tasks. E4-07 implements items 1-12 with controls NC-0615..0621. E11-01
inherits RFC-0015 A1's plan obligation. E11-02 is unaffected: weight sources stay
s=0 (RFC-0015 A1).

### A14 — Policy 2: FS-aware query counts with grinding, admitted for the standard profile (Q12)

Status: Accepted. Question Q12. Task E12-22. Companions RFC-0012 A17 and RFC-0002 A1.
Decision: ADR-091. Review: [Q12 acceptance](../../agents/reviews/q12-amendments-acceptance.md).
Evidence: [PCS parameter study](../../research/fs-pcs/PARAMETERS.md) and its exact
checker `research/fs-pcs/study.py --check`.

**Motivation.** Policy 1 (A3 item 4) targets 2^-130 per query round with no grinding.
Under RFC-0012 A17's profile condition this overspends on the PCS and still fails (C1)
and (C2) elsewhere. Today's development proof has a worst round of 2^-97 (LogUp) and a
floor of 2^-95.6. Meanwhile the column rounds dominate proof size: 13,471 and 6,713
responses for v2. A17 derives what a query round actually needs, which is 2^-108 after
grinding at standard.

Exact addition to §6, after A3:

1. **Policy byte 2.**
   - The source bytes are those of A3 item 2 and A9 §1, for Circle and v2
     identities alike, with policy `u8(2)`.
   - The verifier derives the policy from the profile: standard selects 2. RFC-0026
     development proofs keep policy 1.
   - Any other policy byte is UnsupportedSource. No proof byte selects the policy.
2. **Query counts.** q_c and q_o are the least positive integers with
   `2^92·(N−e−1)^q_c ≤ N^q_c` and `2^92·(N−D+e)^q_o ≤ N^q_o`, with N, D and e from
   A3 item 3. The resulting immutable u16 tables, written as m (or J): q_c/q_o:

   | Code | Entries |
   |---|---|
   | Circle b=1 | 0: 92/1; 1: 222/92; 2: 222/136; 3: 308/136; 4: 308/152; 5: 339/152; 6: 339/156; 7: 347/156; 8: 347/157; 9: 350/157; 10..29: 350/158 |
   | Circle b=2 | 0: 92/46; 1: 222/66; 2: 222/78; 3: 222/85; 4: 222/88; 5: 222/90; 6: 222/91; 7..28: 222/92 |
   | v2 J | 3: 339/156; 4: 8131/4050; 5: 9297/4633; 6: 9467/4718; 7: 9510/4739; 8: 9532/4748; 9: 9532/4751; 10: 9533/4751; 11..14: 9534/4751 |

   `study.py --check` verifies every inequality and its failure at q−1.
3. **Column grinding.**
   - Every certificate column round and every opening column round grinds
     k_q = 16 bits (RFC-0012 A17 item 5).
   - The nonce is a u64le that follows the absorbed CertificateRow (or
     OpeningRow) and precedes the first column draw. On the wire, the 8 bytes
     come immediately before the response block.
   - So each column round's error is at most `2^-92·2^-16 = 2^-108`.
4. **Tensor grinding.**
   - Before the ℓ CertificateWeight draws, the verifier derives
     `k_t = least k ≥ 0 with 2·ell·(e+1)·2^108 ≤ |K|·2^k`.
   - If k_t ≥ 1, the u64le nonce n_t immediately precedes t_bytes:
     `u8(1) || n_t || t_bytes || …` for s = 0, and
     `u8(1) || child_roots || n_t || t_bytes || …` for s ≥ 1 (A13 item 6).
     S is the state after certificate construction.
   - In OM31, k_t is 0 at every admitted size.
5. **Soundness.**
   - Per round: Lemmas 5 and 6 of fs-composition.md, with grinding counted by
     Theorem 1. Each PCS round is then at most 2^-108.
   - Proven chain: Diamond–Posen Theorem 2 at e ≤ ⌊(D−1)/3⌋ (published), the query
     lemmas of tensor-opening.md §3 and certified-functional-opening.md §2, and
     Theorem 1.
   - Unique decoding only. No Johnson-radius, list-decoding or capacity statement
     is used.
6. **Admission.**
   - For a standard request with QM31 or OM31 challenges, A1's resolver returns
     these Policy 2 parameters, for both the Circle and the v2 identities.
   - For every other profile request it returns UnsupportedParameters.
   - The registry `proven` flag is true for standard, Policy 2 and these
     identities. It stays false for treaty.
   - The treaty tables at a 2^-120 column target (`PARAMETERS.md` §3) are a
     conditional record, not an admission.
   - The whole configuration must also pass RFC-0012 A17 (C1)–(C4).
7. **Superseded Accepted text.**
   - A3 item 7's sentence "Policy 1 cannot be admitted to either profile" and its
     query-round requirement `2^-(target+log2 Q)` are superseded by RFC-0012 A17
     for the standard profile.
   - Policy 1 itself is unchanged, and it remains unadmitted to every profile
     (item 1).
   - A3 item 8's "a policy byte other than 1" reads "a policy byte other than 1
     or 2".
8. **Errors.**
   - A nonce that fails the predicate is GrindMismatch, before any column draw.
   - A missing or extra nonce is ProofShape.
   - A9 §8's errors otherwise apply unchanged.
9. **Controls.** NC-0806 and NC-0807 (reserved, todo, E12-23) run through the actual
   certificate and opening verifiers.
10. **Cost.** A response is still `4R + 32·log2 N` bytes. Each column round adds an
    8-byte nonce and 2^16 expected prover hashes.
    - On the stories42M statement (`PARAMETERS.md` §4, a projection and not a
      measurement), Policy 2 gives 91.7 MB with v2 sources and 18.3 MB with
      Circle rate-1/4 sources. Today's proof is 113.4 MB.
    - Choosing the Circle code for witness and weight sources changes encoding
      work in c_c (circle FFT against linear v2). That needs E16-30's benchmark
      before RFC-0026 adopts it.
    - No measured constant moves.
11. **Tasks.**
    - E12-23 implements items 1–9 in `stele-pcs`, with NC-0806/0807 and Python
      parity, and the LU grinding of RFC-0012 A17 in `stele-reductions`.
    - E16-30 measures a development proof on Circle rate-1/4 Policy 2 sources.
    - This table is the standard-profile input to E12-04. E12-04 itself, the
      treaty codes.toml block, remains open.
