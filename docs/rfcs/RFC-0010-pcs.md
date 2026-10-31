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

Status: Draft. Question Q27. Evidence: [conditional tensor opening](../../formal/tensor-opening.md)
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

Status: Draft. Question Q28. Evidence: [packing and fused-row study](../../formal/packed-commitments.md)
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

Status: Draft. Question Q27. Evidence: [frozen-oracle argument](../../formal/merkle-field-oracle.md)
and [executable controls](../../research/merkle-oracle/REPORT.md).
Motivation: A3's complete field oracle does not follow from byte authentication
alone. A malicious root may contain unresolved digests or malformed field leaves.

Candidate addition to A3's authentication premise, pending native contracts:

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

Status: Draft. Question Q27. Proposed exact contract:
[native field PCS](../../formal/native-field-pcs.md). Companion RFC-0012 A10
and RFC-0020 A5. Motivation: A3/A8 need actual source/context, certificate,
opening and original-claim consumers before native arithmetic can terminate
at expected roots without receiving original tables.

Proposed conditional implementation scope:

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
> before invoking the actual A1 verifier and consumes every returned original
> point/value through its matching PCS opening. Original tables and arbitrary
> authentication callbacks are absent from its verifier interface. Every error
> aborts the enclosing attempt with no usable accounting or certificate handle.

The independent policy checker verifies all 59 least-count pairs by exact
integer powers, 12 small uniform index distributions and every M31 threshold
exponent. This evidence does not implement the native consumer or its controls.
The conditional losses retain the certificate tensor/query terms, each opening
query term, A8's complete lifetime hash events and all A1 SC terms. No profile,
proven flag, packed/CQIS ownership, fused B, privacy or extraction is admitted.
General multi-functional batching and the original A1/A3/A6/A7 obligations stay.

Implementation must supply native/Python byte parity, actual source controls
NC-0600/0601/0606..0609 and query-schedule control NC-0803, malformed-proof
testing, exact records and repository gates. Draft proposed IDs are registered
with implementation; this amendment adds no coverage. The original task
criteria remain intact. Cost terms include complete registration, source rows,
encoding, queries, paths, coefficient storage and proof buffers in c_c/T_misc.
No measured constant, native benchmark or extra model weight pass is supplied.
