# Decision log (ADRs, append-only; template in agents/templates/adr.md)

| ADR | Decision | Status | RFC |
|---|---|---|---|
| ADR-001 | Sumcheck/GKR core; no trace, no zkVM, no fork of Stwo | Accepted | 0001 D1 |
| ADR-002 | M31 base field, QM31 challenges; OM31 for treaty sumchecks pending R-OCTIC | Accepted | 0003, 0012 D10 |
| ADR-003 | Residual-stream-only cuts | Accepted | 0007 §3 |
| ADR-004 | Interleaved-code PCS with fused opening; circle RS for weights, RAA for cuts | Accepted | 0010 |
| ADR-005 | CQIS: int8 matmul inputs, int16 wide path, exact int32 accumulation, round-half-away | Accepted | 0004 |
| ADR-006 | LogUp-GKR for every nonlinearity; double challenge in treaty | Accepted | 0008 |
| ADR-007 | Blake3 transcript/Merkle; Poseidon2 only in wrapper | Accepted | 0012 |
| ADR-008 | Stwo as optional outer wrapper | Accepted | 0016 |
| ADR-009 | Codename Stele; rename is a one-line change in `Cargo.toml` workspace metadata and `scripts/rename.sh` | Accepted | — |
| ADR-010 | Output-side softmax normalisation; attained-max selection sumcheck | Accepted | 0009 |
| ADR-011 | Witness recompute from cuts instead of witness storage | Accepted | 0014 §4 |
| ADR-012 | Treaty profile uses proven PCS bounds only | Accepted | 0010 §6 |

## ADR-013 — Locked JSON parser for benchmark ledgers

Context: RFC-0018 §1, task E0-05 requires validation of untrusted JSON records.
Decision: use exact-version `serde` and `serde_json` dependencies in `stele-bench`,
with Cargo.lock checksums, retained parser depth limits, a byte limit, integer-only
visitation, and duplicate-key rejection at every depth. No derive feature is enabled.
A handwritten JSON parser was rejected because correct escaping, Unicode, numeric
syntax, and nesting checks are substantive parsing work. These dependencies do not
enter the prover or verifier dependency paths. Fetch locked sources before offline
builds. No protocol, soundness-ledger line, or cost-model term changes. Status: Accepted.

## ADR-014 — Canonical scalar M31 boundary

Context: RFC-0003 §§1,2,6, task E1-01 requires scalar arithmetic and lazy reduction.
Decision: keep the M31 limb private and canonical. Arithmetic and explicit modular
conversion reduce; decoding rejects noncanonical limbs. Lazy input is accepted only
in `[0, 2p)` and immediately canonicalised. Signed recovery interprets the RFC's `p/2`
mathematically, so `floor(p/2)` is positive. Zero inversion returns `None`.
The kernel traits use fixed-size little-endian byte arrays without dependencies or
allocation. Tests compare against integer remainder arithmetic. No constant-time,
SIMD/GPU parity, or performance claim is made by this scalar implementation.
No protocol challenge, soundness-ledger line, or cost-model constant changes. Status: Accepted.

## ADR-015 — Exact octic tower and checked signed recovery

Context: RFC-0003 A1, E1-02. Decision: use `v²-u` over QM31, ordered tower limbs,
and `Option<i64>` for recovery from the prime subfield. Reject a square modulus,
noncanonical encoded limbs and nonconstant signed recovery. The norm proof and
independent-arithmetic checks support the modulus choice; profile selection stays
with R-OCTIC. Base-field callers migrate with acceptance. No error term or measured
cost constant changes. Status: Accepted after the named same-agent skill passes in
`agents/reviews/field-cqis-a1.md`; independent review is not claimed.

## ADR-016 — Signed magnitude requantisation

Context: RFC-0004 A1, E5-01, ADR-005. Decision: implement round-half-away by rounding
the nonnegative magnitude and restoring its sign. Reject target overflow; bind the
biased quotient/remainder rather than the unadjusted output. The prior half-up
formula and half-even wording conflict with ADR-005 and fail the documented ties.
Static bounds and actual reduction accounting remain implementation obligations.
No benchmark or model-fidelity result is implied. Status: Accepted after the named
same-agent skill passes in `agents/reviews/field-cqis-a1.md`.

## ADR-017 — Scalar quadratic tower reference

Context: RFC-0003 §2/A1, E1-02. Decision: share the quadratic identities through one
local macro with explicit, fixed types and nonresidue maps. Use three lower-field
products for Karatsuba and recursive norm inversion. Fixed Frobenius coefficients
are checked against prime-characteristic powers of every basis vector and against
an independent power-basis oracle on seeded inputs. Public tuple coefficients are
canonical field types, so composition cannot introduce an invalid limb. No generic
configurable modulus or new dependency is exposed. No challenge, soundness-ledger
line or cost-model fit changes. The scalar multiplication ratio is measured by the
E1-02 microbenchmark, without a GPU or inference claim. Status: Accepted.

## ADR-018 — Checked packed SIMD boundary

Context: RFC-0003 §§1,2,6 and E1-04. Decision: expose fixed blocks of sixteen lanes,
with four columns for QM31 in the Accepted tower basis. Constructors reject limbs
outside the lazy range; exports canonicalise. Explicit backend selection rejects
unsupported CPU/OS features, while automatic detection selects a supported backend.
NEON and x86 widening products share the same quadratic identities. Unsafe code is
limited to the SIMD crate exception in AGENTS.md §6, with documented intrinsic and
pointer bounds. Parity tests inspect raw kernel exits before export normalization.
No allocation, new dependency, challenge, proof binding or weight pass is introduced
by these arithmetic calls. Throughput evidence is a separate E1-04 deliverable;
no cost-model fit or GPU/inference performance is claimed. Status: Accepted.

## ADR-019 — Record native SIMD coverage explicitly

Context: E1-04, RFC-0003 §6. Hosted run 40566209234 assigned AVX-512 to the
correctness job but not to its separate throughput job; the latter correctly
failed the explicit requirement. Decision: ordinary x86 CI requires AVX2 and
executes every available backend, retaining the inventory. AVX-512 coverage is
claimed only from a log/ledger that executed it. E1-04 has explicit native NEON
and AVX2/AVX-512 evidence for unchanged kernel sources. Per-head mandatory
AVX-512 coverage requires a dedicated compatible runner; a successful ordinary
run is not evidence for unavailable hardware. No arithmetic test, unsupported
backend rejection, or proof binding is removed. Status: Accepted.

## ADR-020 — Polynomial table order and signed buckets

Context: E1-05, RFC-0005 §2, RFC-0006 §5 and RFC-0007 §§1,5. Decision:
row-major Boolean tables use the first coordinate as the most significant bit;
partial evaluation fixes trailing coordinates, so each contiguous weight row
produces one result. Dense tables must have power-of-two length, including one
for constants. Signed int4 is checked once and packed low nibble first; int8 and
int16 retain native integer storage. Both strategies read each entry once per
call. Buckets are indexed by value plus half the signed domain and combined by
suffix sums with the signed offset restored. The eq table uses one multiply and
one subtraction per split; its allocation-free verifier evaluator is checked at
extension-field points. No challenge, padding, claim edge, integer bound
certificate or cost-model fit is introduced. Status: Accepted.

## ADR-021 — Canonical transcript contract and honest control dependencies

Context: RFC-0012 A1 and E2-01. Decision: fixed framed BLAKE3 operations, a hashed
initial domain, distinct absorb/request/update tags, explicit extension degree,
masked rejection sampling and mandatory state updates define transcript bytes.
A bounded sampler aborts on exhaustion; it never returns biased fallback values.
E2-00 supplies the primitive and actual gate wiring. E3-01 can then implement real
sumcheck consumers; E2-01 remains incomplete until all its original acceptance
criteria, including NC-0800..0802, hold. NC-0801 is explicitly a configuration
control using the production registry validator, not a toy proof verifier.
Same-author skill passes approve the byte contract, not an independent audit or
Fiat-Shamir security theorem. Q12 tracks the unresolved full FS/H budget. No
catalog control is marked done by the research checks. Status: Accepted.

## ADR-022 — Fixed Poseidon2 permutation, explicit wrapper-mode gate

Context: E2-03 and RFC-0012 A2. Decision: pin width 16, exponent 5, 8 full and
14 partial rounds, the exact Plonky3 0.8.0 matrices/constants, and executed
reference vectors. Core implementation is independent and wrapper-feature-only.
A permutation KAT is not a hash-mode or collision-security theorem. Q14 must
resolve wrapper encoding, capacity, digest and accounting before E14-01 uses it;
native BLAKE3 and the Q12 obligation remain unchanged. Status: Accepted.

## ADR-023 — Explicit sumcheck relation and final evaluation obligations

Context: E3-01, RFC-0006 A1 and RFC-0020 A1. Decision: the verifier owns the ordered
polynomial/instance description; degree follows factor counts. Canonical messages
bind it before rounds, and final values precede continuation. A reduction result
leaves explicit evaluations for real consumers; only the public adapter closes
public tables. Post-proof controls retain a real-prover/verifier honest baseline
and one-value tamper. Research bytes earn no protocol coverage. Direct field
dependencies support the implementation without importing proof systems. Status: Accepted.

## ADR-024 — Canonical Merkle bytes with explicit consumer obligations

Context: E2-02, RFC-0012 A3 and Q16. Decision: authenticate fixed-width byte
columns under a verifier-owned descriptor; use typed absent padding, explicit
position/level framing, full 256-bit digests, exact bottom-up paths and complete
ordered batches. Roots of roots hash ordered child roots as type-2 leaves.
Canonical field/code interpretation and transcript-derived indices belong to
PCS consumers. Membership does not certify unopened subtrees or zero knowledge.
Q17 retains the unresolved 1-versus-N-shard digest semantics; different logical
root lists are not claimed to hash equally. Same-author reviews approve these
bytes, not an independent audit or Q12's full security budget. Status: Accepted.

## ADR-025 — Ordered batch powers and explicit zero-extension

Context: E3-02, RFC-0006 A2 / RFC-0012 A4, Q18. Decision: bind the complete ordered
batch before one gamma, use successive powers, and retain every final obligation.
Unequal instances wrap the whole summand in a leading zero-selector; virtual-tensor
claims use a public coefficient with verifier-computed evaluation. Sparse blocks
accumulate overlaps; arbitrary points do not receive an unconditional linear-cost
claim. Exact RLC/SC records and closed labels remain production gates. Same-author
reviews and research vectors give no control/profile credit. Status: Accepted.

## ADR-026 — Eq-factored zerocheck with original slice claims

Context: E3-03, RFC-0006 A3 / RFC-0012 A5, Q19. Decision: use full weighted
endpoints without random-value division; optionally skip at most four leading
coordinates using integer-node interpolation. The verifier's plan fixes k.
Hybrid finals are recombined from all original tensor slice claims, never
misrepresented as a single MLE or committed as an intermediate tensor. Account
separately for weight collapse, skip and tail rounds. Final payload/consumer
costs remain part of the benchmark, including cases where skipping loses.
Same-author reviews approve the contract; production controls, reference parity,
measured improvement and Q12 remain required. Status: Accepted.

## ADR-027 — Typed small-value storage with ordinary A1 proofs

Context: E3-04, RFC-0006 A5 and Q21. Decision: defer a bounded prefix using
base-field monomial grids, combine coefficients and fold only the small grid in
K, then materialize the reduced original-input tail. Signed/unsigned 16-bit
representations establish optimization eligibility; they do not replace range
proofs, original-value consumers or CQIS integer certificates. Every valid k
retains exact A1 bytes, all final obligations and the inherited SC accounting.
NC-0204 must reject a real truncated-input Small artifact for the unchanged public
statement; research rejects earn no catalog credit. Complete costs and memory,
including transition overlap and losses, remain delivery gates. Same-author
reviews approve the contract, not independent audit or profile security.
Status: Accepted.

## ADR-028 — Canonical circle FFT subspace and full input-size benchmark

Context: E4-02, RFC-0010 A2, Q24. Decision: use the fixed M31 circle generator,
odd-exponent ordered domains, LSB-first y/v_h basis and fully normalized inverse.
Only the FFT subspace is interpolated; the extra full-space dimension is excluded.
Use the deterministic distance lower bound N-k, not an ordinary RS MDS claim.
Encoding is non-systematic. Preserve a 2^30-input-symbol benchmark at both rates:
two rows of length 2^29 at rate 1/2, four of length 2^28 at rate 1/4. Each encoded
row has 2^30 symbols, the maximum ordinary twin-coset output size over M31. All
rows must actually run, with total and per-row dimensions recorded. No single
unsupported 2^30-symbol input row or extrapolated timing is claimed.
Same-author reviews approve the encoder contract, not independent audit, PCS
profile parameters or completion of the actual implementation/benchmark.
Status: Accepted.

## ADR-029 — Sequential sources and preallocated streaming buffers

Context: E3-05, RFC-0006 A6 / RFC-0014 A1, Q22. Decision: explicit round windows
read bit-reversed original-input records, interpolate the same A1 polynomial,
then materialize every original tail at canonical suffix positions. Reuse an
owned work arena and preallocated proof/byte buffers in the bounded path.
Reject unsupported schedules/capacities; a universal two-visit fallback is not
promised. Source preparation, retained capacities, original consumption and
process/device peaks remain explicit evidence obligations. Source metadata is
not authentication, and replay cannot add a weight pass. No challenge, loss or
measured constant changes. Same-author reviews approve the contract, not an
independent audit, actual memory measurement or task completion. Status: Accepted.

## ADR-030 — Deterministic encoder implementation before PCS admission

Context: E4-08/E4-01, RFC-0010 A4 and Q23. Decision: accept the exact v2 map,
manifest/capped expansion, sealed code/field factory and bounded native execution
contract independently of A1's registry/consumer admission. EncoderInfo supplies
only lengths and work counts; no distance, loss, proven flag or profile authority.
Use the existing pinned no_std BLAKE3 primitive for setup expansion only. Every
stream is generated and exhaustion rejects the whole operation without fallback.
E4-08 carries native parity, malformed/fault/compile-fail tests and complete cost/
memory ledgers through 2^20 symbols in all three fields. E4-01 retains every original
criterion, depends on E4-08 and stays blocked on A1. A1/A3/A7, actual PCS/source
consumers, all soundness accounting and Q12 remain open. This stages contract
acceptance and implementation delivery; it does not reduce the full MVP scope.
Same-author skill reviews approve the contract, not independent audit, native
implementation, measured memory/performance or a profile. Status: Accepted.

## ADR-031 — Observe complete encoder work on its production path

Context: E4-08, RFC-0010 A5. Decision: ordinary and measured native encoding share
one implementation. Reports count live owned vector capacities and logical work;
they never affect map selection, output values, errors or profile admission.
Borrowed input, stack/hash state and complete process peaks remain separate
benchmark obligations. Sampling, base work, copies and instrumentation are timed,
with no amortization inferred from sparse counts. No binding, error term, accepted
PCS parameter, fitted constant or weight-pass count changes. Same-author skill
reviews accept the contract; actual native/benchmark evidence remains required.
Status: Accepted.

## ADR-032 — Public coefficient arithmetic before stage integration

Context: E3-06a, RFC-0006 A7 / RFC-0020 A3. Decision: implement six checked
Boolean-table evaluators independently of the blocked A4 stage/source contract.
Selectors and padding are inside the extended table. The immutable API returns
only field values and has no authentication flag or callback. Source disclosure,
CQIS generation, private/virtual consumers, transcript and NC-0203 remain E3-06
obligations. This preserves the complete inference objective while allowing
its arithmetic prerequisites to be tested. No challenge, fitted constant or
weight pass changes. Same-author skill reviews, not independent audit.
Status: Accepted.

## ADR-033 — Conditional fraction arithmetic before complete lookup admission

Context: E3-07a, RFC-0008 A3 / RFC-0012 A9 / RFC-0020 A4, Q31. Decision:
implement exact fraction-tree and selected-product native primitives. Parsers
produce unverified objects; reductions emit original claims. Actual consumers,
controls, parity and complete primitive benchmarks are required before E3-07a
delivery. No receipt, revealing adapter or codec grants lookup/profile/ZK
admission. A2 remains Draft; E3-07 retains its private source/multiplicity,
NC-0400..0403 and c_lu criteria. Native labels/accounting must accompany the
actual engine. No constant or weight-pass count changes. Same-author skill
reviews, not independent audit. Status: Accepted.

## ADR-034 — Exact nonlinear functions and canonical table authority

Context: E5-02 / Q25, RFC-0021 and RFC-0004 A4, RFC-0005 A1, RFC-0008 A4,
RFC-0009 A1, RFC-0011 A2. Decision: accept exact product/nearest exponential,
activation and total RMSNorm integer definitions, versioned component/function/
representation bytes, complete canonical data validation and explicit public
table matrix/code/root derivation. A supplied identity or valid Merkle opening
cannot authorize arbitrary rows. The plan binds operation/source context; the
manifest alone is not a full CQIS configuration or passport. The incomplete
RFC-0004 A2 proposal is superseded; A3 certificates remain unresolved.

Implement native E5-02 generators, immutable validators and public MLE evaluation
under the full RFC-0021 §6 delivery gates. Reserve NC-0412/0413/0414 as todo for
actual consuming bindings, with no new configuration-control exception. Preserve
E3/E5/E6/E7/E9/E10/E12 criteria, including larger-dimension norm work, model
fidelity, complete lookup, private PCS, full outer bytes and ZK. No challenge,
fitted constant, weight-pass count or committed intermediate changes. Same-author
coordinated skill sign-off is not independent audit or native task completion.
Status: Accepted.

## ADR-035 — Closed static arithmetic records with separate expected authority

Context: E5-03 / Q26, RFC-0022 and RFC-0004 A5. Decision: adopt exact static
column derivation and fixed canonical records for the existing scalar Requant
and RMSNorm operations. Expected parameters remain separate from supplied bytes;
all values are rederived. Whole source bounds, canonical digits, both zero carries,
signs, table membership and branch/output relations remain actual proof obligations.
Static norm bounds cover every allowed exponent and retain values wider than u128.

Implement native derivation and byte validation under RFC-0022 §6. No new catalog
coverage, challenge, fitted constant, weight pass or cut follows. Preserve E5-03's
complete quantiser/schema/set/plan contract and NC-0109, all other inference and
fidelity tasks, and full private PCS/ZK/lookup delivery. This is coordinated
same-author skill approval, not independent audit or native/proof completion.
Status: Accepted.

## ADR-036: Conditional Circle field-source closure

Context: Q27 and E4-03a. Decision: adopt RFC-0010 A8/A9, RFC-0012 A10
and RFC-0020 A5 for a field-only consistency primitive and its closed RFC-0006
A1 source consumer. The scoped tensor/certificate/individual-opening lemmas
are normative; broad A3 batching and its remaining acceptance gates stay Draft.

Root/context identifies the original fixed oracle; certificate identity records
replay separately. Every returned original remains an opening obligation.
Conditional records retain losses, while observable local usage supplies no
adversarial-cap estimate or profile decision. Every error aborts its attempt.
Reserve NC-0606..0609 as todo and add E4-03a without weakening parent criteria.
Native parity, controls, resource evidence, packing, fused B, privacy, extraction,
Q12 and inference remain unfinished. No measured constant, cut or weight-pass
change. Review: agents/reviews/field-pcs-acceptance.md records internal agent
skill and owner sign-offs; independent audit is not claimed. Status: Accepted.

## ADR-037: Consolidated delivery and scoped CI

Context: E0-06 and the owner's instruction to consolidate existing work and
finish one task through merge before starting the next. Decision: integrate
published and committed research histories through one existing PR, then use
one active implementation task and one PR. Read-only review remains parallel.

Run the actual native controls, independent reference checks and accounting on
every ready PR. Deduplicate their common validators in one invocation. Partition
the unchanged table corpus and select it from its dependency paths. Require the
normal research inventory when research or shared tooling changes; retain
full-size experiments, copied-source gate mutations, upstream regeneration and
throughput measurements in an explicit manual workflow. Full-size Draft
acceptance claims still require their own evidence. No protocol, challenge,
sample-count, cost-model constant or weight-pass change. Status: Accepted.

ADR-037 execution note: required CI runs on PR events only. Verify the tested
merge tree against current main before each sequential merge; direct
implementation pushes to main are forbidden. This avoids repeating the same
research and native work after merge. No new evidence cache is introduced.

## ADR-038: Preserve native comparisons without rerunning unrelated research

Context: lockfile changes selected the complete research inventory, while isolated
field/CQIS edits omitted seven research commands that actually build and compare
native Rust outputs. Decision: move those seven commands and their two ordered
checkpoint downloads into one native-comparisons group. Exact Cargo.lock and
field/CQIS paths select it; existing broad triggers take precedence and select
all 75 groups. The inherited 176-command union is unchanged. Keep native, table
and aggregate checks mandatory under their existing rules, and remove the table
matrix concurrency cap. No performance number, proof sample count, binding,
protocol or cost-model constant changes. Status: Accepted.

## ADR-039: Measure complete conditional field PCS operations in the harness

Context: E4-03a requires registration/opening runtime, memory and proof sizes,
including the actual closed A1 consumer. Decision: use one native release example
in the unpublished control harness and a sequential fresh-process controller.
Keep its equality-table, JSON and receipt-hash dependencies dev-only, enforced
by the exact manifest/layout gate. No production dependency or API changes.

Include real certificate verification, both sequential functional consumers,
and a bounded three-original A1 case with actual point replay and all-original
closure. Charge setup, validation and cleanup in inclusive native time. Report
whole-pipeline RSS and existing preparation capacities with separate scopes;
do not infer a complete owned-vector peak from partial observations. Preserve
all samples and failed-run artifacts with clean source provenance. No profile,
privacy, fitted constant or weight-pass claim. Status: Accepted.

## ADR-040: Separate the stacked field runtime from private coefficient admission

Context: Draft A4 coupled a public stacked reduction runtime to private-source
formats and joint masking. The existing E12-01 dependency path reaches E3-06,
so requiring that completed masking delivery first would create a cycle.
Decision: accept the complete conditional field contract in RFC-0006 A4 with
RFC-0012 A6 and RFC-0020 A2. Fix complete expected source and statement bytes,
reuse actual A1, restore canonical points, check A7 independently and consume
every original through direct public evaluation or actual A9 openings.

Certified originals have full real dimensions; public originals explicitly
check zero padding. No implicit view, private coefficient format, CQIS identity
or privacy authority is inferred. Preserve all original E3-06 criteria and
require complete native source/control/parity/resource delivery before done.
Private source/format and joint-ZK obligations remain Q20/Q29. Both inference
profiles remain unadmitted. No challenge kind, fitted constant, new committed
intermediate or weight-pass claim is introduced. Status: Accepted.

## ADR-041: Close conditional grouped lookup through existing field consumers

Context: E3-07 remains blocked on the full A2/A8/private contract, while actual
A3 arithmetic and A9 certified sources are available. Decision: accept the
separate RFC-0008 A5 / RFC-0012 A11 / RFC-0020 A6 conditional field contract.
Fix originals before independent unit vectors and all multiplicities before
every denominator pair. Store weighted K multiplicities as canonical M31 limbs;
define the real table prefix by a deterministic view and consume it through
one or two separate actual A9 functionals. No physical-tail-zero assumption or
new PCS theorem is introduced.

The reductions-owned closure uses actual A3/Table/source consumers, caller-owned
verified certificates and borrowed opening records. Explicit local/failure work
and certificate lifetimes remain separate from adversarial caps. Add only the
CQIS/poly dependency permissions needed for those actual APIs. E3-07b requires
native controls, complete parity and resource ledgers; E3-07 retains its original
private/full/source/plan obligations. No new committed intermediate, profile,
Q12/ZK result, cost constant or weight-pass claim. Status: Accepted.

## ADR-042: Preserve fixed false lookup statements in their controls

Context: Workflow 08's ordinary accepted-baseline path cannot accept the false
source256/selector1/range_8 statement required by Accepted RFC-0008 A5 §7 for
NC-0401/0419. Decision: follow that specific contract. Keep an independently
accepted source7 sanity fixture, then use the negative statement's own genuine
source256 certificate, fixed before every outer draw. Declare the single source
or mu deviation through ProverHook, regenerate its dependent real proof work,
and require the unchanged actual closed verifier's RootMismatch. Do not claim
acceptance for the false statement or substitute source7 authority. NC-0415
remains its specified static GroupBound admission check. This clarifies test
authoring only; no protocol, accepted RFC, verifier check, soundness bound or
profile admission changes. Status: Accepted.

## ADR-043: Optimize native tests with runtime checks retained

Context: the unchanged maximum-shape table comparison spends substantial time
in unoptimized field arithmetic. The [E0-07 paired ledger](../../bench/ledger/e0-07-test-profile.json)
records the same tests on one frozen source with independent clean build
directories, including the additional compilation cost. Decision: use Cargo
test optimization level 2 and explicitly retain debug assertions and overflow
checks. Keep every test, seed, shape, oracle and gate command. Default dev and
release settings and broad shared-configuration CI routing remain unchanged.
The measured result is a shared-host screening pair; it establishes neither a
full-CI speedup nor an inference cost constant. Status: Accepted.

## ADR-044: Close stacked field matmul through its original source openings

Context: A4 can prove the stacked product relation and A9 can consume original
functionals, but the operation's source mapping was unspecified and ordinary
opening production rereads the original matrix. Decision: accept RFC-0007 A2,
RFC-0010 A10, RFC-0012 A12 and RFC-0020 A7. Fix expected X(i,l,k) and W(j,l,k)
physical layouts before A4. Retain the exact partial rows for both folding
scratch and actual A9 openings; consume both originals under zero products.

Reuse the existing unclosed A4/A1/A7 kernel and A9 verifier, with one new
absorb-only frame and an operation-specific closed consumer. Keep requested
payload admission separate from actual capacities and process memory. Bounded
reference composition supports the contract; native ownership, controls, full
parity and resource ledgers remain E7-01b delivery requirements. This source
representation is not an implicit R_stack view or a new activation cut. Every
original E7/E4, signed/packed, virtual-source, configured-plan, privacy, profile
and W8 requirement remains. No measured constant changes. Status: Accepted.

## ADR-045: Fix integer Requant advice before every dependent challenge

Context: sign, digits and carries lacked a named committed source; one M31
residue cannot distinguish all signed int32 inputs. Decision: accept RFC-0023,
RFC-0005 A2, RFC-0007 A3, RFC-0012 A13 and RFC-0020 A8. Use four offset input
bytes and one explicit byte-plane advice cut, including full-width caps on
shared role results. Close actual A5/A3/A1 work through three actual A9 groups
and charge four independent-weight RLC events plus every child loss.

The bounded reference review supports this contract. Native implementation,
controls, independent parity and complete resource ledgers remain E7-01d work.
The new cut determines accumulator/result information and adds commitment,
lookup and arithmetic costs. It grants no generic auxiliary commitment or
matmul join: signed original ranges, both accumulator bounds and their real
equality consumer remain required. Full plan, privacy, profile and W8 criteria
remain unchanged; no measured constant or extra weight pass. Status: Accepted.

## ADR-046: Run independent required native checks in separate jobs

Context: the required native workflow serializes core Rust/tooling checks and
the complete digest/control/accounting union, although neither needs a result
produced by the other. Decision: E0-08 moves the unchanged native union to its
own plan-dependent job. Both jobs check out the same event merge source, fetch
their own locked dependencies and must succeed before the aggregate can pass.
Use separate Cargo cache keys and restore prefixes; store no pass receipts.

Retain every validation command, feature/profile mode, corpus, seed, control
and standalone gate. Workflow changes still select the complete table and
research checks. Reusing workspace output for default-feature gates is deferred
because their feature graphs and ownership checks differ. Independent runners
can duplicate compilation or wait in queues; no speedup is inferred from the
old serialized timings. No protocol behavior, inference cost term, profile or
weight-pass count changes. Status: Accepted.

## ADR-047: Select the checked test profile for actual control coverage

Context: Cargo run defaults to an unoptimized dev binary even when a gate has
already used the optimized test profile. The [E0-09 pair](../../bench/ledger/e0-09-control-profile.json)
records cold builds and complete coverage execution on one frozen source, with
identical features, runtime checks, coverage output and argument rejections.
Decision: select the existing test profile at all five direct coverage callers.
Keep the ordinary binary, every control, preceding validation and failure path.
Benchmark preflights stay outside their timed workers.

The single ordered pair on a shared host supports this validation-cost change;
it does not establish full-CI latency or inference performance. No profile
settings, CI routing, protocol behavior, soundness term, inference cost constant
or weight-pass count changes. Status: Accepted.

## ADR-048: Join centered integer matmul through the actual Requant tail

Context: standalone Requant authenticates four int32 bytes, while field matmul
alone cannot distinguish integer residues such as 0 and p. Decision: accept
RFC-0024 and RFC-0005 A3/0007 A4/0012 A14/0020 A9/0023 A1. Require actual
whole-source offset-int8 ranges, derive B=d*128^2 with 2B<p, and include U plus
the complete four-byte magnitude cap in the one named advice cut. Its consumed
linear U claim joins signed matmul at A3's actual tail; charge a separate m/|K|
SZ event. Raw retained rows stay immutable and affine scalar restoration uses
ordinary A9 consumers. Static range registration and request capture are real
separate work; online proof retains one original weight visit.

The coordinated review and bounded algebra/reference rejections support this
specification only. E7-01f still owes native consumers/controls, complete parity
and resource ledgers. Full plan/source ownership, scales, wider/packed dots,
private/virtual sources, Q12/Q29, both profiles and W8 remain open. No measured
constant or generic auxiliary cut changes. Status: Accepted.

## ADR-049: Use the checked test profile for the native lookup corpus

Context: the lookup parity caller still built its ordinary native example with
the unoptimized dev profile. The existing test profile retains debug assertions,
overflow checks and default features. Decision: select that profile at this
caller after a frozen-source comparison produced identical complete outputs
for all 88 requests and reduced the measured validation cost. The independent
oracle, digests, rejection paths and every surrounding gate remain unchanged.

The E0-10 micro ledger separates cold build, native execution and reference
generation, and records the measurement-driver recovery without discarding a
native sample. This changes validation execution only; no inference cost term,
protocol, profile admission, CI routing or parent-task requirement changes.
Status: Accepted.

## ADR-050: Preserve frozen oracle sources when selecting lookup optimisation

Context: complete E0-10 validation rejected ADR-049's direct launcher edit
because the integer-linear manifest pins the entire lookup oracle source.
Decision: restore that source byte-for-byte and apply optimization level 2,
debug assertions and overflow checks through Cargo's dev-profile environment
settings at the gate's lookup subprocess only. This supersedes ADR-049's
launcher choice. Preserve every frozen manifest, payload, source pin and
historical receipt; no compatibility exception or evidence regeneration is
introduced. An existing gate test checks override values and isolation from
the parent and other commands. Actual compiler/output qualification and the
complete gates remain required before E0-10 delivery. Status: Accepted.

## ADR-051: Accept the complete numerical contract before native delivery

Context: the accumulated Q26 proposals used partial model/source descriptors
and incompatible identity or scale choices. Decision: accept RFC-0025 and its
nineteen appendices with RFC-0001 A3/0003 A5/0004 A13/0005 A5/0009 A4/0011 A8/
0016 A4/0017 A3/0021 A3. Exact integer preparation and full-model semantics cover
the original GPT-2-small and Llama-3.1-8B targets. Complete source/configuration,
four-artifact numerical identity and acyclic outer passport/public-input joins
replace the older Draft proposals under the explicit §7.1 disposition.

Independent numerical evidence and same-author skill reviews approve this
specification. They do not supply native implementation or cryptographic admission.
The DAG requires complete typed child contracts, real private PCS/ZK, Q12/Q29,
profiles, original source authority, native controls/parity, named fidelity,
W8/8B and benchmarks at their owners. Fixed passport preparation precedes evidence;
evidence precedes final admission. Every original completion criterion remains.
No new cut, challenge, loss theorem, measured constant or online weight pass.
E5-03 can implement this contract after E5-03b delivery; no second task is claimed.
Status: Accepted.

## ADR-052: Revalidate original-file snapshots with pinned SHA-256

Context: RFC-0025 source §4 requires immutable original bytes or validation during
every consuming pass. Whole-file buffering cannot establish bounded native
loading for the original checkpoints. Decision: pin RustCrypto sha2 0.11.1 with
default features disabled, retaining registry checksums for its complete locked
dependency graph. Its Rust 1.88 minimum fits the pinned Rust 1.90 toolchain; the
MIT/Apache-2.0 license and shared cpufeatures dependency need no policy exception.
Build after an explicit locked fetch, with Cargo offline.

Verify the complete declared length, EOF and original SHA-256 using a bounded
buffer. Retain private SHA-256 digests of the same 65536-byte chunks under an
explicit metadata budget; every consuming chunk read must match that index
before returning owned immutable bytes. These digests are local integrity state,
never serialized source identities, tensor commitments or proof authority.
Full package checks, exact conversion and independently expected original
source authority remain required. Account for initial and repeated chunk hashes
in the deterministic hash-use inventory; no new loss formula or profile credit
follows. This remains preparation T_misc with no measured constant or additional
online weight pass. Status: Accepted.

## ADR-053: Bound original-source replay during native conversion

Context: RFC-0025 conversion requires exact indexed source reads for transposes
and fused Q/K/V parts, while source §4 requires the bytes from the authenticated
snapshot. Decision: retain bounded owned SourceSlice chunks within one numerical
conversion. Clear their relative-offset state when the physical ordinal changes.
Use one slot for consecutive views, one per input column when a transposed raw
row spans at least a chunk, and the complete contiguous chunk span for shorter
raw rows. Derive and admit the full cache allowance before source I/O. Replacing
a slot releases its old chunk before allocating and validating the next one.

Only authenticated immutable original bytes are reused. Scales still requires
two complete logical matrix scans, followed by code emission; no whole decoded
matrix or array of row maxima is retained. Keep the full finite scalar domain,
minimal scale rules, all selected-value checks before the first write, bounded
output chunks and complete-emission digest. Failed output remains unusable, and
actual stored Artifact validation is a separate obligation. Preparation T_misc
is the affected cost term; this introduces no measured constant, protocol field,
cut, challenge or additional online weight pass. Status: Accepted.

## ADR-054: Pin the complete original GPT-2 preparation qualification

Context: E5-03 requires original named-model source conversion, beyond numerical
shape fixtures. Decision: qualify the complete public GPT-2-small checkpoint and
all selected auxiliary files at revision 607a30d783dfa663caf39e06633721c8d4cfcd7e.
Retain all 12 layers, 50257 vocabulary entries, 1024 positions, 196 physical
records, fused Q/K/V transforms, original biases and the single tied token/head
record. The checkpoint SHA-256 is
248dfc3911869ec493c76e65bf2fcf7f615828b0254c12b473182f0f81d3a707.

Use explicit int8 matrices, int16 vectors with fraction 8, fraction 7 for all
residual/projection/norm/activation outputs, dynamic row policies, exact weighted
accumulation, score multiplier 1*2^-3 and direct exp with bits=15, F=7, E=14.
Use the original 1/100000 LayerNorm epsilon and greedy decoding. These are fixed
offline qualification inputs, not calibrated defaults or a fidelity claim; no
overflow changes them automatically. Any later numerical choice remains explicit
and requires its own evidence. Compare every converted value with independent
integer/Fraction arithmetic and all Registry/Bounds bytes with complete oracles.

The disk adapter rereads actual stored Artifact bytes under the emitted digest
and leaves failed output incomplete. Its fixed resource allowances are host
admission choices, not canonical model limits. Original Llama qualification,
tokenizer execution, inference/fidelity, actual production controls, passport,
private proofs, profiles and the W8 workload remain required. Preparation affects
T_misc only; no measured constant, challenge, cut or online weight pass changes.
Status: Accepted.

## ADR-055: Qualify original GPT-2 with explicit int4 matrices

Context: E5-03 requires both int8 and int4 weight conversion. ADR-054's complete
original-source qualification covered int8. Decision: run the same pinned
original checkpoint and complete auxiliary files with matrix precision set to
int4, keeping every other ADR-054 numerical parameter and original dimension.
The manual checker accepts an explicit precision argument; its default remains
int8 with byte-identical Model and Preparation inputs. These choices remain
qualification inputs, not calibrated defaults or a fidelity claim.

Compare every selected scalar and packed Artifact byte, every minimal scale,
and complete SourceConfig, Registry, Bounds and identity bytes independently.
Int4 packing crosses row boundaries and pads only a final odd high nibble.
Retain both qualification receipts and exact executables with their complete
output hashes; neither run substitutes for original Llama qualification or
actual production controls. No native converter or canonical format changes.
The affected work is offline preparation T_misc; no measured constant, online
weight pass, cut, challenge or soundness term changes. Status: Accepted.

## ADR-056: Separate complete prerequisites from final production-control tasks

Context: E5-03 and E6-01 require actual controls whose consumers depend on those
tasks. The user delegated the sequencing decision and approved obtaining the
complete checkpoint. Decision: adopt RFC-0025 A1's reviewed dependency edits.
E5-03c delivers complete original GPT-2-small/Llama-3.1-8B native numerical
preparation; E6-00 delivers native lowering with genuine table/private-source
providers. Each new task must finish all its criteria and merge before the next
implementation task starts. Preserve every original acceptance line verbatim.

E5-03 and E6-01 remain final completion tasks. They wait for actual consumers;
numerical artifacts, parsed metadata and dependency reachability earn no control
credit. No original model, fidelity, W8, privacy, profile or benchmark scope is
reduced. Preserve existing implementation history and frozen qualification
receipts on the old branch; continue it on task/E5-03c-native-preparation without
rewriting history or opening a partial original-task PR.

This is a scheduling decision, not a new protocol. No public API, format,
challenge, claim, certificate, source authority, ledger or cost-model term
changes. Approval to acquire the source remains distinct from actual provider
authentication and complete byte validation. Status: Accepted.

## ADR-057: Pin complete original Llama-3.1-8B preparation inputs

Context: E5-03c requires complete original Llama preparation for both matrix
precisions. Decision: use the authorized meta-llama/Llama-3.1-8B revision
d04e592bb4f6aa9cfee91e2e20afa771667e1d4b, all four original BF16 safetensors
shards and their index, config, tokenizer and generation assets. Check every
upstream LFS SHA-256 or Git blob identity and record a complete SHA-256 manifest.
Keep the full 32 layers, width 4096, 32 query/8 KV heads, head width 128,
hidden width 14336, vocabulary 128256 and context 131072. No alias replaces the
original untied head. Original epsilon and complete Llama-3 RoPE parameters stay.

Use explicit int8 and int4 matrix runs with int16 vectors at fraction 8; all
residual/projection/norm/activation fractions are 7, all row policies dynamic,
score multiplier 46341*2^-19, exact weighted accumulation and direct exp with
bits=15, F=7, E=14. Keep the original generation choice sampled with temperature
3/5 and top_p 9/10. These are fixed numerical-preparation qualification inputs,
not calibrated defaults, an inference result or a fidelity claim. Overflow
must reject rather than silently adjust them.

Compare every original scalar, minimal scale, physical role and packed byte,
then complete SourceConfig, Registry, Bounds and numerical identity. Reuse only
the unchanged, fully qualified independent RoPE reference for the byte-identical
128-wide/131072-position definition; validate the pinned receipt, original
reference files, source pins and full definition before use. Native preparation
still regenerates all 8388608 coefficient pairs. All other reference function
data is regenerated. No historic qualification entry point is rerun.

This affects offline preparation T_misc only. No native format, challenge, cut,
online weight pass, cost constant or production-control coverage changes. Full
original preparation, stored Artifact reread, int8/int4 parity and all remaining
E5-03c acceptance criteria are still required. Status: Accepted.

## ADR-058: Select explicit residual units for original-model execution

Context: ADR-054/055/057 fixed preparation inputs without claiming inference or
calibration. E5-04's first complete original GPT-2 execution rejects an int16 FFN
down output in both Rust and NumPy. The independent original Llama pass rejects
the same operation class. Keep those failures and all original prepared bytes.
The [configuration diagnostics](../reviews/e504-native-execution/configuration-diagnostics.json)
record unsuccessful candidates and reference-only forward results.

Decision: explicitly select fraction 2 for each block's O/down projection output,
mid residual and output residual in both original models and matrix precisions.
Set subsequent norm input fractions to those residual units; the first norm still
consumes the original fraction-7 embedding. Keep every other numerical field,
original shape, physical format, weight byte, scale mantissa/exponent, bias,
epsilon, rotation, attention/activation/logit unit and decoding policy unchanged.
The native executor never retries, clips or changes units after overflow.

The changed Model and Scales require their own hashes. Revalidate the complete
original SourcePackage and derive the changed SourceConfig independently in Rust
and Python. Reuse the original Artifact only after complete stored-byte validation
and the unchanged Preparation/physical-scale checks. The old four-artifact
numerical identity belongs to its original preparation; it is not an identity for
this execution configuration. Definition-only nonlinear point evaluation grants
no new Registry/Bounds identity, proof, source authority or profile admission.

Complete all original-model Rust/NumPy, full/cache, generation and stop tests before
closing E5-04. These are numerical qualification settings, not fidelity defaults;
E5-05's original evaluation and paired-error requirements remain. Compare original
residual/logit/cache bytes through an anonymous pipe without persisting those rows.
No core format, challenge, cut, online proof weight pass or measured cost constant
changes. Full numerical execution contributes to witness construction T_witness;
no performance claim follows. Status: Accepted.

## ADR-059: Accept expander code identity and its separate setup event

Context: E4-01 was blocked on Draft RFC-0010 A1 and its companion RFC-0012 A7,
although A4/E4-08 had already fixed and delivered the deterministic v2 encoder.
The owner directed autonomous resolution of blocking amendments; Workflow 02's
review still applies (agents/reviews/code-a1-accepted.md).
Decision: accept A1 and A7. Supported codes are exactly the Circle and v2
expander identities with immutable distance/setup evidence IDs; the registry is a
compiled two-entry catalog and the parameter resolver fails closed with
`UnsupportedParameters` until A3 admits a proximity radius and query count and
Q12 composes FS/H. The v2 setup event, at most 200431782/2^160 under an ideal
random-oracle assumption on BLAKE3, is a separate ledger term that is never folded
into query or hash terms. NC-0612 reserves identity/evidence substitution under
the first expander PCS consumer. No profile, challenge, cost constant, committed
intermediate or weight-pass change. Status: Accepted.

## ADR-060: Take the RFC-0004 §8 wide residual knob after the first G7 measurement

Context: E5-05 measured the E5-04 runtime (int16 residual, fraction 2, ADR-058) on
Llama-3.1-8B against fp32. Perplexity rose from 5.85 to 178,968 and ARC-Challenge fell
to chance. The int16 ablation (fractions 3-5) never recovered either metric. Under int24
the result is flat across fractions 8-12, with perplexity 6.13-6.15 against fp32 5.97.
Evidence is in [the E5-05 report](../../harness/eval/REPORT.md), produced by an exact
torch executor with 1,000-model parity and byte-identical E5-04 output.

Decision: take the first RFC-0004 §8 knob, the int16 → int24 wide residual path. The
residual stream and the O/down outputs become int24 with 10 fractional bits; every
other CQIS field stays the same. This is the fidelity configuration. G7 is still not
met. Perplexity passes at +3.24% ± 0.18%. ARC −2.90 pp, MMLU-Pro −2.11 pp and IFEval
strict +1.48 pp each exceed their paired SE. The residual is saturated, so the
remaining knobs (per-group weight scales, dynamic scales, attention B/E bits) are
follow-up E5-05b.

The wide path exists only in the harness executor. E5-05a must specify it as an
RFC-0004 amendment through Workflow 02, along with its range certificates and its
cost-model terms (DPA lookups or wider limbs). Native, statement and prover support
follow that amendment. No protocol, soundness, cost constant or Artifact byte changes
here. The E5-04 runtime and ADR-058 stay as recorded. GPQA-Diamond was inaccessible
(gated), so ARC-Challenge substitutes until access is granted. Status: Accepted.

## ADR-061: Accept the wide int24 residual (RFC-0004 A14, RFC-0021 A4)

Context: ADR-060 took RFC-0004 §8's wide-residual knob after E5-05. An int16 residual
cannot hold Llama-3.1-8B's range and precision together; int24 at fraction 10 passes the
perplexity criterion. Review record: [wide-residual-a14](../reviews/wide-residual-a14.md).

Decision:
- **Selection.** A Llama Model is wide exactly when every norm is rmsnorm_q version 2.
  - Version 2 means int24 X, int16 gains, d <= 8192 and a <= 16.
  - Mixing versions rejects with `Width`.
  - No new Model framing is needed: the version sits in the FunctionId, so H(Model),
    H(Registry), H(Bounds) and cqis_id bind the width.
- **Value widths.** In a wide Model, O/down outputs, the middle residual and R_1..R_L
  are int24. R_0 and every other value keep their widths.
- **Static records.** New schemas 20 (RMSNorm), 21 (affine) and 22 (alignment) cover
  the wide slots.
- **Cuts.** Cuts commit one int24 per M31 element. The companions are RFC-0005 A6,
  RFC-0007 A5 and RFC-0010 A11.
- **Controls.** NC-0127..0130 are reserved.
- **Task split.** E5-05a now covers the specification and the research/harness
  reference. Native Model/Registry/Bounds/executor support moves to the new task E5-05c.
- **Limit.** d > 8192 (405B) needs a split statistic and is not admitted.

No challenge, loss, profile, weight pass or measured constant changes.
Status: Accepted.

## ADR-062: G7 gap attributed to per-token activation rows; per-group activation scales next

Context: E5-05 left Llama-3.1-8B (wide residual, ADR-061) at +2.90% perplexity with
ARC/MMLU-Pro outside the paired SE. E5-05b had to attribute this gap to RFC-0004 §8 knobs
on fixed subsets. Evidence: harness/eval/REPORT.md "Attribution" and results/e505b.

Decision:
- **Attribution.** Measured on 8 windows:
  - Per-token int8 activation rows explain +1.81 of the +2.90 points (fp32 simulation).
  - One scale per 128 input features cuts that to +0.13.
  - Weight rows cost +0.09.
  - Intermediate fractions recover at most 0.3 points in exact CQIS.
- **No admitted knob closes G7.** The per-group *weight* scales of RFC-0004 §8 target an
  operand that costs under 0.1 point. Raising fractions saturates.
- **Next step.** E5-05d drafts per-group activation scales: a conversion with one scale per
  g input features (g = 128), threaded through the affine cut. Its proof cost is g-many
  scale lookups per row instead of one. It then re-measures G7 on the full protocol.
  Q/K/V cache rows are in scope, because they share the format.
- **G7 is not claimed.** The residual gap stays recorded here and in the report until
  E5-05d measures it.

No specification, challenge, loss or measured constant changes. Status: Accepted.

## ADR-063: Accept grouped activation rows (RFC-0004 A15, RFC-0005 A7, RFC-0007 A6, RFC-0025 A2)

Context: ADR-062 attributed about 1.8 of Llama-3.1-8B's +2.90% perplexity gap to per-token
int8 activation rows. E5-05d drafted per-group activation scales. Review record (three
independent passes, blocking findings B1-B3 resolved):
[grouped-rows-a15](../reviews/grouped-rows-a15.md).

Decision:
- **Encoding.** Policy mode 2, `u8(2) || u32(g)`, gives one dynamic scale per g consecutive
  features: g is a power of two, g < n and g divides n. It is admitted only on the four
  affine-input rows (first norm output, attention row, second norm output, FFN row) and
  Policy(final). Modes 0/1 keep their bytes, so every existing Model keeps its identity.
  g = n rejects, so each conversion has one encoding.
- **Semantics.** Each group is today's dynamic conversion, s_k = ceil(max|X|/127).
  A' = sum_i s_k(i)*q_i*w_i, then the same single rounding. |A'| <= inner*X*qw < 2^51, equal
  to schema 1's accumulator*scale at the dynamic maximum.
- **Proof form.** Folded values s*q are written as T signed radix-256 digits (T = 2 for
  int16 rows with last digit within 128, T = 4 for the gated row within 64). Each digit row
  is an ordinary field matmul with 8*inner*128*qw < p (2130706432 < p at inner 16384); the
  digit index extends the row index, so the weight pass is unchanged. Folding without
  digits is faithful only for inner <= 257, and per-group partial sums would need 1,703,936
  accumulators per token and layer on 8B instead of 51,200 extra.
- **Joins over Z.** All in byte columns, never one field equality:
  - fold sign: sum_t 256^t*o_t + 2*sigma*F = c + F, which rejects the gated X-p alias;
  - accumulator window: U_t = C_t+cmax_t < 2^29 < p (four bytes plus a top-byte cap 31-u_3);
  - recombination sign: sum_t 256^t*U_t + 2*tau*|A'| = V + |A'|.
- **Records.** Schema 23 (grouped row, below 27 KiB), 24/25 (grouped affine, int16/int24
  output, below 48 KiB). Slot order and count of the Bounds collection are unchanged.
- **Cost.** Llama-3.1-8B, g = 128, all four rows and the head grouped, per token and layer:
  +51,200 accumulators, 26,624 folds, 108,544 digit and 299,008 accumulator memberships.
  The estimate (two memberships per N_act element) is N_act about 388,064 (4.3x), T_act
  0.9 s to about 3.9 s. T_weights, the weight pass count, T_attn and the cuts are unchanged.
  No challenge, loss, profile or measured constant changes.
- **Narrowing of ADR-062.** ADR-062 put Q/K/V cache rows in scope. They are deferred: no
  measurement attributes gain to them, and they feed the score/weighted/cache relations, not
  an affine. Mode 2 on Q/K/V is reserved (it rejects). Task E5-05g owns them if E5-05e
  leaves a G7 gap. ADR-062's "g-many scale lookups per row" is corrected to n/g group
  scales per row.
- **Controls.** NC-0131..0136 are reserved as todo for the actual consumers.
- **Tasks.** E5-05d done (amendments, research reference, torch executor parity).
  E5-05e measures G7; E5-05f adds native support; E5-05g covers Q/K/V.

Status: Accepted.

## ADR-064: Native grouped rows keep one QuantisedRow with n/g scales (RFC-0004 A15, task E5-05f)

Context: E5-05f adds native Policy mode 2, schemas 23-25 and the grouped executor. RFC-0004
A15 fixes the bytes and the numbers; three native representation choices are not in it.

Decision:
- **Row bundle.** A grouped row stays one `row::QuantisedRow`: its codes, its n/g group
  scales (`scales()`, one element for policies 0/1) and its fraction (RFC-0025 A2's bundle).
  `scale()` keeps its meaning for policies 0/1 and returns the first group's scale for a
  grouped row. The executor's projection uses `scales()` whenever the policy is 2.
- **Attained-maximum witness.** `maximum()` returns None for a grouped row. The per-group
  local witnesses j_k of A15's "Group indexing" belong to the schema-23 consumer and are
  added with it (a `shortcut:` note marks the place).
- **Record terms.** The private record builder admits five terms per role instead of four:
  schema 23's gated fold sign join has T = 4 offset-digit terms plus (1,X,2). The research
  reference has no per-role term limit; no other schema changes.

Existing Models, Bounds and execution are byte-identical. Parity: crates/stele-cqis/tests/
grouped_rows.rs against fixtures generated by tests/support/grouped_rows.py.

Status: Accepted.

## ADR-065: Accept characteristic-safe lookups as the A5 mode with b=min(m,30) (RFC-0008 A2, RFC-0012 A8)

Context: Q31 showed that p copies of an invalid tuple cancel in ordinary LogUp over any
extension of M31, and E3-07 was blocked on Draft A2/A8. A3 (fraction trees), A5 (grouped
lookup with A9 consumers) and A11 (labels, joint LU record) were already Accepted and
delivered natively by E3-07a/E3-07b. Review record:
[logup-a2-acceptance](../reviews/logup-a2-acceptance.md).

Decision:
- **One mode.** Every lookup is the A5 grouped-equality-unit protocol, unchanged. The §1
  unit-multiplicity equation and its (N+|T|)/|K| error are withdrawn. No partitioned or
  other weighted mode is specified.
- **Static count bound.** The verifier derives N=2^m, b=min(m,30) and the selector from the
  plan, and r and d from the profile (standard r=1, QM31; treaty r=2, OM31). Each group
  holds at most 2^30<p positions. m<=30 is the ordinary lookup with no Unit draw. Every
  other Statement field comes from the consuming operation's Accepted RFC (RFC-0023,
  RFC-0024); other consumers are not admitted. Plan admission rejects other b (GroupBound)
  and r, d, N or sigma (Statement); NC-0420..0424 are reserved.
- **Why grouped, not ordinary only.** Stacked Llama-3.1-8B lookups are about 1.1-3.9·10^10
  positions per table instance (5-18 times p) under the cost-model projections; ordinary
  unit weight would force splitting into many instances with their own trees and
  multiplicity commitments. A5 already handles m<=59 at h=m-30 extra draws. Those shapes
  are still not runnable: every tuple column must be a committed source and the selector
  is N literal bytes, so they need a committed-source producer or a virtual-column
  amendment and a succinct selector first.
- **Sources.** Tuple columns must be A9-bound original sources. Virtual (uncommitted)
  columns are not admitted until a producer fixes them before the Unit draws (Q31). E7-05,
  E7-06 and E7-07 look up virtual tensors and are blocked on that amendment too.
- **Poles.** Any pole aborts; the honest prover is deterministic and no protocol path
  resamples. Honest pole probability is at most r*t/|K| (completeness only).
- **Ledger.** LU = A11's joint record, min(1,(h+N+c*t-1)/|K|)^r; tree, PCS and FS terms are
  separate and never squared. The r-th power is an interactive bound only. Under
  Fiat–Shamir (hand derivation for Q12) the unit round costs about r*h/|K| (re-rolled by
  grinding the Statement) and the pair round about e_LU^r (re-rolled by grinding free
  multiplicity bytes; one state cannot be split across repetitions). With treaty Q=2^100,
  r=1 on OM31 gives about 2^-108..2^-114 and fails 2^-128; r=2 on OM31 gives about 2^-144;
  QM31 gives a unit round near 2^-20. Treaty therefore needs both r=2 and OM31. No standard
  Fiat–Shamir bound is claimed. No new challenge, label or loss.
- **Deferred.** Private PCS (RFC-0010 A3/A6) may replace A9 only by keeping binding,
  pre-Unit fixation and the same openings; ZK is RFC-0013 A1; Fiat-Shamir is Q12.
- **Tasks.** E3-07 is ready with its original criteria plus plan admission and
  NC-0420..0424. No cost-model constant changes; c_lu is measured by E3-07.

Status: Accepted.

## ADR-066: Plan admission is a pure check against plan/profile-derived lookup fields (RFC-0008 A2, task E3-07)

Context: RFC-0008 A2 item 2 says the verifier derives N, b, sigma, r and d from the plan
and profile and rejects anything else before the first transcript absorb. It does not
fix the code shape, the order of the checks, or which plan count the RFC-0023/RFC-0024
consumers use. These are implementation choices with no soundness effect: the A5
Statement, its bytes, labels and order are unchanged, and sigma stays bound in Statement.

Decision:
- **Shape.** `lookup::admit(statement, positions, profile)` is a pure check of a
  candidate A5 Statement. It does not build one. `lookup::Profile` is a local two-value
  enum (standard: r=1, d=4; treaty: r=2, d=8). The PCS registry's `Profile` lives in
  stele-code, which deny.toml lets only stele-pcs depend on, so it is not reused.
- **Order.** r and d first, then N (positions in 1..=2^59, m = log2 of the least covering
  power of two), then b=min(m,30), then sigma. Only b reports GroupBound; the rest report
  Statement, as A2 item 2 lists.
- **Selector layout.** Real positions are the prefix 0..positions; the padding tail up to
  2^m is unselected. A2 item 3 says positions are "padded up to 2^m", and RFC-0023 already
  uses sigma(i)=1[i<n]. No admitted consumer has masked interior entries.
- **Consumer counts.** RFC-0023 §2.3 and RFC-0024 §§1.1, 2.3 select every physical message
  entry, so the plan count of each of their lookups is the full physical cube.
  `requant::Descriptor::admit`, `integer_linear::Descriptor::admit` and
  `byte_range::Descriptor::admit` run `lookup::admit` on every A5 Statement they build.
  These checks are opt-in. The operation-level verifiers stay profile-free, as
  RFC-0023 §§1, 2.3 and RFC-0024 §1 require: they fix K and r independently, select no
  profile, and must deliver both fields and both repetition counts. A5 primitive tests
  and existing corpora keep working. The plan verifier (E8-02) calls `admit` before the
  first transcript absorb.
- **Controls.** NC-0420..0424 are conditional controls. They run `lookup::admit` on a
  candidate whose honest form is fully proved and verified, not through a production
  verifier entry point. E8-02 carries the obligation to route them through its verifier
  entry point so that they fail if the call is removed.
- **c_lu unit.** c_lu is the time to produce one plan-admitted lookup position, divided by
  the time of one chained M31 multiplication measured in the same process (the e1-02
  method). Original-source commitment is c_c and is not timed. The mu commitment and
  every A9 opening are included. This is a CPU observation and does not refit the GPU
  planning constant.

Consequences: until E8-02 lands, a caller that uses an operation verifier (requant,
integer_linear, byte_range or the A5 descriptor) directly without calling `admit` gets no
A2 item-2 enforcement: it accepts any r in {1,2}, either field, and for the A5 descriptor
any b<=min(m,30), m or selector. Only the E8-02 plan verifier closes this; see its
acceptance line.

Status: Accepted.

## ADR-067: Split E3-08a from E3-08 and move E3-08's controls to their consumers (RFC-0025 A3, task E3-08a)

Context: E3-08 requires NC-0404/0405 and actual NC-0412/0413/0414 consumers. Those
consumers are the RFC-0011 A2 TableBindings record (E12-05a), the RFC-0005 A1
operation references in the lowered plan (E6-00), and the exp recombination at the
attention exp (E7-06) and the sampled-decoding exp (E7-08). E12-05a and E6-00
depended on E3-08; E7-06 and E7-08 are blocked. Building the consumers in E3-08
would mean inventing the plan operation codec and the TableBindings tree ids, which
no Accepted contract specifies. The numerical work (≤2^16 components, the closed
representation mode table in stele-cqis including LayerNorm mode 4, the complete
regenerated Registry, table descriptors and data digests under cqis_id) was already
merged in E5-02/E5-03/E5-04 work.

Decision: accept RFC-0025 A3 under the owner's delegated acceptance (review plus
ADR), following A1's E5-03/E5-03c precedent. Add prerequisite E3-08a, done on the
[audit](../reviews/e308-registry-audit.md); repoint E6-00, E7-05, E12-05a and
E15-07 to it. Keep all three E3-08 acceptance lines verbatim; E3-08 depends on
E3-08a, E6-00, E12-05a, E7-06 and E7-08 and stays blocked. Those owners carry the
controls, quoted verbatim with their expected errors: NC-0404 and NC-0414 at E12-05a
and E6-00, NC-0405 at E7-06 and E7-08, NC-0412/0413 at E6-00. The audit adds one
test that flips each configured component's data digest inside the Registry and
requires `TableData` rejection. No table-binding API is added; stele-lookup is
unchanged.

Consequences: all five catalogue rows stay `todo`, and E3-08 cannot be done before
its consumers run them. Until E6-00 lands, a lookup's Table is not checked against
its configured role; the caller chooses it. No challenge, ledger line or cost term
changes. E6-00 stays blocked on its own contracts and E4-05. The same-author review
and the independent review recorded in the audit sign off A3 and this ADR.

## ADR-068: Accept certified openings with v2 sources and one message element per value (RFC-0010 A3/A6, RFC-0012 A15, RFC-0007 A7)

Context: E4-03 was blocked on Draft RFC-0010 A3 (proximity and query parameters) and
A6 (packing). A9 already delivered a conditional Circle certificate and general
functional openings (E4-03a). §8's "4 int8 / 2 int16 per M31" is impossible: 32 bits
do not fit injectively in M31. Review record:
[pcs-a3-a6-acceptance](../reviews/pcs-a3-a6-acceptance.md).

Decision:
- **One opening mode.** Every functional opening is A9's general opening on a
  certified source. The certificate is required. The certificate-free fresh-tensor
  mode, the batch/grouping protocols and Ligerito are not admitted. Each claim is a
  separate opening unless an Accepted consumer reduces claims first.
- **v2 expander sources.** Source version 2 carries the 55-byte v2 manifest, J=3..14
  (N up to 2^29, inside the A10 sampler). Everything else is A9 verbatim. D comes from
  code-identity.md §2 and holds outside the A7 setup event; the setup term is charged
  once per ledger. Policy 1 (least q at 2^-130 per query round) gives v2 tables up to
  q_c=13472, q_o=6714, checked by check_expander_policy.py.
- **Proven terms only.** Diamond–Posen Theorem 2 at e<=(D-1)/3, plus the proven
  query and near-message lemmas. §6's Johnson and capacity options are withdrawn.
  Soundness is relative to the unique near message; no extractor is claimed.
- **No profile.** Under RFC-0012 §4's Q times the largest round error (hand
  derivation for Q12), Policy 1's query rounds give 2^-30 at treaty and 2^-50 at
  standard. The certificate tensor round fails every profile in QM31, and fails
  treaty in OM31 once ell*(e+1) reaches 2^19. E4-05/E12-04 must fix both before
  any profile carries a PCS line; at 2^-228 the treaty counts are q_c=550, q_o=228
  for Circle rate 1/4.
- **One message element per value.** Packing is withdrawn. Values use the signed or
  offset message embedding named by their consumer, one embedding per source.
  Widths are proven only by a whole-source range lookup (RFC-0024 §1.1 for int8).
  packed30 loses under Accepted RFC-0008 A2, because its lanes would need their own
  commitment. RFC-0007 A7 removes the two-per-element cut packing.
- **Ledger.** RFC-0012 A15 replaces the PCS row with the certificate, opening and
  setup terms, and moves the Merkle lift to H. No new label, challenge or registry entry.
- **Controls and tasks.** NC-0603 is redefined against the actual byte-range
  verifier. NC-0612 is refined, and NC-0613 is reserved. E4-03 is ready with its
  original criteria plus NC-0613. E4-04 stays blocked on RFC-0007 A1. E4-05 inherits
  the FS finding.

- **Independent-review fixes.** Every "one batched opening" sentence is replaced:
  RFC-0007 A7 row 17 and RFC-0001 A4 make each R_stack claim its own A3 opening
  with its own q_o term (RFC-0008 §6's was already withdrawn by A2). RFC-0012 A15
  also gives the exact H row with A8's frontier sum. Cut width is unproven until a
  whole-source lookup or a qualifying limb split is specified; E6-02 must reject
  without one. NC-0614 (expansion) and NC-1207/1208 (embedding, E8-02) are reserved.

Consequences: non-wide int16 cut message counts double. A dense layer opens
R_stack at least twice instead of once. v2 openings send about 50 times the query
responses of Circle rate 1/4. No measured constant moves. int16/int24 committed
sources have no range consumer yet; E6-02 makes that a plan rejection.

Status: Accepted.

## ADR-069: Native version-2 sources, expected-statement parsing and A6 expansion (RFC-0010 A3/A6, RFC-0012 A15, task E4-03)

Context: ADR-068 accepted version-2 expander sources, Policy 1 tables and one message
element per value. E4-03 implements them on the E4-03a Circle consumer.

Decision:
- **One source type.** `Source::from_code_id` admits the 21-byte Circle ID (version 1)
  and the 55-byte v2 manifest with J=3..14 (version 2). Every other identity, including
  J=15, is UnsupportedSource before any transcript work. `Source::new` is the Circle
  shorthand. `bytes()` returns `SourceBytes` (105 or 139 bytes). Certificate public
  bytes, opening frames and the RFC-0006 A1 bundle size use the actual length.
- **Expected-statement bytes.** `Source::from_bytes` parses the exact bytes and accepts
  them only if re-serialization is identical. Version, degree, R, C, layout 0 and
  policy 1 are therefore never read from the bytes; anything else is UnsupportedSource.
- **Evidence pin.** Construction checks that the registry's distance and setup evidence
  IDs are the ones policy byte 1 pins (A3 item 3). A mismatch is
  `Encoder(InvalidRegistry)`. `stele_pcs::registry` re-exports the A1 validator because
  deny.toml lets only stele-pcs depend on stele-code.
- **Context check.** `CertificateRecord::check_source` is the A3 item 8 comparison a
  consumer runs before verify_point (CertificateContext). No Accepted consumer takes a
  v2 source yet, so the NC-0612 handle variant is conditional until E8-02 calls it.
- **Ledger PCS line.** `Parameters` now carries `setup_term` (v2, J>=4). Together with
  N, D, e, q_c, q_o, ell and the field degree, every RFC-0012 A15 PCS-line input comes
  from a verifier-derived record. E8-05 owns the ledger arithmetic.
- **Expansion.** `expand` maps typed i8/i16 values to one M31 element each, under the
  signed or offset embedding. int24 (A11) has no native typed input here and is left
  to the wide-cut consumer task.
- **Research oracle.** The v2 byte oracle is a separate `expander_wire.py`. It reuses
  field_wire.py, which other evidence pins by digest, unchanged.

Consequences: no new label, challenge, loss or profile. Circle bytes, proofs and fixtures
are unchanged. NC-0603 and NC-0612..0614 are done (two NC-0612 variants are
conditional, see the catalog note). `check_source` has no production caller yet:
E8-02 gains the criterion that its plan verifier calls it, so NC-0612 runs through it.
The evidence-ID check compares compiled constants; it is a build-time tripwire, held
by a unit test against stele-code's exported IDs, not a runtime check.

Status: Accepted.

## ADR-070: Accept the full-row fused weight opening (RFC-0007 A1, RFC-0010 A12)

Context: E4-04 (fused opening API) was blocked on Draft RFC-0007 A1, which asked how
B relates to a packed or short-column committed row. RFC-0010 A6 and RFC-0007 A7 have
since removed packing, and RFC-0007 A2 / RFC-0010 A10 already define the full-row
matrix and the immutable retained row. Review record:
[rfc0007-a1-acceptance](../reviews/rfc0007-a1-acceptance.md).

Decision:
- **Layout.** A fused weight source is A2's matrix with rows j and columns (l,k),
  full power-of-two extents, Circle code. The split index s is the constant 0, so no
  field or proof byte selects a layout. Short columns and Ligerito are not admitted;
  RFC-0010 A12 withdraws §4's short-column sentence.
- **Row identity.** The opening row is the A10 retained row: u = B under the signed
  embedding, u = B + 2^(w−1) under offset, checked against RFC-0024 §2.2's v_raw.
  No reduction, copy or alternate row.
- **One visit.** R·C source reads at retained-row construction, zero in the opening;
  column responses and registration are counted separately.
- **No new soundness surface.** No challenge, round, label, loss or ledger line. Each
  phase keeps A2's SC term and adds one A3 opening term. Inherited Fiat–Shamir
  findings are recorded: QM31 sumcheck rounds fail both profiles under Q times the
  round error, OM31 passes; Policy 1 query rounds fail both (RFC-0010 A3 item 7).
- **RFC-0008 A1** is moot for this: no packed source exists to decompose. It stays
  Draft for a future packed format.
- **Controls.** NC-0305 (nonzero-factor wrong row, ColumnMismatch) and NC-0605
  (other-point row or centered offset row, ValueMismatch) are refined, todo, E4-04.

Consequences: E4-04 is ready with its original criteria plus the exact control
variants and counter numbers. E4-06 is blocked: its short columns and Ligerito are
not admitted, and full-u openings are L·d K-elements per weight type (at L=128,
d=16384: 32 MiB in QM31, 64 MiB in OM31). E7-02 is blocked on Draft RFC-0007 A8,
the one-source phase with virtual X, which no Accepted text specifies. No measured constant moves.

## ADR-071: Plan-fixed row shards under a root of roots (RFC-0010 A13, RFC-0015 A1, Q17)

Context: E4-07 asks for the same digest on 1 and N shards. RFC-0012 A3 binds a
root of roots to its ordered child list, so the digest can only be stable if the
partition does not follow the device count. RFC-0010 §9 also mixed row and column
sharding. Review record: [sharding-q17-acceptance](../reviews/sharding-q17-acceptance.md).

Decision:
- **Partition in the statement.** The shard exponent s is the source context's
  layout byte; s=0 is the existing source. For 1 <= s <= min(ell, 8) there are 2^s
  shards of consecutive rows, indexed by the top s row bits. s comes from the
  consuming RFC's plan or passport, never from a device count or a proof byte.
  Devices own whole shards, so 1 and N devices produce identical bytes.
- **Row shards only.** Each shard commits its encoded column segments in an A3
  column tree; the expected root is the A3 kind-2 root over the child roots in
  shard order. Every column draw returns one authenticated segment per shard.
  Column sharding of one code is not admitted.
- **Binding order.** Child roots travel once, in the certificate. The verifier
  rebuilds the root of roots before creating the transcript and puts the child
  roots in the certificate public input. Openings use the certificate's child roots.
- **No new message for partial rows.** Devices' partial rows are summed in K by the
  prover; only t and u are sent.
- **Soundness.** Same N, D, e, q and proven PCS terms as s=0. No challenge, round,
  label or ledger line. A8's frozen oracle extends to the two-level tree with the
  same frontier bound; H caps must count the extra hashes.
- **Controls and tasks.** NC-0615..0621 reserved for E4-07 under a new binding.
  E4-07 stays ready. E11-01 must add an Accepted plan field for s before any cut
  uses s>=1. Weight sources stay s=0, so E11-02 is unchanged.

Consequences: a response carries S paths instead of one (about 0.64 MB more per
Circle rate 1/4 opening at N=2^22, S=8). s=0 sources, proofs and fixtures are
unchanged. Different s values are different commitments, as A3 already states.

## ADR-072: Treaty LU ledger line from the verified lookup record (RFC-0008 A2, RFC-0012 A8/A11, task E12-02)

Context: E12-02 asks for the treaty LU ledger line squared and NC-0403. E3-07b/E3-07
already deliver the A5 engine at r=2 (independent Unit and (Beta, Alpha) draws per
repetition, one multiplicity source each, A11 labels and order), treaty admission
(`lookup::admit`, r=2/d=8, NC-0421/0422) and NC-0403 through the closed verifier.
`LookupParameters` already carries the numerator, d and r, but nothing turns them
into A8's line. ADR-069 left ledger sums to E8-05.

Decision:
- **Line shape.** `LookupParameters::identity_term(profile)` returns `(numerator^r, d*r)`,
  the exact ratio numerator^r/p^(d*r). Integers, no floats. numerator<2^64, so the
  square fits u128 and is below p^4: A8's cap at one never binds and is not coded.
  It returns None unless (r, d) is the profile's own pair, (1,4) standard or (2,8)
  treaty. That pair comes from the same private helper `admit` uses, so there is one
  mapping.
- **Source.** The inputs come from the record the verifier returns, so the line follows
  the verified r and d. E8-05a gains the criterion that it uses this line and nothing
  recomputed from proof bytes.
- **Interactive only.** The line is A8's interactive record. Q12 owns the Fiat–Shamir
  unit round (about r*h/|K|) and pair round (about e_LU^r).
- **Evidence.** `accepts_treaty_lu_ledger_squared` runs plan admission and the actual
  producer and verifier for eight range_8 positions under both profiles: standard
  (263, 4), treaty (263^2, 16). The OM31 NC-0403 Statement now also passes treaty
  admission, so the control runs at treaty parameters.

Consequences: no new label, challenge, loss, NC row or proof byte. Catalog counts are
unchanged. The measured treaty cost stays the E3-07 ledgers: c_lu about 3,500
(treaty) against about 595 (standard) at m=18, roughly 5.9x. E12-03 needs that ratio.
No standard-profile Fiat–Shamir bound is claimed (A2 item 8; Q12).

Status: Accepted.

## ADR-073: The A2 producer is the fused weight-opening API; the opening read counter is live (RFC-0007 A1, task E4-04)

Context: ADR-070 accepted the full-row fused weight opening. `matmul::prove` (E7-01b3)
already opens W from the A10 retained row, raw under the offset embedding, and the
verifiers already check the signed final or RFC-0024's v_raw. The opening's
`ProverWork::source_elements` was never written, so its zero proved nothing.

Decision:
- **No new API.** The fused opening is `RetainedRow::opening` called by the A2 producer
  (field and RFC-0024 centered modes). No new public item, wire byte, label or check.
- **Live counter.** `PreparedSource::message()` is the only accessor of the original
  message (the field is private to its module). Each call is charged as one full R·C
  read in `message_reads()`, an upper bound on elements read. `RetainedRow::new`
  borrows it once (R·C); `RetainedRow::opening_measured` reports the reads made during
  the call as `source_elements`, which is 0. The ordinary A9 opening and certificate
  producer borrow it once per call. A mutation that traverses `message()` inside the
  retained opening fails the stele-pcs, matmul producer and centered tests in both
  fields.
- **Controls.** NC-0305 and NC-0605(a)/(b) run through the closed A2 and RFC-0024
  verifiers in QM31 and OM31. The forgeries are made in the bytes or by the control
  composer, never through the RowContext-guarded API.

Consequences: E4-04 is done. The coverage is for the two-source A2 phase. The configured
one-source phase (RFC-0007 A8) is not specified yet. E7-02 still owns re-running
NC-0305 there and its one-pass counter criterion. No constant, challenge or ledger
line moves.

Status: Accepted.

## ADR-074: Development-profile end-to-end proof over committed integer columns (RFC-0026, RFC-0006 A8, RFC-0008 A6, RFC-0012 A16)

Context: the owner directed a working end-to-end prefill prover comparable to the
FlashProve small route. E8-01 requires ZK (RFC-0013 A1) and passports, so it cannot
be the first end-to-end path. The primitives exist (sumcheck, zerocheck, LogUp A5,
PCS A9), but there are no native proofs for most CQIS operations and no witness
capture. Review record: [rfc0026-acceptance](../reviews/rfc0026-acceptance.md).

Decision:
- **Separate parameter set.** The development profile is a non-ZK parameter set
  that certifies no security level. Its PCS lines are conjectural and its FS line
  is unproven (Q12, Q33). It is not an RFC-0002 §8 profile, and `standard` and
  `treaty` are unchanged.
- **Commit everything.** Every intermediate the executor computes is a witness
  column, named as a cut by RFC-0026 for this profile only (INV-6). Every
  looked-up value is therefore committed, so this profile needs no Q31 virtual
  tuple columns.
- **One relation model.** Each operation is expressed with four relation kinds:
  identities, lookups, ranges, two-factor matmuls and limb compositions, with public columns and
  variable maps. One engine proves any validated relation set.
  `stele_ir::relation::check` is the integer oracle: it evaluates every relation
  over Z with no proof.
- **Static bound rule.** The bound rule `Σ|c|Π mag < p`, together with range
  discipline, is the INV-5 bound certificate for this profile. Values that would
  break it are held as limbs with explicit carries.
- **Placement.**
  - The API lives in `stele-ir`, with no new crate and no new Cargo edge.
  - The engine and the modules live in `stele-reductions`.
  - The orchestration and the development verifier live in
    `stele-prover::development`, behind `stele verify-dev`.
  - The no_std `stele-verifier` is unchanged.
- **Statement.** One prefill window: `T` tokens, a checked range `[r, e)` and the
  next token `y`. Each checked token is the least id attaining the maximum logit
  (RFC-0025 §2.6).
- **Transcript.** RFC-0012 A16 adds four labels; every other message reuses an
  existing label. NC-1300..1310 are reserved. RFC-0006 A8 and RFC-0008 A6 admit
  mode-1 claim batching on committed sources and group-column, shifted and
  variable-mapped lookup tuples, under this profile only.

Consequences:
- The E16 epic (E16-01..E16-11) fans out from the stable API: the modules run in
  parallel, and E16-10 integrates them.
- Development proofs disclose model and activation information through openings,
  and are not admissible as `standard` or `treaty` evidence.
- Matmuls whose operands share a free bit sum over it with an `eq` factor
  (RFC-0026 §3.5).
- The output-uniqueness lemma of each module (RFC-0026 §5.2) is the remaining
  soundness obligation. It is tested by near-miss controls, not machine-checked.

Status: Accepted (same-author passes and the independent pass; fixes recorded in the review).

## ADR-075: Relation engine wire, source geometry and derivation order (RFC-0026 §§2-4, RFC-0006 A8, RFC-0008 A6, task E16-02)

Context: RFC-0026 §4 fixes the transcript order of the development-profile engine,
and RFC-0006 A8 and RFC-0008 A6 admit its claim batching and tuple originals. Several
deterministic choices that both sides must derive from the relation are left to
E16-02: the relation codec, the group source geometry, identifiers, the order of
checks within a step, and the engine's proof bytes. None changes a ledger line.

Decision:
- **Codec.** `stele_reductions::relation::encode` writes every relation field in
  declaration order (fixed-width little endian, u32 length prefixes), after the tag
  `stele/v0.1/relation/encoding/v1`; `digest` is its BLAKE3 hash, absorbed under
  `relation/statement`. `stele-reductions` gains the workspace `blake3 =1.8.7` pin.
- **Group geometry.** A group is one RFC-0010 A3 v2 source with the fixed public seed
  of 32 zero bytes (RFC-0012 A7 holds for every seed). Zero columns pad the count to
  `2^c` with `n + c >= 6`, the smallest v2 message. The expander exponent `J` is the
  one in `3..=min(14, (n+c)/2)` with the fewest certificate-plus-opening bytes (ties:
  smallest `J`), and `ell = n + c − 2J`. Column `j` sits at message offset `j·2^n`,
  so its Boolean index is the leading (high) point coordinates.
- **Identifiers.** Group `g` is source `2 + g`; check `i` (lookups in relation order,
  then ranges in relation order) has A5 identity `i` and multiplicity source
  `2 + #groups + i` with layout `ell = k/2`, blowup 1. Zerocheck, matmul and batch
  instances use disjoint `2^62`-tagged namespaces.
- **Order inside steps.** Multiplicity roots follow group roots under
  `relation/roots`. Within one domain size, identities come first and each `Compose`
  follows as one identity, both in relation order. Lookups precede ranges in step 5.
  A source with no claims is neither batched nor opened. Public-column claims are
  evaluated after the last opening (§8 step 4).
- **A5 statement bytes.** The `lookup/statement` payload is the identity, `m`, `b`,
  `r = 1`, `c`, `t`, `k`, the multiplicity layout and the tuple tensor ids. Table
  rows and tuple maps are bound by the relation digest.
- **Weights.** The caller supplies one verified certificate per `Kind::Weight` column
  in `ColumnId` order; its source must hold `2^log_len` entries. The model roots are
  bound by the caller's `Transcript::new(public)` (RFC-0026 §4 step 1).
- **Proof sections.** `Proof` holds one byte string per §4.1 section, grouped by kind
  (groups, multiplicities, identity sizes, lookups, matmuls, openings). `verify`
  takes `&Proof`, derives the count of each kind and the exact length of every
  section, and rejects any missing, extra, short or long section with `ProofShape`.
  E16-10 frames each section with a length prefix in `stele-dev-e2e-v1`.
- **Openings.** The producer opens what the source commits. It batches over the
  committed table whenever the routed claims hold on it, and the honest prover's claims
  always do. Otherwise it batches over its working table. A lying prover, built from
  the test seam that separates committed values from proving values, therefore fails
  only at the verifier's `verify_point` (`ValueMismatch`). Controls (a)-(d) in
  `relation_tests.rs` use this to pin the identity, lookup, matmul-out and weight
  claim routes.
- **Producer seam.** `claim_batch::Batch::prove_with_point` returns the reduced point
  that the producer already computes, so the prover can open it; verification is
  unchanged.

Consequences:
- Changing any of the above changes proofs and needs a new ADR.
- NC-1300..1310 still need the E16-10 harness: `stele-negative-controls` may not
  import `stele-ir` (deny.toml), so the E16-02 controls are engine tests in
  `crates/stele-reductions/tests/relation.rs` and earn no catalog credit.

Status: Accepted.

## ADR-076: Row conversion and projection relations (RFC-0026 §5 rows 3-4, task E16-05)

Context: RFC-0026 §5 rows 3–4 name the integer definitions (RFC-0025 §2.2, RFC-0004
A8/A15) and the relation kinds, but not the column encoding. The projection value
`V·m·s·2^l` reaches 2^77, and an A15 fold reaches 2^37, so both need the limb rule.
The review of PR #307 found that the first near-miss tests recomputed auxiliary
columns with the honest formulas: they still passed after most constraints were
deleted one at a time.

Decision:
- **Row conversion (int16 rows).**
  - Sign/abs on the masked input, which pins padding to 0.
  - The attained maximum: a one-hot `h`, `h·gap = 0` and a matmul row sum.
  - The ceiling `127s − M ∈ [0,126]`, by lookup.
  - The zero-row branch: `z` with `z·M = 0` and divisor `s + z`.
  - RFC-0026's shared round-half-away division, so static scales reach 65535.
  - Per-row and A15 grouped rows share one relation set.
  - The pattern's `z·q = 0` is not declared, because the division and the half
    bit imply it.
  - The gated conversion belongs to E16-08 (PR #305), which emits the same
    `RowOutput`.
- **Projection.**
  - One matmul `C = q·W`. A15 rows add digit rows `q·s = b0 + 256·b1` and a
    second matmul.
  - No wide value appears in one relation. Two byte chains (one identity per
    position, with carries) prove the sign/magnitude of `V` and
    `|V|·m·s + 2^(K−1) = Y·2^K + ρ`.
  - Carries wider than 16 bits are inline (lo, hi) limbs.
  - A left shift moves positions by `l/8` bytes and is clamped to 16. A
    vanishing right shift replaces the chain with `Ymag = 0`.
- **Witness as a dataflow of steps.** Each step solves its own relation from
  earlier steps. `assign` runs the dataflow and compares the result with the
  executor's codes, scales and outputs.
- **Mutation survey.** Tests lie at one step and complete the rest the way an
  attacker would.
  - `stele_ir::relation::check_except` (a test aid) deletes one constraint at a
    time.
  - Every constraint is either killed by an in-range forgery that changes an
    output, or listed with the reason it is implied.
  - Results are in `agents/reviews/e16-05-projections.md`.

Consequences:
- No challenge, label, cut or cost-model term moves.
- `check_except` is test tooling and no verifier path calls it.
- The following plans are rejected with `Unsupported` and owned in
  `agents/tasks/graph.yaml`:
  - projection domains over 30 variables (E16-10, row-block split);
  - A15 digit rows at `d = 16384` (E16-10);
  - grouped gated folds (E16-08).

Status: Accepted (same-author pass; independent review FIX-THEN-MERGE addressed).

## ADR-077: RoPE gathers the paired channel by a public-permutation matmul (RFC-0026 §5 row 5, task E16-06)

Context: an RFC-0026 identity is pointwise, and a `Ref` can only permute or drop
domain bits. It cannot read the paired channel `i XOR 2^k` without an extra domain
bit, and even with one, split layout works only when `r/2` is a power of two. The
whole numerator `x·c − y·s` (up to `759267328`) cannot be one column, and with
signed-16 coefficients it breaks the §3.6 bound. Review notes:
[e16-06-rope](../reviews/e16-06-rope.md).

Decision:
- The module commits `P = x·Perm`, with one matmul against a public 0/1
  permutation over `(i, i')`. This covers every layout, rotary width and head width
  the `Model` admits.
- The numerator stays uncommitted: `N = (out − β)·2^14 + L`. Coefficients are split
  `hi + one` (signed 15 plus `{0,1}`), so the bound is `3·2^29 + 2^16 + 2^15 < p`.
- Ties go away from zero through `ν = [out − β < 0]` (two's-complement column) and
  the §5 `β` pattern, `tie = (2β−1)(L − 2^13 − ν) − (1−β) >= 0`.

Consequences: one extra M relation and one extra witness column per rotated tensor,
recorded as RFC-0026 A1 (row 5 kinds `I, R, M, P`). The output-uniqueness lemma is in
the review notes.

## ADR-078: One A5 statement per table in the development profile (RFC-0026 A3, task E16-12)

Context: the E16-10 integration showed per-source PCS overhead dominating
development proofs. On the 8-layer d=64, T=64 model, 3,755 per-check multiplicity
sources accounted for 945 MB and the lookup proofs for 469 MB, out of 2.1 GB.

Decision:
- Every lookup into one `TableId`, and every range of one `width.bits`, forms one
  check: one RFC-0008 A5 statement, one multiplicity source and one pair of trees.
- Members are concatenated, largest domain first, into `2^m` aligned positions, with
  the padding unselected. The Statement is A2 item 2 over that domain. `m > 30` is
  rejected, so `h = 0` and every count stays below `p`.
- The prover sends each member's tuple evaluations at the low coordinates of the
  selected-product point. The verifier checks their eq-weighted sum against the
  concatenated claim (`MemberSumMismatch`) and routes each value as an RFC-0008 A6
  column claim.
- Member values are bound by the step-7 batch descriptors that absorb them. No new
  label is introduced.

Consequences:
- The lookup-heavy synthetic relation (80 checks, 3 tables) shrinks from 38.2 MB to
  5.6 MB. Its multiplicity bytes go from 22.8 to 0.97 MB and its lookup bytes from
  11.2 to 0.49 MB. Proving drops from 2.2 s to 0.22 s.
- The LU line is charged once per check, with the concatenated `N`.
- Stacking group and multiplicity sources into one commitment is E16-13.

Status: Accepted (RFC-0026 A3).

## ADR-079: Attention relations: byte chains, attained causal maximum, re-divided output (RFC-0026 §5 rows 6-9, task E16-07)

Context: RFC-0026 §5 rows 6–9 name the integer definitions (RFC-0025 §2.4,
RFC-0009 A4, RFC-0004 A6, RFC-0021 §2.1) and relation kinds, not the encoding. The
score numerator `|dot|·sq·sk·m` reaches 2^55, `T` 2^50, and the output divides by a
committed `Z`.

Decision:
- **Layout.** Score domain `(j, head, i)`, output domain `(c, head, i)` (the O-input
  row layout, so head assembly is the identity). GQA reads K/V through the high
  `log g` bits of `head`, which requires `dh` and `h/g` to be powers of two.
- **Wide values** use E16-05's byte `Chain`: `W = sq·sk` on `(j,i)`, then one chain
  `A·W·m + 2^(k−1) = Q·2^k + ρ`; `Pm·sv` in byte rows with one matmul per byte row;
  sign chains give `|X|` as bytes. The score itself is never committed.
- **Causal max** is the attained pattern over the public `causal = [j <= i < n]`:
  the one-hot matmul writes into the public `real(i)`, and the difference `u` is
  the exp lookup input, so its sign and the exp domain come from the tables.
- **Exp** looks up RFC-0021 components converted on their real rows only; canonical
  zero padding rows are excluded, so `(0, 0)` never becomes a spurious row.
- **Division** by `Z` is `2^(E2+1)·n + Z = 2Zq + r` with `0 <= r <= 2Z − 1` on real
  rows (so `Z >= 1`); for `E2 < 0` the numerator is split at `2^(−E2)` and only the
  half bit enters (`floor((2nh + Z + bit)/(2Z))`), so no shifted product appears.
- **Block mode** rounds each absolute 1024-key block sum and adds the blocks by a
  matmul over the block bits.

Consequences:
- No challenge, label, cut or cost-model term moves.
- `Unsupported::Domain` until amended: matmul domains past 30 variables (no
  row-block split), width-based score bounds of 2^28 or more, mode-1 `B > 29`.
- Lemma A and the deletion survey: `agents/reviews/e16-07-attention.md`.

Status: Accepted (same-author pass; soundness-auditor review requested on the PR).

## ADR-080: Embedding and rmsnorm_q relations through radix-256 chains and one-hot constant selection (RFC-0026 §5 rows 1-2, task E16-04)

Context: RFC-0026 §5 row 2 needs `N·fa = M·D + R` with values up to about 2^153, and
`Y = R(X·H·J/2^e)` with a row-dependent `e`. Columns are at most 30 bits, ranges at
most 16 bits, and terms have at most three factors. Review notes:
[e16-04-embedding-norm](../reviews/e16-04-embedding-norm.md).

Decision:
- Every wide equation is a radix-256 carry chain, one identity per byte position.
  Carry widths are derived from the static term magnitudes.
- The exponent `a` is a one-hot `h[t, a+23]` over the valid `a`. Each `a`-dependent
  constant (`ed·fa`, `en·unit·fa`, `P·fd`, `g = 2^(Es−e')`, `pos·g`, `pos`) is read
  per row, byte by byte, as `Σ_K h·c[K]`.
- The output uses one fixed scale `Es`, a multiple of 8:
  `Z = Y·2^Es − g·XHJ + pos·(σ−1)·g + pos·2^(Es−1) ∈ [0, 2^Es)`. This covers both
  branches: half-away rounding when `e >= 1` and the exact multiply when `e <= 0`.
  The shift is capped at `bits(X)+30`, where every result is already 0.
- rmsnorm_q supports `d <= 8192` only, so its matmul row sums are disciplined by their
  operand widths. The embedding narrows `R0` below int16 when the shift allows, so
  that the rounding identity passes the bound rule.

Consequences:
- A version-1 model with `8192 < d <= 16384` is `UnsupportedModel` for E16.
- The modules add no challenge, label or ledger line.
- They reuse the E16-05 `Builder` and `Chain` (ADR-076). The module-local helpers
  (least-width public columns, byte limbs with a Compose, the sign table) are in
  `development/limbs.rs`.
- Every constraint has a unique name, as `check_except` requires: Compose
  `{column}/compose`, row sum `S{p}{q}/sum`, constant selection `{name}/select`.
  A golden mutation survey pins the class of each constraint (RFC-0026 §5.2).

Status: Accepted (same-author pass; independent review FIX-THEN-MERGE addressed).

## ADR-081: The SiLU gated product as two exact limbs, and its gated row conversion (RFC-0026 §5 row 10, §5.1, task E16-08)

Context: `T = U·silu_q[G]` reaches `2^30`, beyond any column width, and `U·a` alone
has static magnitude `2^30`, so no single identity can hold it under the §3.6 bound.
RFC-0026 assigns row 10, including the gated row conversion to down-projection codes,
to E16-08. Review notes: [e16-08-silu](../reviews/e16-08-silu.md).

Decision:
- The `(G, silu_q[G])` lookup runs against the complete generated component table,
  shared across layers. `new` rejects a table with an output of `−2^15`, so
  `|T| < 2^30` and every int16 input has an assignment.
- The product is split by bytes: `U = Ul + 2^8·Uh` (Compose), `Ul·a = 2^8·c + d`,
  `Uh·a + c = 2^7·Th + w`, each masked so that padding is 0. The output is
  `T = 2^15·high + low`.
- `GatedConversion` reads those limbs and keeps every value wider than 16 bits as two
  radix-`2^15` limbs: `|T|`, the row maximum, the scale and the division remainders.
  Each wide identity is a low and a high identity joined by a carry. The division
  uses the executor's form `q = floor((2|T| + s)/(2s))` directly. Its output is
  E16-05's `RowOutput` with `scale_bound = 8454661`.
- Only the dynamic per-row policy is supported; static and grouped gated rows are
  `Unsupported::Policy`.

Consequences: no committed column is wider than 16 bits except the Compose-disciplined
`scale` (u24). The down projection reads the conversion through the existing
E16-05 interface.

Status: Accepted (same-author pass; independent review on the E16-08 PR).

## ADR-082: One stacked source for every commitment group (RFC-0026 A4, task E16-13)

Context: after RFC-0026 A3, per-group PCS overhead dominates development proofs.
On the 8-layer E16-10 model, 255 group certificates took 469 MB and 313 openings
took 232 MB.

Decision:
- All commitment groups of a proof are aligned blocks of one RFC-0010 v2 stacked source
  source. Blocks are placed largest first, with ties in `GroupId` order.
- A column claim maps to the stacked source point with its block and column index as the
  leading Boolean coordinates.
- There is one certificate, one RFC-0006 A8 batch and one opening for the stacked source.
- The geometry (`J`, `ell`) is the byte-minimising choice over the stacked source size,
  `S >= 6`.
- Multiplicity sources keep A5's own layout. There is one per table after A3.
- Weight sources stay the model commitment.
- One stacked source was chosen over one source per `log_len` class. Under Policy 1
  a source costs about `c·sqrt(N)` at large `N`, so `Σ sqrt(N_i) >= sqrt(Σ N_i)`.
  Measured on 40 groups: group certificates went from 7.5 MB to 4.0 MB and openings
  from 3.5 MB to 1.9 MB.

Consequences:
- NC-1306 becomes root substitution: "replace the stacked root with a multiplicity root".
- What remains is the stacked source's own certificate and opening, which grow with the
  stacked source size under the RFC-0010 Policy 1 query counts. Single-digit-MB proofs at the
  8-layer scale need a PCS parameter change outside RFC-0026.

Status: Accepted (RFC-0026 A4).

## ADR-083: The residual add rounds in two stages, the greedy check sums the vocabulary in blocks, and the model boundary only composes (RFC-0026 §5 rows 11-13, task E16-09)

**Context.** RFC-0025 §2.2 admits any residual fractions in `[0, 30]`, so the aligned
numerator `N = X·2^(c−fx) + Y·2^(c−fy)` reaches 46 bits and the divisor `2^(c−fo)` up
to `2^30`; the stele-cqis Llama fixture already has a 23-bit gap. One whole identity
`N = (out − β)·D + L` meets the RFC-0026 §3.6 bound only for gaps below about 15 bits.
Row 13's `sel_i = Σ_v O·L` meets the matmul bound only for `2^15` summed ids, and a
Llama-3 vocabulary has 128256.

**Decision.**
- Residual: with `F` the input of smaller shift and `G` the other, take
  `T = floor(N/2^s)` and the sticky bit `[N mod 2^s ≠ 0]` from Euclidean splits of `F`
  and `G` (`s = max(0, k − 14)`), then round `T` by `2^(k−s) <= 2^14` with the §5
  division pattern, comparing `2L + st` with `D2 + ν`. A shifted input that would
  break the bound is read through a narrow copy (`G' = G`, smaller declared width),
  which every non-overflowing execution satisfies. `k = 0` is an exact sum with the
  common shift factored out. Every fraction triple validates.
- Argmax: the selection matmul keeps the vocabulary block bits free (`2^15` summed
  ids per block) and a second matmul sums the blocks. `chk[i,v]` is held as the
  product of two broadcast public columns (checked row, real id), so no third `T×V`
  public column exists. A checked token `>= V` is a statement error before any
  relation.

- Model boundary (row 12): `finish::Finish` adds no relation. It composes E16-04's
  `RmsNorm`, E16-05's `RowConversion` and `Projection` (own head source, or the
  embedding column when tied) and the argmax, wired by `ColumnId`s. `Finish::new`
  validates every plan and the statement against a scratch copy of the caller's
  relation, and rejects a token count that is not a power of two or not the row count.

**Consequences.** All residual plans of the RFC-0026 §1.3 class are expressible
without an amendment; wide (A14) streams stay out. Every module constraint is shown
load-bearing by a deletion survey or has a stated redundancy reason over Z
(`agents/reviews/e16-09-residual-argmax.md`).

## ADR-085: Development orchestrator, container and verifier input (RFC-0026 §1.1 A2, §2.2, §4.1, §8, task E16-10)

Context: E16-10 composes the RFC-0026 §5 modules into one relation per prefill
window, fixes the `stele-dev-e2e-v1` codec and the verifier's inputs, and runs the
RFC-0026 §9 controls through the actual verifier. RFC-0026 leaves the weight-source
geometry, the public-input encoding, the container section framing and the model
commitment's carrier to E16-10; one statement gap (norm gains) needed an amendment.

Decision:
- **Placement and edges.** `stele_prover::development` orchestrates; `stele-reductions`
  re-exports `stele_cqis`, `stele_field`, `stele_hash`, `stele_ir` and `stele_pcs`, so
  no new workspace crate edge is added (RFC-0026 §8). `stele-prover` gains the
  workspace-pinned `blake3` for the statement digest. `stele-cli` gains the `stele`
  binary (`prove-dev`, `verify-dev`).
- **Gains are public (RFC-0026 A2).** Every 1-D artifact record is a public input, as
  its ordinal and int16 codes in artifact record order, absorbed in the first
  transcript frame with Model, Scales and Preparation.
- **Public input.** `stele/v0.1/dev-e2e/public-input`, `cqis_id` (`NumericalIdentity`
  of Model, Scales, Registry and Bounds, recomputed by the verifier), length-prefixed
  Model, Scales and Preparation, the 1-D records, the weight roots in plan order, `T`
  and the tokens, `r`, `e`, and `y` behind a presence byte. It is the argument of
  `Transcript::new`.
- **Statement digest.** The container's digest is BLAKE3 of
  `stele/v0.1/dev-e2e/statement`, the public-input length and bytes, and the relation
  digest. The verifier recomputes it before any proof byte is read and rejects a
  difference with `StatementMismatch`. The prover writes this field, so it only fails
  fast; the binding is the transcript, which absorbs the same public input and relation
  digest. Controls restamp it with the verifier's digest and require an engine rejection.
- **Model identity.** A self-consistent `public.bin` proves only that the model it names
  ran. `model_identity` is `cqis_id` and BLAKE3 of `stele/v0.1/dev-e2e/model`, `cqis_id`,
  the weight roots and the 1-D records; `stele verify-dev` prints it with the statement
  before its verdict and `--expect-model` rejects a different model. The 1-D records must
  be exactly the Model's, in record order, and `T` at most the Model's context.
- **Model commitment.** Weight `i` in plan order is the v2 source with id `2^40 + i`
  and the smallest certificate-plus-opening size over `J = 3..14` (ties: smallest
  `J`), the engine's group rule; its message is the int8/int4 codes in the signed
  embedding, `[channel][lane]` with both dimensions padded. Roots and certificates
  are prepared once and travel in the verifier's input file `stele-dev-public-v1`.
  The verifier derives each source from the plan and verifies each certificate.
- **Plan obligation (RFC-0026 §2.2).** Both sides compare the declared `Kind::Weight`
  columns with the plan's weight list (embedding; per layer Q, K, V, O, gate, up,
  down; head) and the commitment count, and reject a difference with
  `StatementMismatch`. Gate is declared before up for this order.
- **Container.** Magic, `u16` version 1, `cqis_id`, statement digest, then the six
  section lists of RFC-0026 §4.1, each a `u32` count of `u32`-length-prefixed
  sections. Trailing or missing bytes reject with `ProofShape`.
- **Controls.** The prover runs the plain checker before proving. `prove_tampered`
  applies a prover-side hook and skips that check, so controls reach the verifier;
  the verifier has no bypass. NC-1300, NC-1301, NC-1304, NC-1305 and NC-1309 are
  registered in `tests/negative-controls`, which therefore may import `stele-prover`
  (one `deny.toml` wrapper edge; the harness is test-only and never linked into a
  prover or verifier). NC-1300 and NC-1301 reject with `RootMismatch`, NC-1305 and
  NC-1309 with `RoundSumMismatch` (RFC-0026 E2).
- **Digest scaffold guard.** The development profile claims no profile and so has no
  reference digest (E8-06). The `digest` scaffold guard over `stele-prover` and
  `stele-proof` admits exactly the RFC-0026 development files and the matching `lib.rs`
  and manifest; any other change to those crates still fails it.

Consequences: a verifier needs only `public.bin` and the proof. Weight sources stay
separate from the stacked witness source (RFC-0026 A4), one opening each. Gains must
become committed weights before any zero-knowledge profile.

Status: Accepted (owner authorisation for A2; independent review in the E16-10 PR).

## ADR-086: Grouped Q/K/V rows are not pursued; the residual G7 gap is in exact-only numerics (RFC-0004 A15, task E5-05g)

Context: E5-05e (grouped activation rows, g = 128) halved every G7 gap but left G7 failing
(WikiText +1.57%, ARC −1.54 pp, MMLU-Pro −1.40 pp; IFEval within its paired SE). E5-05g asked
for the Q/K/V share of the residual before any amendment to the reserved Policy mode 2 on
policies 1–3.

Decision: do not pursue grouped Q/K/V rows. On the fixed 8-window WikiText subset
(`harness/eval/REPORT.md`, "Grouped activation rows (E5-05e)"; `results/e505e/items.sha256`):
- per-token int8 Q/K/V rows cost about 0.23 point in fp32 simulation (+0.13% → +0.36%);
  grouping them per head recovers about 0.1 point (+0.24%);
- in-range fraction knobs on the exact grouped model recover at most about 0.45 point
  (+1.37% → +0.93%) before int16 ranges reject;
- about 0.6 point remains beyond every int8 row, in the exact-only numerics.
A score, weighted-sum and KV-cache amendment for at most 0.1 point does not justify its
proof and review cost.

Consequences: E5-05g is done on its first acceptance branch (attribution). New task E5-05h
owns the exact-numerics residual (exp and normaliser tables, attention probability rows,
rsqrt). The simulation quantises Q/K before RoPE while CQIS rows follow it; this is a
simulation caveat, not CQIS evidence.

Status: Accepted.

## ADR-084: Stacked model commitment (RFC-0026 A5, task E16-14)

Context: after A4, weight sources dominated the openings of the E16-10 8-layer proof.
The model commitment also carried one certificate per weight.

Decision:
- Weights are split in `ColumnId` order into v2 model sources of at most `2^30`
  entries (greedy; one source for any model up to `2^30` entries).
- Inside a source, blocks are placed largest first, with ties in `ColumnId` order.
  Source `k` has id `2^32 + k` and A4's byte-minimising geometry.
- The model commitment is the list of source roots, each with one certificate,
  computed once per model. `model_layout` and `model_messages` let the model
  owner prepare it.
- The verifier checks every certificate against its derived layout. The engine
  absorbs every model root right after the statement digest.
- Each proof has one claim batch and one opening per model source.
- The guards match A4: `n > 30` is rejected, and the cap holds per source.
- `prove` and `verify` take the model as slices: `&[(&PreparedSource,
  &VerifiedCertificate)]` and `&[&VerifiedCertificate]`.
- Root-of-roots shards (RFC-0010 A13) were considered for very large models and
  left open.

Consequences:
- A proof has one weight opening per model source, where it had one per weight.
- E16-10 must commit the model once with the new layout.

Status: Accepted (RFC-0026 A5).

## ADR-087: Prover-side batching and threads without proof changes (RFC-0006 A1, RFC-0010 A4, task E16-15)

Context: profiling the development prover found two hotspots.
- v2 encoding regenerated every expander row by BLAKE3 once per message row.
- Dense sumcheck rounds and folds, mostly in the A5 lookup trees, ran on one thread.

Decision:
- `stele_code::Encoder::encode_rows_measured` encodes all rows of a source at once,
  interleaved. Each sparse row is generated once and applied to every row, so each
  row's codeword is unchanged. `PreparedSource` uses it.
- `stele-sumcheck` splits the column range of dense rounds, zerocheck sums and
  folds across `std::thread::scope` workers under its existing `std` feature. Field
  addition is exact, so the round values, transcript and proof bytes are identical.
  `stele-reductions` enables that feature. `ChallengeField` now requires
  `Send + Sync`, which both QM31 and OM31 satisfy.
- There is no new crate and no protocol or RFC change. `no_std` builds keep the
  sequential path.

Consequences:
- Proof bytes are unchanged; the bench prints a proof digest so a change is visible.
- Prover-side speed now depends on core count. The verifier is unchanged.

Status: Accepted.

## ADR-088: Single-pass dense rounds and a public prover work-splitting module (RFC-0006 A1, RFC-0008 A3, task E16-16)

Context: after E16-15, lookup trees and selected products remain the largest
share of the development prover.

Decision:
- `Dense` rounds read each column once. They build every node value
  `t + x·(t' − t)` by repeated addition of the difference, with no product by `x`.
  The round values are unchanged.
- `stele_sumcheck::parallel` becomes public, adding `for_each_chunk` beside
  `sum_ranges` and `fold`. Callers such as `stele-lookup` get threads only when
  some crate enables `stele-sumcheck/std`; otherwise the work runs sequentially.
  No manifest of `stele-lookup` changes.
- Fraction-tree level construction (each parent from its two children) and the
  selected-product MLE dot products use it.
- There is no protocol, transcript or proof-byte change. The E16-10 fixture hashes
  are pinned.

Consequences:
- Pooled threads, a parallel expander encoder and a cheaper certificate
  registration remain open.

Status: Accepted.

## ADR-089: A real llama2.c checkpoint through the development prover, and development-profile ledger records (RFC-0018 A1, RFC-0026 §7 and E3, task E16-11)

Context: E16-11 asks for development-profile prove/verify time and proof size on the
8-layer synthetic model and on one converted small Llama checkpoint, in `bench/ledger/`,
with a comparison against FlashProve's small route. RFC-0018 §1 admits only `standard`
and `treaty` records, each with a Python verifier time; the development profile is
neither, and RFC-0026 has no Python verifier. Several ADR and RFC-0026 amendment texts
quoted measurements without a ledger record.

Decision:
- **Checkpoint.** Karpathy's llama2.c `stories42M` (MIT; d = 512, 8 layers, 8 heads, hidden
  1376, vocabulary 32000), the closest real Llama to FlashProve's small route as RFC-0026
  §7 records it (8 layers, T = 64, d = 512). It needs no change to the RFC-0026 §1.3 class: no GQA, int8 weights,
  dynamic rows with A15 groups of 128 on the d-wide norm-fed inputs and the head, and the
  Llama-3.1 qualification parameters otherwise (F = 7, gains G = 8, direct exp).
- **Conversion.** `research/cqis-model-contract/stories42m.py` converts exactly: fp32
  values copied, Q/K rows permuted to the half-split RoPE layout 1, and the shared
  classifier written as an explicit `lm_head.weight`. RFC-0025 Llama sources are untied
  (`tie_word_embeddings` must be false, no alias), so the head is a second, identical
  source and commitment. Inputs, converted files, frames and prepared Artifact/Scales are
  pinned by SHA-256; the script checks that the original and converted fp32 forwards
  agree.
- **Ledger (RFC-0018 A1).** A development record is `kind: inference`, `profile:
  development`, workload `dev/<name>`, with a Rust verifier time, no Python verifier time,
  proof bytes, and controls run against the recorded proof. `stele-bench` enforces it.
- **Controls on a supplied proof.** The ignored test
  `rejects_tampers_on_a_supplied_proof` reads a `stele prove-dev` output and checks that a
  wrong `y`, a wrong checked token, a tampered weight root and a tampered public gain are
  rejected by the verifier with the header restamped. The first, second and fourth change
  the public input and are caught by its transcript absorption (RFC-0026 §4 step 1, A2) at
  the first zerocheck round; the third is caught by the model-commitment certificate check
  (§2.2). No binding is added.
- **Unledgered figures.** The proof-byte and time figures quoted in ADR-078 (Context and
  Consequences) and ADR-082 (Context and Decision) have no `bench/ledger/` record and are
  superseded; they are not evidence. Development-profile measurements are cited only from
  `bench/ledger/e16-11-dev-synthetic-8layer.json` and `bench/ledger/e16-11-dev-stories42m.json`.
  The RFC-0026 A3/A4 motivations drop the same figures (RFC-0026 E3).

Consequences: the development prover runs a trained checkpoint end to end with no model
class change. Fidelity is informative only
(`agents/reviews/e16-11-stories42m/fidelity.json`). The comparison with FlashProve's small
route is in `docs/development-e2e.md`; the statements differ (FlashProve hides the weights
and runs on a GPU). No GPU path is measured; it stays behind the INV-3 parity gate.

Status: Accepted (owner authorisation for autonomous amendment acceptance; independent
review in the E16-11 PR).

## ADR-090: Rayon as the prover-side work pool, behind opt-in std features (task E16-17)

Context: the scoped-thread splits of E16-15/16 spawned threads on every round. The
v2 encoder ran sequentially during source preparation. The owner chose rayon over
redesigning the sumcheck strategy interface.

Decision:
- `rayon =1.10.0` (MIT/Apache-2.0) is an optional dependency of `stele-sumcheck` and
  `stele-code` only. It is enabled by their `std` features. `stele-pcs` gains
  `std = ["stele-code/std"]`. `stele-reductions`'s `std` forwards to both. Only
  `stele-prover` turns it on.
- `stele_sumcheck::parallel` runs on rayon's global pool: `sum_ranges` (partials
  combined in chunk order), `fold`, `for_each_chunk` and a block-split `eq_table`.
  Worker panics propagate.
- Under `std`, `Encoder::encode_rows_measured` encodes contiguous row groups in
  parallel. Each group regenerates the sparse rows, and every row's codeword is
  unchanged.
- `CodeField` requires `Send + Sync`, as `ChallengeField` does, and every sealed
  implementor already satisfies it.
- The verifier, `stele-verifier` and every `--no-default-features` build stay free
  of rayon. CI checks `stele-code`, `stele-pcs`, `stele-reductions` and
  `stele-verifier` without default features. `cargo tree` shows rayon only under
  `stele-prover`.
- Proof bytes are unchanged; the E16-10 fixture hashes stay pinned.
- Under `std` the encoder work counters (`generated_rows`, `hash_blocks`,
  `peak_owned_bytes`, `encoder_peak_bytes`) depend on the thread count. They are not
  reproducible across machines, so ledgers must not record them from `std` builds.

Status: Accepted.

## ADR-091: Q12 resolved for the classical ROM; standard PCS parameters admitted with grinding (task E12-22)

Context: Q12 (RFC-0019) had blocked every profile.

- The §4 FS line was a placeholder.
- RFC-0002 §8, read as a total error of 2^-100 against 2^80 queries, could not be
  certified by any Fiat–Shamir bound with 256-bit digests: the hash term alone is
  about 2^-94.
- RFC-0010 A3 item 7's hand derivation failed both profiles.
- The stories42M development proof (113.4 MB) is dominated by v2 Policy 1 queries
  (13,471 and 6,713), while its LogUp rounds are only 2^-97.

Decision:

- **FS theorem.** Adopt `formal/fs-composition.md` Theorem 1: classical ROM,
  round-by-round, counted grinding, error `Q·ε* + ε_floor + H* + ε_setup`, with
  Lemmas 2–6 as the per-round errors. Lemma 4 makes a LogUp (β, α) draw one round
  and charges source-tuple collisions.
- **Profile meaning.** It becomes per-query (RFC-0002 A1). λ = 100 (standard) or
  128 (treaty) and g = 8. The four conditions (C1)–(C4) of RFC-0012 A17 are
  checked by the verifier.
- **H line.** H* replaces A15's H line for profile ledgers.
- **Grinding.** Grinding is a transcript primitive: A1 frame tag 3, label
  `stele/v0.1/grind`, and the least nonce. Only LU, PCS tensor and PCS column
  rounds may grind.
- **Policy 2** (RFC-0010 A14) is admitted for the standard profile, for Circle and
  v2 identities: unique decoding, a column target of 2^-92 and k_q = 16. Treaty is
  recorded only as conditional counts.
- **Not adopted.** Johnson-radius, OOD binding and capacity conjectures.

Consequences:

- **Projected proof size.** The stories42M statement is projected at 91.7 MB with
  v2 sources or 18.3 MB with Circle rate-1/4 sources, against 113.4 MB today. This
  is a study, not a benchmark. The Circle switch waits for the E16-30 encoding
  benchmark.
- **Grinding cost.** About 3.1·10^6 BLAKE3 calls per proof.
- **Development profile.** Unchanged: Policy 1, interactive ledger, no profile.
- **Open:** QROM, ZK composition (Q29), exact native round enumeration (E8-05),
  the consumers (E12-23) and R-FORMAL.

Status: Accepted (owner authorisation for autonomous amendment acceptance, after the
Workflow 02 passes in `agents/reviews/q12-amendments-acceptance.md`).

## ADR-092: Row-block split of matmuls past MAX_VARS through fixed Ref bits (RFC-0026 A6, task E16-19)

Context: every relation domain is capped at 30 bits (RFC-0026 §3.1). A `Ref` could
only permute or drop domain bits, so projections and attention rejected any matmul
past the cap with `Unsupported::Domain`. The llama2.c stories110M head
(`6 + 15 + 10 = 31` bits) was the first real model to hit it. Only the E16-04
embedding gather split, through per-block columns.

Decision:
- A matmul `Ref` may fix a column bit to 0 or 1 (`Ref::FIXED_0 = 0xFE`,
  `Ref::FIXED_1 = 0xFF` in `vars`). Identity and lookup refs may not, so zerochecks
  and lookups are unchanged.
- One shared declare-time helper, `Relation::add_matmul`, splits a matmul past the
  cap on its split bit: the highest free bit `rhs` reads, or the highest free bit
  when it reads none. It recurses until every block fits, block 0 first. A matmul that
  fits is pushed unchanged, so existing plans keep their digests and proof bytes
  (the E16-10 FNV pins hold).
- Splitting on a bit of `rhs` cuts a projection's weight into row blocks. The engine's
  operand table skips entries outside a block, so the weight is read once in total
  and the activation once per block.
- Range discipline: a split `out` is enforced when the slices of its qualifying
  matmuls cover every entry.
- Projections (the head included) and attention declare every matmul through the
  helper. They reject only identity domains past 30 bits.
- The embedding keeps its E16-04 construction. It is exact and already plan-fixed;
  moving it onto fixed bits would drop its recombination identity, and is left open.

Alternatives considered: separate weight columns per block, which would change the
model commitment (§2.2) and the A5 layout. Per-block output columns with a
recombination identity, as in E16-04: it adds witness columns and one identity term
per block, where the fixed-bit form adds neither.

Consequences: matmul shapes are bounded only by their identity domains and by the
A5 per-weight cap of `2^30` entries. Each block adds one matmul's SZ and SC lines;
there is no new line kind, label or challenge.

Status: Accepted (owner authorisation for autonomous amendment acceptance; independent
review in the E16-19 PR).

## ADR-093: llama2.c stories110M through the development prover (RFC-0026 A6, RFC-0018 A1, task E16-20)

Context: E16-19 removed the 30-bit matmul limit that kept models larger than stories42M
out of the development prover. stories110M (d = 768, 12 layers, V = 32000) is the next
llama2.c checkpoint. Its head matmul has 31 bits.

Decision:
- `research/cqis-model-contract/stories110m.py` reuses the stories42M pipeline and CQIS
  configuration at the new shape. It pins its own inputs and outputs by SHA-256; the
  `.bin` digest equals the Hugging Face LFS digest. `stories42m.py` gains a `BIN` name,
  and its own pinned digests are unchanged.
- One proof at T = 64 is recorded in `bench/ledger/e16-20-dev-stories110m.json`, with the
  four supplied-proof tampers rejected. The head is proven as two row blocks (A6).

Consequences: fidelity is informative only
(`agents/reviews/e16-20-stories110m/fidelity.json`). The validation perplexity is 2.124
in fp32 and 2.130 under CQIS. The greedy continuations agree on 7 tokens, then diverge
into different fluent text. The proof is about the CQIS continuation. Prove time and
peak memory grow faster than the parameter count: 1979 s and 109.7 GB on the measured
host. That host differs from E16-18, so the times are not compared.

Status: Accepted (owner authorisation; independent review in the E16-20 PR).

## ADR-095: Adopt the build program — tiers, ladder, lanes, milestones (RFC-0027, RFC-0018 A2, task E17-00)

Numbering: ADR-091 and ADR-094 are reserved by changes under review (tasks E12-22 and
E12-11), so this record and the next take 095 and 096.

Context: the owner asked for an assessment of the project and a plan to build the
leading prover of inference in the order "make it work, make it fast, make it right",
in a building mode that reaches a working end-to-end system and then iterates. The
assessment (`docs/assessment.md`, at `6441a90`) found:
- one working end-to-end proof (RFC-0026) that commits about 1,000 cells and runs about
  600 lookup positions per token, layer and unit of width, claims no security level and
  runs on CPU;
- a task graph with 4 pickable tasks out of 157, none on the path to an inference
  proof; the prover task E8-01 has 22 unfinished prerequisites, 11 of them blocked on
  amendments (17 tasks are blocked in all);
- a security target no parameter set can meet (RFC-0019 Q12, RFC-0010 A3 item 7);
- a public system with the thesis's shape (FlashProve v0.16.0, 2026-11-02): 111 tok/s
  on a 400B mixture-of-experts model on one H100, 18.78 MB proofs, zero knowledge.

Decision:
- **RFC-0027 is Accepted by owner direction.** It changes no protocol behaviour. It
  defines three tiers bound to the profiles (development, `standard`, `treaty`), a
  workload ladder L0 to L6 with a generated scoreboard, seven lanes with one open
  change each, and gates M0 to M7.
- **RFC-0018 A2 is Accepted with it**: rung ids are workloads, records carry stage
  times and counters once E17-01 lands, `bench/scoreboard.md` is generated.
- **The task graph gains epics E17 to E23.** Legacy epics E3 to E15 keep their tasks
  and acceptance text as the treaty backlog; RFC-0027 §6 records what supersedes,
  parks or resumes each. E4-07, E5-06 and E15-07, which were pickable, are parked.
- **The small-model gate is stories42M (rung L2).** GPT-2-small (W8) becomes
  architecture coverage and gates nothing in E17 to E23.
- **INV-6 and INV-7 are scoped** to `standard` and `treaty` plans, as RFC-0026 §1.2
  already treated them. INV-14 (ladder evidence) and INV-15 (end to end stays green)
  are added.
- **Development-tier protocol changes take a short amendment** and one reviewer from
  another lane. Promotion to `standard` or `treaty` keeps the full Workflow 02 path
  and the soundness-auditor.
- **Lines of work stopped:** new work on the v2 expander source, per-operation advice
  cuts for new operations, double-challenge LogUp as the route to 100 bits, dual-prime
  accumulation, and epoch beacons before M6. Delivered code stays until replaced.
- `bench/dev_e2e.py` accepts `--counters` so a record can carry proof section bytes;
  `bench/ledger/e17-00-dev-synthetic-8layer-4core.json` is the first record made
  that way.

Alternatives rejected:
- *Continue the first design's graph.* Its critical path waits on at least eight
  amendments, one of which (Q31) asks for something unsound as posed.
- *Adopt or fork FlashProve.* Forbidden by guardrail 5; it is unmaintained, fixed to
  one architecture and a 64-bit field, and its own report lists the optimisations it
  left out. It is the benchmark and a reference for differential study.
- *Rewrite from zero.* The field, transcript, sumcheck, lookup, encoder, CQIS and
  relation-engine code is sound, tested and reusable; the plan changes what is
  composed, not the primitives.
- *One global queue.* It produced the present frontier of four pickable tasks.

Consequences:
- The pickable frontier is nine tasks in six lanes (E5-05h, E17-01, E18-01, E19-01,
  E19-02, E21-01, E21-02, E22-01, E22-03).
- No proof may claim `standard` or `treaty` before RFC-0030 is Accepted.
- Agents read `docs/plan.md` and the lane rules before picking a task; AGENTS.md,
  the workflows, the skills and the templates are updated in the same change.
- No soundness ledger line, cost-model constant or proof byte changes.
- This record was merged with `main` after E16-17 to E16-20. E16-17 (ADR-090) had
  delivered the work pool, so task E20-02 keeps the parallel checks only. E16-19
  (ADR-092) had delivered row blocks, which task E22-03 uses. The E16-18 ledgers are
  the L1 and L2a baseline, with two records from the planning host at `21710de`.
  stories110M (E16-20, ADR-093) is rung L2c. The lane rule allows a stack inside a
  lane, as the changes under review use. `docs/plan.md` §6 lists that work and how
  the plan absorbs it.

Status: Accepted (owner-directed; the lane, tier and gate definitions are the
planning agent's proposal within that direction and are listed for the owner's
confirmation in `docs/plan.md` §10).

## ADR-096: Design direction recorded as Draft — commit rule, commitment scheme v3, per-round accounting, zero knowledge (RFC-0028, RFC-0029, RFC-0030, RFC-0013 A3, RFC-0026 A7/A8)

Context: the plan's gains come from four protocol changes. Each needs evidence and
review before it binds code (INV-1). Recording them as Draft RFCs gives every lane a
precise target without admitting anything.

Decision (direction, not law):
- **Commit rule (RFC-0028).** Commit exactly the advice: outputs of rounding,
  clamping, selection, digit splitting and tables. Arithmetic results are virtual
  columns reduced by sumcheck. The witness is proved in segments that carry only the
  residual boundary, which is committed even when its value is arithmetic. This is
  the sound form of INV-6 and answers Q31 for virtual tuples. The first design's
  lookups over uncommitted tensors are not pursued. Acceptance needs companion
  amendments, because RFC-0008 A2 item 4 and A6 exclude virtual tuple columns today:
  new amendments to RFC-0008, RFC-0026 and RFC-0012, numbered at acceptance
  (RFC-0028 §1.4).
- **Commitment scheme v3 (RFC-0029).** Interleaved circle Reed–Solomon with a
  recursive opening. Fresh mode for the stacked witness source of each segment and
  for the recursion levels; certified mode for model sources, with one claim per
  weight role so that the opening's row combination is the weight pass. Multiplicity
  sources are in neither mode and keep their RFC-0010 A9 form until Q51 is answered.
  Proven parameters only, at radius `D/3` (Policy 3: 241 queries per level at rate
  1/4 for 100 bits). Rows are in coefficient form (a new code identity with the
  codewords of RFC-0010 A2), because the recursion needs the code's evaluation
  functionals to be tensors. Acceptance needs new amendments to RFC-0010 and RFC-0012
  (RFC-0029 §1.4). RFC-0026 A7 moves the development engine from v2 expander sources
  to the circle sources that already exist.
- **Security accounting (RFC-0030).** Round-by-round error with hash queries
  multiplying the largest round; `standard` at 100 bits on QM31 with every round's
  numerator capped at `2^24 − 1` (lookup instances, commitment rows, batches);
  `treaty` at 128 bits on a wider challenge field; no grinding counted; proven bounds
  only in both. RFC-0026 A8 supplies the lookup instance split. The caps cost proof
  bytes (independent instances carry their own tree proofs; short rows mean many
  rows) unless data-parallel instances (Q49) and the challenge field of the
  commitment rounds (Q50) are decided first. Both are priced before promotion.
- **Zero knowledge (RFC-0013 A3).** Bounded-query encodings, mask rows and committed
  sumcheck masks on scheme v3, with an opening budget and a published leak list; a
  pad-and-prove construction is the alternative until task E23-01 decides. The
  encoding hides only when the randomiser block of the generator has full rank on
  every queried set; E23-01 proves that or changes the encoding.
- **Field.** M31 with QM31 challenges stays (ADR-002). A 64-bit field with
  random-projection range checks, as FlashProve uses, is not adopted; bet B2 of
  `docs/plan.md` states when to revisit it.

Alternatives rejected for now:
- *WHIR or FRI openings for the weights.* Each opening hashes a codeword the size of
  the weights; a recursive interleaved opening hashes only the row combination.
- *A linear-time first-layer code.* Its proven radius costs several times the
  queries; kept as the fallback of bet B3 (Q45).
- *List-decoding parameters.* They need a wider field and a transfer lemma for the
  circle code (Q39); unique decoding is enough for `standard`.
- *Conjectural proximity bounds.* The capacity conjectures were disproved in 2025.

Consequences:
- Tasks E18-01, E19-01, E19-02, E20-02, E21-01 and E23-01 carry the acceptance of
  these texts. Until then code follows the Accepted RFC-0026 and RFC-0010. Task
  E20-09 decides Q49. Task E21-09 is the promotion of the lean protocol to
  `standard` and gates M3 and M4.
- New control ids are proposed in the drafts (NC-0630..0635, NC-0810..0812,
  NC-1320..1325) and enter the catalogue at acceptance.
- Questions Q34 to Q51 are opened in RFC-0019.
- The drafts were reviewed once by an independent agent and its findings are applied
  in the texts as recorded here. That review is not an acceptance review.

Status: Proposed (Draft RFCs; each is decided by its acceptance task).
## ADR-094: Accept the proved ZK components separately; keep the complete construction in RFC-0013 A1 (RFC-0013 A2, RFC-0010 A15, RFC-0012 A18, task E12-11)

Context: the owner asked for zero-knowledge (weight hiding) for the development
path, the property FlashProve has and RFC-0026 lacks. RFC-0013 A1 (Draft) asks for
the complete construction: Circle and expander paths, the 5% overhead target and
native evidence. The design note (formal/zk-development.md, task E12-10) proves
four component lemmas but finds two leaks in the obvious claim masking and leaves
the composition open (R1–R13).

Decision:
- A1 is the wrong vehicle for the components: accepting it would claim the whole
  construction. A2 admits only the proved components, with exact bytes, labels,
  order and budgets, for no profile and no consumer: hiding Circle sources
  (version 3, mask half, mask rows, salted leaves, public rank check) and the
  masked A1 sumcheck (`zk/mask-sum`, `zk/mask-weight`, mask obligation).
- Expander sources are excluded: the v2 code is systematic.
- The masked sumcheck's soundness and MASK line are conditional on binding the
  mask before its sum; A2 leaves that open (R2), so no consumer may accept a
  masked reduction.
- Masks derive from a fresh secret seed with a keyed BLAKE3 stream; hiding is
  computational with derived masks. A seed is used for one source or instance.
- No dev-zk profile flag until A1's remaining list is accepted (INV-1).
- A1 stays Draft, with R1–R13 of the design note as its exact remaining list.
- Relation to ADR-096 and RFC-0013 A3 (Draft, scheme v3): A2 is the
  development-tier instance that A3's candidate A says it starts from.
  - A2's randomisers sit on message-domain evaluation points, so A3's
    coefficient-slot counterexample does not apply.
  - Scheme v3's coefficient-form rows must re-prove the rank (E23-01).
  - A2 does not contradict A3; it decides nothing for scheme v3.

Status: Accepted (owner authorisation for autonomous amendment acceptance after
Workflow 02 review; two same-author passes in
agents/reviews/rfc0013-a2-acceptance.md; independent review is still needed).

## ADR-097: Bind the masked sumcheck's mask by a two-block hiding source (RFC-0013 A4, task E12-15)

Numbered after ADR-096 on main; RFC-0013 A3 is the Draft scheme-v3 direction there,
so this amendment is A4.

Context: the independent review of RFC-0013 A2 confirmed that the masked A1
sumcheck is unsound until its mask is bound (design note R2), and
`accepts_forged_mask_final_for_a_false_sum` shows the forgery. A sum of
univariates cannot be opened as one tensor functional. A row that holds all of
`g` would reveal it, and with it `f`'s rounds.

Decision:
- The mask becomes `G = (1 − X_n)·g⁰ + X_n·g¹`, with `deg g^b_n ≤ δ − 1`. It is
  stored as `2D` limb rows of a version-3 hiding source.
- The mask source's bytes are absorbed (`FieldSources`) before `G`. Its
  certificate keeps A2's rank check.
- One A9 opening at `G(ρ)` with zero mask-row weight is admitted for this source
  only (`PreparedSource::hiding_mask`). Its row `(1 − ρ_n)g⁰ + ρ_n g¹` is
  covered by Lemma 5, and the producer aborts when `ρ_n ∈ {0, 1/2}`.
- `stele_reductions::zk` is the only admitted consumer of the raw masked module,
  enforced by the quarantine check.
- No new label: `FieldSources` already means "bind the source bundle before an
  A1 sumcheck" (RFC-0010 A9 §5).
- Independent-review fixes:
  - Seed reuse across proofs leaks the witness rounds. `zk::prove` takes a
    move-only `Seed` that one proof consumes, and both constructors carry
    `# Security` notes.
  - No CSPRNG dependency is added: the caller supplies entropy. `getrandom`
    stays an option for a future std prover entry point.
  - The PCS refuses any mask-source opening outside A3's two-block shape.
  - The quarantine check also covers `hiding_mask`.

Status: Accepted (owner authorisation; two same-author passes in
agents/reviews/rfc0013-a3-acceptance.md; independent review requested).

## ADR-098: Masked claims, dev-zk relation forms and ZK-GKR lookups (RFC-0013 A5, RFC-0026 A9, RFC-0008 A7, task E12-17)

Numbered after ADR-096 (main) and ADR-097.

Context: with A2/A4, sumchecks and sources are simulatable from their final and
opened values, but those values still reveal the witness (design-note R1). The
research note (formal/zk-claims.md) and its exact small-field checks gave a
construction with no leak found.

Decision:
- Each masked occurrence of a committed column gets its own claim-mask block,
  on domain coordinates, with a vanishing factor on a summed variable.
- Matmul becomes a zero-sum with `out` broadcast, so `out~(ρ)` is never sent.
- Small domains are padded.
- Lookups keep A5's GKR trees, masked layer by layer (ZK-GKR, RFC-0008 A7).
  A first draft committed fraction columns instead. The census comparison
  (formal/zk-gkr.md) put it about 780 times larger.
- One shared mask source per proof holds every masked sumcheck's mask and
  every layer block, with one batched opening, in place of one A4 source per
  instance.
- Each source batches its claims with a weight that is zero on the mask rows,
  then makes one A2 opening.
- Every rank condition is a producer abort.
- dev-zk is profile byte 1: defined, not admitted until implemented, controlled
  and independently reviewed.
- Relation to ADR-096 (Draft direction): RFC-0013 A5 is the development-tier
  form of A3's candidate A items 4 and 6. Under RFC-0028's commit rule, claims on
  virtual columns take RFC-0008 A7's per-layer masks. E23-01 can start from this
  stack, as its acceptance text says for E12-11..E12-13.
- E12-14 (end-to-end dev-zk) stays the development-tier deliverable that E23-01
  and E23-02 start from. It is not folded into them. Both now depend on E12-14 in
  graph.yaml; their acceptance lines are unchanged.
- Costs are recorded as a projection: about 4 times the commitment on the
  eight-layer synthetic window, against about 20 times for committed fractions.
  No constant moves.

Status: Accepted (owner authorisation; two same-author passes in
agents/reviews/rfc0013-a5-acceptance.md; independent review requested).

## ADR-099: Masked claims and the matmul zero-sum as engine components (RFC-0013 A5, RFC-0026 A9, task E12-18)

Numbered after ADR-098.

Context: RFC-0013 A5 and RFC-0026 A9 fix masked occurrences, padding, the matmul
zero-sum, the shared mask source and per-source batching. They leave open how the
masked sumcheck learns its higher degree and how the shared source holds the
masks. Task E12-18 builds these as components. Wiring them into the development
prover is E12-14.

Decision:
- `stele_sumcheck::masked` takes a declared degree (`Mask::plain`,
  `verify_degree`). The degree byte of the absorbed `Instance` is that degree. A
  plain mask stores A2's sum of univariates as both blocks of the A4 form, since
  `(1 − X_n)·g + X_n·g = g`. This reuses the A4 formulas unchanged.
- `stele_reductions::zk::claims` is the one new consumer, and the quarantine
  admits it. It proves a statement of identities and matmuls over claim sources.
  It uses one shared mask source and one A4 source per proof. The source layout,
  the ids and the vanishing-variable defaults are plan rules of the module. E12-14
  may replace them with the development plan's.
- Every A5 item-4 abort is a producer error: `ClaimRank`, `Vanishing`,
  `BatchPoint`, `MaskWeight`, and the existing `MaskRank` and `MaskPoint`.
- NC-0910 and NC-0911 run on the composed proof. NC-0909 and NC-0915 run through
  the batch verifier (`claims::verify_batch`), which the composed verifier calls
  once per source. A changed claim at the composed proof first fails its own
  relation's final unless the cheater also re-solves `μ`. The batch-level control
  is that consistent cheat. NC-0915's cheat is a full alternative prover,
  `prove_weighted`, with weight `(S_q, −S_p)` on the mask rows. Each control
  fails when its check is removed (recorded in the PR).
- The verifier evaluates the batch weight densely, in `O(R·C)`. This is a
  `shortcut:` until sources grow.
- Independent review (fix-then-merge, no soundness or privacy bug):
  - Removing the relation `μ_j` from the shared batch survived every test. NC-0916
    now runs A4's NC-0908 attack on a composed relation through `claims::forge`, a
    documented adversary prover like `prove_weighted`. With that binding removed,
    the forgery is accepted.
  - A changed shared opening is now tested. Removing that opening check fails the
    test.
  - A statement without a fresh vanishing variable is refused instead of sharing
    variable 0.
  - The matmul degree is 3 here because this form has no `eq(ρ_shared, ·)`
    factor. A5 item 3's 4 includes that factor.

Status: Accepted (development tier; independent review: fix-then-merge, fixes applied).

## ADR-100: ZK-GKR over the A5 trees as engine components (RFC-0008 A7, task E12-19)

Numbered after ADR-099.

Context: RFC-0008 A7 masks A5's fraction trees for dev-zk. It specifies the
committed top, the masked layer steps with their `s = 1` half, the per-layer
blocks in the shared mask source and the `DenominatorZero` abort. It leaves the
step algebra, the layouts and the degree of a masked step to the implementation.

Decision:
- `stele_reductions::zk::claims` takes lookups in its statement. The tree, top,
  steps and finals live in its child module `lookup` (`src/zk_lookup.rs`) and reuse
  E12-18's masked occurrences, batches and shared source.
- The order:
  - the claim sources, multiplicities included;
  - each lookup's `β, α`;
  - the top source and the shared source;
  - the relations, including each lookup's `h·q − p = 0` and `Σ h = 0`;
  - the GKR steps;
  - the batches.
- The first step is a zero-sum over masked occurrences of the top columns, so no
  top value is revealed. Later steps carry the incoming claims' mask terms in their
  `s = 1` half, whose block finals are claims in the shared batch.
- A masked step's SC degree is the declared one (A5 item 3), not A7 item 6's 3. The
  A7 implementation notes amend that line.
- Controls and tests:
  - NC-0913 runs through `claims::forge_layer`, an adversary with free rounds and
    `μ` solved last, so that only the next step's claimed sum rejects the change.
  - NC-0914 changes the block row's symbol in the shared opening.
  - `rejects_unbound_block_finals` runs `claims::forge_block`. It moves both block
    finals and keeps the step's final check intact. Removing the block claims from
    the shared batch makes it accepted.
- Scope: one unselected member per lookup, with `n ≥ c_D + 1`. Selectors,
  several members, padding and A5's statement messages are left to E12-14.
- Independent review (fix-then-merge, test gaps only):
  - NC-0917 and NC-0918 cover the head and selector final checks, through the
    `claims::forge_final` adversary.
  - NC-0919 covers the top identity `h·q − p = 0` against a false lookup, through
    `claims::forge_ratio`. Removing the identity makes it accepted.
  - Tests at `n = c_D + 4` run the middle layers in both fields. They assert the
    degrees 7, 7, 5, 4, a bad tuple, and χ² of a middle layer value.
  - The A7 notes list the degrees per step. They add the ZD line `2^{n+1}·c/|K|`
    per lookup: A5's `e` assumes the root check, which dev-zk replaces.

Status: Accepted (development tier; independent review: fix-then-merge, fixes applied).

## ADR-101: Every RFC-0026 relation kind as one dev-zk statement (RFC-0013 A5, RFC-0026 A9, RFC-0008 A7, task E12-14a)

Numbered after ADR-100.

Context: E12-18 and E12-19 built masked claims, zero-sums and ZK-GKR as components.
They left selectors, several members per check, padding, A5's statement and unit
messages, and the mapping from a development relation to E12-14. E12-14 is split:
E12-14a maps every relation kind, and E12-14b wires the orchestrator, the CLI, the
fixtures, the privacy tests and the ledger.

Decision:
- `stele_reductions::zk::relation` derives one `zk::claims` statement from any
  validated relation. It proves and verifies it after `relation/statement`.
  - Witness columns and multiplicities go in source 0. Weights go in source 1,
    whose root is the dev-zk model commitment, with `P = 1`.
  - There is one combined identity instance per domain size, `Compose` included.
  - There is one contraction per matmul, with shared and fixed bits.
  - There is one ZK-GKR check per table and per range width.
  - Public operands are evaluated by the verifier.
- A check's leaf takes a selector, several members, shifts and padding, as RFC-0008
  A7's E12-14a notes state.
  - The instance keeps every member claim as a final, with terms of at most four
    factors.
  - The producer folds compact combined factors. The declared degree covers both
    forms.
- The tree limit rises to `n ≤ 23` (the eight-layer window has `n = 22`).
- dev-zk stays defined, not admitted (RFC-0013 A5 item 8). E12-14b wires the
  profile byte. Admission waits for its independent review.
- Evidence:
  - The relation tests' seven fixtures prove and verify through the actual
    verifier.
  - The one-layer window (`T = 4`) proves and verifies at the relation level.
  - The eight-layer window (`T = 64`) proves and verifies at the relation level
    in an ignored release test: 413 s prove and 55 s verify on one laptop. That
    timing is not a ledger number.
- Controls NC-0920..0929 are added and executed, with NC-0927 among them.
  - Independent review (fix-then-merge): NC-0920..0926 and NC-0929 did not
    discriminate. The adversaries now keep honest rounds and the true `μ`, or
    substitute one public column. Each passes on the honest witness and goes red
    when its own check is removed.
  - NC-0930..0932 are `todo`.
  - The adversaries are behind the `controls` feature of `stele-reductions` and
    `stele-sumcheck`.

Status: Proposed (development tier; independent review requested before merge).

## ADR-102: dev-zk through the development orchestrator and CLI; OS-RNG seed; admission proposed (RFC-0013 A5 items 7–8, RFC-0026 A9, task E12-14b)

Numbered after ADR-101.

Context: E12-14a proves any development relation as one dev-zk statement.
RFC-0013 A5 item 8 asks for an ADR when the seed's source is fixed. It also admits
dev-zk only after the implementation, NC-0909..0915, the privacy tests on the one-
and eight-layer windows, and an independent review.

Decision:
- `stele_prover::development::zk` proves and verifies a window under dev-zk.
  - Its public input is the development public input followed by profile byte `1`.
    Development bytes are unchanged.
  - Its container is `stele-dev-zk-v1`.
  - Its public file is `stele-dev-zk-public-v1`.
  - NC-0912 restamps a dev-zk proof with the development statement digest. The
    verifier rejects it with `StatementMismatch`.
- `stele prove-dev --zk` draws the seed from `/dev/urandom`. The library takes a
  move-only `Seed`. The weights are committed per proof (`P = 1`). A persistent model
  seed with `P > 1` block sets is left open.
- The ledger records the eight-layer window, development against dev-zk, on one host:
  `bench/ledger/e12-14-synthetic-8layer-mac.json` and
  `bench/ledger/e12-14-synthetic-8layer-zk-mac.json`. Both carry
  `profile: "development"`, because RFC-0018 A1 admits no other development-tier
  profile. The workload name and `model_config.profile_byte` mark dev-zk.
- Admission of profile byte 1 is not taken. The independent review
  (fix-then-merge) holds it until E12-25 binds the model.
- Independent review fixes:
  - F1: The claim is existential, with `P = 1` per proof. The CLI prints
    `weights: unbound (per-proof commitment)` and refuses `--expect-model`.
    E12-25 gates admission.
  - F2: 1-D records are declared public.
  - F4: An exact leak test runs on the one-layer window, as does a two-witness
    test. The eight-layer leak test is ignored and run locally.
  - F5: NC-0912 gains a transcript-level half.
  - F6: The scoreboard labels the dev-zk record.
  - F7: The adversaries sit behind the `controls` feature.
  - The verifier reports counts, not a soundness ledger (E12-26).

Status: Proposed (development tier; independent review: fix-then-merge, fixes
applied; dev-zk not admitted).

## ADR-103: Provisional NO-GO for a development-profile GPU backend (fixture stage shares) (RFC-0014 §1, §5, RFC-0026 §7, task E16-21)

Context: task E16-21 gates a development-profile GPU backend (tasks E16-21a..e) on a
projected stories42M T = 64 prove-time gain of at least 3x, once dense and zerocheck
rounds, LogUp levels, v2 encoding and Merkle hashing run on the device with state
resident. The measurement and the projection are in
`bench/ledger/e16-21-gpu-gating.json`; the sources are in `research/gpu-gating/`.

Method:
- **Device rounds.** `dense_gpu.cu` runs a dense QM31 sumcheck (one product of K tables)
  with the tables resident on a rented RTX 4090; each round copies the K + 1 node sums
  to the host for the Fiat–Shamir round trip and folds with the host's challenge.
  `dense_cpu.rs` runs `stele_sumcheck::Dense` on the same inputs on the same host. The
  round values agree byte for byte (FNV) at every size.
- **Stage shares.** No stories42M profile exists. `stage_shares.py` charges the
  main-thread samples of one `stele prove-dev` run of the 8-layer fixture to prover
  stages; the main thread waits inside every parallel region, so its samples are wall
  time.
- **Projection.** Amdahl's law on `bench/ledger/e16-18-dev-stories42m.json`, with the
  8-layer shares applied unchanged and the device speedup of the offloaded stages taken
  as the measured rounds-only ratio at its lowest, its highest, and unbounded. The
  measured ratios are against the CPU reference at 46 threads, not the 24 threads of
  the target record; the ceiling at unbounded speed does not depend on them.

Decision: **NO-GO (provisional: fixture stage shares, stories42M unprofiled).** The work the scoped backend leaves on the CPU (relation
registration, lookup leaf preparation and counts, matmul table builds, the PCS row
combination, witness and layout) bounds the projected gain below 3x even at unbounded
device speed on the fixture's shares. No GPU binding is chosen and no RFC-0014
amendment is written.

What flips it: a stories42M profile on the target host whose residual share (the work
outside the offloaded stages) is at most one third (33.3%) of wall time. The fixture's
residual is close to that line, and two biases are not measured:
- *Attribution.* `stage_shares.py` charges a sample to the first stage pattern on its
  stack; field products inside `relation_other` that belong logically to LogUp leaf
  preparation or dense rounds count as residual. This overstates the residual.
- *Threads.* The fixture ran on 16 threads, the target on 24. The offloaded stages are
  mostly parallel and the residual mostly sequential, so more threads raise the
  residual share. Model size changes the mix in ways the fixture cannot show.

Alternatives rejected:
- *Proceed on the rounds-only ratio.* It ignores the residual CPU share, which is the
  binding term.
- *Widen the backend to the residual relation work now.* In the fixture profile almost
  all residual samples have no rayon frame on the stack: they ran sequentially on the
  main thread (counts in the ledger, `main_thread_samples_outside_parallel_region`).
  Making that work parallel on the CPU is cheaper and helps every host. A GPU case
  needs a new profile after that.

Consequences:
- Tasks E16-21a..e are blocked on task E16-22, a stories42M stage-share profile on a
  Linux host. That profile, with this ledger's device ratios, confirms or reverses this
  decision.
- Device upload in the micro-benchmark uses pageable memory; it does not affect the
  verdict, which holds with zero transfer cost.
- The verifier, `no_std` builds and every CPU path are unchanged.

Status: Accepted (owner authorisation for autonomous gating decisions; independent review in the E16-21 PR).

## ADR-104: One published dev-zk model commitment for P proofs (RFC-0013 A6, task E12-25)

Numbered after ADR-103 (main).

Context: E12-14b committed the weights per proof (`P = 1`), so a dev-zk proof bound
no published model. Review F1 asked for a persistent commitment, and E12-25 makes
it the admission gate.

Decision:
- RFC-0013 A6 (Proposed) defines a lifetime hiding weight source.
  - It is committed once from a model seed, with `P·t_x` claim-mask blocks per
    weight column.
  - It is admitted when `R ≥ (P + 1)·D` and `q_c + P·q_o ≤ C − 1`.
  - Proof `j` opens it once and uses block set `j`.
  - The rank check spans every opening of the lifetime.
- `stele-pcs` gains `Source::admits_lifetime` and `PreparedSource::hiding_lifetime`,
  whose opening budget and rank check cover earlier openings. `zk::claims` gains
  `Lifetime`, `prove_lifetime`, `verify_lifetime` and `lifetime_root`.
- The orchestrator and the CLI:
  - `commit-model --zk` writes the public commitment and a secret state with mode
    0600.
  - `prove-dev --zk` persists the counter before it proves.
  - The public input carries the index and the commitment.
  - `--expect-model` pins the commitment's model digest.
- Reviewer nits:
  - `zk::claims::leaks` covers the committed tops and the GKR layer children.
    The unmasked control must leak.
  - The CLI doc reads "A development proof".
  - A gate checks that `cargo tree -p stele-cli` has no `controls` feature.
- Deferred:
  - committing the 1-D records with their CQIS well-formedness relations (E12-27,
    now an admission gate);
  - NC-0930..0932.
- dev-zk stays not admitted.

Independent review (fix-then-merge; A6's `P + 1` extension confirmed by an exact
`F_61²` check, now `research/zk-claims/check_lifetime.py`). Fixes:
- F1: The producer refuses a rebuilt root that differs from the published one,
  before any transcript work. The CLI verifies its own proof before writing it.
- F2: NC-0933 gains a transcript-level half.
- F3:
  - A plan test checks disjoint block sets per index.
  - A `stele-pcs` test sits at `R = (P + 1)·D` and checks a rank-deficient
    revealed set.
  - Both are mutation-checked.
- F4:
  - The CLI validates its inputs before it takes an index.
  - `prove_next` restores the prior state on any error.
  - `write_secret` replaces stale temporaries, sets mode 0600 and syncs the
    parent directory.
- F6:
  - Index reuse is quantified in A6 item 5 and §7.
  - A6 now declares that the certificate is repeated in every proof and that the
    index reveals proof order.
- F7: `is_hiding`'s doc is restored, and block offsets use checked arithmetic.

Status: Accepted (development tier). Independent review in two rounds:
fix-then-merge, then MERGE with "accept A6: yes". dev-zk stays not admitted
until E12-27.

## ADR-105: The development prover's sequential residual on the work pool (RFC-0026 §7, RFC-0006 A1, RFC-0010 A4, task E16-23)

Context: ADR-103 found that in the 8-layer `prove-dev` profile most of the CPU residual
ran on the main thread outside any parallel region: relation registration, lookup leaf
preparation and counts, matmul table builds, the PCS row combination, witness and
layout. Task E16-23 moves that work onto the ADR-090 pool, or removes it where it
was repeated. The measurements are in the E16-23 ledgers.

Decision:
- `stele_sumcheck::parallel` gains `map`, with one pool task per item for a few large
  independent items, `join`, and `gated` (a deciding gate beside the work). Without
  `std`, each runs in order on the calling thread; `gated` runs the gate first.
  `stele-reductions` re-exports `stele_sumcheck::parallel` only.
- `stele-pcs` gains an optional `rayon =1.10.0`, which only its `std` feature enables.
  It does not depend on `stele-sumcheck`, so that edge stays banned (`deny.toml`). A
  crate-private `for_each_block` splits disjoint output blocks.
  - The certificate row and the functional-opening row are combined row-major in
    disjoint column blocks. Before, the loop went column by column with a stride of one
    row through the message.
  - Each column keeps its sum in row order.
  - Source preparation transposes in parallel blocks.
  - Verification code is unchanged.
- The relation engine:
  - Prepares and registers the stacked source and the multiplicity sources as pool
    tasks. It absorbs their roots in step order.
  - Computes lookup counts once, in step 3, and passes them to step 5. They used to be
    computed twice.
  - Fills the lookup selector, original columns, leaves, table fractions and member
    evaluations in parallel blocks.
  - Builds each matmul operand table with a precomputed table of eq weights over the
    bits outside the sumcheck. Each entry no longer needs a linear search and a product
    over every bit. The table build splits the entries over the pool with exact field
    sums.
- The claim-batch coefficient table accumulates in parallel blocks. Zerocheck rounds
  compute their degree + 1 node sums as pool tasks, because late rounds are too short
  for `sum_ranges` to split. The hybrid fold runs in parallel blocks.
- `Layout::declare` generates rotary coefficients once for each distinct rotation, not
  once for Q and again for K in every layer. Activation tables are generated once for
  each distinct descriptor (`Rope::with_input`).
- `prove-dev` runs the plain checker alongside the engine (`parallel::gated`).
  - The engine's output does not depend on the checker.
  - The checker decides. A false witness fails with `Check` and returns no proof,
    even if the engine errs or panics on it; under `std` the engine's panic is caught
    and dropped in that case. When the checker passes, an engine panic propagates.
  - The engine may finish work on a witness the checker rejects. That work is
    discarded. `rejects_false_witness_with_check` tests the outcome.
- Every change is an exact reordering of field additions, or a write into disjoint
  slots. Transcript order, proof bytes, the E16-10 fixture hashes and every proof pin
  are unchanged (INV-3, INV-8). The verifier crates (`stele-verifier`, the engine's
  `verify` paths) and the `--no-default-features` builds are unchanged, and they stay
  free of rayon. `verify-dev` shares `Layout::declare` with the prover, so the
  rotary and activation deduplication also speeds up verification.

Consequences:
- The work left on one thread is `Layout::assign`, witness capture, `Attention::new`
  (per-layer `Exp` tables), the fraction-tree tail rounds and short eq tables. It is
  listed in the E16-23 ledger.
- The plain checker no longer shows up as wall time on the 8-layer fixture.
- `stage_shares.py` charges main-thread samples. Once `prove-dev` joins, the main
  thread only waits. For an after-profile, use the per-thread residual count in the
  E16-23 ledger notes.
- ADR-103 stands. Its gate is a stories42M profile (task E16-22). That profile should be
  taken on this code, because this change lowers the CPU residual it measures.

Status: Accepted (owner authorisation for autonomous performance work; soundness-auditor review requested in the E16-23 PR for the `stele-sumcheck` and `stele-pcs` prover-side changes; ADR-090's list of crates with rayon gains `stele-pcs`).

## ADR-106: Policy 2 and grinding in stele-pcs; development proofs stay on Policy 1; LU split to E12-24 (RFC-0010 A14, RFC-0012 A17, task E12-23)

Numbering: ADR-101..104 are on main and ADR-105 is on main (task E16-23), so this record takes 106.

Context: ADR-091 admitted Policy 2 (RFC-0010 A14) for the standard profile and left
the consumers to E12-23. The request that started this change asked for the
development prover (`prove-dev`/`verify-dev`) to switch to Policy 2. The Accepted text
says otherwise: A14 item 1 ("RFC-0026 development proofs keep policy 1"), RFC-0012
A17 item 7, ADR-091 ("Development profile. Unchanged: Policy 1") and E12-23's own
acceptance ("Policy 1 proof bytes unchanged").

Decision:

- **Spec over request (INV-1).** `stele-pcs` gains Policy 2 as an explicit source
  policy (`Policy::Two`, `Source::from_code_id_policy`,
  `PreparedSource::from_code_id_policy`). Every existing constructor keeps Policy 1,
  so development proof bytes and the E16-10 pins do not move. Moving a development
  proof to Policy 2 is E16-30's measurement and an RFC-0026 amendment, not this task.
- **Resolver.** `registry::resolve_pcs` returns the A14 item 2 tables for a standard
  request with QM31 or OM31 challenges, and `UnsupportedParameters` for treaty, M31
  challenges and v2 J = 15. Policy 2 sources take their counts only from it.
- **Wires.** Certificate: `u8(1) || [n_t] || t_bytes || n_q || responses`. Opening:
  `u8(1) || u_bytes || n_q || responses`. k_q = 16; k_t is the least k of A14 item 4
  computed with exact integers (0 in OM31). The verifier derives both from the
  expected source and checks each nonce before the next draw.
- **Conservative readings.** (1) The opening nonce is checked after the
  `ValueMismatch` check and before the first column draw; both precede any draw, so
  the order changes only which error is reported. (2) The registry export's per-family
  `proven = false` is left as is: A14's `proven` is a profile fact, returned by the
  resolver, and the export format belongs to E12-04. (3) Policy byte 2 in a source
  context is now valid, so NC-0613 tampers with byte 3 instead (A14 item 7).
- **Controls.** NC-0806 (a column or tensor nonce failing the predicate), NC-0807 (a
  k_q − 1 prover), NC-0808 (another valid column nonce: the nonce is absorbed),
  NC-0809 (one response fewer than q_c or q_o) and NC-0813 (another valid tensor nonce)
  run through the actual certificate and opening verifiers. NC-0810..0812 are left to
  the ADR-096 drafts. Tampered nonces come from an independent replay of the A1
  transcript and the A17 predicate in the harness, with every search capped at 2^20.
  Python parity: `research/merkle-oracle/check_policy2_wire.py`, which also recomputes
  all 59 Circle and 12 v2 rows of the A14 table from the exact inequality and pins them
  for the native resolver test.
- **Split.** The LU (β, α) consumer needs its RFC-0008 offset amendment first and has
  no standard-profile LU caller yet. It moves to E12-24.
- **Gate on the first standard caller.** `resolve_pcs` returns `proven: true`, which
  presumes RFC-0012 A17 (C1)–(C4) hold for the whole configuration, and an
  ungrinded QM31 LU round can fail (C1). So no standard-profile caller of
  `resolve_pcs` (or of `Policy::Two`) may land before E12-24 is done; until then
  Policy 2 is exercised only by tests, fixtures and controls.

Consequences: no proof byte, pin or measured constant moves; no ledger is recorded.
E16-30 is unblocked on the stele-pcs side. Open: E12-24, E12-04, E8-05.

Status: Accepted (follows Accepted RFC-0010 A14 and RFC-0012 A17; no protocol change).

## ADR-107: Commit the 1-D records for dev-zk with a CQIS gain-encoding proof (RFC-0013 A7, task E12-27)

Numbered after ADR-106 on main.

Context: under RFC-0013 A5/A6 the RMSNorm gains (the 1-D records, RFC-0026 A2) are
dev-zk public input. Review F2 of E12-14b asked to commit them, and E12-27 is an
admission gate.

Decision:
- RFC-0013 A7 (Proposed): under dev-zk, each RMSNorm's gain-derived columns
  (`H0`, `H1`, `σH`, `flipH`) are weight columns of the A6 lifetime source.
  - They are declared at fixed full widths (`RmsNormPlan::fixed_widths`, set by the
    dev-zk plan), so the relation and its static bounds depend on no gain.
  - `development::zk::commit_records` converts them and adds the encoding
    relations: the ranges, `H1low = H1 + 128·σH ∈ [0, 128)`,
    `flipH = 1 − 2σH`, and zero padding past the model width.
- The dev-zk public input carries a fixed per-format pattern in place of each 1-D
  record's values. The prover builds the relation from the real gains and refuses
  a window whose committed relation differs from the verifier's.
- Development proofs are unchanged; their pinned hashes still match.
- Controls NC-0935..0938 use the unchecked adversary on a one-group relation.
  Each is mutation-checked: removing the flip identity, widening `H1low` to 8 bits,
  removing the padding identity, or removing the sign identity turns exactly its
  control red, with the false encoding accepted.
- The `--expect-model` digest hashes the fixed pattern; the gains are bound only
  through the commitment root. Commitments made before E12-27 must be redone.
- dev-zk stays not admitted. The admission PR follows, with its review and the
  eight-layer ledger.

Independent review of #346 (fix-then-merge): the encoding relations are complete
and unique, the binding is correct, and the full width is necessary (int16 is
fixed). Fixes:
- F1: NC-0938 isolates the sign identity (dropping it had left NC-0935..0937 green).
- F2: the padding mask column is `{prefix}/gainvalid`, not a second `{prefix}/valid`.
- F3: `model_digest`'s doc and A7 item 3 say the digest hashes the pattern and the
  gains are bound through the root; pre-E12-27 commitments do not fit.

Status: Accepted (development tier). Independent review: fix-then-merge, F1 to F3
applied, "accept A7 once F1 is fixed". dev-zk stays not admitted until the
admission PR.

## ADR-108: The standard-profile LU (β, α) nonce and Policy 2 sources; ADR-106's gate enforced until E8-05 (RFC-0008 A8, RFC-0012 A17, task E12-24)

Numbering: ADR-107 is taken by #346 (task E12-27), so this record takes 108.

Context: RFC-0012 A17 item 5 lets LU (β, α) rounds grind, and it requires an RFC-0008
amendment to fix the nonce's byte offset first. ADR-106 split that work from E12-23 into
E12-24. It also barred any standard-profile caller of `registry::resolve_pcs` or
`Policy::Two` until E12-24 was done. The reason: `proven: true` presumes A17 (C1)–(C4),
and an ungrinded QM31 LU round can fail (C1).

Decision:

- **Amendment.** RFC-0008 A8 (Proposed, full path) fixes the placement. The nonce
  follows `Repetition(id, j, 0)` and precedes `Beta`. On the wire, r u64le nonces follow
  the registration packets, and nonce j starts at byte `2 + Σ(32 + C_i) + 8j`. Its
  bits are the least k with `(c(N+t) − 1)·2^108 ≤ p^d·2^k`. k > 32 is
  `Error::Statement` (UnsupportedParameters).
- **Consumer.** `lookup::Descriptor::standard` is the standard-profile A5 lookup. Its
  multiplicity sources use Policy 2, it rejects any original that is not Policy 2
  (`CertificateContext`), and it grinds when k ≥ 1. `Descriptor::new` is
  unchanged: Policy 1, k = 0, no nonce. The RFC-0026 development checks
  (`relation_lookup.rs`) and dev-zk trees are not touched, so no development proof
  byte moves. The existing lookup corpus digests are unchanged.
- **Why the source policy moves too.** Under Policy 1, the ungrinded QM31 tensor round
  `2·ℓ·(e+1)/|K|` of any certificate the lookup relies on can fail (C1). That covers
  its own multiplicity sources and the caller's originals. RFC-0010 A14 item 1 makes
  standard mean Policy 2, so both are required. Grinding only (β, α) would leave the
  lookup inadmissible.
- **Conservative readings.**
  1. Originals stay caller-owned, but a standard lookup accepts only Policy 2
     certificates. A Policy 1 original would let `proven` cover an ungrinded
     certificate round. (The first review draft read this the other way; review F1
     corrected it.)
  2. N is the 2^m positions and t the real rows, as in the recorded LU numerator.
  3. The grind absorb's 9-byte payload is counted in `Limits::public_bytes`.
- **Controls.** NC-0814 (a failing nonce, `GrindMismatch`), NC-0815 (a k−1 prover,
  `GrindMismatch`), NC-0816 (another valid nonce, absorbed, `RoundSumMismatch`) and
  NC-0817 (the statement over Policy 1 originals, `CertificateContext`) run through
  the actual A5 consumer on a QM31 `sigmoid_q` lookup with Policy 2 originals and
  k = 2. Nonces
  come from the independent `Replay` of E12-23, with every search capped at 2^20.
  Mutation checks, each leaving the honest proof accepted:
  1. With the PoW check skipped but the absorb kept, NC-0814 and NC-0815 go red
     (`RoundSumMismatch` instead of `GrindMismatch`).
  2. With the nonce not absorbed on either side, NC-0816 goes red (tamper accepted).
  3. With an off-by-one bit derivation on both sides, no control goes red, because
     the prover and verifier still agree. It is caught by the controls' k = 2 fixture
     guard and by the native pin `matches_reference_lu_grind_bits`. A verifier that
     checks fewer bits than the prover ground rejects the honest proof, because the
     predicate's payload binds k.
  4. With the original-policy check removed, NC-0817 goes red. The Policy 1 roster is
     then rejected only later, as `ProofShape`, because its opening size differs.
- **Parity.** `research/fs-pcs/check_lu_grind.py` recomputes 180 (c, N, t, d) rows
  from the exact inequality. It also runs the unchanged independent A5 producer of
  `lookup_corpus.py` with Policy 2 originals and multiplicity sources and the A8
  nonce, for four standard proofs (k = 0, 0, 1, 1). The last has r = 2, with its
  second nonce at +8. Both are pinned natively in `tests/lookup_grind.rs`,
  which matches the proof bytes, nonce offset, nonce and continuation. The pinned
  `lookup_corpus.py` is not edited, so the requant and integer-linear provenance
  hashes do not move.
- **ADR-106's gate, restated and enforced.** Every family that A17 item 5 lets grind now
  has a consumer that grinds at the least (C1) k: PCS column and tensor rounds
  (E12-23), and LU (β, α) rounds (here).
  - `resolve_pcs`'s `proven: true` (A14 item 6) is a fact about one Policy 2 source's
    rounds. It now holds together with these consumers.
  - It is not a claim about a composed proof. A composed standard proof also needs (C1)
    on every non-grinding round (SC, RLC, SZ, units θ), plus (C2) and (C3). E8-05's
    generator checks these.
  - Until E8-05 lands, the standard-profile entry points sit behind a Cargo feature,
    `standard-unproven`, in `stele-code`, `stele-pcs` and `stele-reductions` (each
    forwards it down):
    - Without it, `resolve_pcs`'s standard path returns `UnsupportedParameters`.
    - Without it, every Policy 2 source constructor fails `UnsupportedSource`. That
      includes `Source::from_bytes` with policy byte 2, so a production verifier
      rejects a Policy 2 context instead of accepting it.
    - `lookup::Descriptor::standard` does not exist without it.
  - No crate turns the feature on in a dependency line. Under resolver 2 that would
    unify it into every crate of a `cargo build --workspace`.
    - `stele-negative-controls` declares its own off-by-default features
      `standard-unproven` and `controls`, which forward to `stele-reductions`. Its
      `pcs_policy2`, `lookup_grind`, `zk` and `zk_relation` modules, the E12-27
      records controls and their CONTROLS entries are `#[cfg]`-gated. Their Cargo test
      targets carry `required-features`, and so does the catalog test.
    - The runners select the features explicitly: `native.sh` and
      `negative-controls.sh` pass `--all-features`, as CI's workspace test and clippy
      already do, and so does Workflow 02's catalog command.
    - The standard tests carry `#![cfg(feature = "standard-unproven")]`. A no-feature
      test pins the rejection.
  - Two native gates check this:
    - `cargo tree -p` on stele-cli, stele-prover and stele-verifier must show no
      `standard-unproven`. Adding it to stele-prover's dependency turns this red.
    - `cargo tree --workspace -e features` with no feature selected must show neither
      `controls` nor `standard-unproven`.
  - Scope extension: the second check also covers the E12-14a/E12-25 `controls`
    feature. Its old gate checked only `cargo tree -p stele-cli`, so a workspace build
    unified the adversaries into every crate.
  - The earlier grep lint (`standard_quarantine`) stays as a second, weaker check. It
    misses turbofish, qualified-path and glob forms.
  - So no prover, CLI or verifier can emit `proven: true` or an admitted level for a
    composed proof. E8-05 removes the feature in the same change that adds the composed
    check.
  - The registry export's per-family `proven = false` is unchanged (E12-04).

Consequences: no development proof byte, pin or measured constant moves, and no ledger
is recorded. Only standard-profile bytes (test fixtures) carry Policy 2 originals and
nonces. Open: E8-05 (composed (C1)–(C3) check, lifts `standard_quarantine`), E12-04,
E16-30.

Status: Accepted with RFC-0008 A8 (independent review: FIX-THEN-MERGE, F1 fixed here).
A8 is the protocol change; this record follows RFC-0012 A17 and RFC-0010 A14.

## ADR-109: Admit dev-zk (profile byte 1) at the development tier (RFC-0013 A5 item 8, task E12-14)

Numbered after ADR-107 on main, skipping ADR-108, which #347 (E12-24) holds.

Context: RFC-0013 A5 item 8 defined dev-zk and withheld admission until its
deliverables and an independent review. The two E12-14b gaps the review named are
closed: the model is bound by one published commitment (A6, ADR-104, Accepted), and
the 1-D records are committed weights (A7, ADR-107, Accepted).

Decision:
- dev-zk is admitted at the development tier. The scope is recorded in RFC-0013 A5,
  under **Admission**:
  - no security level (FS unproven, PCS conjectural);
  - zero knowledge conditional and computational;
  - hiding within the `P`-proof lifetime;
  - no dev-zk soundness ledger yet (E12-26).
- Evidence:
  - item 8's deliverables;
  - NC-0909..0915 and NC-0933..0938, executed (NC-0930..0932 stay `todo` and are
    named under what is not claimed);
  - synthetic one- and eight-layer windows only; no real checkpoint is proved under dev-zk;
  - the ignored eight-layer tests, run at this head and passing:
    `accepts_eight_layer_window_under_dev_zk`,
    `matches_reference_zk_claim_census_eight_layer` and
    `rejects_bare_evaluations_on_the_eight_layer_window`;
  - the eight-layer ledger `e12-14-synthetic-8layer-zk-admission-mac` (one run).
- `bench/dev_e2e.py --zk` records a dev-zk run against a published commitment, so
  dev-zk ledgers come from the same script as development ones.
- No code path changes. The CLI already offers `--zk`, and the verifier accepts
  profile byte 1.

Status: Accepted (development tier). Independent review: fix-then-merge (F1 controls
overclaim, F2 real-model scope, F4 README, F5 wording), then MERGE at 2371198 with
"accept ADR-109". F3 (extra dev-zk tampers in bench/dev_e2e.py) is a follow-up.

## ADR-110: NC-1310 as a two-value tamper on a minimal relation; INV-4 exception (RFC-0026 A10, §3.6, §9)

Numbering: ADR-108 is on main and #348 proposes ADR-109, so this record takes 110.

Context: RFC-0026 §9 reserves NC-1310: commit one ranged witness value as `2^30`,
outside its declared width, with every identity recomputed, rejected by the range
lookup's A5 root equation (`RootMismatch`). It stayed `todo`. On the synthetic
one-layer development window, every column that could rebalance an identity after the
change is itself read by another identity, lookup or compose. That follows from the
RFC-0026 rule that every committed column is range-checked. The two ranged witness
columns that no identity reads, `attention/maximum/lo` and `hi`, are limbs of a
`Compose`. So no single-value or two-value tamper of the development window keeps
every identity true.

Decision:

- **Amendment, not just an ADR (INV-1).** §9 requires every NC-1300..1310 control to run
  through the actual E16-10 verifier. RFC-0026 A10 (Accepted) redefines NC-1310 at the
  relation-engine level that this verifier calls, and states the INV-4 exception. This
  record implements A10.
- **Window-level coverage stays with NC-1300/1301.** Both run through the actual E16-10
  verifier. Each leaves a margin entry at `-1`, outside its unsigned range, and is
  rejected by that range's A5 root equation, `RootMismatch` (RFC-0026 E2). That is
  the same binding at window level.
- **Minimal relation.** NC-1310 runs through the actual relation-engine prover and
  verifier (`stele_reductions::relation::{prove, verify}`), the engine the development
  verifier calls. The relation has the identity `x + 2^22·y − c = 0`, with `x` unsigned
  8, `y` signed 9 and `c` public.
  - The tamper sets `x[0] = 2^30` and `y[0] = −256`.
  - The identity still holds, `y` stays inside its width, and `x` is the only value
    outside one.
  - The plain checker confirms this before the control runs. Its only violation is
    `x`'s range. That check earns no credit.
- **Attribution.** `x`'s range is the relation's first range, and checks run in order
  of first use (RFC-0026 A3). `y` is in its width. So the `RootMismatch` is `x`'s range
  check, deterministically.
- **INV-4 exception, documented.** The control changes two values, `x` and the in-width
  `y` that rebalances the identity. The catalog row states it. The binding under test
  is "a ranged witness value outside its width is rejected".
- **Mutation checks.**
  - With the verifier's A5 root equation skipped (`check_roots`), the control goes red:
    the tamper is accepted.
  - With every range check dropped from the plan, the control goes red the same way.
- **Feature.** The entry and `run_width` are under the negative-controls `controls`
  feature. `relation::prove` never runs the plain checker, so the false witness needs
  no other adversary seam.

Consequences: no proof byte, pin or ledger moves. NC-1310 is `done` (115/219 controls).
A window-level NC-1310 would need an adversary that recomputes the downstream witness.
That is left open.

Status: Accepted with RFC-0026 A10 (independent review: FIX, then accept A10).

## ADR-111: Development proofs on Circle rate-1/4 sources under Policy 2, behind profile byte 2 (RFC-0026 A11, task E16-30)

Numbering: ADR-109 is taken by #348 (task E12-14) and ADR-110 by #350 (NC-1310, RFC-0026 A10), so this record takes 111 and this amendment A11.

Context: ADR-091 projected 18.3 MB for stories42M on Circle rate-1/4 Policy 2 sources,
against 113.4 MB on v2 Policy 1, and left the switch to E16-30's encoding benchmark.
RFC-0010 A14 item 1, RFC-0012 A17 item 7, ADR-091 and ADR-106 keep development proofs
on Policy 1. ADR-108 quarantines every standard-profile Policy 2 entry point behind the
`standard-unproven` feature until E8-05.

Decision:

- **Benchmark first.** Before and after on the 1-layer and 8-layer synthetic windows,
  alternating on one shared host, and stories42M once each
  (`bench/ledger/e16-30-*.json`). Proof bytes fall from 25.4 to 7.3 MB (L0), from 45.0
  to 9.8 MB (L1) and from 113.4 to 18.3 MB (L2a, confirming ADR-091's projection to
  within the 152 bytes of LU nonces it counted). Verification time falls; the prove-time
  difference is within the host's noise. The encoding cost is accepted, so the amendment
  goes ahead (E16-30 acceptance line 2).
- **Amendment.** RFC-0026 A11 (development-tier path): profile byte 2 selects
  Circle rate-1/4 stacked and model sources (Draft A7's geometry, priced under Policy 2)
  and policy byte 2 on every source, multiplicity sources included. LogUp keeps r = 1
  with no (β, α) nonce.
- **Binding and versioning.** A byte-2 public input is the pre-A11 bytes followed by
  `u8(2)`; a pre-A11 input omits the byte, as A9 does for profile 0. Old proofs are the
  same bytes, verify unchanged and keep their E16-10 pins; byte-2 proofs get new pins.
  The input file is `stele-dev-public-v2`; `stele-dev-public-v1` still decodes.
- **No level, no quarantine leak.**
  - `registry::Profile` gains `Development`. `resolve_pcs(.., Development)` returns
    the A14 table with `proven: false` and is not gated. The standard path keeps its
    gate and `proven: true`.
  - The development engine reaches Policy 2 only through
    `Source::from_code_id_development` and `PreparedSource::from_code_id_development`.
    They never call the standard resolver. `Source::from_code_id_policy(.., Two)`,
    `Source::from_bytes` with byte 2 and `Descriptor::standard` are unchanged: without
    the feature they still fail.
  - `standard_quarantine` still passes: no file outside its allow-list names
    `resolve_pcs`, `Policy::Two` or `Descriptor::standard`. The native
    `cargo tree` gates are unchanged: no production crate enables the feature.
- **Conservative readings.**
  1. A development Policy 2 source has the same bytes as a standard Policy 2 source of
     that identity. The policy byte names the counts and k_q, not a profile; λ and
     `proven` are profile facts from the resolver. So a byte-2 certificate grants no
     standard claim. Under the feature (tests and controls only) a standard lookup
     would accept it as an original, as it would any Policy 2 source.
  2. Multiplicity sources move to Policy 2 too, as in the Q12 study.
  3. The stacked source keeps A4's minimum of 6 variables, so the plan's bits do not
     depend on the source set.
- **Controls.** NC-1311 and NC-1312 swap the profile byte both ways (`ProofShape`: the
  derived model sources differ). NC-1313, NC-1314 and NC-1315 replace the column nonce of
  the stacked certificate, the stacked opening and the model certificate with one that
  fails the predicate (`GrindMismatch`). All run through the actual development verifier.
  A native test pins that the byte-2 input is the pre-A11 input followed by `2` and that
  the v1 file still round-trips. Without the byte in the public input, NC-1311 and
  NC-1312 would still pass: the derived sources differ in shape. The transcript binding
  is checked by that native test and, after review fix 1, by NC-1316: the engine run with
  the plan fixed at one source set and the public input of the other, both ways
  (`RoundSumMismatch`). Mutation check: with the byte push removed from `public_input`,
  NC-1316 goes red ("byte not bound": both replays accept).
- **Review fixes (independent soundness review of #351, FIX-THEN-MERGE).** (1) NC-1316.
  (2) `standard_quarantine` also confines `from_code_id_development`,
  `Profile::Development` and `Sources::Circle` to the development path and forbids
  them in stele-verifier, with a gate test. (3) Ledger timing caveats. (4) source.rs
  comment says "every standard Policy 2 source". (5) dev-zk commit, prove and verify
  reject a non-expander source set.

Consequences: development proof bytes change under byte 2 (pins re-recorded); pre-A11
proofs are unchanged. E19-02's Draft A7 is subsumed if A11 is accepted. Open: the
independent review of A11; multiplicity sources at rate 1/4 (now the largest
section on L0 and L1, an RFC-0008 A5 geometry change); RFC-0008 A8 LU grinding for development proofs (not needed: no λ is claimed).

Status: Accepted with RFC-0026 A11 (development tier; independent soundness review of
#351: FIX-THEN-MERGE, no soundness break, fix 1 applied; no distinct policy byte needed).

## ADR-112: dev-zk prover performance: equal-value rewrites, pool use on prover paths only (task E16-24)

Numbered after ADR-109 on main, skipping ADR-110 and ADR-111, which #350 and #351 hold.

Context: the eight-layer dev-zk prove took about 363 s, against 9.5 s for the dev prove.
commit-model took 93 s and verify-dev 56 s. A macOS `sample` profile split the prove as
follows:
- 62% masked occurrence rounds on one thread;
- 25% mask assignment (`vanish`), which compared every earlier input with every
  term;
- 15% the producer's self-verify, most of it the same assignment.

commit-model was 94% assignment.

Decision:
- Every change gives the same field elements, digests and bytes. The dev-zk proofs
  at fixed seeds are pinned (one- and eight-layer), and every development pin is
  unchanged.
- Algorithms:
  - mask assignment indexes the terms each input appears in;
  - the lookup selector and the combined-leaf owner fill each member's range, in
    place of scanning the members for every position;
  - masked rounds step factor values by their slope and compute `κ(t)` once per node;
  - round terms are evaluated through a plan that leaves `±1` coefficients
    unmultiplied and multiplies the factor shared by most terms once.
- `Field::mul_m31` (default `self · from_i64(x)`; M31 towers override it
  coefficient-wise) replaces lifted-scalar products in the Circle transform and the
  PCS row combinations. Verifier code uses it too; the values are unchanged.
- Pool use, all through existing seams (`stele_sumcheck::parallel`, the PCS's
  `for_each_block`):
  - rounds and folds split by work (`sum_ranges_weighted`,
    `for_each_chunk_weighted`);
  - sources prepared, certified and messaged concurrently;
  - the LogUp tree and table denominators.
- `stele-hash` gets no new dependency. `Tree::new_with_usage_filled` takes a
  caller's level fill, with the same digests and usage, and the PCS passes its pool.
  `MaskStream::fill_at` reads the stream at an absolute offset. Mask draws are made
  from block-filled bytes, then scanned in order with the same rejection; leaf
  salts are filled per leaf.
- The pool stays off verifier paths. Pool-backed eq tables in shared prover/verifier
  code woke idle workers in `verify-dev` (about 10 s of system time) with no wall-time
  gain, so those calls stay sequential.
- The self-verify (E12-25 review F1/F4) is kept. It costs about 4 s of the prove after
  this change.

Measured: three alternating runs per commit on one M4 Max, medians.
- prove 362.6 s to 30.7 s;
- commit-model 92.7 s to 3.4 s;
- verify-dev 55.8 s to 4.4 s.

Ledgers: `e16-24-dev-zk-synthetic-8layer-mac-before/-after`.

What remains (main-thread shares of the after profile):
- masked rounds 35%, bound by QM31 products;
- source preparation 17%;
- window build and checks 14%;
- self-verify 13%;
- ZK-GKR factors 9%.

Status: Accepted (development tier). Independent review: MERGE at 84684f3; pins reproduced on base code, mask-draw and salt-offset mutations caught by the 1-layer pin. Follow-ups: unit tests for the draws() wrapper and the leaf-salt sequence, and a read-once rule on MaskStream::fill_at.

## ADR-113: Development multiplicity sources at Circle rate 1/4, behind profile byte 3 (RFC-0026 A12, task E16-31)

Numbered after ADR-112, which #352 (task E16-24) holds.

Context: after ADR-111 the RFC-0008 A5 multiplicity sources, still Circle rate 1/2, are
the largest section of a development proof on L0 and L1 (4.1 MB of 7.3 and of 9.8 MB,
`bench/ledger/e16-30-*.json`). #351's open question 3 left the move to a follow-up.

Decision:

- **Version: profile byte 3, not a change to byte 2.** ADR-111's scheme appends one
  profile byte to the development public input; byte 2 now names a merged, pinned proof
  format. Changing what byte 2 means would make old byte-2 proofs fail. Byte 3
  (`Sources::CircleAll`, input file `stele-dev-public-v3`) is the A11 set with every
  multiplicity layout at `blowup = 2`. Pre-A11 and byte-2 proofs are the same bytes, keep
  their pins and verify. Byte 3 is the default for new proofs.
- **Geometry.** The multiplicity `ell` is chosen by A11's rule (fewest certificate plus
  opening bytes, ties smallest `ell`). The model sources are A11's, so a byte-2 model
  commitment is a byte-3 model commitment.
- **RFC placement.** RFC-0026 A12 only. RFC-0008 A5's layout already admits
  `blowup ∈ {1, 2}`, and A11 item 3 already replaced A5's `policy = 1` for development
  proofs, so no RFC-0008 text changes. A12 is Proposed; it needs one independent reviewer
  from another lane.
- **No λ, quarantine intact.** No new challenge, label or ledger line; no profile is
  claimed. The development path reaches Policy 2 only through
  `from_code_id_development`. `standard_quarantine`'s development pattern widens from
  `Sources::Circle` to `Sources::Circle\w*`, so `Sources::CircleAll` is confined to the
  same allow-list (with a gate test); the allow-list itself is unchanged.
- **Verifier order.** The engine checks a multiplicity section's length before parsing
  its certificate. Without that, an A11 proof read as byte 3 failed at a column nonce
  (`GrindMismatch`), because its larger rate-1/2 certificate covers the shorter rate-1/4
  wire; now it fails as `ProofShape`, the reason NC-1318 states. Accepted bytes do not
  change.
- **Controls.** NC-1317 and NC-1318 (byte 3 against byte 2 both ways, `ProofShape`),
  NC-1319 (transcript binding of the byte alone, `RoundSumMismatch`), NC-1320 (column
  nonce of a rate-1/4 multiplicity certificate, `GrindMismatch`). Mutation-checked: the
  layout forced to rate 1/2 turns NC-1317, 1318 and 1320 red; byte 3 pushed as 2 turns
  NC-1319 red ("byte not bound"); the certificate's column-nonce check removed turns
  NC-1320 red. NC-1311..1316 keep byte-2 honest proofs.
- **Benchmark.** `bench/ledger/e16-31-*.json`, one Apple M4 Max laptop, byte 2 at
  `fe77a02` against byte 3 at `8ae605d`. Proof bytes fall from 7.31 to 4.53 MB (L0),
  9.80 to 7.02 MB (L1) and 18.33 to 15.55 MB (L2a): 2,770,624 bytes on every rung, the
  multiplicity certificates and their openings. Prove and verify time are unchanged
  within the spread of five alternating runs (L0, L1; load 1.5 to 10); L2a is one run
  each (157.3 against 174.3 s prove, 6.30 against 6.31 s verify; not significant).

Consequences: development proof bytes change under byte 3 (new pins); byte-2 and pre-A11
proofs are unchanged. Open: the independent review of A12.

Status: Accepted with RFC-0026 A12 (development tier). Independent review: MERGE at 6044c28. NC-1319 isolates the byte-3 transcript binding, the length-before-parse reorder does not change acceptance, and ADR-108 is still enforced. Follow-ups: explicit match arms for Sources dispatch; note the stories42M split is inferred.

## ADR-114: dev-zk on balanced Policy 2 hiding sources, profile byte 4 (RFC-0013 A8, task E12-28)

Numbered after ADR-113, which #353 holds.

Context: the eight-layer dev-zk proof is 141.7 MB. It is not an expander problem: dev-zk
sources are already Circle rate 1/4 (RFC-0010 A15). Two combined rows of the witness
source, at A5's least row count (`ell = 3`, `2^21` data columns), take 134 MB.

Decision:
- A new profile byte 4 for dev-zk on balanced sources. Byte 1 keeps verifying. Model
  commitments record their byte.
- Each claim source's `ell` is chosen by a byte-count rule subject to A2/A6's row and
  query budgets.
- Policy 2 on every dev-zk source, resolved for development, with least-nonce
  grinding.
- The hiding argument is re-instantiated, not re-proved: Lemma 1's
  `|Q| ≤ C − 1` and Lemma 2's rank budget hold at the new `q`, `C`, `R`. Nonces are
  functions of the public prefix.
- Projected 6.6 MB (design note `formal/zk-sources.md`).
- Rules added after the independent review of the first draft (accept with fixes):
  - a fresh `σ_M` per byte-4 commitment, and a byte-1 secret file refused;
  - every grinder returns the least passing nonce;
  - `k_t` on the source row exponent `ell + 1`;
  - a linear claim and shared layout at any `ell`;
  - `Statement` when no `ell` is admissible;
  - A8 item 7's superseded text in RFC-0010 A14/A15 and RFC-0026 A11.
- Implementation waits for #353 (RFC-0026 A12, byte 3) to land, then lands in the same
  PR as the amendment.

Status: Accepted (development tier) with RFC-0013 A8. Independent review: design ACCEPT-WITH-FIXES
at 2e56537; implementation FIX-THEN-MERGE at afe2fc0 (6,421,222-byte proof and byte-1 pins
reproduced, native green, decode_zk byte-check and Policy::One-downgrade mutations caught);
all fixes applied at 02008a0.

## ADR-115: dev-zk soundness ledger from the verifier, and the dev-zk worst round (RFC-0013 A5, RFC-0008 A7, task E12-26)

Context: `verify-dev` printed only counts for dev-zk proofs (RFC-0013 A5, E12-14b notes).
RFC-0013 A8 item 4 left open which round of a dev-zk proof is the worst. RFC-0026 A11
and A12 state, for development proofs, that the worst round stays the ungrinded LU
round.

Decision:
- The dev-zk verifier (`zk::claims::verify_lifetime`) builds a `Ledger` while it
  replays the proof. `verify-dev` prints it, in the RFC-0026 §6 format.
- It uses only existing lines. `relation::Line` gains `Zd` and `Mask` for RFC-0008
  A7's ZD and RFC-0013 A2's MASK; development ledgers never emit them.
  - RLC: identity coefficients, batch coefficients, ZK-GKR `λ`/`t*`.
  - SZ: `τ`, `ρ` and the first ZK-GKR `r`.
  - SC: each masked instance's record at its declared degree.
  - MASK: 1 per masked instance.
  - LU: `c·(N + t) − 1` per check, with `N = 2^n` (RFC-0012 A17 item 3, Lemma 4;
    the recorded `h + N + c·t − 1` holds only for `c = 1`), in the round and in the
    sum. ZD: `2^{n+1}·c` per check.
- PCS terms per hiding source, from the verifier-derived parameters: the tensor
  round `2·ell·(e + 1)/|K|` over `2^k_t`, and the column rounds at the policy's
  target plus `k_q`. They are printed as conjectural and not summed.
- Producer aborts are printed as completeness terms and not summed:
  - from RFC-0013 A5 item 4: MaskRank `2D·(ell + 1)/p` per source, claim-block rank
    `D·c_D/p` per claim, and the `|K|` terms as one total (2 per claim and 3 per
    masked instance);
  - from RFC-0008 A7 item 4: the ZK-GKR block-rank count (`< 3D`), not bounded yet
    (R9).
- Rounds follow RFC-0012 A17: a maximal run of challenges, with the draws that share
  a run summed. The ledger prints the round with the largest error after grinding.
  Logs are integer (1/1024 bit), and printed values are rounded down to a tenth of a
  bit, toward the larger error.

Findings (the E12-28 eight-layer proofs; the one-layer window in the pinned tests):
- Byte 4: the worst round is one check's ungrinded LU + ZD round, `2^-100.4` (one layer
  `2^-105.0`). Every PCS round is `≤ 2^-108`. This confirms the RFC-0026 claim for
  dev-zk byte 4. ZD is about twice LU in that round.
- Byte 1: the worst round is the narrow witness source's ungrinded Policy 1 tensor
  round, `2^25/|K| ≈ 2^-99.0` (one layer `2^-103.9`). It is ahead of the LU + ZD round
  (`2^-100.4`). The claim is refuted for byte 1. This matches RFC-0008 A8's note that
  Policy 1 tensor rounds can fail (C1).
- `eps_interactive·|K|`: 57,662,820 (byte 4) and 57,662,822 (byte 1) on eight layers;
  2,678,735 and 2,678,737 on one layer.
  The only difference is the shared batch's SC record, 38 against 40: its source
  geometry gives it one round fewer at byte 4.

Consequences:
- No byte, label, loss form or order changes. Proof bytes and pins are unchanged.
- The tests pin `eps_interactive` on both windows and bytes, and the worst-round line
  per byte.
- No level is claimed. (C1)–(C4) are still not checked for dev-zk, and FS stays
  unproven (Q12).
- New byte-1 commitments are opt-in (`--zk-profile 1`); byte 4 is the default.

Status: Accepted (development tier; no security level claimed). Independent review: FIX-THEN-MERGE at 391cd94.
An independent script reproduced every `eps_interactive` and confirmed the round model.
The fixes are applied: LU is `c·(N + t) − 1`, the GKR block-rank and `|K|` abort lines
are printed, the labels are unified, and `rows_log` replaces `ell`, all at 821aef8. Follow-up: the plain development ledger (`relation_lookup.rs`, soundness-accounting.md inventory) still uses `2^m + c·t − 1` and needs the same fix.

## ADR-116: The development ledger's LU line is the (β, α) round numerator c·(2^m + t) − 1 (RFC-0026 A13, task E16-32)

Context: E12-26's independent review found that the dev-zk LU line used RFC-0012
A8/A11's recorded `N + c·t − 1`. RFC-0012 A17 item 3 (`formal/fs-composition.md` Lemma 4)
charges a check's single `(β, α)` round `c·(N + t) − 1`, and the recorded value equals
that only for `c = 1`. The plain development ledger (`relation_lookup.rs`, RFC-0026 A3,
the soundness-accounting inventory) had the same undercount of `(c − 1)·2^m` per `c = 2`
check.

Decision:
- `relation_lookup.rs` charges `c·(2^m + t) − 1` per check. RFC-0026 A13 (Draft)
  replaces A3's ledger item with A17's form, and the soundness-accounting development
  inventory follows.
- The stories42M ledger (`research/fs-pcs/stories42m-ledger.tsv`) is re-printed by the
  fixed verifier on the recorded proof (`e813ce1`, `proof.bin` SHA-256
  `507b52b3…5381`). Only the four `c = 2` tables change: `sign/8` 1,049,087 → 2,097,663,
  `rsqrt_q` 100,351 → 102,399, `exp_q/direct` 327,681 → 589,825 and `silu_q`
  1,179,647 → 2,228,223. `eps_interactive` goes from 350,466,731 to 352,828,075 over
  `p^4`.
- `research/fs-pcs/study.py` charges each LU round its recorded numerator. Before, it
  charged `2·numerator + 1` for every non-range check, an over-charge that was safe.
  - Worst rounds and floors are unchanged: Policy 1 at `2^-97.0` (LU `range_8`, `c = 1`)
    with floor `2^-95.6`, and the Policy 2 rows.
  - The per-proof grind-hash receipts drop by 2: 3,090,950, 3,090,978 and 3,091,010.
    `--check` passes.

Consequences:
- No proof byte, transcript or pin changes; only the printed LU lines and
  `eps_interactive` of proofs with `c = 2` checks.
- RFC-0026 A11's and A12's statement "the worst round is still the ungrinded LU round"
  holds. The largest corrected table round, `silu_q`, is about `2^-102.9`, below
  `range_8`'s `2^-97.0`.
- Open, outside this task: RFC-0030 (Draft) lines 79 and 109 still state
  `h + N + c·t − 1` for the pair round and cap it at `2^24 − 1`; at `c = 2`, `N = 2^23`,
  `t = 2^16` the A17 numerator exceeds that cap. `lookup_records.rs` is an interactive-only
  record (`weighted-logup.md` §2), not a Fiat–Shamir bound, and needs no change; the
  standard profile's LU grinding (`lu_grind_bits`) already uses `c·(N + t) − 1`.

Status: Accepted (development tier) with RFC-0026 A13. Independent review: MERGE at
4bff268; non-blocking follow-ups: RFC-0030 pair-round cap, `study.py --check` pins for
the grind receipts and worst round.

## ADR-117: dev-zk byte 4 on a real checkpoint, llama2.c stories42M at T = 32 (RFC-0013 A9, task E12-29)

Context: dev-zk was admitted for the synthetic windows only (RFC-0013 A5 Admission,
ADR-109). E12-29 aims at a zero-knowledge proof of a real stories42M prefill window, with
`commit-model --zk`, `prove-dev --zk`, `verify-dev`, a measured ledger and a soundness
ledger.

Decision:
- **Blocker found and fixed: the ZK-GKR check-tree cap.** `zk_lookup::plan_lookup`
  refused a check above `2^23` positions, a limit with no RFC text. stories42M's weight
  range check (`range_8`) has `2^27`.
  - The cap is now `2^30` (RFC-0026 A3's `m ≤ 30`; `N < p` per RFC-0012 A8).
  - Columns stay at most `2^24` entries.
  - A boundary test is added.
  - No proof byte of any existing window changes.
- **Not blockers.** Weight import, the A7 gains, the norm and attention relations, and
  the lifetime budget (`P = 8`).
- **Memory.** `T = 64` does not fit a 48 GB host: the prove was killed at about 31 GB
  RSS with heavy paging, twice. The Vast.ai account had no credit for a larger host,
  so this change measures `T = 32` (the E16-11 prompt, checked `23..32`).
- **RFC-0013 A9 (Draft)** records the blockers, the hiding re-check at the stories42M
  geometry (Lemma 1/2/6′ budgets, the rank aborts, the lifetime condition), the
  declared leaks for a real model, and a proposed admission at `T ≤ 32`.
  - The new real-model leak is the per-row quantisation scales in the public Scales
    file.

Measured (`bench/ledger/e12-29-dev-zk-stories42m-t32-mac.json`; M4 Max 48 GB, shared host):
- `commit-model --zk`: 66.0 s, 31.7 GB.
- Three proofs (indices 0, 1, 2): 516.7, 592.7 and 658.1 s, median 592.7 s; peak RSS
  30.5–34.0 GB.
- `verify-dev`: 32.5–33.6 s, 17.7 GB.
- 21,411,006 proof bytes each. Every proof verifies with `--expect-model`, and a wrong
  pin is refused.
- Soundness ledger: `ε_interactive ≤ 731,241,032/p^4`. The worst round is `range_8`'s
  LU + ZD round, `2^-95.4`, ungrinded; every PCS round is `≤ 2^-108`.

Consequences:
- The README and `docs/development-e2e.md` state the real-checkpoint dev-zk claim with
  its leaks and limits.
- Open:
  - `T = 64` on a host with at least 64 GB;
  - the privacy tests on the real checkpoint;
  - tamper controls on the real proof;
  - prover memory.

Status: Accepted (development tier) with RFC-0013 A9. Independent review: FIX-THEN-MERGE at
491f111; fixes applied at bbe98f6. Open: T = 64 (prover memory), privacy tests and tampers
on the real checkpoint.

## ADR-118: dev-zk prover peak memory; one ZK-GKR tree at a time, sources prepared in turn (task E16-33)

Context: E12-29 proved stories42M under dev-zk at `T = 32` only. On the 48 GB laptop,
`T = 64` was killed twice at about 31 GB RSS. macOS compresses and swaps, so RSS hides
the demand: the `T = 32` prove's peak memory footprint was about 122 GB.

Profile (the footprint timeline of one `T = 32` prove, with stack samples):
1. The ZK-GKR leaf step of the `2^27`-position `range_8` check: dense QM31 factor
   tables over `2^28` entries, about +50 GB at the peak.
2. Hiding-source encoding: two large sources encoded together, about +30 GB transient
   (62 GB, down to 30 GB after).
3. Every check's LogUp tree, held from the `(β, α)` draws to the end of the ZK-GKR
   phase, about +25 GB.

The prepared sources' codeword columns (about 17 GB) are fourth.

Decision (stele-reductions only):
- Only each check's top is kept after the `(β, α)` draws. The tree is rebuilt from the
  same `β`, `α` and columns when its ZK-GKR steps start, one check at a time. It is
  dropped before the leaf step, which reads no tree layer.
- The early hiding sources are prepared one at a time. Each encoding is already
  parallel inside.
- Field arithmetic is exact, so every value, round and byte is the same:
  - the one- and eight-layer dev-zk pins (both bytes) and their `eps_interactive` are
    unchanged;
  - the stories42M proofs keep their sizes.
- Not needed: re-deriving the source columns at opening time through a new stele-pcs
  API, M31-typed factor tables, and dropping the doubled leaf tables.

Measured (BSD `/usr/bin/time -l` peak memory footprint; M4 Max 48 GB, shared host; each
figure is the median of its own three values):

| Window | Before | After |
|---|---|---|
| stories42M `T = 32` (medians of three, alternating) | prove 591.2 s, footprint 122.2 GB | prove 518.5 s, footprint 89.9 GB (−26%) |
| stories42M `T = 64` (medians of three) | killed | prove 923.1 s, footprint 107.1 GB, max RSS 33.6 GB; verify 46.5 s; 25,667,970 bytes |

Ledgers: `bench/ledger/e16-33-dev-zk-stories42m-t32-mac-before.json`, `-after.json` and
`e16-33-dev-zk-stories42m-t64-mac.json`.

Status: Accepted (performance only; no protocol, byte or admission change). Independent
review: FIX-THEN-MERGE at 9930b11 (rebuild inputs unchanged, no draw moved, mask streams
per source id; β/α-swap and wrong-β mutations caught by the pins). RFC-0013 A10
(ADR-119) carries the `T = 64` admission separately.

## ADR-119: dev-zk admission on stories42M extended to T ≤ 64 (RFC-0013 A10, task E16-33)

Context: RFC-0013 A9 (ADR-117) admitted stories42M at `T ≤ 32`, because `T = 64` did
not fit the 48 GB host. ADR-118 lowered the prover's peak memory without changing a
byte. `T = 64` now proves and verifies there, three proofs under one commitment.
Shipping a measured `T = 64` proof outside the admission would overstate it.

Decision: RFC-0013 A10 (Draft) extends A9's admission to `T ≤ 64`.
- The hiding re-check is re-instantiated from the `T = 64` verify output:
  - the witness source has `C = 2^17`, the weight source `C = 2^16`, both with
    `R = 2^11` data rows;
  - 314 queries per proof and 958 over the lifetime, against `C − 1`;
  - `R ≥ 2D` and `R ≥ (P + 1)·D`;
  - the MaskRank, claim-block and `|K|` abort terms; the GKR block abort is unbounded,
    completeness only.
- The worst round (`range_8`, LU + ZD, `2^-95.4`) and `ε_interactive ≤
  1,058,031,463/p^4` are recorded.
- The leaks list now names the 41 public greedy choices.
- No byte, label, round or control is added.

Status: Accepted (development tier) with RFC-0013 A10. Independent review: FIX-THEN-MERGE
at 9930b11; fixes applied.

## ADR-120: stories42M stage profile; the GPU NO-GO stands for development, and dev-zk is open at 2.0×–3.6× (upload-inclusive) and 3.8×–4.2× (resident); parallel plain checker (task E16-22, ADR-103 follow-up)

Context: ADR-103 set a provisional GPU NO-GO from fixture stage shares, with a ceiling of
about 2.57× against a 3× gate. It asked for a stories42M profile. The owner asked for it
on the Mac, since no rented host was available.

Measurement (`research/gpu-gating/STORIES42M-STAGES.md`):
- Stage wall times come from `parallel::Laps` (`STELE_STAGE_TIMES`, off by default, no
  byte effect), split by work kind with macOS `sample` (`stage_profile.py`).
- Development, byte 3, `T = 64`:
  - the plain checker was the critical path, 156 s, sequential, beside a 97 s engine;
  - prove 167.6 s (median of three).
- dev-zk, byte 4, `T = 32` (562.5 s):
  - ZK-GKR 178 s;
  - two sequential plain checks 125 s;
  - source preparation 85 s;
  - masked relations 35 s.

Decision:
- **The parallel plain checker.**
  - With `std`, `stele_ir::relation::check` runs its constraints and points on rayon's
    pool (`stele-ir/std` via `stele-reductions/std`).
  - It returns the same result as the sequential checker: pass, or the first failure in
    order. Three tests pin it in both modes:
    - the first failure in category order;
    - constraint order before point order;
    - the least failing point of a `2^16`-entry column, over 20 repeats.

    CI runs the sequential (no `std`) path. `no_std` builds are unchanged.
  - rayon is optional, as in stele-code, stele-pcs and stele-sumcheck. The crate-import
    rules (deny.toml) and rust-policy pass.
  - Results:
    - development `T = 64`: 167.6 → 123.6 s (1.36×; the checker went from 156 to 22 s);
    - dev-zk `T = 32`: 562.5 → 465.7 s (1.21×, single runs);
    - every proof byte-identical.
- **GPU, development: NO-GO stands.**
  - After this change, even an infinitely fast device that took the whole engine leaves
    witness, model sources and the 22.5 s checker: a ceiling of **2.80×**, below 3×.
  - At E16-21's ratios it is 2.80× rounds-only (checker-bound) and 2.19×–2.80× with
    the upload.
  - Before it, the ceiling was about 1.0×, because the CPU checker was the critical path.
- **GPU, dev-zk: not decided.**
  - The offloadable share is 77% (358 of 466 s).
  - The ceiling is 4.34× unbounded, and **3.83×–4.15× at E16-21's rounds-only ratios
    with resident tables**.
  - It is **2.02×–3.58× at its upload-inclusive ratios**. It is above 3× only at the
    smallest size's 15.9×, and 2.02× at the `2^24` size that matches stories42M's
    tables.
  - It assumes the masked factor tables are built on the device.
  - A GO needs a dev-zk device benchmark of the masked and GKR rounds with resident
    tables and device-side factor construction (follow-up). Until then, no GPU binding
    and no RFC-0014 amendment.

Consequences:
- Ledgers:
  - `bench/ledger/e16-22-dev-stories42m-t64-mac-before.json` and `-after.json`, with
    the stage laps in `stage_times_ns`;
  - `bench/ledger/e16-22-dev-zk-stories42m-t32-mac-before.json` and `-after.json`
    (single runs).
- CPU work ranked by expected gain:
  - SIMD QM31 and M31-typed tables in the masked and GKR products (dev-zk's top stage);
  - SIMD Circle encoding;
  - BLAKE3 `std` for runtime AVX2/AVX-512 detection on x86_64 (aarch64 already gets
    NEON from blake3's build script);
  - development LogUp leaf preparation;
  - a single dev-zk plain check.
- These change no bytes.

Status: Accepted (development tier; measurement and a performance change). Independent
review: FIX-THEN-MERGE at 86a4a75; fixes verified at 22f0d6f.
- The checker logic is correct; native is green; the ceilings were recomputed.
- The soundness-auditor pass covered the timing-only `Laps` in
  `stele-sumcheck/src/parallel.rs`: stderr only, under `std` and `STELE_STAGE_TIMES`,
  with no value, transcript or byte effect.
- Fixes applied: the two pinning tests, the CI sequential path, the stele-ir feature
  pin, the upload-inclusive ceiling, and the stage laps in the ledgers.


## ADR-121: dev-zk substitution adversary; NC-0930..0932 executed (RFC-0013 A5, RFC-0008 A7, task E12-31)

Context: NC-0930..0932 pin three public finals that the dev-zk verifier evaluates
itself: a leaf's member weight `B_m·S`, a leaf's `eq·Z`, and a contraction's
`eq(ρ_shared, ·)`. E12-14a's first controls tweaked these finals by one, with free
rounds and `μ` solved last. The independent review found that they did not
discriminate, because the shared batch's `μ` binding rejects any solved `μ`. They went
back to `todo` (ADR-101). NC-0928/0929's adversary, an honest proof of a relation with
one public column changed, cannot reach these three. They come from the statement's
structure (member offsets, the valid row count, shared bits), and changing that
structure changes the A5 statement messages, so the transcript diverges before the
final.

Decision: a controls-only substitution adversary, `zk::claims::forge_substitute`.
- It proves the true statement's plan, so every statement message is unchanged.
- It replaces one public input with a substitute that has the same sum over the cube.
  The rounds, finals and `μ` are therefore honest for the substitute, and only the
  verifier's evaluation of that final differs.
  - Member weight: `(B_m + δ·B_g)·S`, where `B_g` is an aligned block off every member
    (`S = 0`). It enters the producer's combined factors and masks, which stay
    multilinear, so the declared degree holds.
  - `Z` and `eq(ρ_shared, ·)`: moved by `δ` at a cube point where the factor's cofactor
    vanishes, else at two points weighted by each other's cofactor.
- The producer routes the true finals, from an honest twin folded at the same point.
  The verifier is not touched.
- These are substitution controls. On the cube, the substitutes prove the true
  statement, so they test that the verifier pins each public final, not a false
  witness. The final is the only binding of these inputs: a verifier that skipped it
  would accept any polynomial with the same cube sum.

Evidence (synthetic relation fixture, release build):
- `δ = 0` is accepted for all three (M0), and `δ = 1` is rejected with `ClaimMismatch`.
- Removing the member-weight check (`zk_lookup::finals`, `Gin::Member`) turns only
  NC-0930 red. Removing the `eq·Z` check (`Gin::Pad`) turns only NC-0931 red. Removing
  the step's `eq` final check (`zk_claims::public_finals`) turns only NC-0932 red. In
  each case the forged proof is accepted (`unexpected: Ok(())`). The mutations are not
  committed.

No RFC amendment: no label, byte, order or verifier check changes. RFC-0013 A5 gains
implementation notes. Coverage rises by three controls.

Status: Accepted (development tier). Independent review: MERGE at bae3215 (adversary
confined to `controls`, all three mutations reproduced, each turning only its own control
red; coverage 63/109, 131/232). Follow-ups: derive `pad_factor`'s `Z` index from the
`compact_terms` layout; gate the `Substitute` re-export behind `controls`.

## ADR-122: CPU prover speedups with identical bytes; lazy-reduction QM31 product, base-field masked rounds, one dev-zk plain check, blake3 std (task E16-34)

Numbered after ADR-120 (#362) and ADR-121 (#363).

Context: E16-22's stories42M profile ranked the dev-zk masked and ZK-GKR products (QM31)
first among the CPU stages. It also listed BLAKE3 SIMD and dev-zk's second plain check.

Decision (four commits; every pin byte-identical):
- **Lazy-reduction QM31 product** (stele-field).
  - Limb products are summed in u64, with at most four per sum (`< 4p² < 2^64`), and
    each output limb is reduced once. A subtracted product `x·y` is added as
    `x·(p − y)`.
  - It is the same element as RFC-0003 §2's Karatsuba product. That product is kept as
    `QM31::karatsuba`, and a test pins the two equal on 10^6 random pairs and on every
    edge-limb pair. The existing schoolbook-oracle tests pass.
  - CM31 and OM31 keep Karatsuba; OM31 benefits through its QM31 sub-products.
- **Base-field masked rounds** (stele-reductions).
  - A dev-zk masked round treats as base field every factor whose tables are all
    base-field: occurrences and masks before a challenge is folded in. `κ(t)` is an
    integer at integer nodes.
  - Those factors are stepped and multiplied in M31, and the product is applied once
    with `mul_m31`.
  - Rounds with no base factor keep the old path.
- **One dev-zk plain check** (stele-prover). The committed relation keeps every
  constraint of the layout relation over the same values and adds the record encodings,
  so checking it alone rejects every false witness the first check did.
  `rejects_false_witness_with_check_under_dev_zk` pins it: a false next token and a
  false checked token are each rejected with `Check` by `zk::window` and `zk::prove`.
  With the check replaced by a no-op, the test fails.
- **blake3 `std`** (stele-code, under the prover-side `std`) adds runtime AVX2 and
  AVX-512 detection on x86_64.
  - On aarch64, blake3's build script already enables NEON, so this host gains
    nothing from the change.
  - Correction: an earlier draft of this record and of #362 said blake3 ran portable
    on aarch64. That was wrong. #362 merged with the corrected line (ADR-120 and
    `research/gpu-gating/STORIES42M-STAGES.md` §4 item 4), so neither needs an edit.
  - `no_std` builds and every digest are unchanged.
- **Not done: stele-simd in the round loops.** deny.toml lets only stele-code and
  stele-poly import stele-simd, and the scalar lazy product already gives most of the
  gain.

Measured (M4 Max 48 GB; before = main 0298d88, after = 5670be3). Each row is the
median prove run and that run's verify, as the ledgers record:

| Workload | Before | After |
|---|---|---|
| synthetic eight-layer dev-zk byte 4 (median of three) | prove 27.66 s, verify 2.96 s, peak RSS 7.16 GB | prove 21.05 s (1.31×), verify 2.04 s, peak RSS 7.31 GB |
| synthetic eight-layer plain dev (median of three) | prove 8.62 s, verify 0.87 s | prove 6.60 s (1.31×), verify 0.78 s |
| stories42M dev-zk `T = 32` (single runs) | prove 475.6 s, verify 32.3 s, peak RSS 31.9 GB | prove 369.7 s (1.29×), verify 21.6 s, peak RSS 32.5 GB |

- Peak RSS rises by about 2% in these runs (7.16 → 7.31 GB synthetic, 31.9 → 32.5 GB
  stories42M). The cause is not separated from run-to-run variation.
- The stories42M plain dev `T = 64` single runs (175.5 s before, 181.7 s after, same
  bytes) are in the `host_context` of the `e16-34-dev-zk-stories42m-t32` ledgers. That
  run is bound by main's sequential plain checker, which E16-22's parallel checker
  (#362) removes.

Ledgers: `bench/ledger/e16-34-*-mac-{before,after}.json`.

Status: Accepted (performance only; no protocol, byte or admission change). Independent
review: FIX-THEN-MERGE at 6c27032 (lazy QM31 product proven exact and 6/6 mutants caught;
base-field rounds decided per factor at runtime, 3/3 mutants caught; the single dev-zk plain
check covers the dropped one); fixes applied, including the dev-zk false-witness test.

## ADR-123: dev-zk GPU: NO-GO lifted for the masked and ZK-GKR rounds; GO pending E16-36's re-profile and device source-preparation measurement; development stays NO-GO (RFC-0014 §1, §5, task E16-35, ADR-103 and ADR-120 follow-up)

Context: ADR-120 left dev-zk open. Its ceiling was 3.8×–4.2× with resident tables and
2.0×–3.6× with E16-21's upload-inclusive ratios, and a GO first needed a device
benchmark of the masked and GKR rounds with resident, device-built tables.

Measurement (`research/gpu-gating/DEV-ZK-DEVICE.md`,
`bench/ledger/e16-35-dev-zk-gpu-masked.json`):
- **Kernels.** `research/gpu-gating/masked`: one `Occurrences` round (RFC-0013 A5
  item 2) for any term list, generated per round shape and compiled by NVRTC at run
  time; M31 tables stepped in M31; folds in place; tables built on the device (`eq`,
  tiles, layer halves, mask tables); one round polynomial copied back per round.
  Opt-in (`--features cuda`), CUDA loaded at run time (cudarc 0.19.10,
  `dynamic-loading`); CPU only by default.
- **Shapes.** A masked identity relation (degree 4) and a ZK-GKR layer step (RFC-0008
  A7 item 4, nine inputs, degree 5), `2^20..2^27` entries. The shapes are hand-built:
  parity shows the device equals the CPU on them, not that they cover every production
  relation or step.
- **Bit equality.** Every round polynomial and every folded table equals the
  production CPU summand's (`stele_reductions::zk::claims::bench`, feature `bench`)
  at every round: 10 of 10 cases in `tests/parity.rs` and 10 of 10 in the bench's
  check mode.
- **Host.** Rented RTX 4090 with an AMD EPYC 7B13 (61 threads), same box for CPU and
  GPU; CPU = PR #364's tree, faster than main's in every cell.
- **Results at `2^24..2^27`.**
  - Full sumcheck, rounds only (production code on both sides): relation 31–38×,
    GKR layer 14.8–16.5× (e.g. GKR `2^27`: 5.03 s CPU, 0.34 s GPU).
  - With table construction and uploads at the bus rate (17.7 GB/s pageable,
    measured): 38–61×. The CPU construction is part production (`eq_table`,
    `block_table`) and part sequential research-crate loops, so this overstates the
    production CPU's construction cost.
  - The bench's measured upload phase (host staging, about 1.3 GB/s) gives 7–11×.
- **Ceiling.** E16-22's laps (single run), with the stage speedups re-measured against
  the Mac CPU that took them (rounds only, 39.7–83.4×):
  - the other offloadable stages `R` at E16-21's rounds-only ratios: 3.93×–4.16×;
  - `R` at E16-21's upload-inclusive ratios: 2.83×–3.90×;
  - the masked and GKR rounds alone, `R` on the CPU: 1.8×;
  - every stage re-uploading its tables at the bench's staging rate: 2.60×–2.96×.
  Every ceiling above 3× assumes `R`, and in it source preparation (Circle encoding,
  salts, Merkle; 103.5 s), gets a device speedup that was not measured.
- **After PR #364** (estimate; no stage laps): if its 105.9 s all came out of the masked
  stages, the unbounded ceiling is 359.8 / 107.47 = 3.35× (3.44× on the 369.7 s wall),
  and 3× needs all of `R` at about 12× on the device even with `M` free, about 17×
  with `M` at 26.6×.

Decision:
- **dev-zk: NO-GO lifted for the masked and GKR rounds; GO pending E16-36's re-profile
  and device source-preparation measurement.** ADR-120's open question is closed: on
  the device the masked relations and ZK-GKR (208 s of 466 s) cost 2.5–8 s. Whether
  ADR-103's 3× gate holds now depends on the rest of the offloadable work, chiefly
  source preparation, which this task did not measure. A backend that offloads only
  the masked and GKR rounds stays below 1.8×: NO-GO for that partial scope.
- **Development: NO-GO stands** (ADR-120; ceiling 2.80× even at unbounded device
  speed). Tasks E16-21a..e stay blocked.
- **No GPU binding and no RFC-0014 amendment here.** The kernels stay in `research/`;
  `crates/stele-gpu` stays the scaffold under the parity guard (task E10-01).

E16-36 decides GO or NO-GO by a new ADR. It is a NO-GO if either:
- device source preparation at stories42M sizes is below the source-preparation ratio
  the E16-36 re-profile requires for 3× (same host's CPU);
- the re-profile on current main puts the ceiling below 3× even with every
  offloadable stage free.

What full integration needs (task E16-37, after a GO from E16-36):
1. Workflow 02: an RFC-0014 amendment for a dev-zk backend (opt-in feature, run-time
   CUDA, CPU default, verifier and `no_std` builds free of GPU code), RFC-0026 §7
   cross-reference; an ADR for cudarc with run-time loading.
2. E16-21a's backend trait, op table and parity harness, and E10-01's parity gate wired
   for `crates/stele-gpu` (byte-identical proofs on randomised inputs, INV-3), with a
   GPU CI runner or a recorded manual parity run per PR.
3. Device stages with state resident across them: the committed witness uploaded once
   through pinned staging; hiding-source encoding and Merkle; LogUp trees and tops;
   the masked relations and ZK-GKR steps (these kernels, extended to first and leaf
   steps and compact leaves); claim batches. The transcript stays on the host; each
   round sends back only its polynomial.
4. A stories42M dev-zk T = 32 GPU ledger against the same host's CPU, with identical
   proof bytes.

Consequences:
- `stele-reductions` gains the off-by-default `bench` feature (prover-side access to
  the masked summand for the benchmark); no proof byte, transcript or verifier path
  changes. The native gate pins it, and the feature quarantine keeps it out of the
  default workspace build and of stele-cli, stele-prover and stele-verifier.
- `research/gpu-gating/masked` is a standalone crate (own `[workspace]` and lock);
  the workspace jobs do not build it. The research inventory group `gpu-gating-masked`
  runs its CPU tests and checks the `cuda` build; that group runs when a PR touches
  `research/` (or shared build files), not on a change to `stele-reductions` alone.
  No CI host has a GPU, so the device test only runs on a rented host.

Status: Accepted (owner authorisation for autonomous gating decisions). Independent
review: FIX-THEN-MERGE on #368 (kernels, parity and ceilings reproduced); this text
carries its fixes (the post-#364 estimate, the decision wording, rounds-only `M`).

## ADR-124: Non-ZK standard admission does not wait on Q29; E8-05 depends on E8-05b and E8-05c instead of E8-05a (RFC-0002 §8, RFC-0012 A17; tasks E8-05, E8-05c)

Numbering: ADR-121 is #363's, ADR-122 is #364's and ADR-123 is #368's (the GPU device
benchmark, E16-35).

Context:
- E8-05 (soundness ledger generator and accounting gate) depends on E8-05a.
- E8-05a is `blocked(RFC-0013 A1)`. Its first acceptance line asks for "Accepted
  complete Q12 query/FS/hash and Q29 privacy composition before profile admission".
- Q29 is commitment privacy, a zero-knowledge question. RFC-0002 §8 (Accepted, not
  changed by A1) makes ZK optional for `standard` and mandatory for `treaty`.
- So a `standard` proof that claims no zero knowledge does not need Q29 to be sound.
  E8-05a's blocker holds back the soundness work that is ready: Q12 is Accepted
  (RFC-0012 A17, RFC-0002 A1, RFC-0010 A14).

Decision (Proposed):
- **Scope.** A non-ZK `standard` admission needs Q12 and not Q29. A ZK `standard`
  admission and every `treaty` admission still need Q29 (RFC-0013 A1), as E8-05a says.
- **Graph.** E8-05 depends on E8-02, E8-05b and E8-05c, not on E8-05a:
  - E8-05b is the exact (C1)–(C4) decision (`stele_verifier::accounting::admit`, #366);
  - E8-05c enumerates a development proof's rounds and prints the verdict in
    `verify-dev`.

  E8-05a stays `blocked(RFC-0013 A1)` for ZK and treaty admission. Those move to a
  new task, E8-05e, which depends on E8-05 and E8-05a, so treaty cannot close without
  Q29. E8-05 is retitled to the non-ZK standard profile.
- **What E8-05 still owes for non-ZK standard.** These are E8-05a's other acceptance
  lines, now E8-05's for that profile:
  - the canonical ledger derived from the plan and instance geometry;
  - every challenge, query, failed attempt and lifetime obligation kept;
  - `no_std` derivation with an independent exact enumeration;
  - NC-0804/0805 and NC-1205 through the verifier entry point;
  - LU lines from `LookupParameters::identity_term` of an actual verified lookup
    record (ADR-072);
  - no final passport or accepted inference proof as a derivation input.
- **No MASK term.** A non-ZK standard proof has no masked rounds, so E8-05a's "no MASK
  term" is met trivially. A ZK proof's MASK rounds are in its ledger (E12-26) and are
  admitted only with Q29.
- **What does not change.**
  - `standard-unproven` stays until E8-05 adds the composed check at the verifier
    entry point (ADR-108).
  - No proof claims a level, and development proofs claim none (RFC-0026 §1.2).

Consequences:
- No proof byte, pin or ledger line moves.
- E8-05 can proceed on non-ZK standard without RFC-0013 A1.
- Today's development proofs fail the rule, so the verdict line `verify-dev` now prints
  is informational. On the synthetic eight-layer window (T = 64):
  - the worst round is LU range_16 at 2^-101.9;
  - the floor is 2^-99.6 on Policy 1 sources and 2^-99.4 on Policy 2 sources;
  - the verdict is FAIL (C4), because LU rounds are not ground.
- On study.py's recorded stories42M ledger, the same code gives LU range_8 at
  2^-96.99999 (printed 2^-96.9) and a floor of 2^-95.6, as in PARAMETERS.md §4.

Independent review of #367: FIX-THEN-MERGE.
- **Confirmed.**
  - Every draw maps to exactly one round.
  - Sum and max are exact; independent exact-rational sums reproduce the pins.
  - `Q_V = 2^64 − 1` is sound.
  - The RFC-0002 §8 basis holds.
- **Fixes applied.**
  - The moved E8-05a lines are in E8-05's acceptance, scoped "(non-ZK standard)",
    and E8-05e holds ZK and treaty.
  - A zerocheck is three entries: `τ` (j, j), skip (D, D) and tail (j·δ, δ). The
    eight-layer window now has 11,687 rounds, not 11,647; its worst round and floor
    are unchanged.
  - The `2^124`-for-`p^4` display rounding is documented as display only.
  - An unknown round line fails the verdict instead of reading as MASK.
  - The verdict notes that Policy 1 sources always fail (C4).
  - The test checks each entry's rounds, not each name's.

Status: Proposed (governance; no protocol change). Review requested.

## ADR-125: Development proofs with ground lookup (β, α) rounds, profile byte 5 (RFC-0026 A14, task E8-05d)

Context:
- E8-05c's enumeration found that the only development rounds above `2^-108` are the
  checks' ungrinded `(β, α)` rounds.
- RFC-0012 A17 item 5 allows grinding there, and ADR-108 implemented it for the
  standard A5 consumer only.
- `research/fs-pcs/PARAMETERS.md` §4 predicts that Policy 2 Circle rate-1/4 sources
  with ground LU rounds meet (C1)–(C4) on stories42M: worst `2^-108.0`, floor
  `2^-102.2`, 18.3 MB.

Decision (Proposed, with RFC-0026 A14 Draft):
- **New source set and byte.** `Sources::CircleAllGrind` has A12's sources and profile
  byte 5, with input file `stele-dev-public-v4`.
- **Grinding bits.** Each relation-engine check grinds its `(β, α)` round at the least
  `k_LU` meeting (C1), given by `lookup::lu_grind_bits` on A13's numerator. The bits
  come from the plan only.
- **Nonce.** It is placed as in RFC-0008 A8 (after `Repetition(id, 0, 0)`, before
  `Beta`), and on the wire it is the first 8 bytes of the lookup section.
- **Least nonce.** The prover sends the least valid nonce. The verifier does not check
  leastness; any valid nonce is sound.
- **Ledger.** LU entries carry `k_LU`, so E8-05c's `rounds()` and `verify-dev`'s
  verdict count it.
- **CLI.** `stele prove-dev --dev-profile 5` selects byte 5, and byte 3 stays the
  default.
- **Code placement.**
  - The gate's development pattern already covers the new variant
    (`Sources::Circle\w*`).
  - The CLI selects the profile by byte (`prove_window_development`), so the
    variant name stays on the development path.

Consequences:
- **Pins.** Byte 0–4 pins are unchanged. New pins: one-layer T = 16 at byte 5
  (`0x59ee_67e3_9aa2_5d4b`) and eight-layer T = 64 (`0xf66d_7640_b9de_788e`,
  7,024,665 bytes, which is byte 3 plus 144).
- **Synthetic eight-layer verdict.** `verify-dev` prints PASS (C1)–(C4):
  - the worst rounds are the PCS column rounds, at exactly `2^-108`;
  - the largest LU round, silu_q, is at `2^-108.0000055` after 2 bits, a tie at the
    printed resolution (`verify-dev` names silu_q, the first in ledger order);
  - the floor is `2^-101.9`.
- **stories42M T = 64 at byte 5** (`bench/ledger/e8-05d-dev-stories42m-t64-byte5-mac.json`):
  - PASS;
  - worst round: a PCS column round at `2^-108` (the 19 ground LU rounds are below it);
  - floor `2^-101.9` (study.py predicted `2^-108.0` and `2^-102.2`);
  - 15,554,913 bytes, byte 3 plus 152;
  - 137.8 s prove, an upper bound because the load rose to 20.
- **Controls.**
  - NC-1321: `GrindMismatch`.
  - NC-1322 and NC-1324, bytes 5 and 3 read as each other: `RoundSumMismatch`.
  - NC-1323, another valid nonce: `RoundSumMismatch`.
  - Mutation checks:
    - NC-1321 goes red with the predicate skipped;
    - NC-1323 goes red with the nonce not absorbed;
    - the "absorb after `beta`" mutant is caught only by the white-box test
      `draws_beta_and_alpha_after_the_nonce`. No accept-or-reject control can see it.
- **No level claimed.** Nothing is `proven: true`. The composed check at the verifier
  entry point is E8-05's (ADR-108).
- **stories42M.** The T = 64 measurement at byte 5 is pending a quiet host.

Independent review of #369: FIX-THEN-MERGE.
- **Confirmed.** Placement, plan-derived k, least k via `admit` (C4), and identical
  bytes 0–4. All 11,647 eight-layer rounds (11,687 after #367 split each zerocheck into its phases) were recomputed exactly; none is above
  `2^-108`, and the floor is `2^-101.989`.
- **Fixes applied.**
  - RFC-0008 A8 item 1 replacement text (A14 item 9);
  - NC-1323 with its mutation checks;
  - NC-1324;
  - the leastness sentence;
  - the silu_q wording;
  - "Cells, lookups: none added";
  - `--dev-profile` checked against 3 and 5.

Status: Proposed (development tier). Review requested with RFC-0026 A14.
