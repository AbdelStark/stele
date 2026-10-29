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
