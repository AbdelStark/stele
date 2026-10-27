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
