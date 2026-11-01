# RFC-0020 — Monorepo and crate architecture

Status: Accepted · Version: 0.1.0

## 1. Layout
```
crates/
  stele-field       M31/CM31/QM31/OM31/KoalaBear; Field trait; serialisation                 [no deps]
  stele-simd        AVX2/AVX-512/NEON specialisations (unsafe allowed, SAFETY comments)       [field]
  stele-poly        MLEs, eq tables, partial evaluations, bucketed small-value kernels         [field, simd]
  stele-hash        Blake3, Poseidon2-M31, Merkle (short columns), Transcript (RFC-0012)       [field]
  stele-sumcheck    engine, strategies (naive, eq-trick, small-value, streaming), batching     [poly, hash]
  stele-gkr         stacked reductions, claim graph runtime, RLC batching, public MLEs         [sumcheck]
  stele-lookup      LogUp-GKR, table registry, range discipline checker                        [gkr]
  stele-code        circle RS encoder, RAA/expander encoder, Code trait, codes.toml             [field, simd]
  stele-pcs         interleaved-code PCS, functional openings, fused opening, Ligerito mode, blinding [code, hash]
  stele-cqis        CQIS spec types, tables, quantiser, bound certificates, bit-exact reference forward [field]
  stele-ir          Tensor IR, lowering from HF, stacking, plan.json, range-discipline check    [cqis]
  stele-reductions  one module per op: matmul, requant, rmsnorm, rope, silu_gate, attention, embed, lmhead, moe, mla [gkr, lookup, pcs, ir]
  stele-prover      orchestration: stages, witness capture/recompute, memory planner, scheduling [reductions]
  stele-verifier    no_std verifier of stele-proof-v1; accounting; plan derivation              [field, hash, (ir-lite)]
  stele-proof       proof container types and (de)serialisation                                 [field]
  stele-kernels     ops.toml + codegen for CPU reference and CUDA mirrors                        [build-time]
  stele-gpu         CUDA backend (cudarc), parity harness                                        [kernels, prover]
  stele-dist        multi-GPU/multi-node orchestration (NCCL/MPI), checkpoints                   [gpu]
  stele-passport    registration pipeline, certificates, binding proof driver                    [pcs, cqis, wrapper]
  stele-wrapper     recursion wrapper adapters (Stwo verifier circuit), table openings            [verifier]
  stele-bench       ledgers, fitting, roofline, SOTA comparison tables                            [prover]
  stele-cli         `stele quantise|register|prove|verify|bench|plan|controls`                   [all]
  stele-py          PyO3 bindings for the harness                                                [prover, verifier]
harness/            Python: quantiser driver, reference forward (NumPy int), eval suite, Python verifier
tests/negative-controls/  catalog.md + control binaries (each a `#[test]` expecting a specific rejection)
formal/             Lean 4 statements L-1..L-6
```

## 2. Dependency rules
Arrows only downward in the list above; `stele-verifier` depends on nothing above `stele-hash` except a tiny
`stele-ir-lite` plan derivation; `stele-prover` never imports `stele-verifier` (prevents verifier logic leaking into
the prover); no crate imports a third-party proof system. Reference implementations for differential tests live under
`vendor-ref/` and are `dev-dependencies` only.

## 3. Feature flags
`parallel` (rayon), `simd` (default on x86_64/aarch64), `cuda`, `dist`, `treaty` (enables OM31, double-α, ZK by default),
`dpa` (research), `wrapper`.

## 4. Testing layers
1. Unit (ring axioms, kernels, serialisation). 2. Reduction tests: random small tensors, honest prover accepted,
`rejects_*` controls. 3. Differential: Rust vs Python verifier; CPU vs SIMD vs CUDA digests. 4. End-to-end: W8 in CI,
W1 nightly on GPU runners. 5. Fuzz: proof parser, verifier (no panics). 6. Property: bound certificates vs random
shapes. 7. Controls: full catalogue in CI.

## 5. CI gates (`.github/workflows/ci.yml`)
fmt, clippy `-D warnings`, `cargo test --workspace`, digest gate, controls gate, accounting gate (if transcript or
challenge code changed), parity gate (if `stele-gpu` changed, on GPU runner), bench ledger validation, docs link check,
RFC status check (no code references a `Draft` RFC).

## 6. Versioning
Protocol version in `stele-proof-v1` header; CQIS version in `cqis_id`; crates semver; `CHANGELOG.md` per release with
the list of ADRs and RFC amendments.

## 7. Amendment log

### A1 — Direct sumcheck field dependency

Status: Accepted. Review: [skill passes](../../agents/reviews/sumcheck-a1.md). Companion to RFC-0006 A1. The `stele-sumcheck` dependency list is
`[field, poly, hash]`: its generic polynomial, canonical field encoding and
interpolation implementations may use the field contract directly. The negative
control harness may import sumcheck and field for real protocol controls. These
are downward/test-only edges; no core crate may import the control harness or an
upstream proof implementation. No soundness term or cost-model constant changes.
Affected tasks: E3-01, E2-01. Dependency bans must enforce the amended edges when
implementation is delivered; the amendment alone adds no Cargo dependency.

### A2 — Direct stacked-runtime primitive dependencies

Status: Accepted. Review: [coordinated skill passes](../../agents/reviews/stacked-runtime-a4.md). Question Q20. Companion to RFC-0006 A4 and RFC-0012 A6.
For the [conditional stacked runtime](../../formal/stacked-runtime.md),
`stele-gkr` dependencies are exactly `[field, poly, hash, sumcheck]` for public
coefficient arithmetic, direct public originals, canonical framing and A1 reuse.
These are downward edges. Certified-source closure stays in stele-reductions,
using its existing GKR/PCS/field/hash edges and the actual A9 point verifier.
GKR imports no PCS, CQIS, IR or authentication callback. No core crate imports
the control harness, and no new external dependency is authorized.

On implementation replace the A7-only scaffold guard with the actual reviewed
stacked producers/consumers; update exact dependency bans and rejection tests.
The amendment alone changes no Cargo manifest, production gate, challenge,
soundness record, measured constant or weight pass. Affected task: E3-06.
Private coefficient/source and inference admission remain outside this contract;
the coordinated review approves these exact edges for implementation.

### A3 — Public coefficient field dependency

Status: Accepted. Review: [skill passes](../../agents/reviews/public-coefficient-a7.md).
For RFC-0006 A7, `stele-gkr` may directly depend on `stele-field` in addition to
`stele-sumcheck`. This downward edge exposes typed field arithmetic only; no
hash, PCS, poly or authentication edge is authorized by A3. A2 remains Draft.
Update dependency bans with this exact edge. No external dependency, protocol,
challenge, loss or measured constant changes. Affected task: E3-06a.

### A4 — Conditional fraction reduction dependencies

Status: Accepted. Companion RFC-0008 A3 / RFC-0012 A9.
Review: [skill passes](../../agents/reviews/fraction-a3.md).
stele-lookup may directly depend on field, poly, hash and sumcheck in addition
to gkr, for canonical encoding, equality coefficients, production transcript
and A1 reuse. These are downward edges; no authentication callback or upstream
proof implementation is authorized. Test-only serde_json may read the shared
byte corpus. Update dependency policy and native gates at implementation;
preserve guards for unimplemented lookup/PCS/verifier work. Codec tests earn
no binding/profile credit. No measured constant changes. Affected task: E3-07a.

### A5: Conditional field-source primitive dependencies

Status: Accepted. Review: [conditional field PCS skill passes](../../agents/reviews/field-pcs-acceptance.md). Companion RFC-0010 A9 and RFC-0012 A10.
For the exact field PCS contract, stele-pcs may directly depend on stele-field
and stele-poly in addition to code/hash. Canonical field decoding and the
existing MSB equality table must be shared with the native arithmetic.
For the closed A1 field-source adapter, stele-reductions may additionally
depend on stele-field, stele-hash and stele-sumcheck. It invokes the actual
RFC-0006 A1 verifier and each required PCS consumer in the fixed source order.

No PCS dependency or authentication callback enters GKR. stele-prover still
cannot import stele-verifier. This scope changes no full-verifier dependency
exception and introduces no proof-system dependency. Update the exact native
dependency policy and rejection tests only with accepted implementation.
Original stacked, inference, private-source and profile requirements remain.
Specification acceptance alone introduces no Cargo edge or runtime behavior.

### A6 — Closed grouped lookup ownership and public-table dependencies

Status: Accepted. Companions RFC-0008 A5 and RFC-0012 A11.
Review: [coordinated skill sign-off](../../agents/reviews/lookup-contract-accepted.md).
The [conditional native lookup adapter](../../formal/native-lookup.md) belongs
in stele-reductions. Reuse actual stele-lookup A3 arithmetic and stele-pcs A9
consumers; neither arithmetic crate acquires an authentication callback.

For this exact adapter, stele-reductions may additionally depend directly on
stele-cqis for immutable generated Table/actual Table::evaluate and on stele-poly
for shared MSB equality coefficients. Its existing field/hash/lookup/PCS edges
supply canonical limbs, typed transcript/usage and actual consumers. Do not
route those calls through the unimplemented IR or duplicate table/field algebra.
No direct PCS/CQIS edge enters stele-gkr or stele-lookup for this delivery.

The external caller owns original and multiplicity VerifiedCertificate handles;
the closed result borrows the actual opening records. A registration helper may
derive expected contexts and invoke real A9 verification but cannot accept
lookup membership. No new unchecked handle/receipt API or proof dependency is
authorized. Full-verifier integration keeps its separate dependency contract.

Update exact dependency bans/API guards only with the admitted implementation,
including rejection cases for all still-forbidden edges. This amendment alone
changes no Cargo manifest, native allowlist, registry or production behavior.
Affected tasks: conditional E3-07b and E3-07, whose full criteria remain intact.

### A7 — Conditional matmul ownership and existing primitive dependencies

Status: Draft. Companions RFC-0007 A2, RFC-0010 A10 and RFC-0012 A12.
The [conditional matmul](../../formal/native-matmul.md) belongs in
stele-reductions and invokes the actual unclosed GKR kernel and PCS consumers.
Its original-source mapping is operation-owned; neither GKR nor sumcheck
acquires a PCS dependency or authentication callback. The retained-row producer
belongs in stele-pcs and supplies no verifier authority.

Extend A6's reductions-to-poly permission to this operation's shared MSB eq
weights. All other calls use the existing field/hash/GKR/PCS/sumcheck edges.
No Cargo edge or dependency change is needed. External callers retain the real
VerifiedCertificate owners; the complete result borrows their OpeningRecords.
E7-01b must update exact native API policy with the admitted producer/consumer
and its rejection tests. This contract changes no executable allowlist, and
full verifier/plan integration retains its separate ownership contract.
