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

Status: Draft. Question Q20. Companion to RFC-0006 Draft A4 and RFC-0012 Draft A6.
Proposed `stele-gkr` dependencies are `[field, poly, hash, sumcheck]` for exact
coefficient arithmetic, original-point evaluation, descriptor framing and A1
reuse. These are downward edges. Source authentication stays in the existing
reduction/orchestration consumers; GKR must not import PCS upward or accept a
prover-supplied authentication callback. No dependency is added by this Draft.
On acceptance/implementation, update dependency bans and their rejection tests
with the actual API change. No challenge, soundness loss or measured cost changes.
Affected task: E3-06; source/consumer closure and required reviews remain open.

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
