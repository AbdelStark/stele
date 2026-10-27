# Guardrail — code
- Rust 2021, `#![forbid(unsafe_code)]` by default, `clippy -D warnings`, `rustfmt` default; deny `f32`/`f64` in prover/verifier crates (clippy `disallowed_types`).
- Module doc comment: `//! RFC-xxxx §y — <what>`; public fns documented with the claim they consume/emit.
- No generic "utils"; one module per reduction; names from the glossary.
- Tests named `accepts_…`, `rejects_…`, `matches_reference_…`; randomised with recorded seeds.
- Kernels: CPU reference first, SIMD second, CUDA third — never CUDA-only.
- Performance changes must not change proof bytes (digest gate) unless an RFC amendment says so.
- PR ≤ ~800 changed lines; one task per PR.
