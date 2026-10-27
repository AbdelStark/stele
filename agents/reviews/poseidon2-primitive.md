# E2-03 primitive implementation review

Roles: pcs-engineer and soundness-auditor, performed by codex-root (the author).
This is a same-author code review, not an independent cryptographic audit.

- Public items: `poseidon2::permute(&mut [M31;16])` implements RFC-0012 A2.
  The module is compiled only with `wrapper`; a default-build compile-fail test
  checks its absence. No byte input, runtime constants, round count, or mode API.
- Challenges/absorbs: none. A1's Transcript and registered labels are unchanged;
  their KATs still run with and without the new feature.
- Claims/consumers: none emitted. E14-01 must resolve Q14 before consuming this
  permutation in a wrapper protocol; no wrapper or native caller is added here.
- Bindings/controls: none added. Existing NC-0801 still uses the real registry.
  The infrastructure mutation changes one core round constant and requires the
  actual accounting gate to fail; it earns no proof-statement catalog credit.
- Ledger: no formula, count or profile change. The gate runs all hash features
  so the wrapper KAT cannot silently disappear from validation. Q12/Q14 remain open.
- Bound certificates: no integer reduction or instance added; all operations are
  M31 field arithmetic on already-canonical values.
- Padding/masks: no tensor rows or hashing padding introduced.
- Determinism: fixed arrays, exact 4/14/4 round ordering and initial external layer.
  Each external block reads all four inputs before writing; all four block sums
  precede the final additions. Each internal round saves its full sum before
  writing outputs. Constants match the pinned reference individually.
- Parity: all 35 upstream vectors match locally; CI repeats them on x86 and
  regenerates the upstream corpus. No GPU proof-parity claim.
- Cost: A2's 142 fifth powers, nine external and fourteen internal layers. Direct
  small matrix products favor auditability; no optimization or measured claim.
- Verifier: unchanged. Core remains no_std, no unsafe, no allocation, no panics;
  fixed array widths and loop ranges establish indexing bounds. The field type
  excludes noncanonical input, so no new fallible byte parser is needed.
- Glossary: existing field/permutation/wrapper/transcript terminology retained.

I tried to break it by changing one core round constant, and the control
`test_rejects_poseidon2_constant_drift` rejected it through the accounting gate.
This is a gate mutation test, not an inference-proof negative control.

Validation: red tests first failed on the missing primitive/constants; the final
implementation passes 35 vectors, 142 constant checks, default feature exclusion,
all-feature Clippy, the integer oracle and 22 infrastructure tests. Full workspace
and exact-head hosted results are recorded in the PR. MIT notices accompany the
copied constants; no upstream implementation or dependency enters core.
