# Native component descriptor review (E5-02)

Reviewer: codex-root, also author. Same-author cqis-numerics and soundness-auditor
passes; not independent audit. RFC-0021 §§2,4,6 / RFC-0004 A4.

Workflow 03 checklist:
- Public items: closed Descriptor, derived Shape, bounded EncodedDescriptor and
  typed errors. Every public item documents metadata-only authority. Fields are
  private; a compile-fail test rejects direct parameter mutation.
- Challenges: none. TableId uses ordinary unkeyed BLAKE3, not Transcript or a
  substitute FS source. Existing pinned no_std BLAKE3 is reused unchanged.
- Claims/consumers: no claim is emitted or accepted. Parsed metadata cannot
  produce a validated table, authenticated configuration or proof receipt.
- Bindings: no claim-graph edge; native malformed/schema/identity checks are
  ordinary primitive tests. NC-0412/0413/0414 remain pending real consumers.
- Ledger: no loss or label changes, and no complete H/FS/profile claim.
- Bounds: B/F/E/k and cap rules precede checked shape arithmetic. Maximum padded
  shape is 65,536 rows and two columns; inclusive high/direct endpoints remain.
- Padding: shape describes required padding only. There is no table-data or
  valid-row-selector admission in this slice.
- Determinism: one closed name/version/schema, explicit split and cap bytes,
  fixed little-endian framing and no hash-map/timing dependence.
- Parity: all 13 Python descriptor/id vectors match exactly. Native boundary
  grid covers supported exp shapes, including two-row high components and maximum
  dimensions. Complete numerical/Rust/NumPy/MLE parity remains E5-02 work.
- Cost: allocation-free bounded metadata encoding/hash work in T_misc. No measured
  result, fitted constant, weight pass or committed intermediate.
- Verifier: no_std, no unsafe code, no heap allocation. Checked length conversions,
  subslices and arithmetic precede copying. Remaining slices use only closed
  constant lengths or private lengths already bounded by the backing array.
- Glossary: descriptor identity is distinct from table-data validation and model
  configuration authority. Syntactically valid activation parameters can still
  fail whole-table numerical generation, which remains required.

Tests were written first and failed on the absent tables module. All component
vectors, truncations, length caps, versions, non-ASCII names, unknown names,
noncanonical caps, parameter boundaries and identity changes then passed.
The standalone no_std check, focused Clippy and dependency bans pass; lockfile
changes only attach already pinned BLAKE3/serde_json dependencies to this crate.
serde_json is test-only; production encoding has no JSON path or reference process.

I tried to break it by truncating every descriptor, inflating declared lengths,
changing versions and selecting out-of-domain or noncanonical parameters, and
the control checks in the native descriptor tests rejected those encodings.
These primitive checks earn no catalog coverage. E5-02 stays in progress until
every generator, complete canonical validator and reference/MLE gate is delivered.
