# Q26 checkpoint scalar research review

Reviewer: codex-root, also author; same-author cqis-numerics, rfc-author and
soundness-auditor passes, not independent audit. Approve the research evidence
for gated merge only. RFC-0003 A2 and RFC-0004 A3 remain Draft; E5-03 stays blocked.

Workflow 03 checklist:
- Public items: research-only decode and independent check helpers. No core API,
  Accepted protocol text or checkpoint file format is changed.
- Challenges/absorbs: none; fixed test sampling is not transcript randomness.
- Claims/consumers: none emitted. Actual source metadata and passport consumers
  must bind dtype and bytes; this scalar helper authenticates neither.
- Bindings/controls: no catalog credit. Unknown formats, malformed raw inputs,
  infinities and NaN payloads reject in research checks. NC-0109 still needs the
  actual static-certificate consumer; no toy proof verifier is substituted.
- Ledger: no SC/RLC/LU/PCS/MASK or profile term changes; accounting gate required.
- Bounds: significand and exponent bounds follow from finite format bit widths.
  They are preparation arithmetic bounds, not reduction field-faithfulness or
  data-derived model certificates.
- Padding/masks: no tensor layout, mask or lookup selector introduced. Exact
  scalar lengths reject trailing bytes; signed source zeros normalize numerically.
- Determinism: explicit source dtype, little-endian input and integer operations.
  Both subnormal values and NaN rejection are independent of host FP modes.
- Parity: all binary16/bfloat16 words and seeded/boundary binary32/binary64 words
  agree with a separate rational bit-sum oracle and exact inverse encoder. No
  native Rust/NumPy quantiser, CPU/GPU proof or model fidelity result is claimed.
- Cost: bounded per-scalar preparation; no fitted constant, ledger or benchmark.
- Verifier: unchanged; no production dependency or callback into research.
- Glossary: scalar source decoding is distinct from quantisation and proof admission.

I tried to break it by supplying every 16-bit nonfinite word and malformed scalar
lengths/types, and the control `rejects` in check_scalars.py rejected it with the
specified research reason. This is primitive research evidence, not a production
negative control. The format-confusion witness shows why dtype must be bound at
the real consumer; it is not a flaw in an existing checkpoint verifier.
