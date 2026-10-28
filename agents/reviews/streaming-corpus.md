# RFC-0006 A6 independent streaming corpus review

Reviewer: codex-root, also the author; sumcheck-prover-engineer and soundness-auditor.
Not an independent audit. Scope: actual production adapter and differential evidence.

- Public items/RFC: no core protocol API change. The A1 corpus example uses actual
  prepare/FileSource/Streaming/prove_into for streaming fixtures, under opt-in std.
  Missing std explicitly rejects; no silent fallback to Dense is authorized.
- Challenges/absorbs: unchanged A1 engine. Python generates window proofs and
  independently checks Dense equality; canonical payloads and a following A1 proof
  check bytes and continuation through the final absorb.
- Claims/consumer: original public tables and every ordered final claim are compared
  in Rust and Python, together with points and all SC record fields.
- Bindings/controls: no new edge. NC-0210 remains required separately. The corpus
  has 108 honest chains and 312 exact shape/round/unused-final/original-length
  rejections; rejected fixtures are always checked by the real public verifier.
- Ledger: unchanged A1 m*delta/p^d; no profile admission. Q12 remains unresolved.
  Actual source reads/bytes/seeks/EOF counts are adapter evidence, not soundness terms.
- Certificates: no new integer identity or certificate. JSON widths use checked
  conversion, and production schedule/source constructors keep their validation.
- Padding/masks: storage reversal and canonical tail ordering remain internal;
  no inference mask convention changes. Independent bytes cover full K coefficients.
- Determinism: seeded fixtures, complete regeneration equality and fixed schedules;
  cases include m=0, every m=3 schedule, no inputs/constants, repeated/mixed factors,
  zero coefficients, unused inputs and a width-four window with a tail at m=5.
- Window contributions: separately restricted suffix sources sum to the whole
  window before/after a non-Boolean challenge for degrees 1..4 in both fields;
  constant multiplicity is checked separately by the no-input tests.
- Parity: exact Rust/Python decisions, proofs for honest fixtures, all claims and
  continuation. Source receipts derive from the actual FileSource counters and
  independent schedule arithmetic; a Dense fallback fails the directed adapter test.
  No GPU change or GPU evidence.
- Cost model: no constant or benchmark claim. Fixture preparation retains resident
  tables and temporary files; their memory is not a production performance result.
- Verifier: unchanged no_std path. The optional host adapter lives only in the corpus
  executable and requires successful original verification before honest parity checks.
- Glossary: no authenticated-source, cut, profile or complete-memory claim.

I tried to break it by replacing an unused final value, and the corpus requires
ClaimMismatch from both original public consumers. Gate mutants additionally
change a fixture expectation and bypass the actual Streaming adapter.

Sign-off requires local and exact-head hosted gates. E3-05 still needs complete
preparation/proving/consumer cost and memory ledgers, including losing schedules.
