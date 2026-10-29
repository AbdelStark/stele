# Greedy bounds and stopping — same-author skill review

Scope: RFC-0004 §7 / Draft A3/A9. Codex-root applies cqis-numerics,
rfc-author and soundness-auditor; not independent audit. Evidence:
[greedy schema study](../../research/cqis-bounds/GREEDY.md).

- Public items: research Spec/record, plaintext first-maximum checker, generation
  boundary and model metadata; no Accepted RFC-0022 schema or production change.
- Challenges/absorbs: none; no randomness, degree loss or FS ordering change.
- Claims/consumers: no proof claims emitted. Actual logits must come from the
  committed model's preceding-position LM head; source/selection/range consumers
  remain necessary. Same-choice alternative rows illustrate this explicit limit.
- Bindings/controls: selected attainment, first tie, differences/gaps, expected
  tokens/positions, prefix, EOS, count and missing/oversized rows reject stated
  mutations. These are research controls, without NC-0107/0108/0109 credit.
- Ledger: no line changes; accounting gate must preserve current coverage.
- Static bounds: int16 formats and configured V/F/L determine every record;
  differences and strict gap sums are bounded by 65535 and 65536. All modular
  sides are below p/2. Observed maxima are witness values, never certificate caps.
- Padding/masks: exactly V real entries; padded ids/extra logits reject. Prefix
  comparison comes from the expected token and canonical index, not a free bit.
- Determinism: integer comparisons, first-index tie choice, canonical bytes;
  prompt EOS is inactive and generated EOS has priority over the final limit.
- Parity: NumPy row/generation corpus and model prefix replay; shared model
  primitives disclosed. Native/GPU parity and proof admission remain open.
- Costs: fixed derivation, O(V) row or O(n*V) generation work/data; no measured
  constant, benchmark, cut or proof weight-pass change.
- Verifier: production no_std unchanged; research metadata and plaintext row
  checks do not supply a succinct authenticated plan/source verifier.
- Glossary/history: Accepted prefixes and original task criteria preserved;
  self difference is zero, while strict tie comparison concerns earlier competitors.

I tried to break it by selecting a later tied maximum, and the control
FirstMaximum rejected it. A fabricated maximum rejected with Attainment;
premature stopping and tokens after generated EOS rejected with Stop. The
same-choice row replacement control intentionally accepts under separately
expected plaintext sources and establishes no model/source authentication.
