# E5-03 quantiser and certificate draft review

Reviewer: codex-root, also the author; cqis-numerics, rfc-author and
soundness-auditor passes, not an independent audit. Approve research/escalation
for gated merge only. RFC-0003 A2 and RFC-0004 A3 remain Draft.

- Public items: no core API changes. RFC-0003 §4 and RFC-0004 §§2,5.5,6 are
  the examined contracts. Accepted text is retained; proposed replacements and
  incomplete quantiser/certificate requirements are explicitly separated.
- Challenges/absorbs: none added; transcript code and registry unchanged.
- Claims/consumers: none emitted. Future certificate consumers must derive
  shapes/formats/bounds themselves and enforce both sides' integer ranges.
- Bindings/controls: research detects unsafe bound endpoints and an undersized
  scale satisfying the upper-only inequality. NC-0102/0109 remain unimplemented
  obligations here; no toy checker is presented as a production verifier.
- Ledger: no term or profile change. Integer faithfulness is deterministic and
  cannot be repaired by increasing a random challenge's field size alone.
- Certificates: 10,000 seeded static-bound comparisons use exact rational
  p/2 as an independent reference; the proposed production contract explicitly
  forbids data-derived bounds or trusting the supplied certificate fields.
- Padding/masks: no new shape layout, padding or selector. Future chunking must
  preserve exact sums, public plan rules and range consumers.
- Determinism: fixed seed and ordered integer loops. All 98,307 ceiling cases
  use exact integer arithmetic; no model data, host floats or timing.
- Parity: research checks only. No Rust/NumPy quantiser or CPU/CUDA proof parity
  is claimed. Existing scalar arithmetic and field recovery are unchanged.
- Cost: no measured constant, ledger or pass count changes. No speculative
  performance claim for chunking or an unimplemented DPA path.
- Verifier: unchanged, including no_std, parsing and error behavior. The
  proposed closed schema still needs acceptance before core implementation.
- Glossary: static bound certificate, attained maximum, claim and virtual
  tensor retain their meanings. No intermediate commitment is introduced.

Adversarial finding: at the advertised signed-format dimension endpoints,
2^30 and -(2^30-1) have the same M31 residue; the strict bound must reject
that shape before relying on centered recovery. At M=128,s=1 the upper-only
scale check passes while the exact ceiling is 2. These expose prose defects,
not a false acceptance by existing core code; no production approval sentence
or NC credit is asserted. Full quantiser and certificate review remains open.
