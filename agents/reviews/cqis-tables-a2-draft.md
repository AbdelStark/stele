# RFC-0004 A2 draft review

Reviewer: codex-root, also the author; cqis-numerics, rfc-author and
soundness-auditor passes. Not an independent audit. Approve research/escalation
for gated merge; do not accept A2 or implement missing table definitions.

- Public API/RFC: no core API changes. RFC-0004 §§4,5.3 are the examined text;
  A1 remains accepted. A2 is append-only and explicitly incomplete. RFC-0008 §4,
  RFC-0011 §1 and RFC-0017 do not supply the missing closed forms/byte rules.
- Challenges/absorbs: none added; the transcript registry is unchanged.
- Claims/consumers: none emitted. The table definition, table identity, lookup
  membership and normalization relation are distinct future obligations.
- Bindings/controls: none added to the production claim graph. Exact arithmetic
  exposes 16,385 domain elements, 129 high indices and unrepresentable valid
  statistics. These checks earn no production NC credit. Existing table,
  recombination, norm-limb and passport controls remain required.
- Ledger: no new term and no profile approval. Generating correct entries would
  not itself justify the lookup reduction's error term or a Fiat–Shamir bound.
- Certificates: no static CQIS certificate implemented. The counterexamples use
  actual int16 rows and exact sums, not a field wrap or a data-dependent bound.
  Normalization replacements must retain exact integer/remainder relations.
- Padding/masks: zero-padding counterexample rows preserves the statistic. The
  exp zero endpoint is an attained score, not an ignorable padding row.
- Determinism: fixed integer/Fraction checks; set use only compares membership,
  never determines canonical bytes. No timing, floats, data or random seed.
- Parity: independent bit-length criterion and rational exhaustive exponent
  search agree on 139 cases. This is research parity only; no Rust/NumPy table
  parity, model fidelity or CUDA parity is claimed. No GPU files changed.
- Cost model: no constant, measurement, pass count or ledger changes. Future
  decomposition alters c_a/c_lu and needs its own measured evidence.
- Verifier: unchanged; no new allocations, parsing, panic or no_std behavior.
- Glossary: claim, reduction, bound certificate, table identity and passport
  retain their existing meanings. No new cut or intermediate commitment.

Adversarial finding: the identity S=M*4^a fails for S=1 because bit_length(S)
is odd, and for S=131073 despite even bit length because M is nonintegral.
The independent search reproduces both failures and accepts nearby S=2/131072.
No false-acceptance test against a production verifier is possible for this
unimplemented relation; this review therefore provides no production approval
sentence or inference-soundness claim.
