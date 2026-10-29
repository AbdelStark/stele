# Native function and representation review (E5-02)

Reviewer: codex-root, also author. Same-author cqis-numerics and soundness-auditor
passes; not independent audit. RFC-0021 §§2,4,6 / RFC-0004 A4.

Workflow 03 checklist:
- Public items: immutable function descriptors, representation selections and
  bounded canonical bytes. All eleven function schemas and four legal modes are
  closed; component names cannot masquerade as function names. Decoding metadata
  does not authenticate configuration or table contents.
- Challenges: none. FunctionId/RepresentationId use ordinary unkeyed BLAKE3 with
  their specified domain prefixes; no FS operation or new label exists.
- Claims/consumers: metadata only. Expected-object validation rejects another
  representation of the same function. Real plan/passport consumers remain required.
- Bindings: no new claim-graph edge or NC credit. Every representation byte is
  mutated in primitive tests, including component order/count/identity and split.
  NC-0412/0413/0414 remain pending their actual consumers.
- Ledger: no new challenge/loss/profile line; soundness accounting is unchanged.
- Bounds: fixed schema caps, checked stack output lengths and canonical positive
  reduced RMSNorm epsilon. Shape/scale validation is static, but these metadata
  types do not constitute field-faithfulness certificates for reductions.
- Padding: no table generation or MLE evaluation in this slice. Component shapes
  retain their existing checks; actual padding selectors remain separate work.
- Determinism: exact LE framing, closed role order, zeroed unused stack capacity
  excluded from serialization, no maps or iteration-dependent identity selection.
- Parity: all committed Python function/representation bytes and identities match.
  Tests cover all function schemas, legal split boundaries, norm bounds, malformed
  framing, every truncation, excess/trailing lengths, noncanonical epsilon and
  schema-valid substitutions. Private-field mutation fails to compile.
- Cost: bounded metadata work remains T_misc; no benchmark, fitted constant,
  additional weight pass or committed intermediate is introduced.
- Verifier: no_std/no unsafe/no floats, no new dependency, no heap allocation in
  these schemas. Checked lengths preserve borrowed inputs and failed buffer writes;
  private fields prevent unchecked function/component authority.
- Glossary: semantic FunctionId and selected RepresentationId remain distinct.

Tests preceded implementation. I tried to break it by substituting a different
legal representation/split of the same function, reordering components, altering
each encoded byte, supplying unreduced epsilon and exceeding framing/capacity,
and the control checks in native primitive tests rejected those inputs. They earn
no NC credit. Native manifests/public MLEs and all actual lookup/private PCS/ZK/
inference deliveries remain required; E5-02 stays in progress.
