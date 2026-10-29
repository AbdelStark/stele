# Model configuration — same-author skill review

Scope: Q26 / Draft RFC-0004 A10. Codex-root applies cqis-numerics, rfc-author and
soundness-auditor; not independent audit. Evidence: [study](../../research/cqis-checkpoint/MODEL-CONFIG.md).

- Public items: candidate canonical descriptor, identity and bounded model loader.
  A3/A6–A10 remain Draft; no research module is imported by native crates.
- Challenges/claims/ledger: none added. No proof receipt, source conversion proof,
  PCS, lookup/range membership, FS or ZK acceptance is claimed. Accounting unchanged.
- Bindings: expected descriptor/artifact hashes, ordered roles, all units/policies,
  complete function/representation choices and certified rotations. Mutation tests
  reject old expected identities; a self-chosen new identity is not provenance.
- Static bounds: metadata-derived dimensions/score bounds and preallocation limits;
  no runtime-fit certificate or complete field-faithfulness claim. Full static
  schema/consumer sets remain required before configuration admission.
- Padding/masks: real contiguous positions and fixed causal order; no proof padding
  or architecture/request policy is silently derived. Byte frames have no padding.
- Determinism: fixed role/layer order, canonical inner descriptors, sorted function
  identities, exact re-encoding and ordered rotation generation. No host floats.
- Parity: independent outer framing, model object equality, numerical/full/cache
  checks and unchanged pinned checkpoint outputs. Inner codecs/functions shared;
  native/GPU parity and full-model fidelity remain separate requirements.
- Costs: descriptor/physical byte scans and retained allocations are explicit;
  no benchmark constant, extra proof weight pass or new cut.
- Verifier/format: native no_std verifier unchanged. Bounded research parsing is
  not a production plan parser or authenticated registration. Original criteria retained.
- Glossary and append-only RFC history checked by the repository gates.

I tried to break it by swapping equal-shaped Q/K roles while retaining the old
configuration identity, and the Identity control rejected it. ArtifactDigest
rejected a one-value payload change; malformed headers still rejected after their
hashes were recomputed. Direct/corrected representation substitution changes the
configuration identity even though the numerical model remains identical.
