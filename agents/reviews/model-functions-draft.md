# Model function association — same-author skill review

Scope: unchanged Accepted RFC-0021 §4 and Draft RFC-0004 A3/A10 model roles.
Codex-root applies cqis-numerics, rfc-author and soundness-auditor; not independent
audit. Evidence: [model function study](../../research/cqis-checkpoint/MODEL-FUNCTIONS.md).

- Public items: config-derived operation FunctionId/RepresentationId associations,
  exact manifest regeneration and model-specific outer frame. Native parity
  example uses the existing Manifest API; no Accepted behavior or bytes change.
- Challenges/absorbs: none; no new transcript label, degree or random loss.
- Claims/consumers: no proof claims. The config identity comes from the caller;
  every component data digest comes from its complete generated definition.
  Actual source/gain/range/lookup/branch/selector consumers, table roots and
  complete proof-plan identity remain separate. Self-selected hashes prove no provenance.
- Bindings/controls: FunctionSet rejects lost/duplicate/reordered roles, changed
  references, missing functions, changed component digests and byte framing.
  Identity/Digest/Capacity reject wrong expected inputs and oversized frames.
  Native duplicate-function and table-overflow outcomes are checked separately.
  No NC-0412/0413/0414/0701 or source/range control credit is claimed.
- Ledger: no new line; required accounting gate checks existing coverage.
- Static resources: model/descriptor bounds only, 4L+1<=513 references/functions/
  components, each component<=65536 padded rows and two columns. Full metadata
  and data-generation tests have distinct scopes; no runtime-bound tightening.
- Padding/masks: generated table data contains canonical zero padding. This
  does not enforce any query's valid-row selector or source membership.
- Determinism: fixed operation order, unique functions sorted by FunctionId,
  exact component union sorted by TableId, inherited canonical byte encodings.
  Repeated functions keep all model roles. Representation choices remain explicit.
- Parity: independent outer framing and exact native manifest bytes, including
  pinned selections. Inner generators are shared on the Python side and disclosed.
  No native full-model, proof CPU/GPU parity or fidelity claim.
- Costs: canonical definition generation and complete frame comparison in
  T_misc, bounded frame construction, no benchmark, fitted constant, cut or
  inference weight-pass change. Validation is not a succinct proof consumer.
- Verifier: production no_std unchanged. The std parity executable bounds count
  and descriptor lengths before reads, reserves fallibly and exposes no unchecked
  generated-table constructor or supplied-data authority.
- Glossary/history: append-only Draft evidence, unchanged Accepted text and original
  criteria. Previous pinned baseline and block-variant fields remain preserved.

I tried to break it by changing a component data digest while retaining the
model's expected configuration and rebuilding the outer frame, and the control
FunctionSet rejected it. Removing a repeated norm role also rejected despite
its identical FunctionId; alternate representations cannot replace one another.
These checks do not replace real lookup/source/range/PCS consumers.
