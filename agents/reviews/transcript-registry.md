# E2-00 registry delivery review

Scope: RFC-0012 A1 registry, NC-0801, and registry/accounting gate wiring.
Roles: pcs-engineer (hash owner) and soundness-auditor, performed by the author.
This is a same-author review, not an independent audit. Challenge generation and
protocol schedule controls remain pending in E2-00/E3-01/E2-01.

- Public items: `RegistryEntry`, `LabelKind`, `LossLine`, `Error`, `registry` and
  `validate_registry` implement A1's fixed label inventory and validation boundary.
  Exposed metadata permits inspection and configuration controls, not replacement
  of the private production registry. The gate compares all five exact entries.
- Challenges/absorbs: none executed yet. The sole challenge label maps to SC;
  constructor/absorb labels have no random-challenge line. A1 governs the later API.
- Claims/consumers: no polynomial claim or evaluation point is emitted. The example
  emits registry metadata consumed by the gate against the canonical inventory.
- Bindings/controls: NC-0801 accepts the actual fixed registry, mutates only one
  label, and requires `DuplicateLabel` from the production validator. It earns
  configuration coverage only; NC-0800/0802 remain incomplete.
- Ledger: no formula or instance count changed. The accounting gate checks actual
  registry output and unit tests, rejects SC-to-LU inventory drift and missing SC
  metadata, and retains guards on all remaining unimplemented protocol crates.
  It does not certify the unresolved FS/H budget or per-instance accounting.
- Bound certificates: none introduced; no integer identity is proven.
- Padding/masks: no tensor, lookup or zerocheck introduced.
- Determinism: fixed array order, byte equality and deterministic iteration; no
  hash maps, randomness or timing-dependent order.
- Parity: no backend arithmetic or GPU change; no proof parity claim is possible.
- Cost model: no measured term or constant changes, so no new benchmark ledger.
  Registry validation compares five short labels at construction boundaries.
- Verifier: unchanged. Core registry is `no_std`, forbids unsafe, returns typed
  validation errors and has no unchecked external length/index operation.
- Glossary: existing transcript, registry, challenge and accounting terms retained.

I tried to break it by duplicating one registered label across operation kinds,
and the control NC-0801 rejected it with `DuplicateLabel`.

Validation: registry unit tests, actual control and harness tests, workspace
Clippy, full workspace tests, infrastructure mutation tests, digest, controls,
accounting, dependency bans and ledger validation. Hosted exact-head CI is the
publication gate; the PR records its result.
