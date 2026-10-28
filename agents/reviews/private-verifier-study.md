# Private verifier study review (Q30)

Reviewer: codex-root, also author. Same-author pcs-engineer, soundness-auditor
and rfc-author passes; no independent audit or approval of a wrapper protocol.
RFC-0016 A1 stays Draft. The work does not select a new privacy architecture,
admit a backend/profile or complete E14-01, Q29 or the native ZK prover.

The relation fixes the whole approved verifier and expected public statement;
host acceptance, echoed statements and proof-controlled programs are excluded.
The composition inequality is derived only from an explicit conditional
extractor interface and resource bounds. Language soundness is not substituted
for knowledge. The finite oracle experiment is illustrative, not a proof of
any cryptographic separation, extraction theorem or backend vulnerability.
Pinned upstream files establish actual mechanisms and configured targets only.

Workflow 03 checklist:
- Public items: research code/notes and Draft RFC-0016 A1; no core API.
- Challenges: exhaustive deterministic oracle experiments, no Transcript label,
  native randomness or newly accepted protocol challenge. Q12 remains open.
- Claims/consumers: proposed R_V executes every actual inner consumer on exactly
  the expected statement; no arithmetization or wrapper consumer is supplied.
- Bindings/controls: two isolated search mutants test the finite experiment.
  Actual NC-1203 and statement/program/profile substitutions remain required;
  no toy, wrapper flag or host-side verifier earns production coverage.
- Ledger: no production record changes. Quantitative extraction loss, work,
  queries, hash/FS composition and privacy advantage need separate complete
  derivations. The upstream 96-bit target is not a Stele bound or admission.
- Static bounds: no integer field identity, certificate or dynamic bound added.
- Padding/masks: public shapes must determine lengths; outer masks, field support,
  seed lifecycle and joint disclosures still need a complete simulator. Previous
  public passport disclosures are not erased by subsequently wrapping proofs.
- Determinism: exact integer/Fraction enumeration and fixed search orders. The
  standard-library experiment adds no dependency, hidden random seed or core mode.
- Parity: no CPU/GPU proof path or GPU change; no new proof-byte parity claim.
- Cost: explicit total preparation/proving/serialization and peak overlapping
  state; no measurement, constant fit, one-pass result or W8/overhead claim.
- Verifier: no core/no_std change. A complete actual verifier and authenticated
  program/format/parameters remain prerequisites; no bypass API is introduced.
- Glossary: existing Stele terms; upstream API identifiers are retained verbatim.

I tried to break it by returning an unqueried candidate and by repeatedly
querying one candidate, and the control check_search rejected each isolated
search mutant. These are study integrity checks, not proof rejection controls.
The exact 114-case experiment and local RFC status, docs links, glossary,
CI-scope and diff checks pass. Hosted full gates remain required before merge.
