# Function identity review (E5-02 / Q25)

Reviewer: codex-root, also author. Same-author cqis-numerics, rfc-author and
soundness-auditor passes, not independent audit. A2 remains Draft.

Workflow 03 checklist:
- Public items: research function/representation bytes for RFC-0004 A2, pending
  RFC-0008/0011 integration. Accepted prefix/A1 and unrelated A3 unchanged.
- Challenges: none. All identifiers/digests use ordinary BLAKE3; no random
  challenge, transcript label, ledger term or hash-security budget admitted.
- Claims: no native claims discharged. Function identities do not prove the
  operation relations, table membership, source mapping or passport root binding.
- Bindings: changed split/dimension/scales/epsilon change FunctionId. Incorrect
  role ids, role order, mode, parameters, truncation, duplicate functions and
  manifest bytes reject. These are research checks without native NC credit.
- Ledger: no production change; existing H/FS and lookup obligations remain.
- Bounds: function parameters validate against the numerical candidates. All
  component shapes/content derive from those parameters; supplied manifest bytes
  never choose allocations or trusted configuration. Wide relations retain A3.
- Padding: component digests include canonical padding. Actual exclusion by a
  lookup selector is still a separate required relation.
- Determinism: functions/components sorted by raw fixed-length ids; duplicate
  functions reject. One explicit representation per semantic function prevents
  a backend from silently changing configured table ids or proof bytes.
- Parity: independent frame assembly and full manifest reader; direct/corrected
  outputs agree with an independent exact exp oracle on the whole example domain.
  No native Rust/NumPy/MLE/CUDA parity claim.
- Cost: all component generation/hash/validation and manifest work retained in
  T_misc. Membership/arithmetic remain c_lu/c_a. No measured constant or new cut.
- Verifier: native no_std verifier unchanged. Expected configuration owns all
  choices; a self-consistent untrusted manifest is never its own authority.
- Glossary: function, representation, component and whole CQIS/passport identity
  have explicit roles. A function set does not encode operation order or sources.

I tried to break it by swapping component roles, substituting corrected for
direct evaluation under the same FunctionId and tampering with manifest bytes,
and the control cases rejected each. This approves the candidate byte research,
not native reduction/identity admission or a full passport contract.
