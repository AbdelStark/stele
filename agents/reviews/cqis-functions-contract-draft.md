# Nonlinear function contract draft review (Q25 / E5-02)

Reviewer: codex-root, also author. Same-author cqis-numerics, rfc-author,
soundness-auditor, gkr-reduction-author and pcs-engineer passes; not independent
audit. This record approves the coordinated Draft, not acceptance or native work.

The A2 requirements map to concrete definitions:
1. RFC-0021 §2.1 and RFC-0009 A1 fix inclusive domains, all supported B/F/E/k,
   product/corrected/direct behavior, full index bounds and membership counts.
2. RFC-0021 §2.2 and §4 fix every activation variant, exact scales/cap, signed
   rounding, overflow and component/function/representation byte identities.
3. RFC-0021 §2.3 fixes dimension/epsilon/gain formats, total normalization and
   retained remainder, rsqrt scaling and wide output rounding. Static native
   schemas remain A3; nothing is passed through the narrower scalar Requant API.
4. RFC-0021 §4 and companion RFC-0005/0008/0011 amendments bind component data,
   function closure, operation/source references and exact table matrices. The
   full outer plan/passport codec remains a distinct mandatory consumer contract.
5. RFC-0021 §§3,5 give exact interval algorithms, fixed precision/caps and uniform
   error bounds. Native generation/parity/mutations are explicit delivery gates;
   model fidelity remains required by its original dependent tasks.

Workflow 03 checklist:
- Public items: no native API change. Every new rule is Draft; Accepted prefixes
  are preserved and the existing scalar, quantiser, lookup and PCS scopes remain.
- Challenges: none; identifier/data hashing is not an FS challenge escape hatch.
- Claims/consumers: tables/manifests authorize no proof. Actual tuple/source,
  selector, limb, static bound, passport and PCS consumers remain mandatory.
- Bindings: NC-0412/0413/0414 reserved in the Draft for future actual function,
  representation and data consumers. No catalog or statement-coverage credit.
- Ledger: no challenge/loss changes or H/FS/profile certification. Original Q12,
  lookup, privacy and proximity accounting remain open.
- Bounds: parameters and all limits are explicit; wide exp/norm relations are
  named as requiring limbs/ranges, never treated as single M31 integer identities.
- Padding: canonical zero rows and public valid-row selector are distinct.
  Table source matrices retain every tuple column and all prescribed padding.
- Determinism: exact arithmetic, fixed bytes, explicit representation choice,
  sorted sets, complete code identity and verifier-owned tree context. No implicit
  F, epsilon, architecture, score clipping or changed output under a fixed identity.
- Parity: existing full-table/oracle/byte evidence supports the Draft. Native
  Rust/NumPy/MLE parity and table-root record evidence are not yet claimed.
- Cost: all lookup counts, correction storage, limb work, regeneration, coding
  and hashing remain c_lu/c_a/T_misc. No benchmark, new cut or extra weight pass.
- Verifier: native code unchanged; Draft requires checked dimensions and fallible
  allocation before constructing immutable generated-table objects. No callback
  may supply table truth or adopt a claimed manifest as trusted configuration.
- Glossary: component means a small table, not a synonym for reduction. Function
  identity, representation identity, data digest and passport root are distinct.

Before acceptance: execute table-matrix/code/root framing and tamper evidence,
complete the coordinated skill sign-off, reserve real-consumer catalog entries,
append the decision record and update task/index status. Native E5-02 must then
deliver every required generator/identity/validation/parity gate. No synthetic
proof verifier or configuration-control exception is introduced to claim coverage.
