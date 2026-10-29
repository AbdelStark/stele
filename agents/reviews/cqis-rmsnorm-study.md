# Total RMSNorm candidate review (E5-02 / Q25)

Reviewer: codex-root, also author. Same-author cqis-numerics, rfc-author and
soundness-auditor passes, not independent audit. A2/E5-02 remain Draft/blocked.

Workflow 03 checklist:
- Public items: research only. Accepted RFC text, A1 and unrelated A3 unchanged.
  Input/gain/output scales and positive reduced rational epsilon are proposals.
- Challenges: none. No FS/lookup/profile loss is established or waived.
- Claims: no protocol claims discharged; statistic, parameter, table, exponent,
  remainder, sign, range and carry consumers remain mandatory.
- Bindings: one-field statistic/exponent/remainder/table/output/bound and limb/
  carry mutations reject. These are research tests without native NC credit.
- Ledger: no new labels or error terms; native accounting remains unchanged.
- Static bounds: computed from dimensions/formats/parameters, not observed fit.
  Wide integers are explicitly too large for a single M31 equality. The byte
  multiplication identity's two sides fit statically; complete native sign,
  addition, comparison, shift and range schemas remain A3 obligations.
- Padding/masks: 49,152 legitimate mantissas; a padded row cannot be queried.
  Canonical padding bytes and membership exclusion still need registry rules.
- Determinism: exact quotient/remainder, integer sqrt and signed half-away;
  no floats, zero-tail shortcuts, saturation or wrapping. Every original zero/
  nondivisible statistic has a normalization. Output overflow still rejects.
- Parity: bisection roots and exhaustive exponent search agree with generation.
  No native Rust/NumPy inference or GPU parity claim.
- Cost: all limb, table and output work retained in c_a/c_lu/T_misc. No measured
  constant, new commitment or additional weight pass is claimed.
- Verifier: native no_std code unchanged. Mutable research certificates are not
  authenticated protocol objects; identity and consumer delivery remain open.
- Glossary: existing terms. Error from normalization, table rounding and final
  rounding is separated; sample differences are not claimed as uniform bounds.

I tried to break it by changing a remainder, exponent, rsqrt value, output,
static bound, product byte and carry; the control cases rejected each mutation
for its stated reason. Overflowing rows also reject. This approves numerical
research, not native norm admission or fidelity; A2/A3 review remains required.
