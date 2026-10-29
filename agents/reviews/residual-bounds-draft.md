# Residual alignment bounds — same-author skill review

Scope: Q26 / Draft RFC-0004 A3/A8/A9. Codex-root applies cqis-numerics,
rfc-author and soundness-auditor; not independent audit. Evidence:
[residual schema study](../../research/cqis-bounds/RESIDUAL.md).

- Public items: research Spec/record, plaintext relation checker and model roles;
  no Accepted RFC-0022 schema or production verifier changes.
- Challenges/absorbs: none; no randomness, degree loss or FS ordering change.
- Claims/consumers: no proof claims emitted. Both residual sources, configured
  units, canonical source digits and whole ranges require actual consumers.
- Bindings/controls: static fields/roles, coherent source/unit substitutions,
  M31 alias, sign/gap/rounding/output, digits and boundary carries reject.
  These are research controls without production NC-0109 credit.
- Ledger: no line changes; accounting gate must preserve current coverage.
- Static bounds: int16 formats and configured fractions determine every bound;
  no runtime values choose a certificate. Wide identities use seven bounded
  byte-column roles; only the small signed output uses a direct field equality.
- Padding/masks: no proof padding, lookup or zerocheck added. All d pairs are
  checked; D=1 and zero numerators retain every relation. Nonnegative sign_gap
  excludes negative zero without a wide-field comparison or inverse.
- Determinism: exact integer arithmetic, ordered roles/bytes and one rounding
  after exact alignment; no separately rounded input or saturation.
- Parity: Fraction/NumPy, independent bounds/framing/columns, model roles and
  pinned replay; shared primitives disclosed. Native/GPU parity remains open.
- Costs: fixed derivation, O(d) witness/checker work and data; no measured
  constant, benchmark result, cut or proof weight-pass change.
- Verifier: production no_std unchanged; research metadata regeneration is not
  an authenticated plan parser or complete certificate-set check.
- Glossary/history: Accepted prefixes and original task criteria preserved;
  links and glossary covered by repository gates.

I tried to break it by replacing the aligned numerator 2^30-1 with its M31
alias -2^30 and rebuilding the forged sign/rounding columns, and the control
IntegerRelation rejected it. The separate-rounding output rejected with
OutputRelation; coherent source and unit substitutions rejected with IntegerRelation.
