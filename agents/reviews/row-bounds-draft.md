# Row conversion bounds — same-author skill review

Scope: Q26 / Draft RFC-0004 A3/A8. Codex-root applies cqis-numerics,
rfc-author and soundness-auditor; not independent audit. Evidence:
[row schema study](../../research/cqis-bounds/ROW.md).

- Public items: research Spec/record, plaintext relation checker and model roles;
  no Accepted RFC-0022 schema or production verifier changes.
- Challenges/absorbs: none; no new randomness or FS ordering.
- Claims/consumers: no proof claims emitted. Canonical integer source offsets,
  source digits, whole ranges, attained selection and all role associations need
  real consumers. Binding only the source residue is insufficient at gated endpoints.
- Bindings/controls: every certificate field/column role, coherent sign/product/gap
  mutations, modular aliases, false maximum/scale/zero flags, remainders and output
  codes reject. These are research controls without production NC credit.
- Ledger: no line changes; accounting gate must preserve current coverage.
- Static bounds: format C, policy Smax, shape and fraction determine every record;
  observed M belongs only to the witness. Large source and rounding identities
  use limbs; each small identity has a strict centered bound.
- Padding/masks: no new proof padding, lookup or zerocheck. All d real entries
  participate in the maximum; inactive static fields are zero. Zero scale retains
  every arithmetic constraint and forces all codes/magnitudes to zero.
- Determinism: integer arithmetic, ordered roles/bytes and first attaining index
  in witness generation; another attaining index is also semantically valid.
- Parity: Fraction/NumPy corpus, independent columns/framing, mixed model policies
  and pinned replay. Shared helpers disclosed; native/GPU parity remains open.
- Costs: fixed derivation per record, O(d) witness/relations and retained data;
  no measured constant, benchmark, cut or weight-pass change.
- Verifier: production no_std unchanged; bounded research regeneration is not a
  plan parser or authenticated certificate-set registration.
- Glossary/history: Accepted prefixes and original task criteria preserved;
  links and glossary covered by repository gates.

I tried to break it by replacing -2^30 with its M31 alias 2^30-1, and the control
SourceDigits rejected it. Rebuilding the forged sign/magnitude's local columns
still rejected with IntegerRelation. An oversized unattained maximum rejected
with Attainment; a nonzero code in a zero-scale row rejected with ZeroCode.
