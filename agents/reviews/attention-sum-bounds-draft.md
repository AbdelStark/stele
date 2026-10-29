# Attention accumulation bounds — same-author skill review

Scope: Draft RFC-0004 A3/A6 and RFC-0009 A2. Codex-root applies cqis-numerics,
rfc-author and soundness-auditor; not independent audit. Evidence:
[signed sum study](../../research/cqis-bounds/ATTENTION-SUM.md).

- Public items: candidate static sum records, capacity-based column helper,
  plaintext checker and model metadata; Accepted RFC-0022 is unchanged.
- Challenges/absorbs: none; no random challenge, FS order or degree loss changes.
- Claims/consumers: no proof claims emitted. Actual probability/function/max,
  mask, value/scale, head/GQA/position and complete source membership consumers
  remain necessary. Block rounding and output normalization are separate work.
- Bindings/controls: SourceValue/SourceDigits catch changed code/scale/weight;
  IntegerRelation catches changed sums/sign/gap and coherent M31 aliases;
  Positions/Block/MaskWeight/ZeroScale/Range/Boundary catch their named mutations.
  These are research controls, without NC-0109 or NC-0500..0506 credit.
- Ledger: no lines change; accounting gate must retain existing coverage.
- Static bounds: configured C/P0 and conversion policy derive all caps. Every
  source restoration and nibble side has a strict p/2 bound. Sparse actual inputs
  never reduce the certified capacity; byte radix rejects even for one zero term.
- Padding/masks: only expected actual sources are stored; implicit tail is zero.
  Missing/extra source rows reject. Masked weights are zero but source-domain
  checks remain active. Absolute positions fix block membership without compaction.
- Determinism: integer arithmetic, ordered sources/roles, canonical digit equality,
  positive zero sign and exact byte regeneration; no timing-dependent order.
- Parity: independent exact/NumPy corpus and complete-model/checkpoint replay;
  shared numerical inner primitives disclosed. Native/GPU parity remains open.
- Costs: fixed template derivation and O(n*W) witness/checking; no allocated tail,
  measured constant, benchmark claim, new cut or proof weight-pass change.
- Verifier: production no_std unchanged. Research caps/checks are not a succinct
  authenticated source verifier; whole ranges and digit equality need consumers.
- Glossary/history: Accepted prefixes and original task acceptance preserved;
  the new capacity semantics are separate from existing exact-arity records.

I tried to break it by replacing a negative sum with its positive M31 alias,
and the control IntegerRelation rejected it after all nibble witnesses were
rebuilt. A byte-radix maximum-capacity record rejected with FieldBound even when
its sole actual input was zero. This establishes conditional arithmetic only.
