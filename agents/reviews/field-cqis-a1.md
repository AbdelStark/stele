# RFC-0003 A1 and RFC-0004 A1 skill reviews

Reviewer: `codex-root`, also the draft author. These are separate skill passes by
the same agent, **not independent review or human sign-off**. Workflow 02 requires
the named skills but does not require separate agents. The review scope is the
specification and scalar API migration, not a working inference proof.

## Soundness-auditor pass

RFC-0003 A1: the norm argument is valid. The multiplicative-group theorem cited in
`research/r-octic/REPORT.md` gives the quadratic-character test; each tower is a
field before that theorem is applied at the next level. The norm of `2+i` is `5`,
and the norm of `u` is `-(2+i)`. Since `-1=i²` in CM31, the latter remains nonsquare.
Exact-arithmetic checks corroborate the proof. The candidate has order `p⁸`;
`2²⁴⁸` is a bit-width approximation and cannot replace it in error denominators.

I tried to break it by replacing the octic constant `u` with zero, one and four,
and the control `accepts_quadratic_constant` rejected it.

RFC-0004 A1: Euclidean division of the nonnegative biased magnitude uniquely fixes
`q,r`; sign and target-range conditions then uniquely fix the rounded output.
The exact rational reference agrees at both signed ties, zero shift and large
products. Nonnegative `a,q`, the Boolean sign, the zero-sign convention, and all
range bounds are essential. For a future field reduction, static certificates must
bound the complete integer identities (including differences), or use proven limb
decomposition. Integer checks alone are not a field-faithfulness argument.

I tried to break it by changing one witness value at a time and by substituting
the wrong negative-tie output, a noncanonical zero sign, an overflowing result and
`r=D`, and the control `rejects_single_value_tampers` rejected it.

Sign-off: approve these semantic amendments, with no claim that their future
reductions, transcript, range lookups or bound-certificate verifier are implemented.

## RFC-author pass

The amendment logs identify exact replacement text without rewriting the original
Accepted sections. The field basis agrees with the existing CM31/QM31 tower and
little-endian limbs. Checked recovery avoids silent projection onto a constant
coefficient. Profile selection and the R-OCTIC performance comparison remain open.
The rounding amendment matches ADR-005 and the named E5-01 behavior, resolves the
three conflicting rules, and leaves residual-add semantics unchanged.
Q9/Q10 are resolved as specification questions; implementation remains in the DAG.
No new committed tensor or public input is introduced. Glossary checks pass.

Sign-off: approve both A1 texts for consistency and scope. No broader RFC, profile
budget or benchmark claim is approved by this pass.

## Implementing skill / crate-owner passes

`sumcheck-prover-engineer`, owner of `stele-field` for this change: inspected every
signed-recovery caller. Both base-field implementations and their common tests
migrate atomically to `Option<i64>`. E1-02 must test every nonconstant coefficient,
canonical limb and basis order. It retains the million-case field tests and the
measured QM31:M31 ledger requirement. The research code is not imported by crates.
Sign-off: approve the field contract and migration.

`cqis-numerics`, owner of `stele-cqis` for this change: input/product/shift semantics
are explicit, zero shift is defined, and out-of-range results reject without
saturation. E5-01 must document supported arithmetic and compare Rust with NumPy
int64 on 10,000 cases per operation; later reduction tasks must implement the sign,
range and static-bound checks. No core CQIS implementation exists to migrate.
Sign-off: approve the rounding semantics, not model fidelity or a proof relation
implementation. The numerical choice agrees with the existing ADR-005.

## Workflow 03 checklist

| Check | Evidence / disposition |
|---|---|
| Public items and RFC sections | `Field::to_i64_signed`, M31 and KoalaBear implementations: RFC-0003 A1; other changes are specifications and research checks. |
| Challenges and absorbs | None added or changed; no transcript implementation in this change. |
| Claims and consumers | None emitted; amendment describes integer semantics only. |
| Bindings and one-value controls | No implemented claim-graph edge. Research controls above test the proposed conditions; NC-0100/0101/0109 remain requirements for future reductions, with no catalog credit. |
| Soundness ledger | No lines changed. Accounting gate passes on the unchanged guarded scaffold; it does not establish a soundness budget. |
| Bound certificates | No certificate producer/verifier added. RFC-0004 A1 explicitly requires static bounds for all identities; future field checks must not infer them from witnesses. |
| Padding and masks | No padding, lookup implementation or masks changed. |
| Determinism | Exact integer/rational checks and fixed iteration order; no timing-dependent arithmetic. |
| CPU/SIMD/CUDA parity | Only the scalar API changes; shared M31/KoalaBear tests pass. SIMD/CUDA parity is unimplemented and is not claimed. |
| Cost model | No measured constant changes. Additional sign/magnitude relations belong in `c_a` when implemented; E1-02 benchmark remains required. |
| Verifier constraints | Verifier untouched; field crate remains `no_std` with no new allocation, panic path or dependency. |
| Glossary | Gate passes; no exception added. |
