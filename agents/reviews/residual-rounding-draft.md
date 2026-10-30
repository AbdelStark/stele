# Residual magnitude rounding review in progress

Codex-root applies cqis-numerics, gkr-reduction-author, rfc-author and
soundness-auditor. This is a same-author review, not independent audit.
[Scope](../../research/cqis-bounds/RESIDUAL-ROUNDING.md). Tests-first rejected
the missing module. All10000 corpus cases and primary/boundary controls passed. Composition,
matrices, maximum and gates remain under validation;
this is not a completed sign-off.

- Public items: Draft RFC-0004 A3/A8 research. Expected residual units fix
  B and h; complete ranges and exact columns enforce magnitude rounding.
- Challenges: five complete range transcripts remain. Expected schema/roles,
  three external roots, five auxiliary roots and all verified states precede
  terminal and column A3s in fixed order. Existing ZeroWeight and
  Instance/Round/Final schedules retain canonical parent field tuples.
- Claims: all eight originals retain actual consumers at emitted points,
  including both public views and every carry/source view. Actual verified
  quotient bytes supply the dyadic product; no supplied product is trusted.
- Bindings: tests-first covers each external/range root, range-valid M+p,
  coherent r=B with compensating q, omitted bias, terminal/padded carries,
  and compensated final originals. These controls passed. Actual sign-source
  composition is required.
- Ledger: five separately repeated lookup identities and unsquared reductions.
  Appended accounting gives all range/A3 and draw totals; matrix assertions
  and soundness-accounting.sh still need successful execution.
- Bounds: static carry interval[-129,2] becomes[0,131]. Column sides are
  <=66431<p/2 with exact endpoints. Whole M<=H, q<=32768 and r<B are consumed
  ranges. No runtime maximum or wide field residue establishes faithfulness.
- Padding: expected count masks h+32895 and carry endpoints. Actual complete
  ranges retain every source and carry padding position. External M/q/r roots
  include all8/2/4 planes, including high zero extensions. No case skips B=1.
- Determinism: fixed roles, range/A3 order, exact integer metadata and disjoint
  namespace spans. No challenge retry or timing-dependent choice.
- Parity: native CPU/SIMD/CUDA unchanged. Independent Fraction/NumPy rounding
  and carry grids passed10000 cases. Both fields/repetitions and16384 rows
  await validation.
- Costs: O(N) views, two batched A3s and five complete range/hash consumers
  in c_a/c_sc/c_lu/T_misc. Static counts are not benchmarks; no weight pass added.
- Verifier: native no_std unchanged. Strict metadata, roots, proof shape and
  canonical parent fields. No plaintext division authorizes acceptance;
  supplied states, certificates and bias fields confer no authority.
- Glossary/history: append-only Draft/accounting evidence. Full signed residual
  composition, original2^20 domain, native/model/private inference and fidelity
  remain open. Independent review and all remaining validation are required.

I tried to break it by setting r=B and decreasing q while retaining the exact
whole division and coherent carries, and the control
Remainder:CapRelation:RoundSumMismatch rejected it.
