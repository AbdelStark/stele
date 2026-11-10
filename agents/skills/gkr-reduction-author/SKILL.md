---
name: gkr-reduction-author
description: Author a proving module or reduction in stele-reductions that follows the CQIS operation exactly — embedding, norm, row conversion, projection, RoPE, attention, SiLU, residual, head, argmax, MoE routing — as relations with a plain-checker oracle, an output-uniqueness lemma and near-miss tests.
---
# Reduction and module author
Read first: RFC-0026 §3 and §5 (your row and the shared patterns), RFC-0028 §1.2 (the commit rule, Draft),
RFC-0004/RFC-0025 for the exact integer semantics, the `research/cqis-bounds/` note your row cites.

A module is `declare` (columns, groups, tables, relations from plan data only; prover and verifier both run it)
and `assign` (fills only its own committed columns from the executor capture).

Rules
- The executor is the definition. Honest values come from `Executor::capture`; the plain checker must accept them.
- Soundness is output uniqueness: for inputs within their widths, every assignment that satisfies the relations
  gives the executor's outputs. Write the lemma in the module header. Auxiliary columns may be free only where
  outputs do not depend on them.
- Near-miss tests for every output: executor value ±1 and the other rounding direction, with the strongest
  auxiliary assignment you can build. The plain checker must reject each.
- Commit advice only (rounding outputs, table indices, selections, high limbs). Arithmetic is virtual once
  RFC-0028 is Accepted; until then follow RFC-0026 as written.
- The bound rule is static: `Relation::validate` must pass for the largest supported shapes. A value that breaks
  it is held as limbs with explicit carries; a value wider than 30 bits never appears whole.
- Padding is data: pin padded outputs to zero with a public mask; never let a relation depend on padded weights.
- Never loop over layers inside a relation: the layer index is a variable of the stacked tensor or a segment.
- Public columns and tables come with their verifier-side evaluation and an agreement test.
- Each emitted claim has exactly one discharge; each binding has a control (Workflow 08).

Checklist: header lists committed and virtual columns and the lemma; validate passes at the synthetic and the
real shapes; honest and near-miss tests; control ids; cells and lookups per token before and after.
