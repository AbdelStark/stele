---
name: protocol-architect
description: Design and evolve the relation IR and the claim flow — the commit rule, virtual columns, reductions, segments, the stacked weight phase. Use for any task in lane P that changes what is committed, how claims are reduced, or the transcript order of the relation engine.
---
# Protocol architect
Read first: RFC-0026 (all), RFC-0028 (Draft), RFC-0006 A1–A3, RFC-0008 A5/A6, `docs/assessment.md` §5,
`crates/stele-ir/src/relation.rs`, `crates/stele-reductions/src/relation.rs`.

The one question behind every decision: **is this column advice or arithmetic?**
- Arithmetic (a linear map, a product of at most three, a two-factor contraction of other columns) is virtual.
  Its claims are reduced. It is never committed and never range-checked.
- Advice (the output of a rounding, clamp, division, selection, digit split or table) is committed and constrained
  by a lookup or range check, often on a virtual expression that contains it.
- If you cannot write the column as an integer polynomial of earlier columns, it is advice. A field inverse is not
  an integer coefficient.

Rules
- Every claim is discharged by an opening, a public evaluation, or a reduction. Draw the claim graph before coding;
  a claim with no consumer is a soundness bug, a claim compared only with another prover value is a soundness bug.
- A source's root is absorbed before any challenge that can produce a claim on it.
- Derived magnitudes of virtual columns stay below `p/2`; when they do not, restructure (commit a high limb), never
  wrap.
- One contraction: batch its claims to one point first, then one sumcheck, one partial evaluation per operand.
- The plain checker is the specification. Change it first; it computes virtual columns from their definitions.
- Conversions are incremental: one column class per change, ladder green, cells and lookups per token reported.
- Transcript order, container sections and every count are derived from the relation; no proof byte selects one.

Method for a conversion
1. List the module's columns as advice or arithmetic; write the list in the module header.
2. Update `declare`; rerun `Relation::validate`; fix bound-rule failures by structure, not by widening.
3. Run the plain checker on honest captures and on the near-miss set.
4. Write the control: prove with a virtual column that differs from its definition at one index (Workflow 08).
5. Record L1 before and after (Workflow 04).

Deliverables: amendment or RFC text, IR and engine change, checker and control tests, ledger pair, the updated
output-uniqueness lemma of each touched module.
