# RFC-0006 A2 / RFC-0012 A4 review

Reviewer: codex-root, also the author. These soundness-auditor, RFC-author,
sumcheck-prover-engineer and PCS-engineer passes are not independent audit.
Scope: the contract and research oracle, not E3-02 production completion.

Soundness-auditor: ordered claims and all member descriptions precede gamma;
its powers have root loss at most (t-1)/p^d, conservatively recorded as t/p^d.
Zero challenges remain allowed. Disjoint selector/suffix coordinates justify D,
including degree-four unequal-size instances. The mode-1 A evaluation is computed
by the verifier; final input obligations survive zero multipliers and unused
inputs. The formal statement conditions on true emitted evaluations and fresh
interactive challenges. It does not establish FS, PCS, composition or ZK.
Sign-off: approve the contract with Q12 and production gates retained.

I tried to break it by omitting a member contribution from one round evaluation,
and the control RoundSumMismatch rejected it. This is research evidence only;
NC-0202/0206 must still use the real implementations. Early coefficients, unused
false finals and omitted BatchFinal also reject in the research public verifier.

RFC-author: original Accepted RFC prefixes are preserved. Both original batching
modes remain required. The cost qualification states when Boolean-prefix blocks
are linear and when arbitrary points cost t times the table size. The descriptor,
bytes, errors, costs, algebraic bound, controls and Q18 resolution are explicit.
Sign-off: approve; task completion requires every listed production criterion.

Sumcheck-prover-engineer: fold only active suffixes, retain true prefix residual
sums, and never replace them with unverified claimed sums. Constant P requires
the selector outside P; input-level padding would be incorrect. Sparse blocks
accumulate overlaps. Singleton/zero-round batches still bind gamma and finals.
Sign-off: approve; the exhaustive oracle is not an efficient prover benchmark.

PCS-engineer / hash owner: A4 extends the closed registry without changing A1
sampling or existing bytes. Mode 1 requires the plan's virtual-tensor role;
committed tensors keep functional openings. Sign-off: approve this boundary.

Workflow 03 checklist:
- Public items: no core API; RFC-0006 A2 and RFC-0012 A4 govern implementation.
- Challenges: Batch then gamma; each Round then SC; BatchFinal before continuation.
- Claims/consumers: all original inputs at suffix points, or y at the full point;
  real reductions/PCS discharge them; the public adapter checks each table.
- Bindings: NC-0202/0206 planned; NC-0205/0802 extensions remain required.
- Ledger: one RLC t and one SC M D over p^d; production gate unchanged by contract.
- Certificates: field-only identities; no dynamic integer bounds.
- Padding/masks: selector on the summand, no new commitment or ZK assertion.
- Determinism: fixed order, explicit bytes; no map iteration chooses messages.
- Parity: four Python candidate vectors; no Rust/GPU batching parity yet.
- Costs: symbolic formulas only; c_sc and peak-memory ledger remain E3-02 work.
- Verifier: future no_std API checks lengths/aliases and aborts on error.
- Glossary: existing vocabulary; reduction success retains obligations.
