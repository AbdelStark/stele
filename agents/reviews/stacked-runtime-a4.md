# Conditional stacked runtime acceptance

Decision: accept RFC-0006 A4, RFC-0012 A6 and RFC-0020 A2 for the complete
conditional public-coefficient field protocol in
[stacked-runtime.md](../../formal/stacked-runtime.md). E3-06 becomes ready for
implementation; no task, native control or inference profile is complete.

Three separate internal agent passes reviewed clean commit
`86c4a8b02cf4d67cd21c3d5107daa259095b82e5`, whose runtime contract SHA256 was
`4ccd6480dc4cdf073093732dacb21ed6237dc68543114fc8b614695ab9c5ebef`.
The soundness-auditor/PCS-owner pass approved the conditional theorem and real
source consumption. The GKR-reduction-author/RFC-plan pass approved the exact
statement, source authority and claim graph. The sumcheck-prover-engineer/hash
owner pass approved A1 reuse, actual fold-derived points and transcript order.
The author applied the RFC-author consistency pass. This is coordinated agent
review, not an independent cryptographic audit.

Review corrections made before that frozen revision: every failure exposes
actual usage; kernel callers must fix originals before challenges; the producer
retains actual fold challenges with charged O(m) storage; NC-0211 targets the
first unused original; NC-0213 uses an independently verified substituted root
with an all-zero old opening row. Acceptance then updates lifecycle/index/task
metadata and marks the ownership lemma's adoption. It also makes explicit that
NC-0212 needs both onehot and exact-table variants, as required by the reviews.
No Accepted antecedent, A1 wire or A9 interface is changed in place.

The scope correction is deliberate. E12-01 already depends transitively on
E3-06. Completed joint masking cannot be a prerequisite of implementing that
same public runtime. Actual private coefficient formats, source conversion,
packing/range, joint privacy, CQIS table authority and Q12 remain unresolved.
The contract supplies no profile/privilege flag that would bypass those duties.

| Review item | Finding and required implementation evidence |
|---|---|
| Public items and owners | A4 defines GKR statement/strategy/public consumption and the reductions-owned certified adapter. A6 adds two closed absorbs; A2 admits only exact downward dependencies. |
| Challenges | StackSources then Stack precede actual A1 Instance/Round/Sumcheck/Final. Every original opening retains A9's complete schedule. No new draw. |
| Claims | Independently check A7's final at the restored point. Consume every ordered original, including unused inputs. Raw nested draw-order claims stay internal. |
| Source authority | Actual expected public bytes or opaque A9 verified certificates. No synthetic receipt, authentication callback, implicit view or coefficient commitment. |
| Controls | NC-0203/0211..0213 and two NC-0802 frame-omission continuations name exact rejecting consumers. All new native coverage remains pending. |
| Accounting | Retain actual m*delta/p^d and every applicable A9 certificate/opening/lifetime/hash obligation. Report one transcript snapshot and disjoint local work, including failures. |
| Integer certificates | No integer identity is claimed. Future CQIS operations retain their static certificate requirements. |
| Padding and masks | A7 validity is inside the Boolean table. Public originals check zeros; certified mode requires full real dimensions because A9 proves no zero padding. |
| Determinism | Exact canonical bytes and list order, two explicit permutations, disjoint suffix ownership and actual endpoint coalescing before nonlinear evaluation. |
| Parity | Native/Python frames, proofs, restored claims, records, decisions and continuation plus both-field partial agreement remain delivery gates. No GPU claim. |
| Costs | Charge dense preparation, partials, fold overlap, actual challenge retention and all source/PCS work. Complete native time/bytes/memory ledgers remain required; no measured constant or weight-pass claim. |
| Verifier and vocabulary | Checked preflight, fallible allocation, no_std/downward boundaries and typed rejection. Unconsumed field claims do not become inference or privacy authority. |

The author executed six focused attacks through the unchanged research
public-stage consumers in QM31 and OM31. A wrong-layer A final under empty P
passed raw A1 and failed CoefficientMismatch. A draw-order unused original final
passed the conditional stage and failed ClaimMismatch. Changing a scalar exact
table from 7 to 8 changed only its A final and failed CoefficientMismatch.
The preserved receipt SHA256 is
`703f8bfb2d25075d76c0b20e866a56fb4b0085ea6d14e491431fe965abd4d5ab`;
the soundness reviewer inspected its helper and source hashes. Reviewers did not
execute those checks themselves. They cover neither StackSources nor a native
certified stacked adapter and provide no native NC credit.

I tried to break it by changing a coefficient final to its wrong-layer value,
an unused original final to its draw-order value, and one exact public-table
value, and the existing research controls rejected them with CoefficientMismatch,
ClaimMismatch and CoefficientMismatch in both fields. Actual native controls,
complete source closure and the resource/parity gates remain mandatory before
native delivery approval or E3-06 completion.
