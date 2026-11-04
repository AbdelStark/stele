# Q32: concrete sequencing proposal

Disposition: accepted by RFC-0025 A1 after the user delegated the sequencing
choice. The text below and the pinned JSON preserve the reviewed proposal;
its pending-state statements describe that earlier proposal, not current status.
See the [acceptance record](e503-sequencing-acceptance.md).

Status: proposed, not applied or Accepted. The current task graph and all native
admission rules remain unchanged. The [exact proposed dependency edits and new
acceptance criteria](e503-sequencing-proposal.json) are pinned to commit
`eba81244ae9d87885b0f0d2d13bb6740e9458d90`.

Keep E5-03 and E6-01 as final completion tasks, with every current acceptance
line intact. Add two complete artifact prerequisites: E5-03c for native
numerical preparation and E6-00 for native canonical lowering. Each prerequisite
would need its own complete acceptance evidence, required gates and merged PR
before another implementation task starts. Neither would complete its parent.

Both splits are necessary. Splitting only E5-03 leaves E6-01 requiring actual
reduction and public-input controls, while those consumers still depend on
E6-01 through E6-02. A mere topological sort of the current YAML hides both
completion conflicts.

| Task | Proposed prerequisite change | Reason |
|---|---|---|
| E5-03 | Add E5-03c and E6-01 | Final quantiser completion waits for numerical preparation and actual production controls. |
| E5-04 | Replace E5-03 with E5-03c | Reference inference needs complete original numerical artifacts; final passport signatures are not its input. |
| E6-01 | Require E6-00 and E8-02 | Keep the original lowering task incomplete until its real reduction and public-input controls can run. |
| E6-02 | Replace E6-01 with E6-00 | Stacking and range discipline consume the complete native plan and genuine source owners. |
| E12-05a | Replace E5-03 with E5-03c | Subject preparation consumes complete original artifacts; it precedes the final evidence and registration controls. |

E6-00 also requires E3-08 and E4-05. Regenerated numerical table metadata and a
hash of converted weights cannot stand in for the genuine table/private-source
providers. Their existing proof, privacy and Accepted-contract requirements
remain prerequisites. This proposal does not select a missing security theorem,
private protocol, proof backend or signing policy.

The resulting order is complete numerical preparation, native lowering,
stacking/range discipline, the actual reductions and private profile consumers,
fixed Subject, evidence, final Passport, native W8 proving and verification,
then final E6-01 and E5-03 controls/completion. Independent reference inference
and named fidelity still precede Subject and Passport construction. Every task
in that order remains subject to its other existing dependencies and blockers.

The final E6-01 dependency on E8-02 brings all ten E7 tasks, E12-05/06 and E14-02
into its prerequisite closure. E5-03 then reaches those same actual consumers.
This permits their implementations to exist before the final parent controls
run. It does not claim that dependency reachability executes a control or that
an arbitrary accepted inference proof covers every required mutation.

Original Llama-3.1-8B source and assets remain necessary even for the first new
prerequisite. The completed GPT-2 int8/int4 evidence cannot finish it. No model
size, configuration, fidelity suite, proof obligation or benchmark is reduced.
The existing catalogue remains untouched and supplies no new coverage.

This changes task granularity. It needs an explicit sequencing decision because
the current instruction requires complete original tasks to merge one at a time.
The decision is whether two complete prerequisites may merge sequentially while
the original E5-03 and E6-01 stay incomplete. Without that decision, preserve the
current graph and branch; do not relabel the existing work as a completed task.

Same-author RFC-consistency and soundness review: the proposal changes no native
API, protocol bytes, challenge, transcript, proof relation, bound schema, source
authority, profile, ledger term or cost constant. Full review and an Accepted
amendment remain required before applying it. No formal soundness claim follows
from this scheduling check.

Validation: the candidate has 132 tasks and passes both existing task-graph
tests. All non-dependency fields of the 130 existing tasks are unchanged.
The five edited dependency lists match their pinned originals; both final
completion tasks reach all ten E7 consumers, E8-02, E12-05/06 and E14-02.
The live task graph, native code and control catalogue are unchanged. The
documentation gates pass with 533 Accepted RFC references and 759 local targets.
