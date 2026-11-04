# E5-03 completion dependency audit

The native quantiser cannot currently satisfy every E5-03 acceptance line while
following the task graph. This is a completion dependency conflict, although
the explicit YAML edges remain acyclic. No task criterion or control is waived.

E5-03 requires all controls assigned to it by RFC-0025 §6. That section requires
an accepted honest baseline and a single changed value rejected at the actual
owning consumer. The following consumers themselves depend on E5-03:

| Required controls | Actual downstream consumers | Existing dependency path |
|---|---|---|
| NC-0118/0119 | Plan roles, stacked weights and token/head source | E5-03 → E6-01 → E6-02 → E7-01 → E7-02 → E7-08 |
| NC-0120/0121 | Numerical/configuration identity in the plan and passport | E5-03 → E6-01; E5-03 → E5-04 → E5-05 → E12-05 |
| NC-0122 | Full gated scale source in actual reductions | E5-03 → E6-01 → E6-02 → E7-01 → E7-05; E7-01 → E7-06 → E7-09 |
| NC-0704..0710 | Complete passport children, evidence, authority and signatures | E5-03 → E12-05a → E12-06; E12-05 also requires E14-02 |

The existing graph also places E14-02 after E12-05a. These paths follow the
current `depends` edges; they are not proposed scheduling changes. Treating
E5-03's completion requirements as edges back to those consumers exposes the
conflict. E6-01 additionally awaits its Accepted lowering/source contract.

The native SourcePackage, SourceConfig, conversion, stored Artifact and numerical
identity checks supply numerical preparation evidence. They do not validate
private commitments, final evidence children, authorized keys or signatures.
The catalogue explicitly keeps the RFC-0025 reservations `todo`. Its executable
registry permits `Configuration` only for NC-0801; relabelling these numerical
checks cannot supply the required production controls. The earlier Requant
NC-0109 check is scoped to its static record and does not complete the full CQIS
family. Native Bounds parity alone does not change that scope.

Complete original GPT-2 preparation now passes for int8 and int4. Original
Llama-3.1-8B conversion independently still requires the previously requested
authorized complete checkpoint and assets. Full numerical Llama Registry data
and synthetic source fixtures do not satisfy that requirement.

RFC-0025 A1 is a Draft escalation of the completion conflict, mirrored as Q32.
It neither approves a new consumer protocol nor changes any accepted criterion.
E5-03 is blocked on its resolution and the original Llama source. Inspection of
the graph found no other `ready` task whose dependencies are all `done`.
The implementation stays on `task/E5-03-complete-quantiser`; no partial-task PR
or additional implementation task is opened.

Same-author `cqis-numerics`, `soundness-auditor` and `rfc-author` audit: no proof,
new security claim, challenge, transcript field or cost constant is introduced.
All nineteen numerical schemas and the full native preparation evidence remain
available. An accepted resolution must preserve every original model, fidelity,
proof, privacy, profile, production-control and benchmark requirement. It must
also explain how each prerequisite can be completed under the one-task-at-a-time
workflow. This audit records a blocker; it is not an acceptance sign-off.
