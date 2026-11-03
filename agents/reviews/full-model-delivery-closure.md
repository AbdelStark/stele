# E5-03b contract acceptance and native delivery audit

Status: Draft. Same-author rfc-author and soundness-auditor review by codex-root.
This audit adds two prerequisite edges and changes no task status, acceptance
criterion, Accepted requirement, protocol or admission rule. It accompanies
[the twelve review answers](full-model-cqis-draft.md).
The authoritative task definitions remain [graph.yaml](../tasks/graph.yaml).

## 1. Acceptance boundary

[RFC-0025 §7](../../docs/rfcs/RFC-0025-full-model-cqis.md) explicitly requires
the specification, independent numerical evidence, coordinated reviews, controls
and implementation DAG before acceptance. Its final paragraph requires native
implementation, named-model fidelity, private PCS/ZK, profile admission and full
proof delivery after acceptance. E5-03b's task criteria make the same distinction.
INV-1 prevents native code from implementing an unaccepted numerical contract.

Requiring the entire native implementation to accept its governing numerical
specification would reverse that dependency. Conversely, specification acceptance
does not complete E5-03, E5-04, E5-05 or any proof task. A new metadata codec is
useful only when it closes a concrete unresolved contract or consumer requirement.
More random reference frames cannot establish missing cryptographic admission.

Some older Draft amendments, including RFC-0011 A3, contain their own native
evidence conditions. This audit does not waive or silently reinterpret them.
The coordinated amendment review must state the exact scope and disposition of
each condition before acceptance; a new general paragraph cannot override it.
Accepted parent requirements and original native acceptance lines stay intact.

## 2. Contract closure checklist

These are review states, not declarations that an acceptance item is complete.
Existing evidence is in [REPORT.md](../../research/cqis-model-contract/REPORT.md).

| E5-03b requirement | Available evidence | Remaining acceptance work |
|---|---|---|
| Complete GPT-2/Llama arithmetic, full/cache and decoding definitions | Exact whole-model execution, activation-tail regression, source preparation and decoding checks; original named dimensions retained | Finish coordinated numerical amendments and review every operation against the consumer inventory. Generic source cases provide no named fidelity. |
| Canonical Model, Scales, Registry, Bounds, Preparation, Source, Assets, SourceConfig and Artifact | Closed frames, full numerical identity, exact original-file conversion and stored Artifact checks | Review all identity and authority edges through the public-input and passport contracts; no caller-supplied digest becomes authority. |
| Complete static arithmetic and consumer dependencies | Nineteen-schema collection and [operation inventory](../../docs/rfcs/full-model-consumers.md) | Put all missing consumers into the acceptance DAG, including wide affine/position arithmetic, LayerNorm, GPT-2 activation, sampled decoding and actual source joins. |
| Independent evidence for newly specified numerical choices | Pinned exact arithmetic, framing, boundary and malformed-input results | Review the evidence-to-contract mapping and preserve earlier receipts. Re-run a campaign only for a relevant change or unresolved failure. |
| Coordinated amendments and controls | Draft amendments and all twelve review answers | Resolve the Draft dispositions, reserve actual new NC ids and update the reservation snapshot. Complete deterministic hash-use and eventual consumer accounting obligations. |
| Sequential native delivery | Existing parent tasks retain the original workloads | Repair missing prerequisite edges and completion cycles, then review the final graph and run required local and selected hosted gates. |

Outer PlanTemplate, PlanInstance, ledger, private WeightBindings, TableBindings,
certificate, checkpoint-proof, fidelity and registration artifacts still require
complete typed contracts and actual validators. Their references are not opaque
trusted configuration. The final review must distinguish what the numerical
contract defines from what a separately Accepted consumer must define before
instantiation. This audit does not mark the §7 identity-join item closed.

## 3. Native owners and non-negotiable completion evidence

| Required work | Owning tasks | Evidence required before that owner is done |
|---|---|---|
| Original source conversion and full static certificates | E5-03 | Native streaming at the actual model sizes, exact formats/scales/roles, static derivation and NC-0109. |
| Full reference inference and generation | E5-04 | Original GPT-2-small and Llama-3.1-8B, Rust/NumPy parity, all boundaries, full/cache equality and stopping semantics. |
| Original tokenizer/configuration use and named fidelity | E5-05, E12-05 | Authorized complete original assets, actual adapters, item-level report hashes and the unchanged RFC-0004 §8 protocol. A token-id fixture is insufficient. |
| Complete plan, source ownership and request instantiation | E6-01/02/03 | Canonical template/instance bytes, actual claim/transcript/source schedule, range/padding discipline, complete request geometry and one-layer capture/recompute. |
| Original tables and private weight commitments | E3-07/08, E4-03/04/05, E6, E12-05 | Regenerated table roots, complete code/layout/packing/source/lifetime contracts, actual openings and all original privacy/proximity/profile obligations. |
| Every configured numerical relation | E7-01 through E7-10 | Full source/range/branch/index consumers, actual one-value controls and exact point ownership; E7-02 remains the stacked weight phase, E7-09 scale attainment and E7-10 residual/RLC glue. |
| Passport preparation and final registration | E12-05/06, E14-02 | Complete approved key/suite/authority/timestamp policy, valid signatures, required proximity and checkpoint evidence, actual fidelity report and the complete 8B passport. |
| Native proof production and verification | E8-01/02/03/04/05/06 | Full W8 production, independent verification, actual controls, recomputed ledger and digests. A conditional component proof does not complete W8. |
| Privacy, profiles and wrapper | E4-05, E12, E14 | Accepted Q12/Q29 resolutions, full lifetime confidentiality, proven-only treaty parameters, all required profile bounds and the separately accounted wrapper relation. |
| Larger workloads and performance | E9, E10, E11 and original benchmark tasks | Full binding-enabled workloads, ledger-backed measurements, CPU/GPU byte parity and original capacity/throughput criteria. |

The authorized Llama checkpoint location remains pending. Independent contract
work can proceed; the missing source cannot be replaced with a smaller model or
counted as delivered fidelity. E13-04 top-k and E13-05 chaining remain separate
original obligations. No traffic-provenance claim is added to the base statement.

## 4. Dependency findings

The explicit YAML graph is acyclic. Findings 1 and 6 are repaired by adding their
prerequisites. The other findings require separating prerequisite artifacts from
final delivery; adding only the missing completion edges would create cycles.
Resolve those before adopting the final E5-03b implementation DAG.

1. E5-03 now depends on E5-03b as well as E5-03a, requiring the
   complete accepted numerical contract before unblocking E5-03.
   E5-03a's two static schemas do not supply the nineteen-schema model contract.
2. E12-06 depends on E12-05, while a complete treaty
   passport requires the E12-06 certificate. Separate model-subject preparation
   from final passport delivery. Certificate generation consumes that fixed
   subject and its real commitments; final delivery consumes the verified result.
3. E14-02 depends on E12-05 and E14-01,
   while E12-05's complete passport requires checkpoint-binding evidence.
   E14-01 in turn depends on E8-02 and includes a full W8 wrapper result.
   Separate the selected backend/checkpoint-relation prerequisites from the
   completed inference-wrapper workload. The one-time hash relation must bind
   the pre-evidence subject, without needing the final passport root or an
   already accepted inference proof. This does not select a backend or waive
   RFC-0016 A1, Q12/Q14/Q29, private source or extraction requirements.
4. E8-05 follows E8-02, but E8-02 must recompute the
   ledger before acceptance. Make the deterministic ledger/profile checker a
   prerequisite of accepting verification; retain E8-05's complete W8 results
   for both profiles as its final delivery requirement. No supplied ledger hash
   or temporary profile bypass can stand in for that checker.
5. E12-01 follows E8-02. Required privacy cannot
   be deferred past acceptance of a profile that promises it. Distinguish the
   complete native replay engine from final profile admission, and schedule
   the actual privacy prerequisites accordingly. Keep native ZK requirements;
   no optional compact wrapper is silently promoted to the privacy mechanism.
6. E8-01 already reaches E7-06 through E7-09 and now also depends on E7-07.
   Any full target configured for block attention must consume the completed
   E7-07 implementation before its proof can be admitted. A change of attention
   mode is not a scheduling shortcut.

Each split must give the prerequisite task a concrete artifact and acceptance
criteria, retain all parent criteria, preserve actual workload sizes, and leave
the parent unfinished until the complete workload passes. Add no dependency on
a final artifact from a task that constructs an earlier part of that artifact.
The final graph must include all existing dependencies, with any moved edge
justified by the precise prerequisite artifact it needs. Run one task at a time.

## 5. Next contract work

Finish the coordinated amendment dispositions and NC reservations, then apply
the reviewed dependency changes to graph.yaml with explicit acceptance criteria.
Review the resulting specification and all twelve answers before acceptance.
Keep complete child-protocol work assigned to its actual consumers and forbid
production use until their own contracts and gates are satisfied. This audit
adds no challenge, cut, weight pass, cost constant or native completion credit.
