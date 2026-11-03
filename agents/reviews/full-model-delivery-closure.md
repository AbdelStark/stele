# E5-03b contract acceptance and native delivery audit

Status: Draft. Same-author rfc-author and soundness-auditor review by codex-root.
This audit adds prerequisite tasks and edges, retaining every original task
status and acceptance criterion. It changes no Accepted protocol or admission rule. It accompanies
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
| Sequential native delivery | Original workloads retained; four prerequisite tasks separate earlier artifacts from final delivery | Review the complete DAG and run required local and selected hosted gates; no dependency alone proves native completion. |

Outer PlanTemplate, PlanInstance, ledger, private WeightBindings, TableBindings,
certificate, checkpoint-proof, fidelity and registration artifacts still require
complete typed contracts and actual validators. Their references are not opaque
trusted configuration. The final review must distinguish what the numerical
contract defines from what a separately Accepted consumer must define before
instantiation. Section 5 checks the complete outer identity join and its native owners.

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

The explicit YAML graph remains acyclic. Four prerequisite tasks now separate
earlier artifacts from final workload delivery. All original acceptance lines
and statuses remain; the missing numerical consumers have explicit added criteria.

1. E5-03 now depends on E5-03b as well as E5-03a, requiring the
   complete accepted numerical contract before unblocking E5-03.
   E5-03a's two static schemas do not supply the nineteen-schema model contract.
2. E12-05a prepares the fixed subject from complete original artifacts and real
   private commitments. E12-06 now depends on E12-05a instead of the final
   E12-05 passport. E12-05 also depends on E12-06 and must validate its
   certificate before complete 8B passport delivery. The moved edge changes
   which artifact is required, without waiving certificate verification.
3. E14-02a must deliver the complete Accepted standalone checkpoint-proof
   contract, including the selected backend and Q12/Q14/Q29 composition.
   E14-02 now depends on that contract and E12-05a rather than the final
   E12-05 passport or E14-01 W8 inference wrapper. It implements the actual
   backend/relation and retains complete 8B proof production/verification.
   E12-05 consumes this result. E14-01 retains its full W8 wrapper criteria
   and E8-02 dependency. No backend or privacy architecture is selected here.
4. E8-05a derives/checks the complete native ledger and profile from the plan
   and actual consumer schedule, without a final passport or accepted inference
   proof. It remains blocked on the missing security contracts. E8-01 requires
   it and the complete E12-05 passport before full W8 production; E8-02 retains
   its independent accepting verifier. E8-05 retains both-profile W8 ledger
   delivery after E8-02. No supplied hash or profile bypass substitutes for
   the prerequisite checker.
5. E12-01a supplies the actual native masked reductions and private transcript
   composition, after E4-05 and the original source consumers. It remains
   blocked on the complete joint-view/lifetime contract. E8-05a depends on it,
   placing real privacy before accepting proof production/verification.
   E12-01 retains full inference integration and its original overhead gate
   after E8-02. The optional compact wrapper is not a replacement for native ZK.
6. E8-01 already reaches E7-06 through E7-09 and now also depends on E7-07.
   Any full target configured for block attention must consume the completed
   E7-07 implementation before its proof can be admitted. A change of attention
   mode is not a scheduling shortcut.

Each new prerequisite has explicit acceptance criteria and cannot complete its
parent. Native implementation still requires its complete Accepted contract.
Original task criteria, all unaffected edges and workload sizes remain. The
only removed edges are the three final-artifact edges described in findings 2/3;
their complete production/validation work remains in the graph. Run one task at a time.

## 5. Final outer identity and authority review

This review closes the numerical/source/outer-identity definition in RFC-0025
§7 item 1. It does not accept a child protocol or authorize native admission.
The source, encoding, conversion, architecture, public-input and passport
appendices define the exact earlier bytes and joins below. Every later child
has an explicit owner and must acquire its complete Accepted contract before
that owner can construct or validate it. No unspecified child field influences
numerical execution or becomes trusted configuration through a reference.

| Earlier value and exact join | Consumer and authority requirement |
|---|---|
| Original File bytes, SHA-256 and typed Source identity | E5-03 validates complete immutable containers/index/selection; E12-05 authenticates the independently expected source. Single-file SHA-256 remains distinct from indexed H(Source). |
| Original Assets, SourceMap and SourceConfig | E5-03 checks original architecture/role transforms against Model; E5-05 supplies the original tokenizer/generation adapters and named fidelity. File identity alone proves no text consumption. |
| Preparation and complete Artifact | E5-03 reproduces every scalar, scale, role and packed byte; E14-02 binds the same complete Artifact to actual private committed plaintext. |
| Model, Scales and regenerated Registry | E5-03/E3-08 validate complete parameters/data, and E6 derives owned numerical roles. A supplied digest cannot choose the expected model or tables. |
| Bounds and cqis_id | Bounds binds the first three complete artifacts; cqis_id hashes exactly the four artifact digests. Bounds contains no cqis_id, so this join has no cycle. E5-03/E6/E8-02 rederive it. |
| Model-wide PlanTemplate, WeightBindings and TableBindings | E6-01/02, E4-05 and E3-08/E12-05a must supply complete code/layout/source/private-lifetime contracts and actual bindings. References in Subject cannot replace them. |
| Fixed Subject | E12-05a binds the complete numerical/source/artifact and three child references. Subject and all referenced contexts omit later evidence, registration, signatures, final root and request data. |
| Proximity, checkpoint-binding and fidelity evidence | E12-06, E14-02 and E5-05/E12-05 validate the actual required relations for that same fixed Subject. Treaty still requires the actual certificate; both profiles require checkpoint and fidelity evidence. |
| Registration and signing message | E12-05 selects no authority from a self-supplied key. Its separately Accepted suite/key/authority/timestamp contract must validate the independently expected complete roster and every signature. The signing preimage omits signatures and the final root. |
| Final Passport and public passport_root | E12-05 validates all children before signing/final construction; E8-02 checks the externally expected final root, never the earlier subject_id. Prior records must already exist independently; later anchoring receipts stay external. |
| Request, PlanInstance and ledger | E6-02/E8-05a derive complete actual geometry/schedule/profile accounting. The instance omits its own hash, final passport root, I/O roots and ledger; the ledger omits its own hash and final public frame. Q12/Q29 and actual privacy remain prerequisites. |
| PublicInput and actual token sources | E8-01/02 bind the complete policy, q/g/reason, profile, four identities and exactly one I/O mode before transcript construction. E7-08/E8/E14 consume original token/seed/draw/hash relations; commitment mode also requires actual owned token/empty-output sources. |

The topological order is source/configuration and numerical artifacts, complete
model-wide children, fixed Subject, evidence, Registration, signatures, final
Passport, then the independently requested public statement. Request-instance
and ledger derivation depend on the complete earlier template and request,
without embedding the final statement they help identify. The native DAG
places preparation before evidence and evidence before final admission.
The eventual child specifications must preserve this order.

The review found one stale inventory paragraph describing the old E7-03/E7-05
titles; it now names the explicit LayerNorm/GPT-2 criteria already in the DAG.
No numerical definition, identity preimage or qualified oracle changed.
This is same-author review, with no external review claimed. The remaining
coordinated acceptance and full local/selected hosted qualification still apply.

## 6. Next contract work

The coordinated Draft dispositions are now explicit in RFC-0025 §7.1, and
27 new NC ids are reserved as `todo` with the exact catalogue snapshot updated.
The accounting document enumerates deterministic hash-use families without
claiming actual query bounds. The four prerequisite tasks and their consumer
edges are now in graph.yaml. The outer identity/authority review is complete.
Review the resulting specification and all twelve answers before acceptance.
Keep complete child-protocol work assigned to its actual consumers and forbid
production use until their own contracts and gates are satisfied. This audit
adds no challenge, cut, weight pass, cost constant or native completion credit.
