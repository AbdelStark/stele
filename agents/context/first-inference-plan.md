# First native inference: closure plan

Audited against main `ff0f005e87d283d4d2fb8fbce172216b0eda5322`.
The objective is the original W8 proof and independent verification flow,
followed by the existing scale, privacy and performance requirements. This
plan does not redefine W8 or mark any original task complete.

## Project model

Stele uses Rust 2021 for native proof arithmetic and a Python reference.
Accepted RFCs define behavior; Draft studies cannot authorize production.
Field, transcript/Merkle, sumcheck, encoding and CQIS primitives exist.
The native PCS, IR, reductions, prover, proof format, verifier and CLI still
have scaffold guards. A successful arithmetic reduction leaves original
source claims that need actual consumers. Revealing research roots do not
supply private PCS or model ownership. Every original task criterion, bound
certificate and negative control remains required.

## Reconciliation findings

| ID | Evidence | Required action |
|---|---|---|
| F1 | `crates/stele-{pcs,ir,reductions,prover,proof,verifier,cli}/src/lib.rs` | Implement source consumers and the native artifact flow before claiming inference delivery. |
| F2 | E8-01 omitted witness capture and several reductions; E9-01 omitted E8 verification/accounting from its ancestor set | Require E6-03 and the missing operation reductions before E8-01, E8-02 before the digest gate, and E8-05 before E9-01. Preserve global control criteria without introducing a GPU dependency cycle. |
| F3 | `check_norm_statistic_full.py` on PR194 and descendants shadows the `expected()` helper with a digest variable | Rename the local digest, preserve frozen outputs and execute the complete honest/full-size modes. Propagate the same correction through the stack. |
| F4 | W8 is GPT-2-small in RFC-0018; the model study supports RMSNorm/SwiGLU blocks | Specify and implement GPT-2 normalization, learned position and bias semantics. A tiny Llama fixture cannot satisfy W8. |
| F5 | RFC-0006 A4 and RFC-0010 A1/A3/A6 retain unresolved source/PCS contracts | Close exact source descriptors, field-faithful packing, finite parameters, queries and original-claim consumption. |
| F6 | RFC-0012/Q12 and RFC-0013 A1 retain FS/H and privacy gaps | Resolve theorem/assumption and masking obligations before admitting the affected profiles. Tests cannot replace the missing argument. |

The audit found 45 open PRs, primarily one research stack. Keep their scope
and evidence separate from native implementation progress. The CI snapshot
had 40 active hosted runners and 1546 queued jobs. Five runs used superseded
heads; another pair shared one head, workflow and base. Cancel obsolete work
only after confirming current replacement runs. Preserve logs and useful
completed results. Never treat a queued run, a first-page job list or a
successful aggregate alone as complete evidence.

The worktree audit found merged inactive checkouts alongside active jobs
and unpublished commits. Preserve live checkouts and every unique commit.
Remove only rechecked clean, merged, inactive worktrees; retain branches and
archive untracked caches before removal. Keep the user's environment files
and unrelated work untouched.

## Execution DAG

| Node | Depends on | Acceptance |
|---|---|---|
| R0: reconcile existing work | none | Every PR has a base/head and dependency owner; failed checks have a diagnosis; stale runs and merged worktrees are reconciled without losing evidence. |
| R1: complete W8 semantics | R0 | Accepted CQIS/model/quantiser/plan contracts cover actual GPT-2-small operations and preserve all existing architecture requirements. The contract fixes complete causal and cached execution. |
| R2: terminal source, PCS and privacy contracts | R0 | Close RFC-0006 A4 / RFC-0012 A6 / RFC-0020 A2 and RFC-0008 A2 / RFC-0012 A8 alongside PCS. Accepted finite code/query parameters, packing, opening bytes, original-source mapping and fused same-object B semantics have named loss terms and controls. Specify the joint-view masking/source construction needed for W8 treaty admission. |
| R3: native PCS and claim ownership | R2 | E4-01/03/04 and E3-06/07 consume actual private/virtual/public sources, including zero-coefficient originals. No receipt grants statement acceptance. |
| R4: native model proof path | R1, R3 | Rust and NumPy agree on complete causal/cached execution. E5-03/04, E6-01/02/03 and the selected plan's E7 operations meet their original criteria; one-pass and memory counters include every consumer. |
| R5: artifact flow and independent verification | R4 | Register/plan/prove/verify operates on persisted canonical artifacts. W8 proofs pass Rust and independent Python verification, including malformed proofs and each W8-binding substitution. This does not mark the global E8-03/04 criteria complete. |
| R6: profile admission, digests and benchmark | R2, R5 | Implement and validate R2's W8 privacy construction before treaty admission. An accepted W8 proof has a complete ledger meeting its selected profile. E8-05 retains its both-profile and rejection criteria; E8-06 records verified proof digests. Benchmarks include complete proving and both verifiers, all bindings enabled, with resource evidence. |

R6's profile work can begin with R2; no profile result is inferred from R5.
E8-03/04 currently require all controls, including GPU and distributed
controls whose implementations depend on E9. Making them prerequisites of
E8-06 creates a semantic cycle even when the written edges are acyclic.
Their global criteria remain unchanged and required. Define the explicit
native W8 validation inventory before R5, then complete global coverage as
the remaining backends and operations land. Long-context E7-07 remains
required for plans selecting its mode; it does not gate every W8 plan.
W8 privacy/source construction is a prerequisite of treaty admission at R6;
the later E12 W1 performance tasks are not predecessors of R6. Adding all
E12 tasks there would create a cycle through GPU/scaled inference. Their
original criteria, and the larger-model/wrapper requirements, remain open.
A smaller committed-matmul integration can test R3/R4,
but is not W8 or project completion. Do not add another isolated arithmetic
study unless it resolves a named missing condition in this DAG.

The next R2 review package is a native committed-field source consumer.
Use the existing conditional proofs in `formal/certified-functional-opening.md`
and `formal/stacked-statement.md` to specify expected root/layout/code binding,
canonical certificate/opening bytes, unbiased queries and certificate reuse.
First resolve how actual Merkle commitments, including missing or partial
leaves, instantiate the complete field-valued oracle assumed by the proof.
Then terminate existing A1 original claims in Circle/Merkle opening checks;
the verifier receives expected roots rather than the original input tables.
Keep every separate row/group equation and consume zero-coefficient originals.
This package needs RFC review before native code. Packing, CQIS integer
ownership, ZK and Q12 remain separate obligations, not implied achievements.

## Evidence required at the integration boundary

The independent verifier derives the complete plan and certificates from
expected passport/configuration bytes. Tamper passport, prompt, output,
cuts, layer association, function/representation, selected source and
multiplicity independently; each actual consumer must reject with its
catalogued reason. Reject ignored records, noncanonical fields and alternate
proof-supplied authority. An unused original still needs its source check.

The benchmark ledger records the actual commit, plan digest, proof size,
preparation, recompute and prover stages, both verifier times, peak memory
and executed controls. Verify one weight pass per type and one batched
R_stack opening. HF Jobs may supply CPU/GPU capacity for a pinned command
and artifact manifest; a remote exit code alone is not proof evidence.
No benchmark result is claimed by this plan.

## Current validation boundary

The new graph regression first reproduced the missing prerequisite
closures. Review caught the global-control cycle and refined the tested
dependencies to native verification and accounting. The final regression
passes; every task status and acceptance line is unchanged. Baseline gates run on the audited
main checkout; their completion must be recorded before this change lands.
The RMSNorm test correction and its full-size rerun have separate evidence.
No native proof, profile, privacy or independent audit completion is claimed.
