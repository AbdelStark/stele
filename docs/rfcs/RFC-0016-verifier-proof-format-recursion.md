# RFC-0016 — Verifier, proof format, recursion wrapper

Status: Accepted · Version: 0.1.0

## 1. Proof container (`stele-proof-v1`)
Self-describing, versioned, little-endian: header (`magic`, `version`, `profile`, `cqis_id`, `passport_root`,
`io_digest`, `policy`, ledger hash), then stage sections in transcript order, each with its reduction id, round
polynomials, final claims, lookup roots, PCS openings. Size bounds are derived from `plan.json`; the verifier refuses
any proof whose size deviates from the plan (no variable-length prover control).

## 2. Verifier algorithm
1. Parse header; derive `plan.json` from `cqis_id` + passport (never from the proof).
2. Recompute bound certificates (RFC-0004 §6) and the error ledger (RFC-0012 §4); reject if out of profile.
3. Replay the claim graph: initialise transcript with `π`, draw `ρ`, walk stages; for each reduction verify sumcheck
   rounds, evaluate public MLEs (`eq`, masks, RoPE tables, one-hot from opened indices) at the final points, check
   emitted-claim consistency; for lookups verify fraction-tree roots and the table-side sum; for PCS openings verify
   `u·b`, column spot checks, Merkle paths.
4. Accept iff all checks pass. Cost: `O(Σ rounds·δ)` K-ops + `O(q·R)` per opening + `O(2¹⁶)` per table ⇒ seconds on 8 cores.

## 3. Implementation constraints
`stele-verifier` is `no_std` + `alloc`, < 15k LoC, zero dependencies beyond `stele-field`/`stele-hash`, every check
annotated with the RFC section, panics forbidden (all errors typed). An independent Python verifier in `harness/verifier`
is kept in lockstep by CI (RFC-0002 S10).

## 4. Table MLEs
Natively: evaluate `T̃(r)` over the 2¹⁶ entries. Wrapper mode: open the passport-committed table matrix (RFC-0011 §1.3).

## 5. Recursion wrapper
Purpose: compact certificates (≤ 500 KB, ≤ 200 ms) for registries and on-chain use. The wrapper proves "the Stele
verifier accepted" — a layered computation dominated by Blake3/Merkle checks and K-arithmetic — in an M31-native STARK
(Stwo/stwo-cairo verifier infrastructure, StarkWare-maintained) with Ligerito-mode openings to keep column openings
small. The wrapper is **optional** and **outside the soundness-critical path of native verification**; its own
accounting is a separate ledger. Hash: Blake3 for the inner proof; the wrapper's transcript may use Poseidon2-M31.

## 6. One-time wrapper jobs
Checkpoint-binding proof (RFC-0011 §1.5): hash `digest_cqis` over the committed plaintext in-circuit; batched over the
column leaves so that the Merkle structure is reused.

## 7. Negative controls
NC-1200 proof section reordered; NC-1201 plan derived from proof header instead of passport; NC-1202 panic path in verifier
(fuzz target); NC-1203 wrapper accepting a rejected inner proof.

## Amendment log

### A1 — Bind the complete private verifier relation and composition

Status: Draft. Question Q30; related Q12, Q14 and Q29 / RFC-0013 A1.
Evidence: [private verification derivation](../../formal/private-verification.md),
[finite experiment and report](../../research/private-verifier/REPORT.md),
[pinned upstream source inspection](../../research/private-verifier/UPSTREAM.md).
Review: [same-author skill passes](../../agents/reviews/private-verifier-study.md).
Motivation: §5 does not fix the exact public/private relation or quantitative
knowledge composition. A generic proof of existential acceptance alone need not
preserve computational soundness of the inner argument. Upstream privacy code
exists, but its inspected configuration does not establish Stele's profile.

Proposed replacement for §5, pending the complete instantiation below:

> The compact wrapper proves knowledge of the entire canonically parsed inner
> proof pi accepted by the approved complete Stele verifier V on exactly the
> externally expected public statement s. Bind spec/format, verifier/program,
> profile, field/CQIS/plan, passport, input/output, policy and all public security
> parameters. Recompute the ledger from authenticated configuration. No supplied
> accept bit, unchecked plan/program identity or host-side call replaces the
> constraints enforcing R_V(s,pi). All acceptance-affecting parser, field,
> transcript, claim, certificate, lookup and PCS checks must execute in relation.
>
> Pin the selected backend/mode, verifier/preprocessing identity and quantitative
> argument-of-knowledge theorem. Compose its extraction loss, work and queries
> with the inner argument's actual resource-dependent bound. Account for all
> statement-digest, hash, Fiat-Shamir, recursion and grinding terms jointly under
> RFC-0002; a backend name or parameter bit count is not profile admission.
> Supply a simulator for the complete public view and its repeated-use/privacy
> lifecycle whenever this proof is used to hide the inner witness. Secret masks,
> seeds, code fields, quotient/FRI disclosures and public outputs are explicit.
>
> The compact wrapper remains optional and outside native verification's critical
> path. Selecting it instead as the source of treaty privacy requires an explicit
> Accepted architecture change making it mandatory and soundness-critical for
> that path, defining its external proof format and forbidding unwrapped fallback.
> Native ZK and every original source/claim obligation remain until such a change.
> There is no downgrade from treaty to standard and no missing-MASK bypass.
>
> Charge the full preparation, verifier execution, outer proving, serialization
> and peak overlapping state to the cost model. Preserve one weight pass and the
> original complete workload gates. W8 remains <=500 KB and <=200 ms; if selected
> for ZK, the original <=5% overhead requirement still applies. Separate native
> and outer ledgers; Poseidon2 use additionally requires Q14's Accepted mode and
> accounting. Implement NC-1203 against the real wrapper with a rejected inner
> proof, plus actual statement/program/parameter substitution controls.

Before acceptance: specify every message/constraint/encoding and allowed public
output, instantiate a proven-only backend and exact extraction/simulator/FS/hash
theorems, resolve Q12/Q14 dependencies, provide complete native evidence and
source/claim/control coverage. The conditional relation and finite experiment
do not select a privacy architecture or complete these obligations.

Soundness: no production challenge, binding or accounting record changes. The
formal note's kappa + L*epsilon_inner implication is conditional on an extractor
with its stated resource bounds; it is not a generic backend theorem or an
automatic loss-one sum. Privacy advantage is separately derived, not conflated
with false-statement acceptance. No conjectural term is admitted to treaty.
Cost: T_misc / explicit outer preparation/proving work, source reads, retained
proof and peak state. No measured constant or extra weight pass is introduced.
Affected tasks: E14-01 (blocked on A1), E14-02/E14-03; E12-01/Q29 if an eventual
privacy architecture selects this path. All original acceptance criteria remain.
