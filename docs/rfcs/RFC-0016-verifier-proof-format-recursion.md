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

### A2 — Exact public input before transcript construction

Status: Draft. Question Q26; task E5-03b. Motivation: §1's header sketch does
not determine complete policy bytes, actual request geometry or I/O mode.
Companions: RFC-0001 A2, RFC-0005 A4 and RFC-0011 A5.

Proposed addition to §§1,2: the complete externally expected public statement
has the [RFC-0025 public-input bytes](full-model-public-input.md). A proof's copy
must match them exactly. Validate the complete passport, derive its numerical
identity and request-specific plan/ledger, and enforce the expected profile
before constructing the transcript. Its existing constructor absorbs those full
bytes once; no separately serialized subset, supplied plan or accept bit suffices.
Public generated length and stop reason reach the same actual token sources,
selectors and stop/inference relations. Both I/O modes retain private proof and
source obligations. The outer wrapper, if used, binds this same complete input.

This does not select a wrapper/ZK architecture or instantiate missing plan,
passport, private commitment, ledger or native verifier contracts. A1/Q12/Q29,
all original source checks and full native/W8 requirements remain. No challenge,
additional absorb, profile or loss line changes; existing complete H/query
accounting remains mandatory. Parsing/derivation contributes T_misc without a
measured constant or weight-pass change. Affected tasks: E5-03b, E6, E8,
E12-05 and E14. NC-0804/0805 and NC-1201/1203 remain actual-consumer gates.

### A3 — Checkpoint evidence binds the pre-evidence subject

Status: Draft. Question Q26; task E5-03b. Companion RFC-0011 A6 and the
[passport composition contract](full-model-passport-composition.md).
Motivation: a checkpoint-binding proof included in a passport cannot depend on
the final root that includes that proof's own bytes or digest.

Proposed clarification of §6: checkpoint evidence binds the exact subject_id
and the same complete original Artifact, numeric/source, commitment/layout/code
and plan/table fields in that subject. Its actual relation proves the required
commitment-to-Artifact hash binding; repeating subject_id establishes nothing.
Its complete proof/public-input codec and private source consumers remain
mandatory. The resulting evidence is referenced before registration/signing and
the final passport root are formed. Proximity evidence follows the same identity
order under its own complete certificate contract.

This supplies no wrapper/backend, new proof acceptance path, challenge or
profile. Complete H/query and signature/evidence composition remains required;
Q12/Q29 and A1's actual verifier/privacy/extraction obligations remain unchanged.
No cut, online weight pass or measured constant changes. Evidence generation
and verification remain T_misc/registration work. Affected tasks: E5-03b,
E12-05/06 and E14, with actual wrong-subject/root/source controls still required.

### A4 — Accept statement and checkpoint-subject identity order

Status: Accepted. Question Q26; task E5-03b.
Review: [coordinated skill sign-offs](../../agents/reviews/full-model-cqis-draft.md#coordinated-acceptance-sign-offs).

Motivation: full statement bytes and checkpoint evidence need acyclic identities.
Exact additions to §§1,2,6: adopt A2/A3's complete statement and pre-evidence
subject rules under [RFC-0025 public input](full-model-public-input.md) and
[passport composition](full-model-passport-composition.md).
A2/A3's Draft proposals are superseded. Validate the externally expected
complete statement, real passport children, instance/ledger and profile before
the existing transcript constructor absorbs the public bytes once.
Checkpoint/proximity evidence must establish its real relation for the same
earlier Subject and original private sources; repeating subject_id proves nothing.
No evidence or signing preimage contains the later final passport root.

A1's wrapper/backend/privacy/extraction and Q12/Q29 work is not accepted here.
Complete native verifier, private source and child contracts remain mandatory.
No new challenge, absorb, loss, profile, cut or weight pass. H/signature/evidence
accounting and NC-0804/0805/1201/1203..1206 remain real-consumer gates.
Derivation/verification is T_misc/registration work without a measured constant.
Affected tasks: E5-03b, E6, E8, E12-05/06 and E14.
