# E8-02f3c: publisher and CLI soundness review

Reviewer: `registry_cli_spec_review`, fresh soundness-auditor and other-lane C
reviewer. Integration owner: `codex-root`, lane V. Fixed base:
`c0263e3e9ec3389c8154606fa6a3435932265755`. Implementation reviewed:
`dece84b219aadfcee622dcf31c03aead6b626f12` (claim commit `f6910bd9`, then
implementation). Diff: `git diff c0263e3e9ec3389c8154606fa6a3435932265755...dece84b2`.

**Verdict: approve on specification, soundness and lane C review axes.** No
missing or partially implemented runtime requirement, unrequested behavior, or
incorrect implementation found in this diff. Approval does not certify the
integration owner's pending cumulative gates or current-main merge tree.

Read AGENTS.md, the soundness-auditor skill, invariants, glossary,
code/security/soundness/forbidden guardrails, the complete review checklist,
Workflows 03/10/12, the E8-02f3c acceptance criteria, Accepted RFC-0026 §8 and
A15/E1, and all of Accepted A16. RFC-0030 was read as required background only;
Draft text grants no implementation or promotion authority.

## Requirements and trust boundary

- **Production validation.** A16 §5 (RFC lines 2172–2176) requires publication
  from a "production-validated model, commitment and window size" and says it
  "must not read a model secret." `registry::publish` checks the byte-5 source
  set, uses existing `decode` for canonical Model/Scales/Preparation and exact
  ordered/ranged 1-D records, validates the sample request and A16 dimension
  limits, then derives the production layout. The layout checks the §2.2 weight
  role/column order and source count. The original `Relation::validate` runs
  before publication; every supplied model root/certificate is checked against
  its plan-derived source geometry by existing `certificates`. No artifact,
  executor, witness, secret file or hiding state is loaded by publication.
- **Canonical entry.** A16 §1 (lines 2076–2077) requires metadata from "the Model
  and the Token scale row in the exact static bytes authenticated below."
  The publisher gets V/d/f0 from the decoded Model and ee/mantissas from the
  Token ordinal's decoded Scales row. Field order, widths, tags, digest preimages,
  original relation length and ordered roots match A16 §§1–2. The factored
  `bundle::static_data` preserves the existing bundle bytes and record byte
  lengths; model identity continues to use code counts as required by A15 §3.
- **Request invariance.** A16 §5 says the result "must be invariant under tokens,
  checked range and next token for that key." The existing production declaration
  supplies precisely the request columns named in A16 §3. Publication saves the
  original declaration, then sets only their public values to zero and widths
  to unsigned 1 for hashing. Names, kinds, counts, order, log lengths and all
  static declaration bytes remain unchanged. Both shift branches, selected
  mantissa widths, checked ranges, next-token changes and saturation matched the
  existing vectors. A well-formed sample with false greedy claims also produced
  the same entry: publication does not accidentally require an inference proof.
- **Original relation and independent replay.** A16 §4 (lines 2150–2154) says
  "N is a hash preimage, not a relation to validate or prove" and "Validate and
  replay the **original** relation." Export returns bytes captured before
  normalization. `verify_registered` calls `stele_verifier::registered::verify`
  before its production bundle decode or model identity computation. The
  independent entry point still executes entry/public/key/static/length/request/
  template checks and original A15 replay. No verifier or proof runtime source
  changed in this PR.
- **Display decoding is not verification.** The post-replay production calls in
  `crates/stele-cli/src/main.rs:436` obtain the printed identity/request and the
  optional expected-model comparison. Their errors can only reject; they cannot
  create `Verified`, skip independent replay or make a rejected proof succeed.
  The same in-memory public bytes are used throughout. A valid preflight with
  invalid proof bytes failed with `Header`, before any identity display. It
  would be incorrect to describe this CLI as independently deriving the model;
  its documentation correctly makes no such claim.
  The CLI does not separately compare its recomputed identities with the opaque
  verifier's accepted entry key. They agree under A16 §1's correct-publisher
  premise. If a caller pins inconsistent CQIS/model metadata, the printed and
  `--expect-model` identity could differ from that accepted key; this is not
  independently enforced by the display path. A16 §6 conditions its guarantee
  on a correct trusted entry and does not require this extra consistency check.
  I therefore record the limitation without demanding duplicate entry parsing
  or a verifier API change in this task.
- **Caller trust and tier.** A16 §1 (lines 2047–2052) states that a matching entry
  from the prover "is not authentication"; A16 §4 (lines 2162–2168) requires the
  exact-request scope and both "trusted plan registry" and "development: no
  security level." API/CLI documentation and the actual success verdict preserve
  these premises. Printed tokens/range/next let the caller compare its expected
  request; `--expect-model` rejects a wrong model expectation. There is no
  signature service, new trust mechanism, ZK replay or profile promotion.
- **CLI, gates and compatibility.** A16 §5 requires a usable four-file path and
  says "exporting the relation changes no public/proof byte." The new commands
  implement that path, reject unsupported options/profiles, and retain existing
  verify-dev APIs. L0/L1 examples and the process harness check original
  public/proof/relation bytes against unchanged pins. The native gate requires
  each rung receipt and the completion marker; its targeted missing-receipt
  regression passed. No dependency, Accepted RFC, golden vector or existing
  verification API was changed.

The task's third acceptance line also requires all native gates. Those remain
the integration owner's required final evidence; this scoped review neither
replaced nor reran the cumulative gate run. This is an integration dependency,
not an omitted implementation requirement.

## Executed checks and attacks

Used already-built release artifacts from this worktree, avoiding compilation
contention with the integration owner's gate run. Each following development
test ran directly as
`target/release/deps/development-c2976b731a4364b3 <name> --exact --nocapture`
and passed:

- `matches_reference_published_entries_and_request_invariance` — both L0/L1 entry
  and original-relation pins, both exponent branches, selected widths, ranges
  and next-token changes.
- `accepts_registry_saturation_without_request_dependent_entry_bytes`.
- `rejects_invalid_registry_model_commitment_profile_and_request` — malformed
  Model/Scales/Preparation/vector ordinal, absent commitment, other source sets,
  changed root/certificate, invalid tokens/next/presence/range/window length.
- `accepts_one_layer_window_on_a14_sources` — honest L0 proof, unchanged proof
  digest, plain checker and verifier acceptance.
- `rejects_false_witness_with_check` — false next-token and checked-token cases
  rejected by the plain checker with `Error::Check`.

`python3 crates/stele-cli/tests/registered.py target/release/stele . options`
passed, including real-process wrong-entry rejection, required byte-5 relation
export, refusal of `--zk --relation`, `plan-digest --secret` and registered
`--admit`, with no secret lock or output created by those rejected options.

An additional assert-based Python process probe used only temporary data files
and the checked-in A16 vectors. It passed with receipt
`A16_SPEC_REVIEW_ADVERSARIAL_PROCESSES_PASSED`:

- An L0 publication equaled its pinned entry. Replacing every token, the checked
  range start and next token with a different well-formed sample retained exactly
  the entry, without checking whether those greedy claims were true.
- Separate one-byte Model, Scales and Preparation corruptions and a changed
  public-record length rejected with `StatementMismatch`. Removing all
  commitments also rejected with `StatementMismatch`.
- A root-byte change rejected with `Commitment(Transcript(GrindMismatch))`; a
  certificate-byte change rejected with `Commitment(Merkle(RootMismatch))`.
  Failed publication preserved a pre-existing sentinel output file.
- Public magics v1/v2/v3 and both dev-zk public magics were refused by
  `plan-digest` with `StatementMismatch`.
- All nineteen request-negative vectors and three malformed/precedence vectors
  ran through actual `verify-registered` processes with deliberately invalid proof
  bytes. They returned the specified preflight errors; changed-length vectors
  correctly returned `RegistryTemplateMismatch` before request decoding.
- The genuine L0 entry/public/relation with invalid proof bytes returned
  `Header`, proving that successful preflight cannot replace proof replay.
  Changing the entry profile to 4 instead returned `RegistryEncoding` first.

A second actual-process probe used the unchanged full public/proof/relation files
in `/tmp/stele-a16-windows/{one-layer,eight-layer}` and passed with receipt
`A16_SPEC_REVIEW_FULL_WINDOW_REPLAY_PASSED`. Both accepted with their pinned
entry and model expectation, printed all six identity/request lines and the
required trust/tier verdict. Both rejected an all-zero model expectation and a
one-byte trusted-entry model-identity corruption; the latter printed only
`NO: RegistryKeyMismatch`. Fresh CLI proof generation and byte equality on both
rungs were also reported passed by the integration owner; I inspected their
mandatory harness assertions rather than repeat that generation.

`python3.12 -m unittest scripts.tests.test_native_gate.NativeGateTests.test_rejects_missing_accounting_receipt_and_unadmitted_verifier_surface`
passed. This is the targeted mocked receipt-removal regression, not an actual
native gate run. The first invocation under system Python 3.9 could not import
`tomllib`; rerunning with installed Python 3.12 resolved that environment issue.

I tried to break it by publishing changed model roots and certificates and by
supplying changed request columns through the CLI, and the control
`rejects_invalid_registry_model_commitment_profile_and_request` and the executed
A16 request-negative process controls rejected it with commitment errors and
`RegistryRequestMismatch`, respectively.

## Workflow 03 checklist

- **Public items / RFC:** `registry::publish`, `plan-digest`, byte-5
  `prove-dev --relation` and `verify-registered` implement Accepted A16 §5;
  entry/metadata/hash rules are §§1–4. `static_data` is private to the production
  module and preserves A15 §2 bytes. No item relies on a Draft rule.
- **Challenges / absorbs:** none added or moved. A15 replay retains the full
  transcript input, original relation digest and ordered model roots; source
  certificates use their existing context-bound transcripts. Identity, lookup
  nonce/β/α, matmul, claim-batch and opening orders are unchanged. Registry
  bytes never enter the proof transcript.
- **Claims / consumers:** none added or moved. Original public MLE claims reach
  the existing public evaluations; witness/weight claims retain the existing
  source opening or reduction and the same points. Publication emits static
  authenticated metadata, not a substitute proof claim.
- **Bindings / controls:** existing NC-1325/1327 bind key/roots, NC-1326 static
  bytes, NC-1328–1333 request values/widths and NC-1334 the static template;
  they are unchanged, and their composed proof construction remains owned by
  E8-02f3b. I did not rerun that full catalog. This review executed the new
  publisher rejection test, real wrong-entry processes on both full proofs,
  and all A16 request-negative/preflight vectors through the CLI. No new
  protocol binding is introduced by this adapter.
- **Ledger / accounting:** no SC/SZ/RLC/LU/PCS/MASK line, round or theorem
  changes. A16 §6's static/model/template hash invocations and their compression
  work, including publisher/adversary/repeated attempts, remain part of global
  H. Registry trust is an explicit premise, not a probability. Cumulative
  soundness-accounting/native agreement remains the integrator's gate.
- **Bound certificates:** no new arithmetic instance. Production Model/Bounds
  derivation, A16 static dimension limits, original `Relation::validate` and
  plan-derived source certificate verification all run. Normalized widths are
  used only in the hash preimage and never as arithmetic bounds.
- **Padding / masks:** no relation construction or masks change. Existing
  embedding padding and argmax padded/unchecked zeros are preserved; only
  listed request values/widths normalize. Both sign branches and checked-range
  changes match the locked declaration vectors.
- **Determinism:** canonical vector iteration and explicit encoding only; no
  hash-map order, clock, randomness or parallel reduction was introduced.
- **Parity:** no SIMD/CUDA source changed. CPU L0 digest and L0/L1 entry/relation
  pins passed; full pinned proofs passed independent CLI replay. No new GPU
  parity result is claimed, and integrated GPU work is outside this task.
- **Cost model:** publication/export and registry comparisons add `T_misc`
  work; no `T_weights`, `T_act`, `T_attn`, `T_cuts`, committed-cell, lookup or
  weight-pass change. No measured speedup or before/after benchmark claim,
  therefore no new timing ledger is asserted by this review.
- **Verifier:** runtime and dependencies are unchanged and remain independent
  and `no_std`. Existing registered parser uses trusted lengths and fallible
  allocation. New production publication and CLI code contain no unsafe,
  float, verifier bypass or proof-derived parameter. I did not repeat the
  unchanged verifier's no_std build or fuzz campaign.
- **Glossary:** established Model/Scales/Preparation, relation, column, root,
  certificate, source and development-tier terms are retained.
- **Tier:** development byte 5 only. Unsupported public/profile forms reject;
  the success message claims neither a security level nor standard/treaty
  admission, independent model derivation or ZK replay.
- **Commit rule:** no committed/virtual column, advice, source or cut changed.
  The request normalization is only a hash preimage transformation.
- **Plain checker:** ran the honest L0 proof and both existing false-witness
  near-miss cases; honest acceptance and `Error::Check` rejections are preserved.
- **Segments:** no segment, carried-column or cross-segment-read change.
- **Proof bytes:** original declaration returned before normalization; bundle
  refactoring preserves the A15 bytes. L0 proof digest and existing declaration
  pins passed; the integration process harness compares all L0/L1 public/proof/
  relation bytes. No golden vector was regenerated or changed.
- **Ladder:** independently exercised L0 honest prove/verify, L0/L1 publisher
  pins and both complete L0/L1 proofs through the registered CLI. This is
  functional/control evidence, not a performance comparison; no mixed-rung,
  host or thread-count timing claim is made.

Skipped cumulative workspace/native/current-merge-tree and GPU gates, which
remain integration responsibilities. Residual premise: callers must trust the
publisher and separately pin the correct entry and expected public request.
