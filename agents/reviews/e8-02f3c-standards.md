# E8-02f3c — independent standards review

Reviewer: `registry_cli_standards_review`, other-lane B/P review.
Base: `c0263e3e9ec3389c8154606fa6a3435932265755` (PR #388 merge).
Implementation reviewed: `dece84b2`, including task claim `f6910bd9`.

**Decision: APPROVE for standards and the B/P-owned integration surface.**
No unresolved documented standards violation or actionable design-smell finding.
This review does not replace the separate specification review or the required
current-base, intended-merge-tree and complete workspace/native validation.

Sources read: AGENTS.md; invariants and glossary; code, security, forbidden,
soundness and review-checklist guardrails; Workflows 01, 03 and 10; the
soundness-auditor skill; task E8-02f3c; Accepted RFC-0026 A16 and the referenced
production validation paths. RFC-0030 was read as skill-requested background only;
its Draft text supplies no authority for this change. No CONTRIBUTING.md or
CODING_STANDARDS.md was identified in the coordinator's repository search.

## Scope and standards assessment

The change reaches the public publisher module, shared bundle serialization,
the CLI commands/options, publisher and process tests, examples, and native gate
inventories/receipts. It adds no dependency, verifier implementation, GPU path,
new relation, profile admission or benchmark claim. The base contains the merged
E8-02f3b predecessor; the claim records E8-02f3c as the serial successor. The
user's requirement to validate and merge this PR before starting another
implementation task still applies.

`registry::publish` implements A16 §5 using production decoding, statement
validation, static relation validation and commitment-certificate validation
before returning bytes. It captures the original declaration before normalizing
only the specified request-column values and widths for the hash preimage.
The metadata comes from the decoded Model and Token scale row. Its inputs contain
no model secret or inference witness. A sample's greedy claims need not be true
to publish the static entry; the documentation says so.

`plan-digest` validates before writing the entry. `prove-dev --relation` completes
publication before writing its outputs. Write errors propagate as exit code 2;
these ordinary output writes are not a multi-file transaction. This adds no
secret-state persistence path. New incompatible options are rejected by the
existing allowlist or the relation/profile check before reaching dev-zk ownership;
the lock, counter, persistence and rollback implementation is unchanged.

`verify-registered` calls `stele_verifier::registered::verify`, then displays the
authenticated public request with the existing identity formatter. The shared
expected-model parser preserves the old verification behavior. The API, command
documentation and success verdict retain **trusted plan registry; development:
no security level** and tell callers to pin the entry separately and compare the
displayed request. They claim no independent model derivation, ZK replay or
admission (A16 §§1,4–5).

The two gate inventory changes admit the exact publisher path; they do not allow
standard-profile calls or arbitrary sibling files. The CLI integration test is
ignored in ordinary test execution but explicitly required by native admission:
both rung receipts, the exact passing test line and the harness completion marker
must be present. No optional missing-directory return can earn this receipt.

The supplied smell catalog is advisory. Existing serialization and identity
helpers are reused. Keeping production derivation separate from the independently
authored verifier preserves the architectural boundary; it is not an actionable
duplication finding. The small publisher module and direct CLI calls need no new
wrapper, generic abstraction or domain type solely to satisfy that catalog.
Tool-enforced formatting/lint matters are left to the required coordinator gates.

## Executed checks and rejection experiments

- Existing release development test binary: publisher entry/request invariance,
  saturation, malformed model/commitment/profile/request rejection, and both
  plain/dev-zk false-witness checks passed. The L0 byte-5 honest prove/verify test
  also passed its existing proof digest pin. The honest prover invokes the plain
  checker; the near-miss tests require `Error::Check` for changed next/checked tokens.
- Actual release CLI option harness passed. Additional actual processes published
  the pinned entries and independently verified both reference windows in
  `/tmp/stele-a16-windows`; a changed trusted model-key byte was rejected as
  `RegistryKeyMismatch` on each rung.
- Actual publication failure probes: malformed Model bytes and a byte-3 public
  file returned `StatementMismatch` without overwriting a pre-existing entry
  sentinel. An unwritable output destination returned exit code 2. Incompatible
  `--zk`, `--relation`, `--dev-profile 3` and `--admit` combinations left the
  temporary secret, sidecar lock and relation output absent.
- Python 3.12 native accounting receipt/surface regression and quarantine tests
  passed. The regression removes each required CLI rung receipt, test result and
  completion marker and requires admission failure; its success messages are
  mocked gate behavior, not evidence of actual proof execution.
- Additional assert-based probes admitted the exact publisher inventory while
  rejecting unauthorized sibling source entries. In isolated temporary source
  fixtures, the publisher could name its development source set, but
  `resolve_pcs`, `Descriptor::standard` and `Policy::Two` were rejected; a sibling
  module naming `Sources::CircleAllGrind` was also rejected. Shared source files
  were not mutated.

I tried to break it by changing a trusted entry's model-key byte against each
genuine reference proof, and the actual CLI wrong-entry control rejected it with
`RegistryKeyMismatch`. I also supplied invalid publication data and suppressed
mandatory gate receipts; publication preserved the existing entry and admission
rejected the missing receipts.

## Workflow 03 checklist

| Question | Assessment |
|---|---|
| New public items and RFC | `development::registry` and `publish` implement A16 §5; `plan-digest`, relation export and `verify-registered` expose A16 §§1,4–5. Public API documentation states the trust premise and output meanings. |
| Challenges and absorb order | No new challenge or transcript mutation. Certificate verification reuses its existing path; original public/proof/relation bytes reach independent A15 replay. |
| Emitted claims and consumers | No new proof claim. The exported original relation is consumed by the independent registered verifier; normalized bytes are only a hash preimage. |
| Binding controls | Existing A16 NC-1325..1334 own the registered bindings. The new actual CLI wrong-key control exercises NC-1325's edge; publisher rejection tests cover malformed model/scales/preparation/records, roots/certificates, source profile and request. |
| Ledger/accounting | No SC/SZ/RLC/LU/PCS/MASK line changes. A16 §6 retains global H/compression obligations for wrapper, publisher and adversary queries; no security level is inferred. Complete accounting/native execution remains the coordinator's required gate. |
| Bound certificates | No new arithmetic instance. `Relation::validate` checks the original production-derived relation before normalization; trusted dimension sums are checked explicitly. |
| Padding/masks | No proof-padding or mask change. Request normalization preserves counts/order/log lengths, with original request values supplied by existing production layout. |
| Determinism | Ordered vectors, fixed request-name matching and canonical encodings; no hash-map iteration or timing-dependent reduction introduced. Publisher pins and request-invariance tests passed. |
| Parity | No SIMD/CUDA change. L0's existing proof digest passed; both L0/L1 reference proofs passed actual registered CLI verification. New full CLI byte comparisons are mandatory in native admission; no GPU parity claim is made here. |
| Cost model | Publication and registered verification add deterministic work under A16 §6; no measured constant, proof size, committed-cell count or weight-pass count is claimed to improve. No new benchmark ledger is warranted by this diff. |
| Verifier bounds | Verifier source and dependencies are unchanged and remain `no_std`. New CLI plumbing calls the existing independent entry point; no new verifier panic or length derivation is introduced. |
| Glossary | No forbidden synonym introduced in the changed implementation. |
| Tier | Development only; the API/docs/verdict retain the trust premise and no-security-level qualification. No promotion. |
| Commit rule | No committed or virtual column introduced or reclassified. Development columns retain Accepted RFC-0026 authority; Draft RFC-0028 is not substituted as law. |
| Plain checker | Honest L0 byte-5 prove/verify and plain/dev-zk changed-next/checked-token rejection tests executed successfully. No numerical module changed. |
| Segments | No segment or carried-column behavior changed. |
| Proof bytes | No intended encoding change; shared static serialization retains field order. L0 digest and publication pins passed. Full CLI equality of public/proof/relation bytes on both rungs is required by the coordinator's native gate. |
| Ladder | Actual publication and registered verification exercised L0/L1 reference windows; L0 was freshly proved here. No before/after performance comparison or H100 execution claim. |

Skipped duplicate full workspace/native and GPU suites because the coordinator
owns those validations. Entry correctness/distribution remains trusted, and
ordinary output writes are not transactional; this review grants no profile admission.
