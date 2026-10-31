# Certificate production review

Codex-root applied pcs-engineer. A separate read-only soundness-auditor approved
this producer-only slice after code, fixture and gate review. This is internal
agent review; full repository gates remain queued.

- PreparedSource::certificate and CertificateFailure implement RFC-0010 A9 §§3,9;
  Transcript::certificate_column implements RFC-0012 A10 and native contract §2.
- Source context precedes row draws; all canonical t bytes precede query draws;
  the complete ordered response block precedes a real continuation challenge.
- Output consists of unverified bytes and hash observations. No certificate ID,
  CertificateRecord, verified handle or accepting verifier is introduced.
- Independent full-wire and continuation fixtures check producer correctness.
  Native query-binding rejection controls remain required with the actual verifier.
- Four consumed labels map to PCS_TENSOR and PCS_QUERY as documented in the
  accounting ledger. No evaluated FS/H, global cap or profile claim follows.
  The complete accounting gate remains queued with the other required gates.
- Existing static source geometry and all 59 finite query policies remain.
  Proof sizing is checked; proof and coefficient allocations are fallible.
- Dimensions coincide with logical dimensions; there is no implicit padding.
- Fixed iteration and full repeated responses preserve determinism. All six
  QM31/OM31 full-wire fixtures and actual continuation values match.
- Production reuses prepared columns/paths and performs no encoding or Merkle
  hashing. Coefficients are dropped before response paths. Complete resource
  measurements remain open; no measured constant or matmul pass count changes.
- no_std and unsafe prohibition remain. Every failure after transcript creation
  snapshots its usage before returning; no failed proof or continuation escapes.
- Glossary review found no conflicting term. Stale sampler/identity comments
  found during review were corrected before commit.

Focused root checks passed: both-crate native tests/doctests, Clippy,
workspace/no_std and dependency checks, seven gate regressions and two scaffold
tests. Review independently ran both sampler and producer tests, gate rejection
regressions and the Python wire/continuation checker.

I tried to break it by supplying invalid column domains, exhausting the
64-attempt decoder, overflowing usage, and adding unwired accepting APIs, and
the sampler controls and gate regressions rejected it.
