# E16-40f importer Standards review — FIX

Fixed point: absent files; reviewed complete contents of the two external additions. No repository or shared-source changes.

SHA-256:
- `package.py`: `204e1a6f34dc360a39fb3d32e40e96c6b6ac01a3d12508c6ac84eca4f6e70a4b`
- `test_package.py`: `ce1107fdd69eef29d76f4920155622e3400538370965b7fd4f0b8bb5ad9f3480`
- Unchanged sibling `capture.py`: `b31c0a867cb291aed2ab911d124d1458b95e12c304fd1bae6ac1d5e19f2a6e5d`

Applied AGENTS.md, relevant guardrails/invariants, benchmark-runner, Workflows 04/09, RFC-0018 A1/A2, RFC-0027 §3 and existing micro-ledger conventions.

**Hard finding (P2): failed/contradictory timing evidence is accepted.** `package.py:76` trusts `gnu_time`, whose GNU success check is a substring search and whose BSD branch ignores exit status. In isolated fixtures, changing only `build-baseline.time` and resealing the manifest allowed all six records for each of: appended `Exit status: 1` after `Exit status: 0`; replacement with `Exit status: 01`; and a BSD-shaped report containing `Exit status: 1`. Metadata still reported success, so contradictory evidence escaped rechecking. This violates the requested refusal of failing evidence. Require one exact GNU exit-status field equal to zero for this Linux capture before using the shared parser; add resealed controls for these cases. Keep the reviewed capture unchanged.

**Validation:** Python 3.12.12: all eight supplied tests passed. Independent synthetic probes rejected wrong host, nonzero/boolean metadata exit codes, timeout, NaN/Infinity, duplicate keys, and optimized Python. CLI probes preserved an existing destination and created no destination for validator failure or missing validator. A temporary CLI validator stub observed six calls and six emitted synthetic records; this was orchestration testing, not ledger-schema or hardware evidence. Positive and negative speed hypotheses retained six records.

The existing duplicate-key unit test currently fails at the manifest hash check before exercising duplicate parsing; resealing that mutation would make its stated control effective. Direct and resealed independent probes confirmed duplicate rejection works.

**Heuristics:** no additional smell-based changes recommended; the single-purpose importer and reuse of the pinned capture keep scope narrow.

Skipped GPU work, actual job6643 import, full repository suites and native schema validation. No measurements or hardware outcome are established; timing rejection remains the release risk.

## Final re-review — PASS (supersedes FIX)

Final SHA-256:
- `package.py`: `e711a2db22a81a2e49d13f1981cb3d0ec8ffd4b1115acc60ca08f440b1be72be`
- `test_package.py`: `a11f7a4875daa44dc111fd95b5d87b1b77222fec727bccf40221f4e7f037b611`

Capture remains unchanged. All 12 tests pass. Original failures and prefixed timing-field counterexamples now reject. Duplicate parsing, chronology, same-seed roots and canonical plan checks pass. Both synthetic CLI outcomes produce six native-schema-validated records; temporary outputs were removed. No hard findings or additional heuristics remain.

Still skipped hardware and full suites; synthetic validation establishes no measurement result.
